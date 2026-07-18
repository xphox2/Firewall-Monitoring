package handlers

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ipFilterClause turns a user-supplied `src_addr` or `dst_addr` query value
// into a WHERE clause + bound argument. Supports:
//
//   - exact match:        "10.0.0.5"           → column = ?
//   - octet-aligned CIDR: "10.0.0.0/8|16|24"   → column LIKE prefix.%
//   - /32 CIDR:           "10.0.0.5/32"        → column = ? (network IP)
//   - any other input:    fall back to exact match against the raw string,
//     so a malformed CIDR doesn't crash and the operator still sees something
//
// We use prefix matching on the text column rather than casting to inet
// because flow_samples.src_addr/dst_addr are stored as strings and we want
// the same code path to work on SQLite (test DB) and Postgres (prod).
// Non-octet-aligned CIDRs (e.g. /20, /28) fall back to exact match on the
// network address — improving that needs a numeric range query on a parsed
// IPv4-as-int column, which is a bigger refactor.
//
// Returns (sqlFragment, boundArg, applied). applied=false means caller
// should NOT apply this filter (invalid CIDR, etc.).
func ipFilterClause(column, val string) (string, interface{}, bool) {
	val = strings.TrimSpace(val)
	if val == "" {
		return "", nil, false
	}
	if !strings.Contains(val, "/") {
		return column + " = ?", val, true
	}
	_, ipNet, err := net.ParseCIDR(val)
	if err != nil {
		return column + " = ?", val, true
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		// IPv6 CIDR — fall back to exact match for now. Proper IPv6 CIDR
		// matching on a text column needs lexicographic prefixing on the
		// canonical form, which our store doesn't guarantee.
		return column + " = ?", ipNet.IP.String(), true
	}
	netStr := ipNet.IP.To4().String()
	parts := strings.Split(netStr, ".")
	if len(parts) != 4 {
		return column + " = ?", val, true
	}
	switch ones {
	case 8:
		return column + " LIKE ?", parts[0] + ".%", true
	case 16:
		return column + " LIKE ?", parts[0] + "." + parts[1] + ".%", true
	case 24:
		return column + " LIKE ?", parts[0] + "." + parts[1] + "." + parts[2] + ".%", true
	case 32:
		return column + " = ?", netStr, true
	default:
		return column + " = ?", netStr, true
	}
}

// applyAlertFilters writes every query-string filter into the GORM
// chain. Extracted from the listing + count paths (v0.10.218, bundle G2)
// so a new snooze filter only needs to be added in one place.
//
// Snooze behavior: by default, alerts with `snoozed_until > now` are
// hidden — the operator who snoozed them doesn't want to see them. Pass
// `include_snoozed=true` to override (used by the bulk-ack flow + the
// snoozed-alerts view).
func applyAlertFilters(c *gin.Context, q *gorm.DB) *gorm.DB {
	if deviceID := c.Query("device_id"); deviceID != "" {
		q = q.Where("device_id = ?", deviceID)
	}
	// site_id scopes to a site: device-scoped alerts via device→site, plus
	// site-scoped alerts (e.g. SFLOW_SECURITY_DIGEST) via the alerts.site_id column
	// (v0.11.57). "unassigned" = the null-site bucket the NOC dashboard surfaces.
	if siteID := c.Query("site_id"); siteID != "" {
		if siteID == "unassigned" {
			q = q.Where("device_id IN (SELECT id FROM devices WHERE site_id IS NULL)")
		} else {
			q = q.Where("device_id IN (SELECT id FROM devices WHERE site_id = ?) OR site_id = ?", siteID, siteID)
		}
	}
	if severity := c.Query("severity"); severity != "" {
		q = q.Where("severity = ?", severity)
	}
	if alertType := c.Query("alert_type"); alertType != "" {
		q = q.Where("alert_type = ?", alertType)
	}
	if ack := c.Query("acknowledged"); ack != "" {
		q = q.Where("acknowledged = ?", ack == "true")
	}
	if c.Query("include_snoozed") != "true" {
		q = q.Where("snoozed_until IS NULL OR snoozed_until < ?", time.Now())
	}
	return q
}

func (h *Handler) GetAlerts(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{"alerts": []models.Alert{}, "total": 0}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	query := applyAlertFilters(c, db.Gorm().Order("timestamp DESC").Limit(limit).Offset(offset))

	var alerts []models.Alert
	if err := query.Find(&alerts).Error; err != nil {
		httputil.InternalError(c, "Failed to get alerts", err)
		return
	}
	enrichAlertsDeviceSite(db.Gorm(), alerts)

	var total int64
	applyAlertFilters(c, db.Gorm().Model(&models.Alert{})).Count(&total)

	c.JSON(http.StatusOK, response.Success(gin.H{"alerts": alerts, "total": total}))
}

// enrichAlertsDeviceSite fills each alert's transient DeviceName/SiteName from its
// DeviceID in two batched queries (devices, then their sites), so the alerts list
// and detail identify the device by NAME and show its site without an N+1.
func enrichAlertsDeviceSite(g *gorm.DB, alerts []models.Alert) {
	if len(alerts) == 0 {
		return
	}
	idset := map[uint]struct{}{}
	siteIDset := map[uint]struct{}{}
	for _, a := range alerts {
		if a.DeviceID != 0 {
			idset[a.DeviceID] = struct{}{}
		}
		// Site-scoped alerts (e.g. the SFLOW_SECURITY_DIGEST storm rollup) carry no
		// device but persist their own SiteID — resolve those site names too.
		if a.SiteID != nil {
			siteIDset[*a.SiteID] = struct{}{}
		}
	}
	type devRow struct {
		ID     uint
		Name   string
		SiteID *uint
	}
	devByID := make(map[uint]devRow)
	if len(idset) > 0 {
		ids := make([]uint, 0, len(idset))
		for id := range idset {
			ids = append(ids, id)
		}
		var devs []devRow
		g.Model(&models.Device{}).Where("id IN ?", ids).Select("id, name, site_id").Scan(&devs)
		for _, d := range devs {
			devByID[d.ID] = d
			if d.SiteID != nil {
				siteIDset[*d.SiteID] = struct{}{}
			}
		}
	}
	siteName := map[uint]string{}
	if len(siteIDset) > 0 {
		sids := make([]uint, 0, len(siteIDset))
		for id := range siteIDset {
			sids = append(sids, id)
		}
		type siteRow struct {
			ID   uint
			Name string
		}
		var sites []siteRow
		g.Model(&models.Site{}).Where("id IN ?", sids).Select("id, name").Scan(&sites)
		for _, s := range sites {
			siteName[s.ID] = s.Name
		}
	}
	for i := range alerts {
		if d, ok := devByID[alerts[i].DeviceID]; ok {
			alerts[i].DeviceName = d.Name
			if d.SiteID != nil {
				alerts[i].SiteName = siteName[*d.SiteID]
			}
		}
		// Fall back to the alert's own persisted SiteID (site-scoped, device-less
		// alerts) when the device→site path didn't set a name.
		if alerts[i].SiteName == "" && alerts[i].SiteID != nil {
			alerts[i].SiteName = siteName[*alerts[i].SiteID]
		}
	}
}

func (h *Handler) GetAlert(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusNotFound, response.Error("Alert not found"))
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var alert models.Alert
	if err := db.Gorm().First(&alert, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Alert not found"))
		return
	}
	alerts := []models.Alert{alert}
	enrichAlertsDeviceSite(db.Gorm(), alerts)
	alert = alerts[0]
	// The linked flow detections are the flows/detectors behind this alert — the
	// detail view renders src→dst (with country/ASN) and which detectors fired.
	detections, _ := db.GetDetectionsByAlert(alert.ID)
	c.JSON(http.StatusOK, response.Success(gin.H{"alert": alert, "detections": detections}))
}

// SuggestEventRuleForAlert returns a prefilled Event Rule that would suppress (or,
// with the action flipped, customize) the class of a given alert — the backend
// for the "Create Event Rule from this alert" buttons. Admin-only (rule creation
// is admin-only). The alert→matcher mapping lives in alerts.SuggestRuleForAlert so
// it's derived from the same fields the engine matches on, not re-parsed in JS.
func (h *Handler) SuggestEventRuleForAlert(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var alert models.Alert
	if err := db.Gorm().First(&alert, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Alert not found"))
		return
	}
	al := []models.Alert{alert}
	enrichAlertsDeviceSite(db.Gorm(), al)
	alert = al[0]

	in := alerts.SuggestInput{
		AlertType:  alert.AlertType,
		DeviceID:   alert.DeviceID,
		SiteID:     alert.SiteID,
		MetricName: alert.MetricName,
		Message:    alert.Message,
		DeviceName: alert.DeviceName,
		SourceAddr: alert.SourceAddr,
		ProbeID:    alert.ProbeID,
		StateOwned: h.stateOwnedSet(db),
	}
	if alert.DeviceID != 0 {
		if d, err := db.GetDevice(alert.DeviceID); err == nil && d != nil {
			in.Vendor = d.Vendor
		}
	}
	// v48 profile targeting context: the Default profile, the alert device's
	// governing profile (chain head: device config → site config → Default),
	// and per-profile names. Dangling assignments fall through like the
	// fire-time resolver.
	profileName := map[uint]string{}
	if profiles, err := db.GetAllEventRuleProfiles(); err == nil {
		for _, p := range profiles {
			profileName[p.ID] = p.Name
			if p.IsDefault {
				in.DefaultProfileID = p.ID
				in.DefaultProfileName = p.Name
			}
		}
	}
	in.GoverningProfileID, in.GoverningProfileName = in.DefaultProfileID, in.DefaultProfileName
	governSet := false
	if alert.DeviceID != 0 {
		if cfg, err := db.GetDeviceAlertConfig(alert.DeviceID); err == nil && cfg.EventProfileID != nil {
			if name, ok := profileName[*cfg.EventProfileID]; ok {
				in.GoverningProfileID, in.GoverningProfileName = *cfg.EventProfileID, name
				governSet = true
			}
		}
	}
	if !governSet && alert.SiteID != nil {
		if cfg, err := db.GetSiteAlertConfig(*alert.SiteID); err == nil && cfg.EventProfileID != nil {
			if name, ok := profileName[*cfg.EventProfileID]; ok {
				in.GoverningProfileID, in.GoverningProfileName = *cfg.EventProfileID, name
			}
		}
	}

	// For syslog and flow rule-match alerts, the firing rule's name is stored in
	// MetricName; find it so the suggestion out-prioritizes it (and, for flow,
	// reuses its matcher) and "customize" can open it directly. Only for those —
	// for metric/state/spike/trap, MetricName is a resource key
	// ("cpu_usage"/"interface_port5"/…), which must NOT be treated as a rule name.
	rules, rulesErr := db.ListEventRules()
	if alert.MetricName != "" && alerts.IsRuleNameAlertType(alert.AlertType) && rulesErr == nil {
		for i := range rules {
			if rules[i].Name == alert.MetricName {
				p := rules[i].Priority
				rid := rules[i].ID
				in.FiringRulePriority = &p
				in.ExistingRuleID = &rid
				in.FiringRuleMatchJSON = rules[i].MatchJSON
				// Same-layer targeting: fold the 0-sentinel into Default.
				fpid := rules[i].ProfileID
				if fpid == 0 {
					fpid = in.DefaultProfileID
				}
				in.FiringRuleProfileID = fpid
				in.FiringRuleProfileName = profileName[fpid]
				break
			}
		}
	}
	// Global source-mute honesty: warn when any non-default profile carries an
	// enabled flow_security ALERT rule (its layer would run before a Default
	// mute for devices it governs).
	if rulesErr == nil {
		for i := range rules {
			pid := rules[i].ProfileID
			if pid == 0 {
				pid = in.DefaultProfileID
			}
			if rules[i].Enabled && rules[i].Source == "flow_security" && rules[i].Action == "alert" && pid != in.DefaultProfileID {
				in.ScopeWarnFlowSec = true
				break
			}
		}
	}

	c.JSON(http.StatusOK, response.Success(alerts.SuggestRuleForAlert(in)))
}

// stateOwnedSet reads the state_engine_owns SystemSetting (CSV of event_types the
// state-rule engine owns), so a suggestion for an unowned interface/VPN type can
// warn that a rule would be inert.
func (h *Handler) stateOwnedSet(db database.Store) map[string]bool {
	m := map[string]bool{}
	var s models.SystemSetting
	if err := db.Gorm().Where(`"key" = ?`, "state_engine_owns").First(&s).Error; err == nil {
		for _, t := range strings.Split(s.Value, ",") {
			if t = strings.TrimSpace(t); t != "" {
				m[t] = true
			}
		}
	}
	return m
}

func (h *Handler) GetTraps(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success([]models.TrapEvent{}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	query := db.Gorm().Order("timestamp DESC").Limit(limit).Offset(offset)

	if deviceID := c.Query("device_id"); deviceID != "" {
		query = query.Where("device_id = ?", deviceID)
	}
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if trapType := c.Query("trap_type"); trapType != "" {
		query = query.Where("trap_type = ?", trapType)
	}

	var traps []models.TrapEvent
	if err := query.Find(&traps).Error; err != nil {
		httputil.InternalError(c, "Failed to get traps", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(traps))
}

func (h *Handler) GetSyslogMessages(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{"messages": []models.SyslogMessage{}, "total": 0}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	// Bound the list (and the COUNT below) to a recent time window so we
	// never scan/count the full partitioned syslog_messages table — at prod
	// volume that's millions of rows and an exact COUNT(*) is what made this
	// page slow and showed a nonsensical "of 3,353,148" pager. The frontend's
	// range pills already send `hours` (default 24h). The cutoff lets Postgres
	// prune partitions and use the timestamp index.
	hours := httputil.ParseHours(c)
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// Apply the SAME filters to both the list query and the COUNT query. These
	// were previously two hand-copied filter blocks; keeping them in one closure
	// removes the drift hazard where editing one (e.g. adding a filter) but not
	// the other would silently desync the pager total from the rows returned.
	applyFilters := func(q *gorm.DB) *gorm.DB {
		q = q.Where("timestamp >= ?", cutoff)
		if probeID := c.Query("probe_id"); probeID != "" {
			q = q.Where("probe_id = ?", probeID)
		}
		if deviceID := c.Query("device_id"); deviceID != "" {
			q = q.Where("device_id = ?", deviceID)
		}
		if severity := c.Query("severity"); severity != "" {
			if s, err := strconv.Atoi(severity); err == nil {
				q = q.Where("severity <= ?", s)
			}
		}
		if search := c.Query("search"); search != "" {
			escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(search)
			like := "%" + escaped + "%"
			q = q.Where("message LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\' OR app_name LIKE ? ESCAPE '\\'", like, like, like)
		}
		return q
	}

	var messages []models.SyslogMessage
	if err := applyFilters(db.Gorm().Order("timestamp DESC")).Limit(limit).Offset(offset).Find(&messages).Error; err != nil {
		httputil.InternalError(c, "Failed to get syslog messages", err)
		return
	}

	var total int64
	applyFilters(db.Gorm().Model(&models.SyslogMessage{})).Count(&total)

	c.JSON(http.StatusOK, response.Success(gin.H{"messages": messages, "total": total}))
}

func (h *Handler) GetSyslogMessage(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusNotFound, response.Error("Syslog message not found"))
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var msg models.SyslogMessage
	if err := db.Gorm().First(&msg, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Syslog message not found"))
		return
	}
	c.JSON(http.StatusOK, response.Success(msg))
}

func (h *Handler) GetFlowSamples(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success([]models.FlowSample{}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	query := db.Gorm().Order("timestamp DESC").Limit(limit).Offset(offset)

	// Optional time window (LC-36): the Flows page range pills and the CSV
	// export label an hours-bounded slice, so the list must actually honor it —
	// pre-fix an "last 1h" export could span days of newest-first rows. Same
	// validation shape as httputil.ParseHours (1..8760), but absent means "no
	// time filter" for back-compat with existing API consumers.
	if hq := c.Query("hours"); hq != "" {
		if v, err := strconv.Atoi(hq); err == nil && v > 0 && v <= 8760 {
			query = query.Where("timestamp > ?", time.Now().Add(-time.Duration(v)*time.Hour))
		}
	}

	// L24 of the 2026-07-01 audit: parse every numeric-column filter with
	// strconv and only apply on success. Binding a raw non-numeric query string
	// against an integer column throws 22P02 on PostgreSQL (a 500), while SQLite
	// silently matches nothing — a dialect divergence and a bad-URL-becomes-500
	// bug. The sibling filters below (dst_port, app_category, …) already do this.
	if probeID := c.Query("probe_id"); probeID != "" {
		if v, err := strconv.ParseUint(probeID, 10, 32); err == nil {
			query = query.Where("probe_id = ?", v)
		}
	}
	if deviceID := c.Query("device_id"); deviceID != "" {
		if v, err := strconv.ParseUint(deviceID, 10, 32); err == nil {
			query = query.Where("device_id = ?", v)
		}
	}
	// Site filter (NOC drill-down): matches every device in the site.
	if siteID := c.Query("site_id"); siteID != "" {
		if v, err := strconv.ParseUint(siteID, 10, 32); err == nil {
			query = query.Where("device_id IN (SELECT id FROM devices WHERE site_id = ?)", v)
		}
	}
	if src := c.Query("src_addr"); src != "" {
		if frag, arg, ok := ipFilterClause("src_addr", src); ok {
			query = query.Where(frag, arg)
		}
	}
	if dst := c.Query("dst_addr"); dst != "" {
		if frag, arg, ok := ipFilterClause("dst_addr", dst); ok {
			query = query.Where(frag, arg)
		}
	}
	// Optional dst port filter — top-port drill-down sends this.
	if dport := c.Query("dst_port"); dport != "" {
		if p, err := strconv.ParseUint(dport, 10, 16); err == nil {
			query = query.Where("dst_port = ?", p)
		}
	}
	if proto := c.Query("protocol"); proto != "" {
		if v, err := strconv.ParseUint(proto, 10, 8); err == nil { // L24: was raw-bound → 22P02/500 on PG
			query = query.Where("protocol = ?", v)
		}
	}
	// Classification drill-down (By Application / By Direction click-to-filter).
	if cat := c.Query("app_category"); cat != "" {
		if v, err := strconv.ParseUint(cat, 10, 8); err == nil {
			query = query.Where("app_category = ?", v)
		}
	}
	if dir := c.Query("direction"); dir != "" {
		if v, err := strconv.ParseUint(dir, 10, 8); err == nil {
			query = query.Where("direction = ?", v)
		}
	}
	if cc := c.Query("dst_country"); cc != "" {
		query = query.Where("dst_country = ?", cc)
	}
	if asn := c.Query("dst_asn"); asn != "" {
		if v, err := strconv.ParseUint(asn, 10, 32); err == nil {
			query = query.Where("dst_asn = ?", v)
		}
	}
	// Tranche 3: exporting-protocol filter (0=sFlow is a real value — the UI
	// sends the param only when a source is explicitly selected).
	if fs := c.Query("flow_source"); fs != "" {
		if v, err := strconv.ParseUint(fs, 10, 8); err == nil {
			query = query.Where("flow_source = ?", v)
		}
	}
	// IE 233 event filter (LC-52) — the denied-flow drill-down. Mirrors the
	// flow_source pattern: 0 (none) is a real value, param sent only when an
	// event is explicitly selected.
	if fe := c.Query("firewall_event"); fe != "" {
		if v, err := strconv.ParseUint(fe, 10, 8); err == nil {
			query = query.Where("firewall_event = ?", v)
		}
	}

	var samples []models.FlowSample
	if err := query.Find(&samples).Error; err != nil {
		httputil.InternalError(c, "Failed to get flow samples", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(samples))
}

func (h *Handler) GetFlowStats(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}

	hours := httputil.ParseHours(c)

	// Build the same filter set the Flow Samples list honors, so the Flows
	// page's shared filter row narrows the aggregate views too.
	var filter database.FlowStatsFilter
	if did := c.Query("device_id"); did != "" {
		if v, err := strconv.ParseUint(did, 10, 32); err == nil {
			filter.DeviceID = uint(v)
		}
	}
	if sid := c.Query("site_id"); sid != "" {
		if v, err := strconv.ParseUint(sid, 10, 32); err == nil {
			filter.SiteID = uint(v)
		}
	}
	if pid := c.Query("probe_id"); pid != "" {
		if v, err := strconv.ParseUint(pid, 10, 32); err == nil {
			filter.ProbeID = uint(v)
		}
	}
	if proto := c.Query("protocol"); proto != "" {
		if v, err := strconv.ParseUint(proto, 10, 8); err == nil {
			p := uint8(v)
			filter.Protocol = &p
		}
	}
	if dport := c.Query("dst_port"); dport != "" {
		if v, err := strconv.ParseUint(dport, 10, 16); err == nil {
			p := uint16(v)
			filter.DstPort = &p
		}
	}
	if cat := c.Query("app_category"); cat != "" {
		if v, err := strconv.ParseUint(cat, 10, 8); err == nil {
			p := uint8(v)
			filter.AppCategory = &p
		}
	}
	if dir := c.Query("direction"); dir != "" {
		if v, err := strconv.ParseUint(dir, 10, 8); err == nil {
			p := uint8(v)
			filter.Direction = &p
		}
	}
	if cc := c.Query("dst_country"); cc != "" {
		filter.DstCountry = cc
	}
	if asn := c.Query("dst_asn"); asn != "" {
		if v, err := strconv.ParseUint(asn, 10, 32); err == nil {
			a := uint32(v)
			filter.DstASN = &a
		}
	}
	if fs := c.Query("flow_source"); fs != "" {
		if v, err := strconv.ParseUint(fs, 10, 8); err == nil {
			p := uint8(v)
			filter.FlowSource = &p
		}
	}
	if fe := c.Query("firewall_event"); fe != "" {
		if v, err := strconv.ParseUint(fe, 10, 8); err == nil {
			p := uint8(v)
			filter.FirewallEvent = &p
		}
	}
	filter.SrcAddr = c.Query("src_addr")
	filter.DstAddr = c.Query("dst_addr")

	stats, err := db.GetFlowStats(hours, filter)
	if err != nil {
		httputil.InternalError(c, "Failed to get flow stats", err)
		return
	}

	// Dual-export visibility: devices whose last hour contains more than one
	// distinct flow_source are double-counting bytes (same traffic metered by
	// two protocols) — the UI shows a warning banner. Cheap 1h-window GROUP BY
	// on the indexed (device_id, timestamp) prefix; failure is non-fatal.
	stats.MixedSourceDevices = db.GetMixedFlowSourceDevices()

	// Surface geo enrichment state so the UI renders the Top Countries / ASNs
	// cards with a "disabled" / source hint instead of hiding them silently.
	stats.GeoEnabled = h.config.Server.GeoIPEnabled
	stats.GeoSource = h.geoResolver.Source()

	c.JSON(http.StatusOK, response.Success(stats))
}

// GetFlowDetections returns recent sFlow detection-engine findings (good-vs-bad
// traffic verdicts) for the Flows page detections panel and the alerts view.
// Query params: hours (window, default via ParseHours), limit (<=1000),
// unacked=true to exclude acknowledged rows.
func (h *Handler) GetFlowDetections(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	hours := httputil.ParseHours(c)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	limit := 200
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	unacked := c.Query("unacked") == "true"
	// Single feed: by default the detections card shows only detections that did
	// NOT escalate to an alert (those live on the Alerts page). ?all=true includes
	// alerted detections for debugging.
	includeAlerted := c.Query("all") == "true"
	rows, err := db.GetRecentDetections(since, limit, unacked, includeAlerted)
	if err != nil {
		httputil.InternalError(c, "Failed to get flow detections", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(rows))
}

// AckFlowDetection marks one detection acknowledged (dismissed from the active
// list). Admin-gated by the route group it's registered under.
func (h *Handler) AckFlowDetection(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		httputil.InternalError(c, "Database unavailable", nil)
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("invalid detection id"))
		return
	}
	if err := db.AckFlowDetection(uint(id)); err != nil {
		httputil.InternalError(c, "Failed to acknowledge detection", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"acknowledged": true}))
}

// SearchThreatIntel returns a filtered, paginated page of threat-intel entries
// for the admin Threat Intelligence page (manual search). Query params: q
// (substring on cidr/AS), source, category, severity, active (bool),
// offset, limit.
func (h *Handler) SearchThreatIntel(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	f := database.ThreatIntelFilter{
		Query:      strings.TrimSpace(c.Query("q")),
		Source:     strings.TrimSpace(c.Query("source")),
		Category:   strings.TrimSpace(c.Query("category")),
		Severity:   strings.TrimSpace(c.Query("severity")),
		ActiveOnly: c.Query("active") == "true" || c.Query("active") == "1",
	}
	offset, _ := strconv.Atoi(c.Query("offset"))
	limit := 100
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 {
		limit = l
	}
	rows, total, err := db.SearchThreatIntel(f, offset, limit)
	if err != nil {
		httputil.InternalError(c, "Failed to search threat intel", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"entries": rows, "total": total, "offset": offset, "limit": limit,
	}))
}

// LookupThreatIntel resolves a single IP or ASN (?q=) into geo + threat context
// for the admin lookup tool: country, ASN + org (for an IP), and whether it is
// known-bad (by IP prefix and/or ASN reputation) with the matching source
// metadata. This is the first HTTP surface for the resolver + matcher.
func (h *Handler) LookupThreatIntel(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusBadRequest, response.Error("q (an IP or AS number) is required"))
		return
	}
	out := gin.H{"query": q, "geo_enabled": h.config.Server.GeoIPEnabled}

	if asn, ok := parseASNQuery(q); ok {
		// ASN lookup: reputation only (no geo for a bare ASN).
		out["kind"] = "asn"
		out["asn"] = asn
		if hit, bad := h.threatMatch.MatchASN(asn); bad {
			out["known_bad"] = true
			out["threat"] = gin.H{"scope": "asn", "category": hit.Category, "severity": hit.Severity}
		} else {
			out["known_bad"] = false
		}
		c.JSON(http.StatusOK, response.Success(out))
		return
	}

	if _, err := netip.ParseAddr(q); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("q must be a valid IP address or AS number"))
		return
	}
	out["kind"] = "ip"
	out["country"] = h.geoResolver.Country(q)
	asn, org, prefix := h.geoResolver.ASNInfoNet(q)
	out["asn"] = asn
	out["asn_org"] = org
	out["asn_prefix"] = prefix
	scopes := []gin.H{}
	if hit, bad := h.threatMatch.Match(q); bad {
		scopes = append(scopes, gin.H{"scope": "ip", "category": hit.Category, "severity": hit.Severity})
	}
	if asn != 0 {
		if hit, bad := h.threatMatch.MatchASN(asn); bad {
			scopes = append(scopes, gin.H{"scope": "asn", "category": hit.Category, "severity": hit.Severity})
		}
	}
	out["known_bad"] = len(scopes) > 0
	out["threats"] = scopes
	c.JSON(http.StatusOK, response.Success(out))
}

// LookupGeoBatch resolves many IPs at once to {country, asn, asn_org, asn_prefix}
// for the client-side IP enrichment that shows a country flag + ASN chip wherever
// an IP appears in the admin UI. Private/loopback/link-local and unparseable
// addresses are skipped, and IPs with no data are omitted, so the response only
// carries what the UI can render. Bounded to 256 IPs per request (one call
// enriches a whole table).
func (h *Handler) LookupGeoBatch(c *gin.Context) {
	raw := strings.TrimSpace(c.Query("ips"))
	out := gin.H{}
	if raw == "" {
		c.JSON(http.StatusOK, response.Success(out))
		return
	}
	seen := make(map[string]bool)
	n := 0
	for _, part := range strings.Split(raw, ",") {
		ip := strings.TrimSpace(part)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		if n++; n > 256 {
			break
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.IsValid() || addr.IsPrivate() || addr.IsLoopback() ||
			addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
			continue
		}
		country := h.geoResolver.Country(ip)
		asn, org, prefix := h.geoResolver.ASNInfoNet(ip)
		if country == "" && asn == 0 {
			continue // nothing to render for this IP
		}
		out[ip] = gin.H{"country": country, "asn": asn, "asn_org": org, "asn_prefix": prefix}
	}
	c.JSON(http.StatusOK, response.Success(out))
}

// GetThreatFeeds returns the per-source feed status (last sync, counts, errors)
// joined with runtime config (enabled, interval, TTL) and the active by-source
// indicator counts, for the admin feeds panel.
func (h *Handler) GetThreatFeeds(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	status, err := db.ListThreatFeedStatus()
	if err != nil {
		httputil.InternalError(c, "Failed to list feed status", err)
		return
	}
	bySource, _ := db.CountThreatIntelBySource()
	// v0.11.46: report the RESOLVED master switch (admin-UI setting, env default),
	// not the raw env. The per-feed `enabled` flag rides on each status row.
	c.JSON(http.StatusOK, response.Success(gin.H{
		"feeds_enabled": db.GetBoolSetting("threat_feeds_enabled", h.config.ThreatFeed.Enabled),
		"interval":      h.config.ThreatFeed.Interval.String(),
		"ttl_days":      h.config.ThreatFeed.TTLDays,
		"loaded_count":  h.threatMatch.Len(),
		"status":        status,
		"by_source":     bySource,
	}))
}

// parseASNQuery accepts "AS64496"/"as64496" (not a bare number, which is
// ambiguous with other inputs) and returns the numeric ASN.
func parseASNQuery(s string) (uint32, bool) {
	if len(s) < 3 || (s[0] != 'A' && s[0] != 'a') || (s[1] != 'S' && s[1] != 's') {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s[2:]), 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// AddThreatIntel upserts one threat-intel feed entry (keyed by cidr+source) and
// refreshes the in-memory matcher so the change takes effect immediately rather
// than on the next periodic reload. Admin-gated by its route group.
func (h *Handler) AddThreatIntel(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		httputil.InternalError(c, "Database unavailable", nil)
		return
	}
	var req struct {
		CIDR      string     `json:"cidr"`
		Category  string     `json:"category"`
		Source    string     `json:"source"`
		Severity  string     `json:"severity"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("invalid request body"))
		return
	}
	req.CIDR = strings.TrimSpace(req.CIDR)
	if req.CIDR == "" {
		c.JSON(http.StatusBadRequest, response.Error("cidr is required"))
		return
	}
	// Validate the CIDR/IP up front so a bad feed entry is rejected at the API
	// rather than silently skipped by the matcher at build time.
	if !validThreatCIDR(req.CIDR) {
		c.JSON(http.StatusBadRequest, response.Error("cidr must be a valid IP or CIDR (e.g. 203.0.113.0/24 or 203.0.113.9)"))
		return
	}
	if req.Source == "" {
		req.Source = "manual"
	}
	// L22 of the 2026-07-01 audit: store the CANONICAL (masked) prefix, so the
	// stored (cidr,source) key, the value shown in the UI, and the prefix the
	// matcher actually enforces are all identical. Pre-fix, "203.0.113.9/24"
	// was stored verbatim but enforced as "203.0.113.0/24" — creating duplicate
	// rows for equivalent prefixes (deleting the visible one left a hidden dup
	// still escalating detections) and a displayed-vs-enforced scope mismatch.
	req.CIDR = canonicalThreatCIDR(req.CIDR)
	entry := &models.ThreatIntel{
		CIDR:      req.CIDR,
		Category:  req.Category,
		Source:    req.Source,
		Severity:  req.Severity,
		ExpiresAt: req.ExpiresAt,
	}
	if err := db.UpsertThreatIntel(entry); err != nil {
		httputil.InternalError(c, "Failed to save threat intel", err)
		return
	}
	h.RefreshThreatMatcher()
	c.JSON(http.StatusOK, response.Success(entry))
}

// DeleteThreatIntel removes one feed entry by id and refreshes the matcher.
func (h *Handler) DeleteThreatIntel(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		httputil.InternalError(c, "Database unavailable", nil)
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("invalid id"))
		return
	}
	if err := db.DeleteThreatIntel(uint(id)); err != nil {
		httputil.InternalError(c, "Failed to delete threat intel", err)
		return
	}
	h.RefreshThreatMatcher()
	c.JSON(http.StatusOK, response.Success(gin.H{"deleted": true}))
}

// validThreatCIDR accepts a CIDR ("10.0.0.0/8"), a bare IP ("10.0.0.1"), or an
// AS number ("AS64496") — matching what threatintel.New parses.
func validThreatCIDR(s string) bool {
	if _, ok := parseASNQuery(s); ok {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// canonicalThreatCIDR returns the canonical form of a validated CIDR/IP/AS so it
// matches exactly what the matcher enforces (L22). A bare IP becomes a host
// prefix (/32 or /128); an AS number is upper-cased to "AS<n>". Assumes the
// input already passed validThreatCIDR.
func canonicalThreatCIDR(s string) string {
	if asn, ok := parseASNQuery(s); ok {
		return "AS" + strconv.FormatUint(uint64(asn), 10)
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return s
}

// parseStatsDeviceFilter reads an optional device_id query parameter from
// /stats endpoints (v0.10.217, bundle D4). Returns 0 if absent or invalid,
// matching the "no filter" sentinel used by the database layer.
func parseStatsDeviceFilter(c *gin.Context) uint {
	raw := c.Query("device_id")
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0
	}
	return uint(n)
}

func (h *Handler) GetAlertStats(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}

	hours := httputil.ParseHours(c)
	deviceID := parseStatsDeviceFilter(c)

	stats, err := db.GetAlertStats(hours, deviceID)
	if err != nil {
		httputil.InternalError(c, "Failed to get alert stats", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(stats))
}

func (h *Handler) GetTrapStats(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}

	hours := httputil.ParseHours(c)
	deviceID := parseStatsDeviceFilter(c)

	stats, err := db.GetTrapStats(hours, deviceID)
	if err != nil {
		httputil.InternalError(c, "Failed to get trap stats", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(stats))
}

func (h *Handler) GetSyslogStats(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}

	hours := httputil.ParseHours(c)
	deviceID := parseStatsDeviceFilter(c)

	stats, err := db.GetSyslogStats(hours, deviceID)
	if err != nil {
		httputil.InternalError(c, "Failed to get syslog stats", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(stats))
}

func (h *Handler) AcknowledgeAlert(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var body struct {
		Notes string `json:"notes"`
	}
	// Allow empty body for backward compatibility
	c.ShouldBindJSON(&body)

	if err := db.AcknowledgeAlertEnhanced(id, body.Notes); err != nil {
		httputil.InternalError(c, "Failed to acknowledge alert", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Alert acknowledged"))
}

// SnoozeAlert temporarily silences an alert until SnoozedUntil. Distinct
// from acknowledge: the alert resurfaces in the default list once the
// snooze expires (v0.10.218, bundle G2). Common operator pattern is
// "snooze for 4 hours while I finish unrelated triage".
//
// Body: { "hours": 4, "reason": "weekly rotation, check Monday" }
// `hours` is clamped to [1, 720] (30 days max). Empty/zero hours = 1.
func (h *Handler) SnoozeAlert(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var body struct {
		Hours  int    `json:"hours"`
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&body)

	hours := body.Hours
	if hours < 1 {
		hours = 1
	}
	if hours > 720 {
		hours = 720
	}

	until := time.Now().Add(time.Duration(hours) * time.Hour)
	// Best-effort capture of who snoozed for the audit fields. Username
	// lookup happens in the database layer to avoid threading session
	// state through this handler.
	user, _ := c.Get("username")
	username, _ := user.(string)

	if err := db.SnoozeAlert(id, until, username, body.Reason); err != nil {
		httputil.InternalError(c, "Failed to snooze alert", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"snoozed_until": until,
		"hours":         hours,
	}))
}

// UnsnoozeAlert clears the snooze, re-surfacing the alert immediately
// (v0.10.218, bundle G2).
func (h *Handler) UnsnoozeAlert(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := db.UnsnoozeAlert(id); err != nil {
		httputil.InternalError(c, "Failed to unsnooze alert", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Alert unsnoozed"))
}

// BulkSnoozeAlerts snoozes every alert whose ID is in the request body.
// AUDIT-143: mirror of BulkAcknowledgeAlerts for the snooze flow.
// Body: { "ids": [1, 2, 3], "hours": 4, "reason": "..." }
func (h *Handler) BulkSnoozeAlerts(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var body struct {
		IDs    []uint `json:"ids"`
		Hours  int    `json:"hours"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("ids is required"))
		return
	}
	if len(body.IDs) > maxBulkAckIDs {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("too many ids (max %d per request)", maxBulkAckIDs)))
		return
	}

	hours := body.Hours
	if hours < 1 {
		hours = 1
	}
	if hours > 720 {
		hours = 720
	}
	until := time.Now().Add(time.Duration(hours) * time.Hour)

	user, _ := c.Get("username")
	username, _ := user.(string)

	affected, err := db.SnoozeAlertsBulk(body.IDs, until, username, body.Reason)
	if err != nil {
		httputil.InternalError(c, "Failed to snooze alerts", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"snoozed":       affected,
		"snoozed_until": until,
		"hours":         hours,
	}))
}

// BulkSnoozeAlertsByFilter snoozes every alert matching the filter.
// AUDIT-143: mirror of BulkAcknowledgeAlertsByFilter. Same filter
// semantics (device_id, alert_type, severity, acknowledged). At
// least one filter is required to prevent accidental "snooze
// everything" calls.
func (h *Handler) BulkSnoozeAlertsByFilter(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var body struct {
		Hours  int    `json:"hours"`
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&body) // body is optional

	hours := body.Hours
	if hours < 1 {
		hours = 1
	}
	if hours > 720 {
		hours = 720
	}
	until := time.Now().Add(time.Duration(hours) * time.Hour)

	filter := database.AlertFilter{}
	hasAnyFilter := false
	if v := c.Query("device_id"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 32); err == nil && id > 0 {
			filter.DeviceID = uint(id)
			hasAnyFilter = true
		}
	}
	if v := c.Query("alert_type"); v != "" {
		filter.AlertType = v
		hasAnyFilter = true
	}
	if v := c.Query("severity"); v != "" {
		filter.Severity = v
		hasAnyFilter = true
	}
	if v := c.Query("acknowledged"); v != "" {
		ack := v == "true"
		filter.Acknowledged = &ack
		hasAnyFilter = true
	}
	if !hasAnyFilter {
		c.JSON(http.StatusBadRequest, response.Error("at least one filter is required (device_id, alert_type, severity, acknowledged)"))
		return
	}

	user, _ := c.Get("username")
	username, _ := user.(string)

	affected, err := db.SnoozeAlertsByFilter(filter, until, username, body.Reason)
	if err != nil {
		httputil.InternalError(c, "Failed to snooze alerts", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"snoozed":       affected,
		"snoozed_until": until,
		"hours":         hours,
	}))
}

// maxBulkAckIDs caps how many alerts can be acked in a single bulk request.
// Picked to keep SQL parameter lists comfortable across SQLite and Postgres.
const maxBulkAckIDs = 500

// BulkAcknowledgeAlerts acks every alert whose ID is in the request body, in a
// single SQL UPDATE. Used by the admin UI's "Acknowledge selected" toolbar so
// the user doesn't have to ack alerts one at a time.
func (h *Handler) BulkAcknowledgeAlerts(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var body struct {
		IDs   []uint `json:"ids"`
		Notes string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("ids must be a non-empty array"))
		return
	}
	if len(body.IDs) > maxBulkAckIDs {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("too many ids (max %d per request)", maxBulkAckIDs)))
		return
	}

	affected, err := db.AcknowledgeAlertsBulk(body.IDs, body.Notes)
	if err != nil {
		httputil.InternalError(c, "Failed to acknowledge alerts", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"acknowledged": affected,
		"requested":    len(body.IDs),
	}))
}

// BulkAcknowledgeAlertsByFilter acks every alert matching the filter (same
// query parameters as GET /api/alerts: device_id, alert_type, severity,
// acknowledged). Body carries the optional notes. Used by the admin UI's
// "Select all N matching" flow when the result set exceeds maxBulkAckIDs and
// can't be shipped as an ID list.
//
// At least one filter must be specified to prevent accidental "ack everything
// in the database" calls.
func (h *Handler) BulkAcknowledgeAlertsByFilter(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var body struct {
		Notes string `json:"notes"`
	}
	c.ShouldBindJSON(&body) // body is optional

	filter := database.AlertFilter{}
	hasAnyFilter := false
	if v := c.Query("device_id"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 32); err == nil && id > 0 {
			filter.DeviceID = uint(id)
			hasAnyFilter = true
		}
	}
	if v := c.Query("alert_type"); v != "" {
		filter.AlertType = v
		hasAnyFilter = true
	}
	if v := c.Query("severity"); v != "" {
		filter.Severity = v
		hasAnyFilter = true
	}
	if v := c.Query("acknowledged"); v != "" {
		ack := v == "true"
		filter.Acknowledged = &ack
		hasAnyFilter = true
	}

	if !hasAnyFilter {
		c.JSON(http.StatusBadRequest, response.Error("at least one filter is required (device_id, alert_type, severity, acknowledged)"))
		return
	}

	affected, err := db.AcknowledgeAlertsByFilter(filter, body.Notes)
	if err != nil {
		httputil.InternalError(c, "Failed to acknowledge alerts", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"acknowledged": affected,
	}))
}

func (h *Handler) UpdateAlertNotes(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var body struct {
		Notes string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if len(body.Notes) > 4000 {
		c.JSON(http.StatusBadRequest, response.Error("Notes must be under 4000 characters"))
		return
	}

	if err := db.UpdateAlertNotes(id, body.Notes); err != nil {
		httputil.InternalError(c, "Failed to update alert notes", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Alert notes updated"))
}

func (h *Handler) GetUptime(c *gin.Context) {
	db := h.reqDB(c)
	stats := h.uptimeTrack.GetStats()
	fiveNines := h.uptimeTrack.CalculateFiveNines()

	var records []models.UptimeRecord
	if db != nil {
		var err error
		records, err = db.GetUptimeRecords(100)
		if err != nil {
			log.Printf("Failed to get uptime records: %v", err)
		}
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"stats":      stats,
		"five_nines": fiveNines,
		"history":    records,
	}))
}

func (h *Handler) ResetUptime(c *gin.Context) {
	if err := h.uptimeTrack.Reset(); err != nil {
		httputil.InternalError(c, "Failed to reset uptime", err)
		return
	}
	c.JSON(http.StatusOK, response.Message("Uptime tracking reset successfully"))
}
