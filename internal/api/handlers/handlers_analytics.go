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

	var total int64
	applyAlertFilters(c, db.Gorm().Model(&models.Alert{})).Count(&total)

	c.JSON(http.StatusOK, response.Success(gin.H{"alerts": alerts, "total": total}))
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
	c.JSON(http.StatusOK, response.Success(alert))
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

	if probeID := c.Query("probe_id"); probeID != "" {
		query = query.Where("probe_id = ?", probeID)
	}
	if deviceID := c.Query("device_id"); deviceID != "" {
		query = query.Where("device_id = ?", deviceID)
	}
	// Site filter (NOC drill-down): matches every device in the site.
	if siteID := c.Query("site_id"); siteID != "" {
		query = query.Where("device_id IN (SELECT id FROM devices WHERE site_id = ?)", siteID)
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
		query = query.Where("protocol = ?", proto)
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
	filter.SrcAddr = c.Query("src_addr")
	filter.DstAddr = c.Query("dst_addr")

	stats, err := db.GetFlowStats(hours, filter)
	if err != nil {
		httputil.InternalError(c, "Failed to get flow stats", err)
		return
	}

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
	rows, err := db.GetRecentDetections(since, limit, unacked)
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

// GetThreatIntel returns the threat-intel feed (known-bad CIDRs) for the admin
// view, plus the active (non-expired) count and the in-memory matcher's live
// prefix count — a quick way to confirm the ingest path is actually using the
// feed. Newest-first, capped at ?limit (default 500).
func (h *Handler) GetThreatIntel(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	limit := 500
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 5000 {
			limit = v
		}
	}
	rows, err := db.ListThreatIntel(limit)
	if err != nil {
		httputil.InternalError(c, "Failed to list threat intel", err)
		return
	}
	active, _ := db.CountActiveThreatIntel()
	c.JSON(http.StatusOK, response.Success(gin.H{
		"entries":      rows,
		"active_count": active,
		"loaded_count": h.threatMatch.Len(),
	}))
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

// validThreatCIDR accepts a CIDR ("10.0.0.0/8") or a bare IP ("10.0.0.1"),
// matching what threatintel.New parses.
func validThreatCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
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
