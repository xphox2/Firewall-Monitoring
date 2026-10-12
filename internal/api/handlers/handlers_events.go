package handlers

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// GetNetEvents lists normalized network events for the admin Events page. It
// is the first reader of the net_events table (Phase 2, PR 1) and a read-only
// viewer-accessible endpoint — registered beside /api/syslog, NOT in
// adminOnlyRoutes. Filters are time (hours), device/probe/site, the
// activity/action enum columns, and (Phase 2, PR 2) src_ip / dst_ip (a bare IP
// or CIDR, served by the indexes migration v82 re-adds) and rule_key (exact).
func (h *Handler) GetNetEvents(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{"events": []database.NetEventRow{}, "total": 0, "total_capped": false}))
		return
	}

	// AUDIT-251: reject non-numeric numeric filters before binding them against
	// the uint/smallint columns (22P02/500 on Postgres; SQLite silently matches
	// nothing). activity/action are non-negative smallint enums, so the shared
	// uint validator covers them too.
	for _, name := range []string{"device_id", "probe_id", "site_id", "activity", "action"} {
		if msg := validateNumericFilter(c, name); msg != "" {
			c.JSON(http.StatusBadRequest, response.Error(msg))
			return
		}
	}

	// src_ip / dst_ip must be a bare IP or a CIDR before they reach the query:
	// a malformed value cast to inet would abort the statement (22P02/500 on
	// Postgres). rule_key is an exact string — anything goes.
	srcIP := strings.TrimSpace(c.Query("src_ip"))
	dstIP := strings.TrimSpace(c.Query("dst_ip"))
	if srcIP != "" && !validIPOrCIDR(srcIP) {
		c.JSON(http.StatusBadRequest, response.Error("Invalid src_ip (expected an IPv4/IPv6 address or CIDR)"))
		return
	}
	if dstIP != "" && !validIPOrCIDR(dstIP) {
		c.JSON(http.StatusBadRequest, response.Error("Invalid dst_ip (expected an IPv4/IPv6 address or CIDR)"))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	f := database.NetEventFilter{Hours: httputil.ParseHours(c)}
	if v, ok := httputil.ParseUintQuery(c, "device_id"); ok {
		f.DeviceID = v
	}
	if v, ok := httputil.ParseUintQuery(c, "probe_id"); ok {
		f.ProbeID = v
	}
	if v, ok := httputil.ParseUintQuery(c, "site_id"); ok {
		f.SiteID = v
	}
	f.Activity = parseInt16Query(c, "activity")
	f.Action = parseInt16Query(c, "action")
	f.SrcIP = srcIP
	f.DstIP = dstIP
	f.RuleKey = strings.TrimSpace(c.Query("rule_key"))

	rows, total, capped, err := db.ListNetEvents(f, offset, limit)
	if err != nil {
		httputil.InternalError(c, "Failed to get network events", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{"events": rows, "total": total, "total_capped": capped}))
}

// validIPOrCIDR reports whether s is a bare IP address or a CIDR prefix — the
// only forms the src_ip / dst_ip filters accept. Anything else is rejected with
// a 400 before it reaches the query.
func validIPOrCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// parseInt16Query returns a pointer to the named query parameter parsed as an
// int16, or nil when it is absent or out of range. Callers validate the
// parameter first (validateNumericFilter), so a nil here means "no filter";
// the out-of-range guard keeps an absurd value from silently narrowing to the
// int16 truncation of a larger number.
func parseInt16Query(c *gin.Context, name string) *int16 {
	raw := c.Query(name)
	if raw == "" {
		return nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < -32768 || v > 32767 {
		return nil
	}
	n := int16(v) // #nosec G109 -- v is guarded to the int16 range immediately above
	return &n
}

// GetSecEvents lists normalized security events for the admin Events page's
// Security tab (Phase 2, PR 3). It is the first reader of sec_events — the
// non-network half of the Events page — and, like GetNetEvents, a read-only
// viewer-accessible endpoint (registered beside /api/events, NOT in
// adminOnlyRoutes). Filters are time (hours), device/probe, the
// class/activity/action/severity enum columns, and substring filters on
// admin_user / sig_name / tunnel_name / wan_name. sec_events is already indexed
// (idx_sec_events_ts, idx_sec_events_device_ts, idx_sec_events_class_ts), so
// this reader adds no index or migration.
func (h *Handler) GetSecEvents(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{"events": []database.SecEventRow{}, "total": 0, "total_capped": false}))
		return
	}

	// AUDIT-251: reject non-numeric numeric filters before binding them against
	// the uint/smallint columns (22P02/500 on Postgres; SQLite silently matches
	// nothing). class/activity/action/severity are non-negative smallint enums,
	// so the shared uint validator covers them too.
	for _, name := range []string{"device_id", "probe_id", "class", "activity", "action", "severity"} {
		if msg := validateNumericFilter(c, name); msg != "" {
			c.JSON(http.StatusBadRequest, response.Error(msg))
			return
		}
	}

	limit, offset := httputil.ParsePagination(c)

	f := database.SecEventFilter{Hours: httputil.ParseHours(c)}
	if v, ok := httputil.ParseUintQuery(c, "device_id"); ok {
		f.DeviceID = v
	}
	if v, ok := httputil.ParseUintQuery(c, "probe_id"); ok {
		f.ProbeID = v
	}
	f.Class = parseInt16Query(c, "class")
	f.Activity = parseInt16Query(c, "activity")
	f.Action = parseInt16Query(c, "action")
	f.Severity = parseInt16Query(c, "severity")
	f.AdminUser = strings.TrimSpace(c.Query("admin_user"))
	f.SigName = strings.TrimSpace(c.Query("sig_name"))
	f.TunnelName = strings.TrimSpace(c.Query("tunnel_name"))
	f.WanName = strings.TrimSpace(c.Query("wan_name"))

	rows, total, capped, err := db.ListSecEvents(f, offset, limit)
	if err != nil {
		httputil.InternalError(c, "Failed to get security events", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{"events": rows, "total": total, "total_capped": capped}))
}

// GetNetEvent returns one normalized network event by id (Phase 2, PR 8) — the
// detail view behind a row click on the Events page. Like GetNetEvents it is a
// read-only viewer-accessible endpoint (registered beside /api/events, NOT in
// adminOnlyRoutes). A malformed id is a 400; an unknown id is a 404; the row is
// returned directly under `data`, carrying the raw_id/raw_ts provenance the
// "View raw syslog" link reads.
func (h *Handler) GetNetEvent(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusNotFound, response.Error("Event not found"))
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	row, err := db.GetNetEvent(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("Event not found"))
			return
		}
		httputil.InternalError(c, "Failed to get network event", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(row))
}

// GetSecEvent returns one normalized security event by id (Phase 2, PR 8) — the
// detail view behind a row click on the Events page's Security tab. Like
// GetSecEvents it is a read-only viewer-accessible endpoint (registered beside
// /api/security-events, NOT in adminOnlyRoutes). A malformed id is a 400; an
// unknown id is a 404; the row carries the raw_id/raw_ts provenance the
// "View raw syslog" link reads.
func (h *Handler) GetSecEvent(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusNotFound, response.Error("Event not found"))
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	row, err := db.GetSecEvent(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("Event not found"))
			return
		}
		httputil.InternalError(c, "Failed to get security event", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(row))
}

// GetNetEventRollups returns the Events page's long-term analytics series
// (Phase 2, PR 4) from net_event_rollups: top policy rules and bytes, the deny
// trend, and the app-category / direction / ruleset breakdowns, over up to 365
// days. It is a read-only viewer-accessible endpoint (registered beside
// /api/events, NOT in adminOnlyRoutes) and adds no index or migration — every
// series groups over `day >= from`, served by the rollup table's unique
// (day, device_id, …) key.
func (h *Handler) GetNetEventRollups(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"policy_hits":    []database.NetEventRollupRule{},
			"policy_bytes":   []database.NetEventRollupDay{},
			"deny":           []database.NetEventRollupDay{},
			"app_categories": []database.KeyCount{},
			"directions":     []database.NetEventRollupDirection{},
			"rulesets":       []database.KeyCount{},
		}))
		return
	}

	// days is the rollup window: 1..365, default 30. Reject a non-integer or
	// out-of-range value up front (AUDIT-251 discipline — a bad value is a 400,
	// never a 500 from binding a bogus number into a LIMIT/bound).
	days := 30
	if raw := strings.TrimSpace(c.Query("days")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 365 {
			c.JSON(http.StatusBadRequest, response.Error("Invalid days (expected 1..365)"))
			return
		}
		days = n
	}

	// device_id / site_id must be valid uints before they are bound against the
	// uint columns (22P02/500 on Postgres; SQLite silently matches nothing).
	for _, name := range []string{"device_id", "site_id"} {
		if msg := validateNumericFilter(c, name); msg != "" {
			c.JSON(http.StatusBadRequest, response.Error(msg))
			return
		}
	}

	f := database.NetEventRollupFilter{Days: days}
	if v, ok := httputil.ParseUintQuery(c, "device_id"); ok {
		f.DeviceID = v
	}
	if v, ok := httputil.ParseUintQuery(c, "site_id"); ok {
		f.SiteID = v
	}

	stats, err := db.NetEventRollupStats(f)
	if err != nil {
		httputil.InternalError(c, "Failed to get event rollup analytics", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"policy_hits":    stats.PolicyHits,
		"policy_bytes":   stats.PolicyBytes,
		"deny":           stats.Deny,
		"app_categories": stats.AppCategories,
		"directions":     stats.Directions,
		"rulesets":       stats.Rulesets,
	}))
}

// GetNetEventAnalytics returns the Events page's short-window analytics series
// (Phase 2, PR 5) from the raw net_events table: the geo / identity / user /
// app / web-category / DNS / NAT breakdowns for the dimensions the rollups do
// not retain, over up to 720 hours (30 days, default 24). It is a read-only
// viewer-accessible endpoint (registered beside /api/events, NOT in
// adminOnlyRoutes) and adds no index or migration — every series groups over
// `ts >= cutoff`, served by the existing (ts) / (device_id, ts) indexes.
func (h *Handler) GetNetEventAnalytics(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"geo_src":        []database.NetEventGeoStat{},
			"geo_dst":        []database.NetEventGeoStat{},
			"identity":       []database.NetEventIdentityStat{},
			"users":          []database.KeyCount{},
			"apps":           []database.KeyCount{},
			"app_categories": []database.KeyCount{},
			"web_categories": []database.KeyCount{},
			"dns":            []database.KeyCount{},
			"nat":            []database.NetEventNATStat{},
		}))
		return
	}

	// hours is the short-window lookback: 1..720, default 24. Reject a
	// non-integer or out-of-range value up front (AUDIT-251 discipline — a bad
	// value is a 400, never a 500 from binding a bogus number into a bound).
	hours := 24
	if raw := strings.TrimSpace(c.Query("hours")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 720 {
			c.JSON(http.StatusBadRequest, response.Error("Invalid hours (expected 1..720)"))
			return
		}
		hours = n
	}

	// device_id / site_id must be valid uints before they are bound against the
	// uint columns (22P02/500 on Postgres; SQLite silently matches nothing).
	for _, name := range []string{"device_id", "site_id"} {
		if msg := validateNumericFilter(c, name); msg != "" {
			c.JSON(http.StatusBadRequest, response.Error(msg))
			return
		}
	}

	f := database.NetEventStatsFilter{Hours: hours}
	if v, ok := httputil.ParseUintQuery(c, "device_id"); ok {
		f.DeviceID = v
	}
	if v, ok := httputil.ParseUintQuery(c, "site_id"); ok {
		f.SiteID = v
	}

	stats, err := db.NetEventStats(f)
	if err != nil {
		httputil.InternalError(c, "Failed to get event analytics", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"geo_src":        stats.GeoSrc,
		"geo_dst":        stats.GeoDst,
		"identity":       stats.Identity,
		"users":          stats.Users,
		"apps":           stats.Apps,
		"app_categories": stats.AppCategories,
		"web_categories": stats.WebCategories,
		"dns":            stats.DNS,
		"nat":            stats.NAT,
	}))
}

// GetSecEventAnalytics returns the Security tab's class-scoped analytics
// (Phase 2, PR 6) from the raw sec_events table: the per-class day trends and
// top-N rankings for findings, admin logins, config changes, VPN sessions and
// WAN health. The window is named in `days` (1..365) or `hours` (1..720); when
// both are absent the store's 30-day default applies. It is a read-only
// viewer-accessible endpoint (registered beside /api/security-events, NOT in
// adminOnlyRoutes) and adds no index or migration — every series groups over
// `ts >= cutoff`, served by the existing (class, ts) / (device_id, ts) / (ts)
// indexes.
func (h *Handler) GetSecEventAnalytics(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"findings":          []database.SecEventDayCount{},
			"top_signatures":    []database.SecEventFindingStat{},
			"admin_logins":      []database.SecEventDayCount{},
			"top_admin_users":   []database.KeyCount{},
			"top_admin_src_ips": []database.KeyCount{},
			"config_changes":    []database.SecEventDayCount{},
			"top_config_paths":  []database.KeyCount{},
			"top_config_admins": []database.KeyCount{},
			"vpn_sessions":      []database.SecEventDayCount{},
			"top_tunnels":       []database.KeyCount{},
			"top_tunnel_peers":  []database.KeyCount{},
			"wan_health":        []database.SecEventWanHealth{},
		}))
		return
	}

	// days (1..365) and hours (1..720) name the lookback window; a non-integer
	// or out-of-range value is rejected up front (AUDIT-251 discipline — a bad
	// value is a 400, never a 500 from binding a bogus number into a bound).
	days := 0
	if raw := strings.TrimSpace(c.Query("days")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 365 {
			c.JSON(http.StatusBadRequest, response.Error("Invalid days (expected 1..365)"))
			return
		}
		days = n
	}
	hours := 0
	if raw := strings.TrimSpace(c.Query("hours")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 720 {
			c.JSON(http.StatusBadRequest, response.Error("Invalid hours (expected 1..720)"))
			return
		}
		hours = n
	}

	// device_id / site_id must be valid uints before they are bound against the
	// uint columns (22P02/500 on Postgres; SQLite silently matches nothing).
	for _, name := range []string{"device_id", "site_id"} {
		if msg := validateNumericFilter(c, name); msg != "" {
			c.JSON(http.StatusBadRequest, response.Error(msg))
			return
		}
	}

	f := database.SecEventStatsFilter{Days: days, Hours: hours}
	if v, ok := httputil.ParseUintQuery(c, "device_id"); ok {
		f.DeviceID = v
	}
	if v, ok := httputil.ParseUintQuery(c, "site_id"); ok {
		f.SiteID = v
	}

	stats, err := db.SecEventStats(f)
	if err != nil {
		httputil.InternalError(c, "Failed to get security event analytics", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"findings":          stats.Findings,
		"top_signatures":    stats.TopSignatures,
		"admin_logins":      stats.AdminLogins,
		"top_admin_users":   stats.TopAdminUsers,
		"top_admin_src_ips": stats.TopAdminSrcIPs,
		"config_changes":    stats.ConfigChanges,
		"top_config_paths":  stats.TopConfigPaths,
		"top_config_admins": stats.TopConfigAdmins,
		"vpn_sessions":      stats.VPNSessions,
		"top_tunnels":       stats.TopTunnels,
		"top_tunnel_peers":  stats.TopTunnelPeers,
		"wan_health":        stats.WanHealth,
	}))
}
