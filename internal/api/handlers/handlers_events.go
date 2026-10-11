package handlers

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
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
