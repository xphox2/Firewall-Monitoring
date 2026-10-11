package handlers

import (
	"net/http"
	"strconv"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
)

// GetNetEvents lists normalized network events for the admin Events page. It
// is the first reader of the net_events table (Phase 2, PR 1) and a read-only
// viewer-accessible endpoint — registered beside /api/syslog, NOT in
// adminOnlyRoutes. Filters are time (hours), device/probe/site, and the
// activity/action enum columns; src/dst/rule-key filters are a later PR that
// also adds their indexes (v80 dropped them after their one reader moved to
// net_event_rollups).
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

	rows, total, capped, err := db.ListNetEvents(f, offset, limit)
	if err != nil {
		httputil.InternalError(c, "Failed to get network events", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{"events": rows, "total": total, "total_capped": capped}))
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
