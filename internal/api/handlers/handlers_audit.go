package handlers

import (
	"net/http"
	"time"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// GetAuditLogs returns the admin-action audit trail (AUDIT-078), newest first,
// with optional filters: ?actor=<username>, ?action=<route-template>, and
// ?hours=<N> (records since N hours ago), plus standard ?limit/?offset
// pagination. Read-only — the trail is written exclusively by the audit
// middleware.
func (h *Handler) GetAuditLogs(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	limit, offset := httputil.ParsePagination(c)
	actor := c.Query("actor")
	action := c.Query("action")

	var since time.Time
	if c.Query("hours") != "" {
		since = time.Now().Add(-time.Duration(httputil.ParseHours(c)) * time.Hour)
	}

	logs, total, err := db.GetAuditLogs(actor, action, since, limit, offset)
	if err != nil {
		httputil.InternalError(c, "Failed to get audit logs", err)
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"audit_logs": logs,
		"total":      total,
		"limit":      limit,
		"offset":     offset,
	}))
}
