package handlers

import (
	"net/http"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
)

// Incidents (F12): read-only views over the grouped alert storms. Writes
// happen exclusively in the poller's correlator.

func (h *Handler) ListIncidents(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	limit, offset := httputil.ParsePagination(c)
	incs, total, err := db.ListIncidents(limit, offset)
	if err != nil {
		httputil.InternalError(c, "Failed to list incidents", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"incidents": incs, "total": total}))
}

func (h *Handler) GetIncidentAlerts(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	alerts, err := db.GetIncidentAlerts(id)
	if err != nil {
		httputil.InternalError(c, "Failed to load incident alerts", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(alerts))
}
