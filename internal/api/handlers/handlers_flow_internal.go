package handlers

import (
	"net/http"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
)

// GetFlowInternalNetworks lists the networks flow direction currently treats
// as the operator's own — the manual list and what was derived from the
// monitored devices — each with its source, so the Settings page can show
// exactly why an address counts as inside. Admin-only (adminOnlyRoutes): it
// reveals the network layout.
func (h *Handler) GetFlowInternalNetworks(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	nets, err := db.LoadInternalNetworks()
	if err != nil {
		httputil.InternalError(c, "Failed to load internal networks", err)
		return
	}
	if nets == nil {
		nets = []database.InternalNetwork{}
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"networks": nets,
		"auto":     db.GetBoolSetting(database.FlowInternalAutoKey, true),
	}))
}
