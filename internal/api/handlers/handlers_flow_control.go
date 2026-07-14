package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// itoa formats a uint for the small string-building helpers in this package.
func itoa(n uint) string { return strconv.FormatUint(uint64(n), 10) }

// upsertSettingValue writes one system_settings row (create-or-update just the
// value/label/category), for the bespoke admin-UI toggles that are deliberately
// NOT part of the general Settings form + allowedKeys whitelist (v0.11.46 config
// principle: UI-managed, single source of truth on the owning page).
func (h *Handler) upsertSettingValue(c *gin.Context, key, value, label, category string) bool {
	db := h.reqDB(c)
	existing := models.SystemSetting{Key: key}
	if err := db.Gorm().FirstOrCreate(&existing, models.SystemSetting{Key: key}).Error; err != nil {
		httputil.InternalError(c, "Failed to persist setting", err)
		return false
	}
	existing.Value = value
	existing.Label = label
	existing.Category = category
	existing.Type = "string"
	existing.IsSecret = false
	if err := db.Gorm().Save(&existing).Error; err != nil {
		httputil.InternalError(c, "Failed to persist setting", err)
		return false
	}
	return true
}

// PatchThreatFeed toggles ONE feed on/off (admin-only). On disable it IMMEDIATELY
// purges that feed's indicators and refreshes the API matcher so ingest stops
// flagging them at once; on enable it only flips the flag + refreshes (the poller
// repopulates on its next per-cycle recheck — the API can't sync across the
// process boundary). v0.11.46.
func (h *Handler) PatchThreatFeed(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	source := strings.TrimSpace(c.Param("source"))
	if source == "" {
		c.JSON(http.StatusBadRequest, response.Error("Missing feed source"))
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enabled == nil {
		c.JSON(http.StatusBadRequest, response.Error("Body must include enabled (bool)"))
		return
	}
	if err := db.SetThreatFeedEnabled(source, *body.Enabled); err != nil {
		httputil.InternalError(c, "Failed to set feed state", err)
		return
	}
	purged := int64(0)
	if !*body.Enabled {
		if n, err := db.DeleteThreatIntelBySource(source); err != nil {
			httputil.InternalError(c, "Failed to purge feed indicators", err)
			return
		} else {
			purged = n
		}
	}
	// Refresh the API-local matcher either way: on disable the purged rows leave
	// immediately; on enable the (still-empty-for-this-source) matcher is a no-op
	// until the poller repopulates.
	h.RefreshThreatMatcher()
	c.JSON(http.StatusOK, response.Success(gin.H{
		"source":  source,
		"enabled": *body.Enabled,
		"purged":  purged,
		"note":    feedToggleNote(*body.Enabled),
	}))
}

func feedToggleNote(enabled bool) string {
	if enabled {
		return "Feed enabled — indicators repopulate within a few minutes on the next sync."
	}
	return "Feed disabled — its indicators were purged from matching immediately."
}

// PatchThreatFeedsGlobal flips the master switch (admin-only). Writes the
// admin-UI setting (env is only the default) and refreshes the matcher: off →
// empty immediately (rows kept, so re-enabling is instant); on → the poller syncs
// on its next recheck. v0.11.46.
func (h *Handler) PatchThreatFeedsGlobal(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enabled == nil {
		c.JSON(http.StatusBadRequest, response.Error("Body must include enabled (bool)"))
		return
	}
	val := "false"
	if *body.Enabled {
		val = "true"
	}
	if !h.upsertSettingValue(c, "threat_feeds_enabled", val, "Threat feeds master switch", "threat_intel") {
		return
	}
	h.RefreshThreatMatcher()
	note := "Threat feeds turned off — matching stopped immediately (indicators retained for instant re-enable)."
	if *body.Enabled {
		note = "Threat feeds turned on — syncing; indicators repopulate within a few minutes."
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"enabled": *body.Enabled, "note": note}))
}

// PatchStormTuning sets the global cross-source storm threshold
// (detect_security_storm_sources) from the admin UI (admin-only). The poller
// reads it each detection cycle, so a change takes effect without a restart; a
// value <= 0 disables the digest globally. v0.11.46.
func (h *Handler) PatchStormTuning(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var body struct {
		StormSources *int `json:"storm_sources"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.StormSources == nil {
		c.JSON(http.StatusBadRequest, response.Error("Body must include storm_sources (int)"))
		return
	}
	n := *body.StormSources
	if n < 0 {
		n = 0
	}
	if n > 100000 {
		n = 100000
	}
	if !h.upsertSettingValue(c, "detect_security_storm_sources", strconv.Itoa(n), "Security storm digest threshold", "threat_intel") {
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"storm_sources": n}))
}

// GetStormTuning returns the current storm threshold for the admin UI control.
func (h *Handler) GetStormTuning(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"storm_sources": db.GetIntSetting("detect_security_storm_sources", 25),
	}))
}
