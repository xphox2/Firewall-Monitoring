package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// itoa formats a uint for the audit-note strings below.
func itoa(n uint) string { return strconv.FormatUint(uint64(n), 10) }

// clampHours bounds a suppression/snooze duration to [1, 720] (30 days), with a
// zero/negative input defaulting to 24h — the operator's "silence this attacker
// for a day" case.
func clampHours(h int) int {
	if h == 0 {
		return 24
	}
	if h < 1 {
		return 1
	}
	if h > 720 {
		return 720
	}
	return h
}

// actor returns the authenticated username for audit fields, or "" if unknown.
func actor(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// alertSources returns the distinct source IPs behind an alert: its persisted
// SourceAddr plus every linked detection's SrcAddr. Used to validate a caller-
// supplied src and to enumerate a digest's offenders.
func (h *Handler) alertSources(db interface {
	GetDetectionsByAlert(uint) ([]models.FlowDetection, error)
}, a *models.Alert) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add(a.SourceAddr)
	if dets, err := db.GetDetectionsByAlert(a.ID); err == nil {
		for i := range dets {
			add(dets[i].SrcAddr)
		}
	}
	return out
}

// isSuppressibleAlert reports whether an alert type supports source silencing —
// only the consolidated security alert and its storm digest.
func isSuppressibleAlert(t models.AlertType) bool {
	return t == models.AlertTypeSFlowSecurity || t == models.AlertTypeSFlowSecurityDigest
}

// SuppressAlertSource silences ONE attacking source behind an sFlow security
// alert for {hours} (default 24). Body: {hours, src?}. When src is supplied it
// MUST be one of the alert's sources (rejected otherwise); when omitted it uses
// the alert's SourceAddr, falling back to the first linked detection's source. A
// per-source alert is also acked (the attacker is handled); a digest is NOT
// auto-acked (other offenders remain). v0.11.46.
func (h *Handler) SuppressAlertSource(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var body struct {
		Hours int    `json:"hours"`
		Src   string `json:"src"`
	}
	c.ShouldBindJSON(&body)

	var alert models.Alert
	if err := db.Gorm().First(&alert, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Alert not found"))
		return
	}
	if !isSuppressibleAlert(alert.AlertType) {
		c.JSON(http.StatusUnprocessableEntity, response.Error("Only sFlow security alerts can silence a source"))
		return
	}

	sources := h.alertSources(db, &alert)
	src := strings.TrimSpace(body.Src)
	if src != "" {
		valid := false
		for _, s := range sources {
			if s == src {
				valid = true
				break
			}
		}
		if !valid {
			c.JSON(http.StatusUnprocessableEntity, response.Error("src is not one of this alert's sources"))
			return
		}
	} else {
		if len(sources) == 0 {
			c.JSON(http.StatusUnprocessableEntity, response.Error("No source to silence for this alert"))
			return
		}
		src = sources[0]
	}

	hours := clampHours(body.Hours)
	until := time.Now().Add(time.Duration(hours) * time.Hour)
	reason := "silenced from alert #" + itoa(id)
	if err := db.SuppressFlowSource(src, until, actor(c), reason); err != nil {
		httputil.InternalError(c, "Failed to silence source", err)
		return
	}
	// Per-source alert: the attacker behind it is handled — ack it so it leaves
	// the open queue. Digest: leave open (other offenders remain).
	if alert.AlertType == models.AlertTypeSFlowSecurity {
		if err := db.AcknowledgeAlertEnhanced(id, "Source "+src+" silenced for "+itoa(uint(hours))+"h"); err != nil {
			httputil.InternalError(c, "Failed to acknowledge alert", err)
			return
		}
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"src": src, "hours": hours, "suppressed_until": until}))
}

// SuppressAlertAllSources silences EVERY source behind a digest alert for {hours}
// and acks the digest (all offenders handled). Digest-only. v0.11.46.
func (h *Handler) SuppressAlertAllSources(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var body struct {
		Hours int `json:"hours"`
	}
	c.ShouldBindJSON(&body)

	var alert models.Alert
	if err := db.Gorm().First(&alert, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Alert not found"))
		return
	}
	if alert.AlertType != models.AlertTypeSFlowSecurityDigest {
		c.JSON(http.StatusUnprocessableEntity, response.Error("Silence-all applies only to a storm digest"))
		return
	}
	sources := h.alertSources(db, &alert)
	if len(sources) == 0 {
		c.JSON(http.StatusUnprocessableEntity, response.Error("No sources to silence"))
		return
	}
	hours := clampHours(body.Hours)
	until := time.Now().Add(time.Duration(hours) * time.Hour)
	reason := "silenced from digest #" + itoa(id)
	who := actor(c)
	for _, s := range sources {
		if err := db.SuppressFlowSource(s, until, who, reason); err != nil {
			httputil.InternalError(c, "Failed to silence sources", err)
			return
		}
	}
	if err := db.AcknowledgeAlertEnhanced(id, itoa(uint(len(sources)))+" sources silenced for "+itoa(uint(hours))+"h"); err != nil {
		httputil.InternalError(c, "Failed to acknowledge digest", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"count": len(sources), "hours": hours, "suppressed_until": until}))
}

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

// ListFlowSuppressions returns the active silenced sources for the admin panel.
func (h *Handler) ListFlowSuppressions(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	rows, err := db.ListActiveFlowSuppressions()
	if err != nil {
		httputil.InternalError(c, "Failed to list silenced sources", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(rows))
}

// DeleteFlowSuppression un-silences a source (removes the suppression row).
func (h *Handler) DeleteFlowSuppression(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if err := db.DeleteFlowSuppression(id); err != nil {
		httputil.InternalError(c, "Failed to un-silence source", err)
		return
	}
	c.JSON(http.StatusOK, response.Message("Source un-silenced"))
}
