package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) ListAlertPolicies(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	policies, err := db.GetAlertPolicies()
	if err != nil {
		httputil.InternalError(c, "Failed to get alert policies", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(policies))
}

func (h *Handler) GetAlertPolicy(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	policy, err := db.GetAlertPolicy(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Alert policy not found"))
		return
	}

	c.JSON(http.StatusOK, response.Success(policy))
}

func (h *Handler) CreateAlertPolicy(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var policy models.AlertPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if strings.TrimSpace(policy.Name) == "" {
		c.JSON(http.StatusBadRequest, response.Error("Policy name is required"))
		return
	}
	if len(policy.Name) > 200 || len(policy.Description) > 1000 {
		c.JSON(http.StatusBadRequest, response.Error("Name (max 200) or description (max 1000) too long"))
		return
	}
	if _, err := alerts.ParseEscalationSteps(policy.EscalationSteps); err != nil {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("Invalid escalation steps: %v", err)))
		return
	}

	policy.ID = 0
	if err := db.CreateAlertPolicy(&policy); err != nil {
		httputil.InternalError(c, "Failed to create alert policy", err)
		return
	}
	h.refreshAlertConfigCache(db)

	c.JSON(http.StatusCreated, response.Success(policy))
}

func (h *Handler) UpdateAlertPolicy(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	existing, err := db.GetAlertPolicy(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Alert policy not found"))
		return
	}

	var policy models.AlertPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if _, perr := alerts.ParseEscalationSteps(policy.EscalationSteps); perr != nil {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("Invalid escalation steps: %v", perr)))
		return
	}

	policy.ID = existing.ID
	policy.CreatedAt = existing.CreatedAt
	if err := db.UpdateAlertPolicy(&policy); err != nil {
		httputil.InternalError(c, "Failed to update alert policy", err)
		return
	}
	h.refreshAlertConfigCache(db)

	c.JSON(http.StatusOK, response.Success(policy))
}

func (h *Handler) DeleteAlertPolicy(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := db.DeleteAlertPolicy(id); err != nil {
		if err.Error() == "cannot delete the default alert policy" {
			c.JSON(http.StatusBadRequest, response.Error(err.Error()))
		} else {
			httputil.InternalError(c, "Failed to delete alert policy", err)
		}
		return
	}
	h.refreshAlertConfigCache(db)

	c.JSON(http.StatusOK, response.Message("Alert policy deleted"))
}

func (h *Handler) CloneAlertPolicy(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	src, err := db.GetAlertPolicy(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Alert policy not found"))
		return
	}

	clone := *src
	clone.ID = 0
	clone.Name = src.Name + " (Copy)"
	clone.IsDefault = false
	clone.Rules = nil

	if err := db.CreateAlertPolicy(&clone); err != nil {
		httputil.InternalError(c, "Failed to clone policy", err)
		return
	}

	// Clone rules
	if len(src.Rules) > 0 {
		rules := make([]models.AlertRule, len(src.Rules))
		for i, r := range src.Rules {
			rules[i] = r
			rules[i].ID = 0
			rules[i].PolicyID = clone.ID
		}
		if err := db.BatchUpsertAlertRules(clone.ID, rules); err != nil {
			httputil.InternalError(c, "Failed to clone rules", err)
			return
		}
	}

	h.refreshAlertConfigCache(db)

	// Reload with rules
	result, _ := db.GetAlertPolicy(clone.ID)
	c.JSON(http.StatusCreated, response.Success(result))
}

func (h *Handler) BatchUpsertAlertRules(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	// Verify policy exists
	if _, err := db.GetAlertPolicy(id); err != nil {
		c.JSON(http.StatusNotFound, response.Error("Alert policy not found"))
		return
	}

	var rules []models.AlertRule
	if err := c.ShouldBindJSON(&rules); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if err := db.BatchUpsertAlertRules(id, rules); err != nil {
		httputil.InternalError(c, "Failed to save rules", err)
		return
	}
	h.refreshAlertConfigCache(db)

	// Reload policy with rules
	policy, _ := db.GetAlertPolicy(id)
	c.JSON(http.StatusOK, response.Success(policy))
}

// refreshAlertConfigCache reloads the AlertManager's policy/threshold cache
// immediately after an admin edits an alert config, so the modal's own
// save→re-render loop shows the new value instead of waiting up to 60s for the
// background ticker (cmd/api LC-9). Admin-rate, nil-safe.
func (h *Handler) refreshAlertConfigCache(db database.Store) {
	if h.alertManager == nil || db == nil {
		return
	}
	h.alertManager.RefreshThresholds(db.Gorm())
}

// metricSampleKey maps a metric AlertType to the telemetry sample key the metric
// Event Rule engine matches on (mirrors CheckSystemStatus). Empty for non-metric
// types — the effective endpoint restricts to these four.
func metricSampleKey(at models.AlertType) string {
	switch at {
	case models.AlertTypeCPUHigh:
		return "cpu_usage"
	case models.AlertTypeMemoryHigh:
		return "memory_usage"
	case models.AlertTypeDiskHigh:
		return "disk_usage"
	case models.AlertTypeSessionsHigh:
		return "session_count"
	}
	return ""
}

// GetEffectiveAlertConfig returns the RESOLVED alert config that actually fires
// for a device or site + metric alert type, with per-field provenance, so the
// device/site modals can show "inherits 80 from Global" vs "overridden to 85
// here" vs "set by rule X". Read-only, admin-only. Reconciles both the layered
// resolve chain AND a matching metric Event Rule (via AlertManager.EffectiveAlertConfig).
func (h *Handler) GetEffectiveAlertConfig(c *gin.Context) {
	if h.alertManager == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Alert engine not ready"))
		return
	}

	alertType := models.AlertType(strings.TrimSpace(c.Query("alert_type")))
	metric := metricSampleKey(alertType)
	if metric == "" {
		c.JSON(http.StatusBadRequest, response.Error("alert_type must be one of CPU_HIGH, MEMORY_HIGH, DISK_HIGH, SESSIONS_HIGH"))
		return
	}

	deviceID, dOK := httputil.ParseUintQuery(c, "device_id")
	siteRaw, sOK := httputil.ParseUintQuery(c, "site_id")
	if !dOK && !sOK {
		c.JSON(http.StatusBadRequest, response.Error("device_id or site_id is required"))
		return
	}
	var siteID *uint
	if sOK {
		siteID = &siteRaw
	}

	resolved, prov := h.alertManager.EffectiveAlertConfig(deviceID, siteID, alertType, metric)

	c.JSON(http.StatusOK, response.Success(gin.H{
		"alert_type": alertType,
		"effective": gin.H{
			"threshold":        resolved.Threshold,
			"clear_threshold":  resolved.ClearThreshold,
			"mode":             resolved.Mode,
			"zscore_k":         resolved.ZScoreK,
			"cooldown_minutes": resolved.CooldownMinutes,
			"severity":         resolved.Severity,
			"alert_enabled":    resolved.AlertEnabled,
			"storm_sources":    resolved.StormSources,
		},
		"provenance": gin.H{
			"threshold":          prov.Threshold,
			"cooldown":           prov.Cooldown,
			"suppressed_by_rule": prov.SuppressedByRule,
			"alerts_disabled":    prov.AlertsDisabled,
			"rule_id":            prov.RuleID,
			"rule_name":          prov.RuleName,
		},
	}))
}

// Device alert config endpoints

func (h *Handler) GetDeviceAlertConfig(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	cfg, err := db.GetDeviceAlertConfig(id)
	if err != nil {
		// Return empty config (not an error — device just has no overrides)
		c.JSON(http.StatusOK, response.Success(models.DeviceAlertConfig{
			DeviceID:      id,
			AlertsEnabled: true,
		}))
		return
	}

	c.JSON(http.StatusOK, response.Success(cfg))
}

func (h *Handler) UpsertDeviceAlertConfig(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	// v0.10.234: load existing first, then bind the request onto it. The
	// previous code did ShouldBindJSON into a FRESH struct then Save'd
	// the whole thing — any field absent from the PUT body landed as Go
	// zero-value, so a partial edit silently wiped sibling fields (memory
	// threshold zeroed when only cpu was sent, alerts_enabled flipped to
	// false because the bool zero is false, policy_id cleared, etc.).
	// encoding/json (which ShouldBindJSON wraps) only writes struct fields
	// that ARE present in the JSON body, so loading first preserves the
	// untouched columns. The "create if absent" path keeps the model's
	// AlertsEnabled=true default.
	cfg, err := db.GetDeviceAlertConfig(id)
	if err != nil {
		cfg = &models.DeviceAlertConfig{DeviceID: id, AlertsEnabled: true}
	}
	if err := c.ShouldBindJSON(cfg); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	cfg.DeviceID = id // prevent client from rewriting the FK

	if msg := validateAlertConfigThresholds(cfg.CPUThreshold, cfg.MemoryThreshold, cfg.DiskThreshold, cfg.SessionThreshold, cfg.CooldownMinutes); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}

	if err := db.UpsertDeviceAlertConfig(cfg); err != nil {
		httputil.InternalError(c, "Failed to save device alert config", err)
		return
	}
	h.refreshAlertConfigCache(db)

	c.JSON(http.StatusOK, response.Success(cfg))
}

// validateAlertConfigThresholds enforces sensible ranges shared by both the
// device and site alert-config upserts. v0.10.234: previously no validation
// at all, so a buggy UI could persist negative thresholds or 200% CPU.
func validateAlertConfigThresholds(cpu, mem, disk float64, sessions, cooldown int) string {
	for _, p := range []struct {
		name string
		val  float64
	}{{"cpu_threshold", cpu}, {"memory_threshold", mem}, {"disk_threshold", disk}} {
		if p.val < 0 || p.val > 100 {
			return p.name + " must be between 0 and 100"
		}
	}
	if sessions < 0 {
		return "session_threshold must be non-negative"
	}
	if cooldown < 0 {
		return "cooldown_minutes must be non-negative"
	}
	return ""
}

func (h *Handler) DeleteDeviceAlertConfig(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := db.DeleteDeviceAlertConfig(id); err != nil {
		httputil.InternalError(c, "Failed to delete device alert config", err)
		return
	}
	h.refreshAlertConfigCache(db)

	c.JSON(http.StatusOK, response.Message("Device alert config deleted"))
}

// Site alert config endpoints

func (h *Handler) GetSiteAlertConfig(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	cfg, err := db.GetSiteAlertConfig(id)
	if err != nil {
		c.JSON(http.StatusOK, response.Success(models.SiteAlertConfig{
			SiteID: id,
		}))
		return
	}

	c.JSON(http.StatusOK, response.Success(cfg))
}

func (h *Handler) UpsertSiteAlertConfig(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	// v0.10.234: same load-then-bind pattern as UpsertDeviceAlertConfig
	// above. See the comment there for the rationale. SiteAlertConfig has
	// no AlertsEnabled column (site configs always apply when present);
	// the rest of the threshold/cooldown surface mirrors DeviceAlertConfig.
	cfg, err := db.GetSiteAlertConfig(id)
	if err != nil {
		cfg = &models.SiteAlertConfig{SiteID: id}
	}
	if err := c.ShouldBindJSON(cfg); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	cfg.SiteID = id // prevent client from rewriting the FK

	if msg := validateAlertConfigThresholds(cfg.CPUThreshold, cfg.MemoryThreshold, cfg.DiskThreshold, cfg.SessionThreshold, cfg.CooldownMinutes); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}

	if err := db.UpsertSiteAlertConfig(cfg); err != nil {
		httputil.InternalError(c, "Failed to save site alert config", err)
		return
	}
	h.refreshAlertConfigCache(db)

	c.JSON(http.StatusOK, response.Success(cfg))
}

func (h *Handler) DeleteSiteAlertConfig(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := db.DeleteSiteAlertConfig(id); err != nil {
		httputil.InternalError(c, "Failed to delete site alert config", err)
		return
	}
	h.refreshAlertConfigCache(db)

	c.JSON(http.StatusOK, response.Message("Site alert config deleted"))
}
