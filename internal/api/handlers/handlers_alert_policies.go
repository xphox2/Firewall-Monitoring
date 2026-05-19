package handlers

import (
	"net/http"
	"strings"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) ListAlertPolicies(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	policies, err := h.db.GetAlertPolicies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get alert policies"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(policies))
}

func (h *Handler) GetAlertPolicy(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	policy, err := h.db.GetAlertPolicy(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Alert policy not found"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(policy))
}

func (h *Handler) CreateAlertPolicy(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	var policy models.AlertPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if strings.TrimSpace(policy.Name) == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Policy name is required"))
		return
	}
	if len(policy.Name) > 200 || len(policy.Description) > 1000 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Name (max 200) or description (max 1000) too long"))
		return
	}

	policy.ID = 0
	if err := h.db.CreateAlertPolicy(&policy); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create alert policy"))
		return
	}

	c.JSON(http.StatusCreated, models.SuccessResponse(policy))
}

func (h *Handler) UpdateAlertPolicy(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	existing, err := h.db.GetAlertPolicy(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Alert policy not found"))
		return
	}

	var policy models.AlertPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	policy.ID = existing.ID
	policy.CreatedAt = existing.CreatedAt
	if err := h.db.UpdateAlertPolicy(&policy); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update alert policy"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(policy))
}

func (h *Handler) DeleteAlertPolicy(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := h.db.DeleteAlertPolicy(id); err != nil {
		if err.Error() == "cannot delete the default alert policy" {
			c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		} else {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete alert policy"))
		}
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Alert policy deleted"))
}

func (h *Handler) CloneAlertPolicy(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	src, err := h.db.GetAlertPolicy(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Alert policy not found"))
		return
	}

	clone := *src
	clone.ID = 0
	clone.Name = src.Name + " (Copy)"
	clone.IsDefault = false
	clone.Rules = nil

	if err := h.db.CreateAlertPolicy(&clone); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to clone policy"))
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
		if err := h.db.BatchUpsertAlertRules(clone.ID, rules); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to clone rules"))
			return
		}
	}

	// Reload with rules
	result, _ := h.db.GetAlertPolicy(clone.ID)
	c.JSON(http.StatusCreated, models.SuccessResponse(result))
}

func (h *Handler) BatchUpsertAlertRules(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	// Verify policy exists
	if _, err := h.db.GetAlertPolicy(id); err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Alert policy not found"))
		return
	}

	var rules []models.AlertRule
	if err := c.ShouldBindJSON(&rules); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if err := h.db.BatchUpsertAlertRules(id, rules); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save rules"))
		return
	}

	// Reload policy with rules
	policy, _ := h.db.GetAlertPolicy(id)
	c.JSON(http.StatusOK, models.SuccessResponse(policy))
}

// Device alert config endpoints

func (h *Handler) GetDeviceAlertConfig(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	cfg, err := h.db.GetDeviceAlertConfig(id)
	if err != nil {
		// Return empty config (not an error — device just has no overrides)
		c.JSON(http.StatusOK, models.SuccessResponse(models.DeviceAlertConfig{
			DeviceID:      id,
			AlertsEnabled: true,
		}))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(cfg))
}

func (h *Handler) UpsertDeviceAlertConfig(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
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
	cfg, err := h.db.GetDeviceAlertConfig(id)
	if err != nil {
		cfg = &models.DeviceAlertConfig{DeviceID: id, AlertsEnabled: true}
	}
	if err := c.ShouldBindJSON(cfg); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}
	cfg.DeviceID = id // prevent client from rewriting the FK

	if msg := validateAlertConfigThresholds(cfg.CPUThreshold, cfg.MemoryThreshold, cfg.DiskThreshold, cfg.SessionThreshold, cfg.CooldownMinutes); msg != "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(msg))
		return
	}

	if err := h.db.UpsertDeviceAlertConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save device alert config"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(cfg))
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
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := h.db.DeleteDeviceAlertConfig(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete device alert config"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Device alert config deleted"))
}

// Site alert config endpoints

func (h *Handler) GetSiteAlertConfig(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	cfg, err := h.db.GetSiteAlertConfig(id)
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(models.SiteAlertConfig{
			SiteID: id,
		}))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(cfg))
}

func (h *Handler) UpsertSiteAlertConfig(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
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
	cfg, err := h.db.GetSiteAlertConfig(id)
	if err != nil {
		cfg = &models.SiteAlertConfig{SiteID: id}
	}
	if err := c.ShouldBindJSON(cfg); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}
	cfg.SiteID = id // prevent client from rewriting the FK

	if msg := validateAlertConfigThresholds(cfg.CPUThreshold, cfg.MemoryThreshold, cfg.DiskThreshold, cfg.SessionThreshold, cfg.CooldownMinutes); msg != "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(msg))
		return
	}

	if err := h.db.UpsertSiteAlertConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save site alert config"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(cfg))
}

func (h *Handler) DeleteSiteAlertConfig(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := h.db.DeleteSiteAlertConfig(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete site alert config"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Site alert config deleted"))
}
