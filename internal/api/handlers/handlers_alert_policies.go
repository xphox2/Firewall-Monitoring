package handlers

import (
	"fmt"
	"net/http"
	"strconv"
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

	// AUDIT-249: per-policy webhook URLs are postable bearer credentials and
	// this GET is viewer-visible — mask them like every other read path.
	httputil.RedactAlertPolicies(policies)
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

	// AUDIT-249: mask the webhook URLs on this read path too.
	httputil.RedactAlertPolicy(policy)
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
	// AUDIT-249: a literal mask on CREATE can only be a client bug — there is
	// no stored value to preserve, and storing it would make "********" the
	// live webhook URL.
	if policy.SlackWebhookURL == httputil.RedactedMask ||
		policy.DiscordWebhookURL == httputil.RedactedMask ||
		policy.WebhookURL == httputil.RedactedMask {
		c.JSON(http.StatusBadRequest, response.Error("Webhook URL must be a real URL, not the redacted placeholder"))
		return
	}

	policy.ID = 0
	if err := db.CreateAlertPolicy(&policy); err != nil {
		httputil.InternalError(c, "Failed to create alert policy", err)
		return
	}
	h.refreshAlertConfigCache(db)

	// AUDIT-249: mask the response copy like every other policy read.
	httputil.RedactAlertPolicy(&policy)
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
	// AUDIT-249 preserve-on-write: reads mask the webhook URLs, the admin UI
	// round-trips every field, and db.UpdateAlertPolicy is a full-column Save
	// — so without this restore, the FIRST save of any policy after the mask
	// landed would overwrite every stored webhook with "********" (the exact
	// mask-overwrite bug class documented on httputil.RedactedMask).
	if policy.SlackWebhookURL == httputil.RedactedMask {
		policy.SlackWebhookURL = existing.SlackWebhookURL
	}
	if policy.DiscordWebhookURL == httputil.RedactedMask {
		policy.DiscordWebhookURL = existing.DiscordWebhookURL
	}
	if policy.WebhookURL == httputil.RedactedMask {
		policy.WebhookURL = existing.WebhookURL
	}
	if err := db.UpdateAlertPolicy(&policy); err != nil {
		httputil.InternalError(c, "Failed to update alert policy", err)
		return
	}
	h.refreshAlertConfigCache(db)

	// Mask the response copy (in memory only — the row is already saved):
	// a save must not become the read path that hands the live URLs back.
	httputil.RedactAlertPolicy(&policy)
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
	// AUDIT-249: the clone COPIES the source's live webhook URLs straight from
	// the DB (correct — no masked client payload is involved), but the
	// response is a read and gets the mask like every other.
	if result != nil {
		httputil.RedactAlertPolicy(result)
	}
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
	// AUDIT-249: mask the webhook URLs on this read path too.
	if policy != nil {
		httputil.RedactAlertPolicy(policy)
	}
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
			"in_maintenance":   resolved.InMaintenance,
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

// alertOverrideRow is one customized-threshold entry for the Alerting hub's
// overrides overview. Value/AlertType are omitted for non-threshold kinds
// (e.g. "disabled").
type alertOverrideRow struct {
	Scope          string           `json:"scope"` // global|policy|site|device|rule
	ScopeID        uint             `json:"scope_id"`
	ScopeName      string           `json:"scope_name"`
	AlertType      models.AlertType `json:"alert_type,omitempty"`
	Value          float64          `json:"value,omitempty"`
	Kind           string           `json:"kind"` // threshold|disabled|custom
	ShadowedByRule bool             `json:"shadowed_by_rule,omitempty"`
}

// metricThresholdRows emits one "threshold" row per metric the config overrides
// (stored value > 0), so the overview lists only what's actually customized.
func metricThresholdRows(scope string, id uint, name string, cpu, mem, disk float64, sess int) []alertOverrideRow {
	var out []alertOverrideRow
	add := func(at models.AlertType, v float64) {
		if v > 0 {
			out = append(out, alertOverrideRow{Scope: scope, ScopeID: id, ScopeName: name, AlertType: at, Value: v, Kind: "threshold"})
		}
	}
	add(models.AlertTypeCPUHigh, cpu)
	add(models.AlertTypeMemoryHigh, mem)
	add(models.AlertTypeDiskHigh, disk)
	add(models.AlertTypeSessionsHigh, float64(sess))
	return out
}

// alertGlobalDefaults reads the global threshold + spike defaults from
// SystemSettings (fresh DB read), falling back to the process config for any
// key not yet persisted. These are the values the Alerting hub edits.
func (h *Handler) alertGlobalDefaults(db database.Store) gin.H {
	// AUDIT-250: one locked snapshot — the poller/API refresh loop rewrites
	// the shared config.Alerts in place under the AlertManager's lock.
	ac := h.alertsConfigSnapshot()
	g := gin.H{
		"cpu_threshold":              ac.CPUThreshold,
		"memory_threshold":           ac.MemoryThreshold,
		"disk_threshold":             ac.DiskThreshold,
		"session_threshold":          ac.SessionThreshold,
		"spike_alert_enabled":        ac.SpikeAlertEnabled,
		"spike_stddev_threshold":     ac.SpikeStdDevThreshold,
		"spike_min_duration_minutes": ac.SpikeMinDurationMinutes,
		"spike_min_throughput_mbps":  ac.SpikeMinThroughputMbps,
		// Code default matches telemetryStaleDefaultMinutes in cmd/poller.
		"telemetry_stale_minutes": 60,
		// The fwmon server's own volumes; see serverhealth.
		"server_disk_threshold":     85,
		"server_disk_free_floor_gb": 5,
	}
	var settings []models.SystemSetting
	db.Gorm().Where(`"key" IN ?`, []string{
		"cpu_threshold", "memory_threshold", "disk_threshold", "session_threshold",
		"spike_alert_enabled", "spike_stddev_threshold", "spike_min_duration_minutes",
		"spike_min_throughput_mbps", "telemetry_stale_minutes",
		"server_disk_threshold", "server_disk_free_floor_gb",
	}).Find(&settings)
	for _, s := range settings {
		if s.Value == "" {
			continue
		}
		switch s.Key {
		case "cpu_threshold", "memory_threshold", "disk_threshold", "spike_stddev_threshold",
			"spike_min_throughput_mbps", "server_disk_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil {
				g[s.Key] = v
			}
		case "session_threshold", "spike_min_duration_minutes", "telemetry_stale_minutes",
			"server_disk_free_floor_gb":
			if v, err := strconv.Atoi(s.Value); err == nil {
				g[s.Key] = v
			}
		case "spike_alert_enabled":
			g[s.Key] = s.Value == "true"
		}
	}
	return g
}

// GetAlertConfigOverview returns the global defaults plus a bounded list of every
// scope that customizes a threshold (site/device/policy-rule/metric-rule) — the
// data behind the Alerting hub. Read-only; viewer-accessible (thresholds aren't
// secrets, matching the effective endpoint).
func (h *Handler) GetAlertConfigOverview(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	devName := map[uint]string{}
	if devs, err := db.GetAllDevices(); err == nil {
		for _, d := range devs {
			devName[d.ID] = d.Name
		}
	}
	siteName := map[uint]string{}
	if sites, err := db.GetAllSites(); err == nil {
		for _, s := range sites {
			siteName[s.ID] = s.Name
		}
	}

	var rows []alertOverrideRow

	// Device overrides (threshold rows + an alerts-disabled row).
	if cfgs, err := db.GetAllDeviceAlertConfigs(); err == nil {
		for _, cfg := range cfgs {
			name := devName[cfg.DeviceID]
			if !cfg.AlertsEnabled {
				rows = append(rows, alertOverrideRow{Scope: "device", ScopeID: cfg.DeviceID, ScopeName: name, Kind: "disabled"})
			}
			rows = append(rows, metricThresholdRows("device", cfg.DeviceID, name,
				cfg.CPUThreshold, cfg.MemoryThreshold, cfg.DiskThreshold, cfg.SessionThreshold)...)
		}
	}
	// Site overrides.
	if cfgs, err := db.GetAllSiteAlertConfigs(); err == nil {
		for _, cfg := range cfgs {
			rows = append(rows, metricThresholdRows("site", cfg.SiteID, siteName[cfg.SiteID],
				cfg.CPUThreshold, cfg.MemoryThreshold, cfg.DiskThreshold, cfg.SessionThreshold)...)
		}
	}
	// Policy AlertRule thresholds (metric types only). NOTE (v48): r.Enabled is
	// no longer consulted — the resolver ignores it (per-type on/off moved to
	// event-profile toggles), so a stale disabled row's threshold DOES apply at
	// fire time and must show here.
	if policies, err := db.GetAlertPolicies(); err == nil {
		for _, p := range policies {
			for _, r := range p.Rules {
				if r.Threshold > 0 && alerts.IsMetricAlertType(r.AlertType) {
					rows = append(rows, alertOverrideRow{Scope: "policy", ScopeID: p.ID, ScopeName: p.Name, AlertType: r.AlertType, Value: r.Threshold, Kind: "threshold"})
				}
			}
		}
	}
	// Event-profile toggle Offs (v48): the per-type kill switches. Surfaced
	// explicitly so a type turned off by a profile is visible in the hub — the
	// retired AlertRule.Enabled=false state was invisible here, a known gap.
	if profiles, err := db.GetAllEventRuleProfiles(); err == nil {
		profName := make(map[uint]string, len(profiles))
		for _, p := range profiles {
			profName[p.ID] = p.Name
		}
		if toggles, err := db.GetAllEventRuleProfileToggles(); err == nil {
			for _, t := range toggles {
				if !t.Enabled {
					rows = append(rows, alertOverrideRow{Scope: "event_profile", ScopeID: t.ProfileID, ScopeName: profName[t.ProfileID], AlertType: t.AlertType, Kind: "disabled"})
				}
			}
		}
	}
	// Metric Event-Rule thresholds (enabled, dampen threshold > 0).
	if evRules, err := db.ListEventRules(); err == nil {
		metricEvents := []string{alerts.MetricEventCPU, alerts.MetricEventMemory, alerts.MetricEventDisk, alerts.MetricEventSessions}
		for _, r := range evRules {
			if !r.Enabled || r.Source != "metric" {
				continue
			}
			th, _, _, _, ok := alerts.ParseMetricDampen(r.DampenJSON)
			if !ok || th <= 0 {
				continue
			}
			at := r.AlertType
			if !alerts.IsMetricAlertType(at) {
				at = "" // derive from the match tree, never guess
				for _, ev := range metricEvents {
					if strings.Contains(r.MatchJSON, `"`+ev+`"`) {
						at = alerts.MetricAlertTypeForEvent(ev)
						break
					}
				}
			}
			row := alertOverrideRow{Scope: "rule", ScopeID: r.ID, ScopeName: r.Name, Value: th, Kind: "threshold"}
			if alerts.IsMetricAlertType(at) {
				row.AlertType = at
			} else {
				row.Kind = "custom"
			}
			rows = append(rows, row)
		}
	}

	// Truthfulness: flag site/device threshold rows a metric rule currently
	// overrides at fire time (bounded by the override count).
	if h.alertManager != nil {
		for i := range rows {
			r := &rows[i]
			if r.Kind != "threshold" || !alerts.IsMetricAlertType(r.AlertType) {
				continue
			}
			key := metricSampleKey(r.AlertType)
			switch r.Scope {
			case "device":
				_, prov := h.alertManager.EffectiveAlertConfig(r.ScopeID, nil, r.AlertType, key)
				r.ShadowedByRule = prov.Threshold == "rule"
			case "site":
				sid := r.ScopeID
				_, prov := h.alertManager.EffectiveAlertConfig(0, &sid, r.AlertType, key)
				r.ShadowedByRule = prov.Threshold == "rule"
			}
		}
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"global":    h.alertGlobalDefaults(db),
		"overrides": rows,
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
