package alerts

import (
	"log"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// ResolvedAlertConfig is the computed configuration for a specific (device, alertType) pair.
// It is not persisted — it is resolved on-the-fly from the inheritance chain.
type ResolvedAlertConfig struct {
	PolicyID     *uint
	AlertEnabled bool
	Threshold    float64
	// ClearThreshold is the F14 hysteresis recovery band from the winning
	// AlertRule (0 = recover at Threshold, legacy behavior).
	ClearThreshold float64
	// Mode/ZScoreK select the F17 firing model from the winning AlertRule
	// ("static" default; "zscore" = baseline + K·σ with Threshold as floor).
	Mode    string
	ZScoreK float64
	// RuleMatched / RuleSeverity report whether an enabled AlertRule matched
	// this type, and whether that rule explicitly set a severity. Trap alerts
	// keep the trap parser's own severity unless a rule overrides it (LC-14),
	// so the defaulted Severity below can't distinguish "rule said warning"
	// from "no rule matched".
	RuleMatched  bool
	RuleSeverity models.Severity
	Severity     models.Severity
	// StormSources is the resolved cross-source digest threshold for
	// SFLOW_SECURITY_DIGEST (v0.11.46). Starts from the global SystemSetting
	// default (am.stormSourcesDefault) and is overridden per-policy-rule / per-site
	// with `!= nil` semantics (NOT the CooldownMinutes `> 0` guard): a non-nil 0
	// disables the digest at that scope. A resolved value <= 0 means "digest off".
	StormSources      int
	CooldownMinutes   int
	NotifyEmail       bool
	NotifySlack       bool
	NotifyDiscord     bool
	NotifyWebhook     bool
	NotifyPagerDuty   bool
	NotifyOpsgenie    bool
	NotifyTeams       bool
	EmailRecipients   string
	SlackURL          string
	DiscordURL        string
	WebhookURL        string
	InMaintenance     bool
	EscalationEnabled bool
	EscalationMinutes int
	EscalationRepeat  int
}

// ConfigProvenance reports WHERE each resolved field's winning value came from,
// for the read-only "effective config" endpoint (Phase 5a). It is populated only
// when a non-nil sink is threaded through resolveAlertConfigProv / EffectiveAlertConfig;
// the firing path passes nil and pays a single nil-check. Layer tags:
// "global" | "policy" | "site" | "device" | "rule" (metric Event Rule override).
type ConfigProvenance struct {
	// Threshold names the layer that supplied the effective Threshold.
	Threshold string
	// Cooldown names the layer that supplied the effective CooldownMinutes
	// ("default" = the per-type default, no override).
	Cooldown string
	// SuppressedByRule is true when a metric suppress Event Rule mutes firing
	// (recovery still runs on the legacy band). RuleID/RuleName identify it.
	SuppressedByRule bool
	// AlertsDisabled is true when this scope is turned off — device
	// AlertsEnabled=false OR a matched policy AlertRule is disabled — so the UI
	// renders "alerts disabled here", never "inherits 0".
	AlertsDisabled bool
	// RuleID/RuleName identify a metric Event Rule that overrode or suppressed
	// the effective config (0/"" when no rule participated).
	RuleID   uint
	RuleName string
}

// PolicyCache holds in-memory copies of all policy-related data.
// Refreshed once per poll cycle alongside threshold refresh.
type PolicyCache struct {
	policies      []models.AlertPolicy
	policyByID    map[uint]*models.AlertPolicy
	deviceConfigs map[uint]*models.DeviceAlertConfig
	siteConfigs   map[uint]*models.SiteAlertConfig
	windows       []models.MaintenanceWindow
	defaultPolicy *models.AlertPolicy
	// anyZScore is true when at least one rule uses Mode=zscore, so the
	// baseline prefetch (a DB read) only ever runs on installs that opted in.
	anyZScore bool
	loaded    bool
}

// RefreshPolicyCache reloads all policy data from the database.
func (am *AlertManager) RefreshPolicyCache(db *database.Database) {
	if db == nil {
		return
	}

	policies, err := db.GetAlertPolicies()
	if err != nil {
		log.Printf("RefreshPolicyCache: failed to load policies: %v", err)
		return
	}

	deviceConfigs, err := db.GetAllDeviceAlertConfigs()
	if err != nil {
		log.Printf("RefreshPolicyCache: failed to load device configs: %v", err)
		return
	}

	siteConfigs, err := db.GetAllSiteAlertConfigs()
	if err != nil {
		log.Printf("RefreshPolicyCache: failed to load site configs: %v", err)
		return
	}

	// LC-9: load future-scheduled windows too, not just currently-active ones —
	// resolveAlertConfig re-checks start/end against time.Now(), so a window
	// created in advance suppresses correctly the moment it starts even if the
	// cache was loaded before then.
	windows, err := db.GetUnexpiredMaintenanceWindows()
	if err != nil {
		log.Printf("RefreshPolicyCache: failed to load maintenance windows: %v", err)
		return
	}

	cache := PolicyCache{
		policies:      policies,
		policyByID:    make(map[uint]*models.AlertPolicy, len(policies)),
		deviceConfigs: make(map[uint]*models.DeviceAlertConfig, len(deviceConfigs)),
		siteConfigs:   make(map[uint]*models.SiteAlertConfig, len(siteConfigs)),
		windows:       windows,
		loaded:        true,
	}

	for i := range policies {
		cache.policyByID[policies[i].ID] = &policies[i]
		if policies[i].IsDefault {
			cache.defaultPolicy = &policies[i]
		}
		for j := range policies[i].Rules {
			if policies[i].Rules[j].Mode == "zscore" {
				cache.anyZScore = true
			}
		}
	}
	for i := range deviceConfigs {
		cache.deviceConfigs[deviceConfigs[i].DeviceID] = &deviceConfigs[i]
	}
	for i := range siteConfigs {
		cache.siteConfigs[siteConfigs[i].SiteID] = &siteConfigs[i]
	}

	am.mu.Lock()
	am.policyCache = cache
	am.mu.Unlock()

	// Reload the event-rule engine on the same cadence (v35). Kept after the
	// policy swap so a rule's resolveAlertConfig sees the fresh policy cache.
	am.RefreshEventRules(db)
}

// resolvedPolicyIDLocked returns the ID of the AlertPolicy that governs a
// (device, site) pair, following the same device → site → default precedence as
// resolveAlertConfig. It returns the ID of the policy actually FOUND via
// findPolicy — so a dangling PolicyID (points at a deleted policy) correctly
// falls through to the next layer instead of naming a nonexistent policy. Nil
// when the cache holds no default policy. Caller holds am.mu (reads policyCache).
func (am *AlertManager) resolvedPolicyIDLocked(deviceID uint, siteID *uint) *uint {
	if devCfg := am.policyCache.deviceConfigs[deviceID]; devCfg != nil && devCfg.PolicyID != nil {
		if p := am.findPolicy(*devCfg.PolicyID); p != nil {
			return &p.ID
		}
	}
	if siteID != nil {
		if siteCfg := am.policyCache.siteConfigs[*siteID]; siteCfg != nil && siteCfg.PolicyID != nil {
			if p := am.findPolicy(*siteCfg.PolicyID); p != nil {
				return &p.ID
			}
		}
	}
	if am.policyCache.defaultPolicy != nil {
		return &am.policyCache.defaultPolicy.ID
	}
	return nil
}

// resolveAlertConfig computes the effective alert configuration for a given device and alert type.
// Resolution order: Device Override → Site Override → Policy AlertRule → Policy defaults → Global defaults
func (am *AlertManager) resolveAlertConfig(deviceID uint, siteID *uint, alertType models.AlertType) ResolvedAlertConfig {
	return am.resolveAlertConfigProv(deviceID, siteID, alertType, nil)
}

// resolveAlertConfigProv is resolveAlertConfig with an optional provenance sink.
// When prov != nil it records which layer supplied the winning Threshold/Cooldown
// (and the disabled state), so the "effective config" endpoint reports the value
// that actually FIRES — computed by the real resolver, never a reimplementation.
// A nil sink is the hot firing path. Caller holds am.mu.
func (am *AlertManager) resolveAlertConfigProv(deviceID uint, siteID *uint, alertType models.AlertType, prov *ConfigProvenance) ResolvedAlertConfig {
	resolved := ResolvedAlertConfig{
		AlertEnabled:    true,
		CooldownMinutes: defaultCooldownForType(alertType),
		Severity:        defaultSeverityForType(alertType),
		StormSources:    am.stormSourcesDefault, // global SystemSetting default (0 = off)
	}
	if prov != nil {
		prov.Cooldown = "default"
	}

	if !am.policyCache.loaded {
		// Fallback to global config when cache not loaded
		resolved.Threshold = am.globalThresholdForType(alertType)
		if prov != nil {
			prov.Threshold = "global"
		}
		return resolved
	}

	devCfg := am.policyCache.deviceConfigs[deviceID]

	// Check device alerts enabled
	if devCfg != nil && !devCfg.AlertsEnabled {
		resolved.AlertEnabled = false
		if prov != nil {
			prov.AlertsDisabled = true
		}
		return resolved
	}

	// Resolve policy: device → site → default (shared helper, dangling-safe)
	var policy *models.AlertPolicy
	if pid := am.resolvedPolicyIDLocked(deviceID, siteID); pid != nil {
		policy = am.findPolicy(*pid)
	}

	if policy != nil {
		applyPolicyChannels(&resolved, policy)
		if prov != nil && policy.CooldownMinutes > 0 {
			prov.Cooldown = "policy"
		}
	}

	// Find matching AlertRule
	var rule *models.AlertRule
	if policy != nil {
		for i := range policy.Rules {
			if policy.Rules[i].AlertType == alertType {
				rule = &policy.Rules[i]
				break
			}
		}
	}

	if rule != nil {
		if !rule.Enabled {
			resolved.AlertEnabled = false
			if prov != nil {
				prov.AlertsDisabled = true
			}
			return resolved
		}
		resolved.RuleMatched = true
		if rule.Severity != "" {
			resolved.Severity = rule.Severity
			resolved.RuleSeverity = rule.Severity
		}
		if rule.Threshold > 0 {
			resolved.Threshold = rule.Threshold
			if prov != nil {
				prov.Threshold = "policy"
			}
		}
		if rule.ClearThreshold > 0 {
			resolved.ClearThreshold = rule.ClearThreshold
		}
		if rule.Mode != "" {
			resolved.Mode = rule.Mode
		}
		if rule.ZScoreK > 0 {
			resolved.ZScoreK = rule.ZScoreK
		}
		// M3: same `> 0` floor for a per-rule override (an explicit 0 inherits
		// the default rather than disabling the cooldown entirely).
		if rule.CooldownMinutes != nil && *rule.CooldownMinutes > 0 {
			resolved.CooldownMinutes = *rule.CooldownMinutes
			if prov != nil {
				prov.Cooldown = "policy"
			}
		}
		// StormSources uses `!= nil`, NOT `> 0` (v0.11.46): a non-nil 0 must
		// DISABLE the digest for this policy, whereas 0 means "inherit" for
		// CooldownMinutes. Copying the `> 0` guard here would silently invert it.
		if rule.StormSources != nil {
			resolved.StormSources = *rule.StormSources
		}
		// Per-rule channel overrides (non-nil = override)
		if rule.NotifyEmail != nil {
			resolved.NotifyEmail = *rule.NotifyEmail
		}
		if rule.NotifySlack != nil {
			resolved.NotifySlack = *rule.NotifySlack
		}
		if rule.NotifyDiscord != nil {
			resolved.NotifyDiscord = *rule.NotifyDiscord
		}
		if rule.NotifyWebhook != nil {
			resolved.NotifyWebhook = *rule.NotifyWebhook
		}
	}

	// Site-level threshold/cooldown overrides
	if siteID != nil {
		if siteCfg := am.policyCache.siteConfigs[*siteID]; siteCfg != nil {
			if v, ok := overrideThreshold(resolved.Threshold, alertType,
				siteCfg.CPUThreshold, siteCfg.MemoryThreshold, siteCfg.DiskThreshold, siteCfg.SessionThreshold); ok {
				resolved.Threshold = v
				if prov != nil {
					prov.Threshold = "site"
				}
			}
			if siteCfg.CooldownMinutes > 0 {
				resolved.CooldownMinutes = siteCfg.CooldownMinutes
				if prov != nil {
					prov.Cooldown = "site"
				}
			}
			// Per-site storm-threshold override — `!= nil` semantics (see the
			// rule-level override above): non-nil 0 disables the digest for this site.
			if siteCfg.StormSources != nil {
				resolved.StormSources = *siteCfg.StormSources
			}
		}
	}

	// Device-level threshold/cooldown overrides (most specific wins)
	if devCfg != nil {
		if v, ok := overrideThreshold(resolved.Threshold, alertType,
			devCfg.CPUThreshold, devCfg.MemoryThreshold, devCfg.DiskThreshold, devCfg.SessionThreshold); ok {
			resolved.Threshold = v
			if prov != nil {
				prov.Threshold = "device"
			}
		}
		if devCfg.CooldownMinutes > 0 {
			resolved.CooldownMinutes = devCfg.CooldownMinutes
			if prov != nil {
				prov.Cooldown = "device"
			}
		}
	}

	// If threshold is still 0, fall back to global
	if resolved.Threshold == 0 {
		resolved.Threshold = am.globalThresholdForType(alertType)
		if prov != nil {
			prov.Threshold = "global"
		}
	}

	// Check maintenance windows
	now := time.Now()
	for _, w := range am.policyCache.windows {
		if now.Before(w.StartTime) || now.After(w.EndTime) {
			continue
		}
		// Check scope
		if w.DeviceID != nil && *w.DeviceID != deviceID {
			continue
		}
		if w.SiteID != nil && (siteID == nil || *w.SiteID != *siteID) {
			continue
		}
		// Check alert type filter
		if !w.SuppressAll && w.AlertTypes != "" {
			types := strings.Split(w.AlertTypes, ",")
			found := false
			for _, t := range types {
				if strings.TrimSpace(t) == string(alertType) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		resolved.InMaintenance = true
		break
	}

	return resolved
}

func (am *AlertManager) findPolicy(id uint) *models.AlertPolicy {
	return am.policyCache.policyByID[id]
}

// applyPolicyChannels copies a policy's notification channels, escalation, and
// (non-zero) cooldown onto a resolved config. Shared by resolveAlertConfig and
// applyRulePolicy so the two can't drift.
func applyPolicyChannels(resolved *ResolvedAlertConfig, policy *models.AlertPolicy) {
	resolved.PolicyID = &policy.ID
	resolved.NotifyEmail = policy.NotifyEmail
	resolved.NotifySlack = policy.NotifySlack
	resolved.NotifyDiscord = policy.NotifyDiscord
	resolved.NotifyWebhook = policy.NotifyWebhook
	resolved.NotifyPagerDuty = policy.NotifyPagerDuty
	resolved.NotifyOpsgenie = policy.NotifyOpsgenie
	resolved.NotifyTeams = policy.NotifyTeams
	resolved.EmailRecipients = policy.EmailRecipients
	resolved.SlackURL = policy.SlackWebhookURL
	resolved.DiscordURL = policy.DiscordWebhookURL
	resolved.WebhookURL = policy.WebhookURL
	// M3 (2026-07-01 audit): a 0 cooldown means "inherit the per-type default",
	// not "zero" (which caused a per-cycle storm).
	if policy.CooldownMinutes > 0 {
		resolved.CooldownMinutes = policy.CooldownMinutes
	}
	resolved.EscalationEnabled = policy.EscalationEnabled
	resolved.EscalationMinutes = policy.EscalationMinutes
	resolved.EscalationRepeat = policy.EscalationRepeat
}

// applyRulePolicy re-resolves the notification channels/escalation from a
// SPECIFIC policy — used when an Event Rule pins a PolicyID different from the
// device's resolved policy. Without this the rule's first notification would go
// out on the device policy's channels (the rule's policy only took effect at
// escalation time). Caller holds am.mu (reads policyCache).
func (am *AlertManager) applyRulePolicy(resolved *ResolvedAlertConfig, policyID uint) {
	if p := am.findPolicy(policyID); p != nil {
		applyPolicyChannels(resolved, p)
	}
}

func (am *AlertManager) globalThresholdForType(alertType models.AlertType) float64 {
	switch alertType {
	case "CPU_HIGH":
		return am.config.Alerts.CPUThreshold
	case "MEMORY_HIGH":
		return am.config.Alerts.MemoryThreshold
	case "DISK_HIGH":
		return am.config.Alerts.DiskThreshold
	case "SESSIONS_HIGH":
		return float64(am.config.Alerts.SessionThreshold)
	default:
		return 0
	}
}

// defaultCooldownForType is the per-type default alert cooldown in minutes when
// no policy/rule/site/device override applies.
//
// M3 of the 2026-07-01 audit: the SFLOW_* flow detections run on a 15-minute
// window scanned every 5 minutes (cmd/poller runFlowDetectionCycle), so one
// underlying event is re-detected in ~3 consecutive cycles. With the old flat
// 5-minute default (== the cycle period) each re-detection got past the
// cooldown and notified 2-3 times, and a persistently-present condition
// re-alerted every ~5 minutes forever. A default cooldown >= the detection
// window collapses the duplicates and paces a persistent condition to once per
// window. Operators can still override lower per policy/rule/site/device.
func defaultCooldownForType(alertType models.AlertType) int {
	switch alertType {
	case models.AlertTypeSFlowSecurity, models.AlertTypeSFlowSecurityDigest:
		// v0.11.46: the consolidated security alert and its storm digest are the
		// noisiest types (one per attacking source / per storm). A 6h re-fire
		// cadence tames the post-ack churn while still reminding once per window.
		// A seeded Default-policy rule carries this explicitly so it isn't
		// shadowed by the policy-level CooldownMinutes:5 (see EnsureDefaultPolicy).
		return 360
	}
	if strings.HasPrefix(string(alertType), "SFLOW_") {
		return 15 // >= runFlowDetectionCycle's 15-minute window
	}
	return 5
}

func defaultSeverityForType(alertType models.AlertType) models.Severity {
	switch alertType {
	case "DISK_HIGH", "INTERFACE_DOWN", "VPN_TUNNEL_DOWN", "DEVICE_OFFLINE",
		"SYSLOG_EMERGENCY", "SYSLOG_CRITICAL", "SSH_HOST_KEY_CHANGED":
		return "critical"
	case "SYSLOG_ALERT":
		return "warning"
	default:
		return "warning"
	}
}

// overrideThreshold returns the override threshold for the given alert type if > 0.
// Works for both device and site configs by accepting raw field values. The
// second return is true when this layer actually supplied the value (a stored
// value > 0) — so provenance can distinguish a real override from inheritance
// even when the override is numerically equal to the upstream value (`> 0` is the
// single source of override truth, matching the firing path).
func overrideThreshold(current float64, alertType models.AlertType, cpu, mem, disk float64, sess int) (float64, bool) {
	switch alertType {
	case "CPU_HIGH":
		if cpu > 0 {
			return cpu, true
		}
	case "MEMORY_HIGH":
		if mem > 0 {
			return mem, true
		}
	case "DISK_HIGH":
		if disk > 0 {
			return disk, true
		}
	case "SESSIONS_HIGH":
		if sess > 0 {
			return float64(sess), true
		}
	}
	return current, false
}

// EffectiveAlertConfig resolves the config that actually FIRES for a (device, site,
// metricType) — reconciling BOTH threshold stores: the layered resolve chain AND
// a matching metric Event Rule (which overrides the chain, or suppresses firing).
// It returns per-field provenance for the read-only editor. Read-only: takes the
// RLock and only reads shared state (resolveAlertConfigProv / matchMetricRuleLocked /
// applyMetricRuleOverridesLocked are mutation-free; recordHit is firing-path only).
// When siteID is nil and deviceID != 0, the device's site is filled from deviceMeta
// so the result matches what the poller resolves. metric is the sample key
// ("cpu_usage"/"memory_usage"/"disk_usage"/"session_count"); "" skips rule reconciliation.
func (am *AlertManager) EffectiveAlertConfig(deviceID uint, siteID *uint, alertType models.AlertType, metric string) (ResolvedAlertConfig, ConfigProvenance) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Match the firing path: a bare device resolves through its own site's overrides.
	effSite := siteID
	if effSite == nil && deviceID != 0 {
		if m, ok := am.deviceMeta[deviceID]; ok {
			effSite = m.SiteID
		}
	}

	var prov ConfigProvenance
	resolved := am.resolveAlertConfigProv(deviceID, effSite, alertType, &prov)
	if !resolved.AlertEnabled {
		// Already flagged AlertsDisabled in the resolver; no rule reconciliation.
		return resolved, prov
	}

	// Reconcile the metric Event Rule store for the four metric types, mirroring
	// resolveMetricEffectiveLocked so the displayed value equals the fired value.
	event := metricEventType(alertType)
	if event == "" {
		return resolved, prov
	}
	vendor := "generic"
	if m, ok := am.deviceMeta[deviceID]; ok && m.Vendor != "" {
		vendor = m.Vendor
	}
	action, rule, matched := am.matchMetricRuleLocked(metricFields(deviceID, event, metric, vendor), deviceID, effSite)
	if !matched {
		return resolved, prov
	}
	prov.RuleID = rule.id
	prov.RuleName = rule.name
	if action == "suppress" {
		prov.SuppressedByRule = true
		return resolved, prov
	}
	am.applyMetricRuleOverridesLocked(&resolved, rule)
	// A rule that explicitly set a threshold wins over the chain (metricrules.go),
	// so the effective threshold provenance is the rule.
	if rule.dampen.Threshold > 0 {
		prov.Threshold = "rule"
	}
	if rule.cooldownMin != nil && *rule.cooldownMin > 0 {
		prov.Cooldown = "rule"
	}
	return resolved, prov
}

// BuildNotifyConfigFromResolved creates a NotifyConfig for use with the notifier.
// It merges resolved policy config with global notification settings as fallbacks.
func BuildNotifyConfigFromResolved(resolved ResolvedAlertConfig, globalNC notifier.NotifyConfig) notifier.NotifyConfig {
	nc := notifier.NotifyConfig{
		PolicyActive:    resolved.PolicyID != nil,
		EnableEmail:     resolved.NotifyEmail,
		EnableSlack:     resolved.NotifySlack,
		EnableDiscord:   resolved.NotifyDiscord,
		EnableWebhook:   resolved.NotifyWebhook,
		EnablePagerDuty: resolved.NotifyPagerDuty,
		EnableOpsgenie:  resolved.NotifyOpsgenie,
		EnableTeams:     resolved.NotifyTeams,
		// Incident-channel creds are global-only (no per-policy override)
		PagerDutyRoutingKey: globalNC.PagerDutyRoutingKey,
		OpsgenieAPIKey:      globalNC.OpsgenieAPIKey,
		TeamsWebhookURL:     globalNC.TeamsWebhookURL,
		// SMTP settings always come from global
		EmailEnabled: globalNC.EmailEnabled,
		SMTPHost:     globalNC.SMTPHost,
		SMTPPort:     globalNC.SMTPPort,
		SMTPUsername: globalNC.SMTPUsername,
		SMTPPassword: globalNC.SMTPPassword,
		SMTPFrom:     globalNC.SMTPFrom,
		// Public base URL for alert deep-links is global-only.
		BaseURL: globalNC.BaseURL,
	}

	// Recipients: policy override or global
	if resolved.EmailRecipients != "" {
		nc.SMTPTo = resolved.EmailRecipients
	} else {
		nc.SMTPTo = globalNC.SMTPTo
	}

	// Webhook URLs: policy override or global
	if resolved.SlackURL != "" {
		nc.SlackWebhookURL = resolved.SlackURL
	} else {
		nc.SlackWebhookURL = globalNC.SlackWebhookURL
	}
	if resolved.DiscordURL != "" {
		nc.DiscordWebhookURL = resolved.DiscordURL
	} else {
		nc.DiscordWebhookURL = globalNC.DiscordWebhookURL
	}
	if resolved.WebhookURL != "" {
		nc.WebHookURL = resolved.WebhookURL
	} else {
		nc.WebHookURL = globalNC.WebHookURL
	}

	return nc
}
