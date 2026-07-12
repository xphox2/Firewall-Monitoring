package alerts

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// Metric-source rule evaluator (Phase 4a). When a metric event_type is owned
// (state_engine_owns), CheckSystemStatus sources its per-check config from the
// matching source="metric" Event Rule instead of the raw resolveAlertConfig —
// scope/suppress + per-rule severity/threshold/routing. Non-regressive: the
// shipped seeds carry no threshold (dampen {"mode":"static"}), so an untouched
// install inherits the exact global/policy/device/site threshold it uses today;
// the rule only overrides fields an operator explicitly set. The stateful
// threshold math (zscoreFireAt + hysteresis) is REUSED unchanged in
// CheckSystemStatus — the rule only supplies the ResolvedAlertConfig it reads.

// ParseMetricDampen parses a metric Event Rule's DampenJSON into its threshold
// fields. ok reports whether the JSON parsed (NOT whether a threshold is set —
// callers check threshold > 0 for a live override). Exported so the alert-config
// overview handler reuses the one dampen schema instead of re-declaring it.
func ParseMetricDampen(dampenJSON string) (threshold, clear, k float64, mode string, ok bool) {
	s := strings.TrimSpace(dampenJSON)
	if s == "" {
		return 0, 0, 0, "", false
	}
	var dp dampenParams
	if err := json.Unmarshal([]byte(s), &dp); err != nil {
		return 0, 0, 0, "", false
	}
	return dp.Threshold, dp.ClearThreshold, dp.ZScoreK, dp.Mode, true
}

// MetricAlertTypeForEvent maps a metric event_type token (cpu_high/…) to its
// AlertType, or "" if the token isn't one of the four metric checks.
func MetricAlertTypeForEvent(event string) models.AlertType {
	switch event {
	case MetricEventCPU:
		return models.AlertTypeCPUHigh
	case MetricEventMemory:
		return models.AlertTypeMemoryHigh
	case MetricEventDisk:
		return models.AlertTypeDiskHigh
	case MetricEventSessions:
		return models.AlertTypeSessionsHigh
	}
	return ""
}

// IsMetricAlertType reports whether at is one of the four metric threshold types.
func IsMetricAlertType(at models.AlertType) bool {
	return metricEventType(at) != ""
}

// metricEventType maps a metric AlertType to its rule scoping token (the
// event_type the seed matches + the ownership flag key).
func metricEventType(at models.AlertType) string {
	switch at {
	case models.AlertTypeCPUHigh:
		return MetricEventCPU
	case models.AlertTypeMemoryHigh:
		return MetricEventMemory
	case models.AlertTypeDiskHigh:
		return MetricEventDisk
	case models.AlertTypeSessionsHigh:
		return MetricEventSessions
	}
	return ""
}

// metricFields is the matchable field set for a metric check.
func metricFields(deviceID uint, event, metric, vendor string) map[string]string {
	return map[string]string{
		"event_type": event,
		"metric":     metric,
		"vendor":     vendor,
		"device_id":  fmt.Sprintf("%d", deviceID),
	}
}

// matchMetricRuleLocked returns the first (priority-ordered) enabled metric rule
// that applies + matches. Caller holds am.mu.
func (am *AlertManager) matchMetricRuleLocked(fields map[string]string, deviceID uint, siteID *uint) (action string, rule *compiledRule, matched bool) {
	vendor := "generic"
	if m, ok := am.deviceMeta[deviceID]; ok && m.Vendor != "" {
		vendor = m.Vendor
	}
	for i := range am.eventRules {
		r := &am.eventRules[i]
		if r.source != "metric" {
			continue
		}
		if !r.appliesTo("metric", vendor, deviceID, siteID) {
			continue
		}
		if !r.match.eval(fields) {
			continue
		}
		return r.action, r, true
	}
	return "", nil, false
}

// resolveMetricEffectiveLocked computes the effective config for one metric check.
// It is used for BOTH the fire and recovery legs (resolved once), so they always
// agree. Returns:
//   - resolved: the config the fire/recovery math uses (rule-overridden when a
//     metric alert rule matches; the legacy resolveAlertConfig otherwise).
//   - skipFire: a suppress rule matched — mute the fire, but recovery still runs
//     so an already-open alert isn't stranded open.
//
// The metric evaluator ALWAYS consults matching rules and falls back to legacy on
// no match (never silently drop a CPU/disk alert) — so it needs no ownership
// flag; the shipped seeds carry no threshold and thus inherit exactly today's
// config (non-regressive). To turn a metric type OFF, use a suppress rule or
// disable it in Settings→Alerts / the policy. `now`/`siteID` reserved for parity
// with the other evaluators. Caller holds am.mu.
func (am *AlertManager) resolveMetricEffectiveLocked(deviceID uint, siteID *uint, alertType models.AlertType, metric string, now time.Time) (resolved ResolvedAlertConfig, skipFire bool) {
	resolved = am.resolveAlertConfig(deviceID, siteID, alertType)
	event := metricEventType(alertType)
	if event == "" {
		return resolved, false // unknown metric type → legacy
	}
	effSite := siteID
	vendor := "generic"
	if m, ok := am.deviceMeta[deviceID]; ok {
		if m.Vendor != "" {
			vendor = m.Vendor
		}
		if effSite == nil {
			effSite = m.SiteID // site-scoped rules match without a per-call siteID
		}
	}
	action, rule, matched := am.matchMetricRuleLocked(metricFields(deviceID, event, metric, vendor), deviceID, effSite)
	if !matched {
		return resolved, false // no rule → legacy
	}
	if action == "suppress" {
		return resolved, true // mute fire; recovery still runs on the legacy band
	}
	am.applyMetricRuleOverridesLocked(&resolved, rule)
	return resolved, false
}

// applyMetricRuleOverridesLocked overlays a matched metric alert rule onto the
// resolved config: override ONLY the fields the rule explicitly sets, so an
// untouched seed inherits everything. Mode is UPGRADE-ONLY — a rule can opt into
// zscore but cannot downgrade a policy-level zscore to static (a value of
// "static" here can't be told apart from the seed default). Caller holds am.mu.
func (am *AlertManager) applyMetricRuleOverridesLocked(resolved *ResolvedAlertConfig, rule *compiledRule) {
	if rule.severity != "" {
		resolved.Severity = rule.severity
	}
	if rule.policyID != nil {
		am.applyRulePolicy(resolved, *rule.policyID)
	}
	if rule.cooldownMin != nil && *rule.cooldownMin > 0 {
		resolved.CooldownMinutes = *rule.cooldownMin
	}
	dp := rule.dampen
	if dp.Threshold > 0 {
		resolved.Threshold = dp.Threshold
	}
	if dp.ClearThreshold > 0 {
		resolved.ClearThreshold = dp.ClearThreshold
	}
	if dp.ZScoreK > 0 {
		resolved.ZScoreK = dp.ZScoreK
	}
	if dp.Mode == "zscore" {
		resolved.Mode = "zscore" // upgrade-only
	}
}
