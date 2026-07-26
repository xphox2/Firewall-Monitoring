package alerts

import (
	"strconv"
	"time"

	"firewall-mon/internal/models"
)

// "device"-source rule evaluator: makes the device/probe-scoped one-shot alert
// families first-class in the Event Rule engine — DEVICE_OFFLINE,
// TELEMETRY_STALE, INTERFACE_ERRORS, CONFIG_CHANGE, SSH_HOST_KEY_CHANGED,
// PROBE_DATA_LAG, PROBE_DATA_TRUNCATED. Cloned from the metric pattern
// (resolveMetricEffectiveLocked): resolveAlertConfig runs first, the matcher is
// always consulted, and no match means exactly today's behavior — so an empty
// rule set is non-regressive and no ownership flag is needed. A suppress rule
// mutes the fire (recovery legs still run, so an already-open alert isn't
// stranded); an alert rule overlays severity/policy/cooldown.

// deviceEventType maps the device-family alert types to their matcher
// event_type values ("" = not a device-family type). The *_RESOLVED companions
// are intentionally absent: rules gate the FIRE, and sendRecovery only
// notifies when the fire was active, so suppressing the fire silences the
// recovery too.
func deviceEventType(at models.AlertType) string {
	switch at {
	case models.AlertTypeDeviceOffline:
		return "device_offline"
	case models.AlertTypeTelemetryStale:
		return "telemetry_stale"
	case models.AlertTypeInterfaceErrors:
		return "interface_errors"
	case models.AlertTypeConfigChange:
		return "config_change"
	case models.AlertTypeSSHHostKeyChanged:
		return "ssh_host_key_changed"
	case models.AlertTypeProbeDataLag:
		return "probe_data_lag"
	case models.AlertTypeProbeDataTruncated:
		return "probe_data_truncated"
	case models.AlertTypeServerDiskHigh:
		return "server_disk_high"
	}
	return ""
}

// deviceFields builds the matchable field set for one device-family event.
// severity is the severity the alert would carry WITHOUT a rule override (the
// resolved/computed default), so a severity-scoped rule matches what the
// operator sees. extra carries the family-specific fields (interface_name,
// probe_id/probe_name, method/changed_by/impact, fingerprint, detail); empty
// values are omitted so a missing field never phantom-matches an eq.
func deviceFields(eventType string, deviceID uint, siteID *uint, severity string, extra map[string]string) map[string]string {
	f := map[string]string{
		"event_type": eventType,
		"device_id":  strconv.FormatUint(uint64(deviceID), 10),
	}
	if severity != "" {
		f["severity"] = severity
	}
	if siteID != nil {
		f["site_id"] = strconv.FormatUint(uint64(*siteID), 10)
	}
	for k, v := range extra {
		if v != "" {
			f[k] = v
		}
	}
	return f
}

// matchDeviceRuleLocked returns the first (priority-ordered) live device rule
// of ANY action that applies + matches, or nil. Caller holds am.mu (RLock
// suffices). The exact source=="device" filter is REQUIRED — appliesTo alone
// admits "any" rules, and a missing-field neq evaluates true, so a broad "any"
// syslog-noise suppress rule would otherwise silently start eating device
// health alerts (same guard as flow_security).
func (am *AlertManager) matchDeviceRuleLocked(fields map[string]string, deviceID uint, siteID *uint) *compiledRule {
	vendor := "generic"
	if m, ok := am.deviceMeta[deviceID]; ok && m.Vendor != "" {
		vendor = m.Vendor
	}
	return firstMatch(am.chainRulesLocked(deviceID, siteID), "device", false, vendor, deviceID, siteID, fields, time.Now())
}

// consultDeviceRuleLocked is the one-stop consult every device-family emitter
// calls under am.mu: match, and on an alert-action rule overlay severity/
// policy/cooldown onto resolved in place. Returns the matched rule (nil = no
// match; caller records the hit AFTER releasing am.mu) and whether the fire is
// suppressed. effSite falls back to the device's cached site so site-scoped
// rules match without a per-call siteID.
func (am *AlertManager) consultDeviceRuleLocked(at models.AlertType, deviceID uint, siteID *uint, severity string, extra map[string]string, resolved *ResolvedAlertConfig) (rule *compiledRule, suppressed bool) {
	event := deviceEventType(at)
	if event == "" {
		return nil, false
	}
	effSite := siteID
	if effSite == nil {
		if m, ok := am.deviceMeta[deviceID]; ok {
			effSite = m.SiteID
		}
	}
	rule = am.matchDeviceRuleLocked(deviceFields(event, deviceID, effSite, severity, extra), deviceID, effSite)
	if rule == nil {
		return nil, false
	}
	if rule.action == "suppress" {
		return rule, true
	}
	if rule.severity != "" {
		resolved.Severity = rule.severity
	}
	if rule.policyID != nil {
		resolved.PolicyID = rule.policyID
		am.applyRulePolicy(resolved, *rule.policyID)
	}
	if rule.cooldownMin != nil && *rule.cooldownMin > 0 {
		resolved.CooldownMinutes = *rule.cooldownMin
	}
	return rule, false
}
