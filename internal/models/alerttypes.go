package models

// AlertTypeInfo describes one canonical alert type for API consumers (the
// Event Rule Profile toggle matrix, the rule-builder alert-type select). The
// server is the single source of truth here — the admin UI must never carry
// its own hardcoded alert-type list (the old JS ALERT_TYPES array silently
// drifted: LINK_DOWN was missing from it).
type AlertTypeInfo struct {
	Type        AlertType `json:"type"`
	Family      string    `json:"family"`
	Description string    `json:"description"`
}

// Alert-type families group the toggle matrix and drive its bulk actions.
const (
	FamilyMetrics       = "Metrics"
	FamilyAvailability  = "Availability"
	FamilyInterfaces    = "Interfaces & VPN"
	FamilyConfig        = "Config & SSH"
	FamilyProbe         = "Probe & Telemetry"
	FamilyHA            = "High Availability"
	FamilySyslog        = "Syslog"
	FamilyFlowTelemetry = "Flow Telemetry"
	FamilyFlowSecurity  = "Flow Security"
	FamilyCustomRules   = "Custom Rules"
)

// AllAlertTypes returns every togglable alert type, grouped by family in
// display order. Contract (enforced by TestAllAlertTypes_CoverEveryAlertType,
// which parses this package's AlertType constants):
//   - every AlertType constant appears exactly once, EXCEPT TEST_ALERT (a
//     wiring probe, never operator-tunable);
//   - *_RESOLVED companions never appear — they are derived from their base
//     type and always follow it (recovery is never gated by toggles);
//   - a NEW alert type must be added here in the same change that adds the
//     constant, or the guardrail fails. Its absence from every profile's
//     toggle rows means it starts as Inherit → ON fleet-wide.
func AllAlertTypes() []AlertTypeInfo {
	return []AlertTypeInfo{
		// Metrics
		{AlertTypeCPUHigh, FamilyMetrics, "CPU usage above threshold"},
		{AlertTypeMemoryHigh, FamilyMetrics, "Memory usage above threshold"},
		{AlertTypeDiskHigh, FamilyMetrics, "Disk usage above threshold"},
		{AlertTypeSessionsHigh, FamilyMetrics, "Session count above threshold"},
		{AlertTypeTrafficSpike, FamilyMetrics, "Throughput anomaly vs the device's own baseline"},

		// Availability
		{AlertTypeDeviceOffline, FamilyAvailability, "Device stopped responding to polling"},
		{AlertTypeTelemetryStale, FamilyAvailability, "Device reachable but SNMP/SSH telemetry stopped arriving"},

		// Interfaces & VPN
		{AlertTypeInterfaceDown, FamilyInterfaces, "Monitored interface lost link"},
		{AlertTypeInterfaceErrors, FamilyInterfaces, "Interface error/discard rate above threshold"},
		{AlertTypeLinkDown, FamilyInterfaces, "Generic SNMP linkDown trap"},
		{AlertTypeVPNTunnelDown, FamilyInterfaces, "VPN tunnel went down"},

		// Config & SSH
		{AlertTypeConfigChange, FamilyConfig, "Device configuration changed"},
		{AlertTypeSSHHostKeyChanged, FamilyConfig, "SSH host key changed (possible MITM or reinstall)"},

		// Probe & Telemetry
		{AlertTypeProbeDataLag, FamilyProbe, "Collector data arriving late for this probe"},
		{AlertTypeProbeDataTruncated, FamilyProbe, "Collector payload truncated (governed by the Default layer only — no device attribution)"},

		// High Availability
		{AlertTypeHAHeartbeatFail, FamilyHA, "HA heartbeat failure trap"},
		{AlertTypeHAMemberDown, FamilyHA, "HA cluster member down"},
		{AlertTypeHAMemberUp, FamilyHA, "HA cluster member rejoined"},
		{AlertTypeHAStateChange, FamilyHA, "HA state transition"},
		{AlertTypeHASwitch, FamilyHA, "HA failover switch occurred"},

		// Syslog
		{AlertTypeSyslogEmergency, FamilySyslog, "Syslog severity 0 (emergency) message"},
		{AlertTypeSyslogCritical, FamilySyslog, "Syslog severity 2 (critical) message"},
		{AlertTypeSyslogAlert, FamilySyslog, "Syslog severity 1 (alert) message"},

		// Flow Telemetry
		{AlertTypeSFlowAgentDrops, FamilyFlowTelemetry, "sFlow agent reported dropped samples"},
		{AlertTypeSFlowSamplingBackoff, FamilyFlowTelemetry, "sFlow sampling rate backed off under load"},
		{AlertTypeSFlowCapacity, FamilyFlowTelemetry, "Flow volume approaching link capacity"},
		{AlertTypeSFlowSamplingRateChange, FamilyFlowTelemetry, "sFlow sampling rate changed (pre-multiplied byte contract guard)"},

		// Flow Security
		{AlertTypeSFlowCleartext, FamilyFlowSecurity, "Cleartext protocol seen where encryption is expected"},
		{AlertTypeSFlowUnexpectedEgress, FamilyFlowSecurity, "Egress traffic to an unexpected destination"},
		{AlertTypeSFlowSecurity, FamilyFlowSecurity, "Consolidated per-source security detection (port scan, threat intel, exfil, super spreader, C2 beacon, deny storm)"},
		{AlertTypeSFlowSecurityDigest, FamilyFlowSecurity, "Cross-source storm rollup for a detector"},
		{AlertTypeSFlowDDoSVolumetric, FamilyFlowSecurity, "Victim-keyed volumetric DDoS detection"},
		{AlertTypeSFlowDDoSPrefix, FamilyFlowSecurity, "Prefix-targeted DDoS detection"},
		{AlertTypeSFlowDenyStorm, FamilyFlowSecurity, "Deny storm from one source (consolidates into the SFLOW_SECURITY card; toggling THIS type off drops deny-storm detections before consolidation)"},
		{AlertTypeSFlowDenyStormVictim, FamilyFlowSecurity, "Deny storm aimed at one victim"},
		{AlertTypeSFlowDeniedThenAllowed, FamilyFlowSecurity, "Denied traffic later allowed (possible policy gap)"},

		// Custom Rules
		{AlertTypeLogRuleMatch, FamilyCustomRules, "Default type emitted by custom syslog rules (toggling Off mutes rules that emit it)"},
		{AlertTypeFlowRuleMatch, FamilyCustomRules, "Default type emitted by custom flow rules (toggling Off mutes rules that emit it)"},
	}
}

// TogglableAlertType reports whether t may carry an EventRuleProfileToggle
// row. Used by toggle validation so the sparse matrix can only ever contain
// canonical types.
func TogglableAlertType(t AlertType) bool {
	for _, info := range AllAlertTypes() {
		if info.Type == t {
			return true
		}
	}
	return false
}
