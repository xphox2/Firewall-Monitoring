package database

import (
	"firewall-mon/internal/config"
)

// Operator-tunable data-retention knobs, settable from Settings → Retention
// and read through over the environment.
//
// This mirrors the per-severity syslog mechanism (syslogretention.go): each
// knob is a system_settings key whose stored value, when present, wins over
// the matching RETENTION_* environment variable, which stays the default.
// Nothing is ever seeded or written back — reading a stored value that does
// not exist resolves to the environment value, so an install that never saves
// the form is byte-for-byte an env-only one. Read-through, never seeded: the
// same reason as SyslogRetentionWindows (see there).

// The operator-tunable retention settings keys. The key is the environment
// variable name, lower-cased (RETENTION_DEFAULT_DAYS → retention_default_days),
// matching how the archive settings name their admin keys. SyslogDays /
// SyslogInfoDays / SyslogCriticalDays are deliberately NOT here: they are
// already settable from the GUI via the per-severity syslog_retention_days_*
// keys, and the summary knobs (syslog_summary_retention_days /
// flow_summary_retention_days) are their own SystemSettings.
const (
	RetentionDefaultDaysKey         = "retention_default_days"
	RetentionSyslogMonthsKey        = "retention_syslog_months"
	RetentionFlowDaysKey            = "retention_flow_days"
	RetentionFlowRollupDaysKey      = "retention_flow_rollup_days"
	RetentionTrapDaysKey            = "retention_trap_days"
	RetentionStatusDaysKey          = "retention_status_days"
	RetentionAlertDaysKey           = "retention_alert_days"
	RetentionDeniedEventDaysKey     = "retention_denied_event_days"
	RetentionNetEventDaysKey        = "retention_net_event_days"
	RetentionSecEventDaysKey        = "retention_sec_event_days"
	RetentionSecConfigChangeDaysKey = "retention_sec_config_change_days"
	RetentionNetEventRollupDaysKey  = "retention_net_event_rollup_days"
	// The remaining RetentionConfig knobs (AUDIT-029 / AUDIT-031 / H4 /
	// LC-20 / LC-22 and ping_results). Same read-through pattern.
	RetentionPingDaysKey        = "retention_ping_days"
	RetentionInterfaceErrorsKey = "retention_interface_errors_days"
	RetentionProcessorStatsKey  = "retention_processor_stats_days"
	RetentionProcessStatsKey    = "retention_process_stats_days"
	RetentionIRCMessageLogKey   = "retention_irc_message_log_days"
	RetentionUnackAlertKey      = "retention_unack_alert_days"
	RetentionFlowDetectionKey   = "retention_flow_detection_days"
	RetentionAgentDropsKey      = "retention_agent_drops_days"
	RetentionVPNStatusKey       = "retention_vpn_status_days"
	RetentionHAStatusKey        = "retention_ha_status_days"
	RetentionSecurityStatsKey   = "retention_security_stats_days"
	RetentionSDWANHealthKey     = "retention_sdwan_health_days"
	RetentionLicenseInfoKey     = "retention_license_info_days"
	RetentionIncidentKey        = "retention_incident_days"
)

// ResolveRetention returns a copy of env with each operator-tunable retention
// knob overridden by its stored system_settings value, when one is set.
//
// The read uses the existing syslogRetentionInherit sentinel (-1) as the
// "absent" default: GetIntSetting collapses absent, blank and unparseable onto
// its default argument, so only the sentinel distinguishes "no value stored"
// from a real value. A result >= 0 is a real stored value and overwrites the
// field; anything else (absent / blank / unparseable / negative) inherits the
// environment value. A stored 0 is therefore honoured as 0 and never
// reinterpreted — each knob's 0-semantics stay downstream: Days()→DefaultDays,
// NetEventWindow()→30, SecConfigChangeDays→forever, SyslogMonths→off.
//
// SyslogDays / SyslogInfoDays / SyslogCriticalDays are left untouched: they
// are already resolved per-severity by SyslogRetentionWindows.
func (d *Database) ResolveRetention(env config.RetentionConfig) config.RetentionConfig {
	out := env
	if v := d.GetIntSetting(RetentionDefaultDaysKey, syslogRetentionInherit); v >= 0 {
		out.DefaultDays = v
	}
	if v := d.GetIntSetting(RetentionSyslogMonthsKey, syslogRetentionInherit); v >= 0 {
		out.SyslogMonths = v
	}
	if v := d.GetIntSetting(RetentionFlowDaysKey, syslogRetentionInherit); v >= 0 {
		out.FlowDays = v
	}
	if v := d.GetIntSetting(RetentionFlowRollupDaysKey, syslogRetentionInherit); v >= 0 {
		out.FlowRollupDays = v
	}
	if v := d.GetIntSetting(RetentionTrapDaysKey, syslogRetentionInherit); v >= 0 {
		out.TrapDays = v
	}
	if v := d.GetIntSetting(RetentionStatusDaysKey, syslogRetentionInherit); v >= 0 {
		out.StatusDays = v
	}
	if v := d.GetIntSetting(RetentionAlertDaysKey, syslogRetentionInherit); v >= 0 {
		out.AlertDays = v
	}
	if v := d.GetIntSetting(RetentionDeniedEventDaysKey, syslogRetentionInherit); v >= 0 {
		out.DeniedEventDays = v
	}
	if v := d.GetIntSetting(RetentionNetEventDaysKey, syslogRetentionInherit); v >= 0 {
		out.NetEventDays = v
	}
	if v := d.GetIntSetting(RetentionSecEventDaysKey, syslogRetentionInherit); v >= 0 {
		out.SecEventDays = v
	}
	if v := d.GetIntSetting(RetentionSecConfigChangeDaysKey, syslogRetentionInherit); v >= 0 {
		out.SecConfigChangeDays = v
	}
	if v := d.GetIntSetting(RetentionNetEventRollupDaysKey, syslogRetentionInherit); v >= 0 {
		out.NetEventRollupDays = v
	}
	if v := d.GetIntSetting(RetentionPingDaysKey, syslogRetentionInherit); v >= 0 {
		out.PingDays = v
	}
	if v := d.GetIntSetting(RetentionInterfaceErrorsKey, syslogRetentionInherit); v >= 0 {
		out.InterfaceErrorsDays = v
	}
	if v := d.GetIntSetting(RetentionProcessorStatsKey, syslogRetentionInherit); v >= 0 {
		out.ProcessorStatsDays = v
	}
	if v := d.GetIntSetting(RetentionProcessStatsKey, syslogRetentionInherit); v >= 0 {
		out.ProcessStatsDays = v
	}
	if v := d.GetIntSetting(RetentionIRCMessageLogKey, syslogRetentionInherit); v >= 0 {
		out.IRCMessageLogDays = v
	}
	if v := d.GetIntSetting(RetentionUnackAlertKey, syslogRetentionInherit); v >= 0 {
		out.UnackAlertDays = v
	}
	if v := d.GetIntSetting(RetentionFlowDetectionKey, syslogRetentionInherit); v >= 0 {
		out.FlowDetectionDays = v
	}
	if v := d.GetIntSetting(RetentionAgentDropsKey, syslogRetentionInherit); v >= 0 {
		out.AgentDropsDays = v
	}
	if v := d.GetIntSetting(RetentionVPNStatusKey, syslogRetentionInherit); v >= 0 {
		out.VPNStatusDays = v
	}
	if v := d.GetIntSetting(RetentionHAStatusKey, syslogRetentionInherit); v >= 0 {
		out.HAStatusDays = v
	}
	if v := d.GetIntSetting(RetentionSecurityStatsKey, syslogRetentionInherit); v >= 0 {
		out.SecurityStatsDays = v
	}
	if v := d.GetIntSetting(RetentionSDWANHealthKey, syslogRetentionInherit); v >= 0 {
		out.SDWANHealthDays = v
	}
	if v := d.GetIntSetting(RetentionLicenseInfoKey, syslogRetentionInherit); v >= 0 {
		out.LicenseInfoDays = v
	}
	if v := d.GetIntSetting(RetentionIncidentKey, syslogRetentionInherit); v >= 0 {
		out.IncidentDays = v
	}
	return out
}

// RefreshRetentionLookbacks re-resolves the daily net_events partition lookback
// from the current settings and environment. Connect records it once at boot;
// the poller calls this under the maintenance lock just before
// EnsurePartitionsForCron so a widened RETENTION_NET_EVENT_DAYS creates the
// older daily leaves in the same pass it will drop them at.
func (d *Database) RefreshRetentionLookbacks(env config.RetentionConfig) {
	resolved := d.ResolveRetention(env)
	d.netEventRetentionDays = resolved.NetEventWindow()
}
