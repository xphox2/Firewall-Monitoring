package database

import (
	"reflect"
	"testing"

	"firewall-mon/internal/config"
)

// envRetention returns a retention config with every GUI knob set to a
// distinguishable non-zero value, so each "stored inherits" assertion can
// tell the stored value apart from the environment value it must fall back to.
func envRetention() config.RetentionConfig {
	return config.RetentionConfig{
		DefaultDays:         90,
		SyslogMonths:        3,
		FlowDays:            365,
		FlowRollupDays:      400,
		TrapDays:            30,
		StatusDays:          60,
		AlertDays:           45,
		DeniedEventDays:     2,
		NetEventDays:        30,
		SecEventDays:        365,
		SecConfigChangeDays: 0,
		NetEventRollupDays:  365,
		PingDays:            15,
		InterfaceErrorsDays: 30,
		ProcessorStatsDays:  31,
		ProcessStatsDays:    32,
		IRCMessageLogDays:   7,
		UnackAlertDays:      90,
		FlowDetectionDays:   91,
		AgentDropsDays:      33,
		VPNStatusDays:       40,
		HAStatusDays:        41,
		SecurityStatsDays:   42,
		SDWANHealthDays:     43,
		LicenseInfoDays:     365,
		IncidentDays:        44,
	}
}

// A stored value wins over the environment.
func TestResolveRetention_StoredOverridesEnv(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, RetentionDefaultDaysKey, "45")
	setRetention(t, d, RetentionNetEventDaysKey, "14")
	setRetention(t, d, RetentionVPNStatusKey, "21")
	setRetention(t, d, RetentionUnackAlertKey, "120")

	out := d.ResolveRetention(envRetention())
	if out.DefaultDays != 45 {
		t.Errorf("DefaultDays = %d, want 45 — a stored value must override the environment", out.DefaultDays)
	}
	if out.NetEventDays != 14 {
		t.Errorf("NetEventDays = %d, want 14", out.NetEventDays)
	}
	if out.VPNStatusDays != 21 {
		t.Errorf("VPNStatusDays = %d, want 21", out.VPNStatusDays)
	}
	if out.UnackAlertDays != 120 {
		t.Errorf("UnackAlertDays = %d, want 120", out.UnackAlertDays)
	}
}

// Blank, unparseable and negative stored values are all "absent" and inherit
// the environment value, exactly like SyslogRetentionWindows' sentinel.
func TestResolveRetention_BlankUnparseableNegativeInherit(t *testing.T) {
	d := NewDatabaseForTesting(t)
	setRetention(t, d, RetentionDefaultDaysKey, "")  // cleared
	setRetention(t, d, RetentionFlowDaysKey, "abc")  // unparseable
	setRetention(t, d, RetentionTrapDaysKey, "-5")   // negative
	setRetention(t, d, RetentionStatusDaysKey, "  ") // whitespace

	env := envRetention()
	out := d.ResolveRetention(env)
	if out.DefaultDays != env.DefaultDays || out.FlowDays != env.FlowDays ||
		out.TrapDays != env.TrapDays || out.StatusDays != env.StatusDays {
		t.Errorf("blank/unparseable/negative must inherit the environment, got %+v", out)
	}
}

// A stored 0 is a real value and must flow through, keeping each knob's
// existing 0-semantics downstream: NetEventWindow()→30, Days(0)→DefaultDays,
// SecConfigChangeDays→forever, SyslogMonths→off.
func TestResolveRetention_StoredZeroFlowsThrough(t *testing.T) {
	d := NewDatabaseForTesting(t)
	env := envRetention() // DefaultDays 90
	setRetention(t, d, RetentionNetEventDaysKey, "0")
	setRetention(t, d, RetentionFlowDaysKey, "0")
	setRetention(t, d, RetentionSecConfigChangeDaysKey, "0")
	setRetention(t, d, RetentionSyslogMonthsKey, "0")

	out := d.ResolveRetention(env)
	if out.NetEventDays != 0 {
		t.Fatalf("NetEventDays = %d, want 0 — the stored 0 must not be dropped", out.NetEventDays)
	}
	if got := out.NetEventWindow(); got != 30 {
		t.Errorf("NetEventWindow() = %d, want 30 — NetEventDays 0 keeps its own floor, never the default", got)
	}
	if got := out.Days(out.FlowDays); got != env.DefaultDays {
		t.Errorf("Days(FlowDays=0) = %d, want DefaultDays %d", got, env.DefaultDays)
	}
	if out.SecConfigChangeDays != 0 {
		t.Errorf("SecConfigChangeDays = %d, want 0 (keep forever)", out.SecConfigChangeDays)
	}
	if out.SyslogMonths != 0 {
		t.Errorf("SyslogMonths = %d, want 0 (off)", out.SyslogMonths)
	}
}

// A stored 0 must beat the environment's value (0 is not "unset").
func TestResolveRetention_StoredZeroBeatsEnv(t *testing.T) {
	d := NewDatabaseForTesting(t)
	env := envRetention() // NetEventDays 30
	setRetention(t, d, RetentionNetEventDaysKey, "0")

	out := d.ResolveRetention(env)
	if out.NetEventDays != 0 || out.NetEventWindow() != 30 {
		t.Errorf("stored 0 must override the environment, got NetEventDays=%d window=%d", out.NetEventDays, out.NetEventWindow())
	}
}

// The LC-20 status tables (VPN / HA / security / SD-WAN health) fall back to
// RETENTION_STATUS_DAYS, not RETENTION_DEFAULT_DAYS: a stored 0 must flow
// through and keep that fallback (statusFallback), and a stored value must
// override it.
func TestResolveRetention_StatusFallbackKnobs(t *testing.T) {
	d := NewDatabaseForTesting(t)
	env := envRetention() // StatusDays 60, DefaultDays 90
	for _, key := range []string{RetentionVPNStatusKey, RetentionHAStatusKey,
		RetentionSecurityStatsKey, RetentionSDWANHealthKey} {
		setRetention(t, d, key, "0")
	}
	out := d.ResolveRetention(env)
	if out.VPNStatusDays != 0 || out.HAStatusDays != 0 || out.SecurityStatsDays != 0 || out.SDWANHealthDays != 0 {
		t.Errorf("a stored 0 must flow through for the status-fallback knobs, got %+v", out)
	}
	// 0 falls back to StatusDays (60), never DefaultDays (90).
	if got := statusFallback(out.VPNStatusDays, env.StatusDays); got != env.StatusDays {
		t.Errorf("statusFallback(VPNStatusDays=0, statusDays) = %d, want %d (follow RETENTION_STATUS_DAYS)", got, env.StatusDays)
	}
}

// SyslogDays / SyslogInfoDays / SyslogCriticalDays are not among the GUI keys
// and must pass through unchanged.
func TestResolveRetention_SyslogFieldsUntouched(t *testing.T) {
	d := NewDatabaseForTesting(t)
	env := envRetention()
	env.SyslogDays = 11
	env.SyslogInfoDays = 7
	env.SyslogCriticalDays = 30
	setRetention(t, d, RetentionDefaultDaysKey, "45")

	out := d.ResolveRetention(env)
	if out.SyslogDays != 11 || out.SyslogInfoDays != 7 || out.SyslogCriticalDays != 30 {
		t.Errorf("syslog day fields changed: %+v — they are resolved per-severity, not by these keys", out)
	}
}

// THE NO-OP: with no stored keys the resolved config is exactly the
// environment config, so an install that never saves the form is unchanged.
func TestResolveRetention_NoStoredKeysIsNoop(t *testing.T) {
	d := NewDatabaseForTesting(t)
	env := envRetention()
	if out := d.ResolveRetention(env); !reflect.DeepEqual(out, env) {
		t.Errorf("no stored keys must leave the config unchanged:\n got %+v\nwant %+v", out, env)
	}
}
