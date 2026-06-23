package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

// AUDIT-117: first tests for internal/alerts — covering the two pure policy
// helpers that decide severity and threshold overrides. These are the
// branch-heavy, easy-to-regress bits of the alert policy resolution; the
// DB/notifier-bound methods are exercised by the handler/integration suites.

func TestDefaultSeverityForType_AUDIT117(t *testing.T) {
	t.Parallel()
	cases := map[models.AlertType]models.Severity{
		"DISK_HIGH":        "critical",
		"INTERFACE_DOWN":   "critical",
		"VPN_TUNNEL_DOWN":  "critical",
		"DEVICE_OFFLINE":   "critical",
		"SYSLOG_EMERGENCY": "critical",
		"SYSLOG_CRITICAL":  "critical",
		"SYSLOG_ALERT":     "warning",
		"CPU_HIGH":         "warning", // default bucket
		"MEMORY_HIGH":      "warning",
		"something-novel":  "warning", // unknown → default warning, never ""
	}
	for alertType, want := range cases {
		if got := defaultSeverityForType(alertType); got != want {
			t.Errorf("defaultSeverityForType(%q) = %q, want %q", alertType, got, want)
		}
	}
}

func TestOverrideThreshold_AUDIT117(t *testing.T) {
	t.Parallel()
	const current = 75.0

	// A positive per-config value for the matching type overrides the current.
	if got := overrideThreshold(current, "CPU_HIGH", 90, 0, 0, 0); got != 90 {
		t.Errorf("CPU_HIGH override: got %v, want 90", got)
	}
	if got := overrideThreshold(current, "MEMORY_HIGH", 0, 80, 0, 0); got != 80 {
		t.Errorf("MEMORY_HIGH override: got %v, want 80", got)
	}
	if got := overrideThreshold(current, "DISK_HIGH", 0, 0, 95, 0); got != 95 {
		t.Errorf("DISK_HIGH override: got %v, want 95", got)
	}
	if got := overrideThreshold(current, "SESSIONS_HIGH", 0, 0, 0, 1000); got != 1000 {
		t.Errorf("SESSIONS_HIGH override: got %v, want 1000", got)
	}

	// A zero/unset value falls back to the current threshold.
	if got := overrideThreshold(current, "CPU_HIGH", 0, 0, 0, 0); got != current {
		t.Errorf("CPU_HIGH with no override: got %v, want %v", got, current)
	}
	// An unrelated type never touches the current threshold.
	if got := overrideThreshold(current, "INTERFACE_DOWN", 90, 80, 95, 1000); got != current {
		t.Errorf("non-threshold type: got %v, want %v", got, current)
	}
}
