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

	// A positive per-config value for the matching type overrides the current,
	// and reports ok=true so provenance can label it an override.
	if got, ok := overrideThreshold(current, "CPU_HIGH", 90, 0, 0, 0); got != 90 || !ok {
		t.Errorf("CPU_HIGH override: got %v ok=%v, want 90 true", got, ok)
	}
	if got, ok := overrideThreshold(current, "MEMORY_HIGH", 0, 80, 0, 0); got != 80 || !ok {
		t.Errorf("MEMORY_HIGH override: got %v ok=%v, want 80 true", got, ok)
	}
	if got, ok := overrideThreshold(current, "DISK_HIGH", 0, 0, 95, 0); got != 95 || !ok {
		t.Errorf("DISK_HIGH override: got %v ok=%v, want 95 true", got, ok)
	}
	if got, ok := overrideThreshold(current, "SESSIONS_HIGH", 0, 0, 0, 1000); got != 1000 || !ok {
		t.Errorf("SESSIONS_HIGH override: got %v ok=%v, want 1000 true", got, ok)
	}

	// An override numerically EQUAL to current still reports ok=true (the `>0`
	// stored value is the single source of override truth, not value comparison).
	if got, ok := overrideThreshold(current, "CPU_HIGH", current, 0, 0, 0); got != current || !ok {
		t.Errorf("CPU_HIGH equal-value override: got %v ok=%v, want %v true", got, ok, current)
	}

	// A zero/unset value falls back to the current threshold, ok=false.
	if got, ok := overrideThreshold(current, "CPU_HIGH", 0, 0, 0, 0); got != current || ok {
		t.Errorf("CPU_HIGH with no override: got %v ok=%v, want %v false", got, ok, current)
	}
	// An unrelated type never touches the current threshold.
	if got, ok := overrideThreshold(current, "INTERFACE_DOWN", 90, 80, 95, 1000); got != current || ok {
		t.Errorf("non-threshold type: got %v ok=%v, want %v false", got, ok, current)
	}
}
