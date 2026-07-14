package alerts

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// The suggestion feeds the Event Rule editor; a suggestion that doesn't compile,
// doesn't out-rank the shipped seed (priority 100), or targets the wrong field
// would make the "Suppress" button a silent no-op — so pin all three.

const seedPriority = 100 // all shipped alert seeds ship at priority 100

func mustCompile(t *testing.T, matchJSON string) {
	t.Helper()
	if _, err := CompileTestRule(matchJSON); err != nil {
		t.Fatalf("suggested match_json does not compile: %v — %s", err, matchJSON)
	}
}

func TestSuggestRule_Metric(t *testing.T) {
	r := SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeCPUHigh, DeviceID: 7, DeviceName: "fw-01"})
	if !r.Supported || r.Rule.Source != "metric" {
		t.Fatalf("metric: got %+v", r)
	}
	if !strings.Contains(r.Rule.MatchJSON, `"event_type"`) || !strings.Contains(r.Rule.MatchJSON, `"cpu_high"`) {
		t.Fatalf("metric match_json wrong: %s", r.Rule.MatchJSON)
	}
	if r.Rule.DeviceID == nil || *r.Rule.DeviceID != 7 {
		t.Fatalf("metric should be device-scoped: %+v", r.Rule)
	}
	if r.Rule.Priority >= seedPriority {
		t.Fatalf("priority %d must beat the seed (%d)", r.Rule.Priority, seedPriority)
	}
	if r.Rule.Action != "suppress" || r.Rule.DampenJSON != `{"mode":"static"}` {
		t.Fatalf("metric action/dampen: %+v", r.Rule)
	}
	mustCompile(t, r.Rule.MatchJSON)
}

func TestSuggestRule_StateOwnedAndNot(t *testing.T) {
	base := SuggestInput{AlertType: models.AlertTypeInterfaceDown, DeviceID: 7, DeviceName: "fw-01", MetricName: "interface_port5"}

	// Owned → supported, event_type + interface_name conditions.
	base.StateOwned = map[string]bool{"interface_down": true}
	r := SuggestRuleForAlert(base)
	if !r.Supported || r.Rule.Source != "state" {
		t.Fatalf("state owned: got %+v", r)
	}
	if !strings.Contains(r.Rule.MatchJSON, `"interface_down"`) || !strings.Contains(r.Rule.MatchJSON, `"port5"`) {
		t.Fatalf("state match should scope to the interface: %s", r.Rule.MatchJSON)
	}
	mustCompile(t, r.Rule.MatchJSON)

	// Not owned → unsupported (a rule would be inert).
	base.StateOwned = map[string]bool{}
	if r := SuggestRuleForAlert(base); r.Supported {
		t.Fatalf("state not-owned should be unsupported, got %+v", r)
	}
}

func TestSuggestRule_Spike(t *testing.T) {
	r := SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeTrafficSpike, DeviceID: 7, DeviceName: "fw-01", MetricName: "traffic_wan1"})
	if !r.Supported || r.Rule.Source != "spike" || !strings.Contains(r.Rule.MatchJSON, `"wan1"`) {
		t.Fatalf("spike: %+v", r)
	}
	mustCompile(t, r.Rule.MatchJSON)
}

func TestSuggestRule_Trap(t *testing.T) {
	r := SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeLinkDown, DeviceID: 7, DeviceName: "fw-01"})
	if !r.Supported || r.Rule.Source != "trap" || !strings.Contains(r.Rule.MatchJSON, `"LINK_DOWN"`) {
		t.Fatalf("trap: %+v", r)
	}
	if r.Rule.DeviceID == nil {
		t.Fatalf("trap with device should be device-scoped")
	}
	mustCompile(t, r.Rule.MatchJSON)

	// device_id=0 (unresolved source) → not device-scoped, still supported.
	r0 := SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeLinkDown, DeviceID: 0})
	if !r0.Supported || r0.Rule.DeviceID != nil {
		t.Fatalf("trap device0: %+v", r0)
	}
}

func TestSuggestRule_SyslogKVAndFallback(t *testing.T) {
	// FortiGate KV line → picks logid; firing-rule priority makes the suggestion win.
	fp := 40
	r := SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeSyslogCritical, DeviceID: 7, DeviceName: "fw-01",
		Vendor: "fortigate", MetricName: "Syslog sev0-2",
		Message:            "[Syslog sev0-2] fw-01: logid=0100044546 subtype=system level=critical msg=boom",
		FiringRulePriority: &fp,
	})
	if !r.Supported || r.Rule.Source != "syslog" {
		t.Fatalf("syslog kv: %+v", r)
	}
	if !strings.Contains(r.Rule.MatchJSON, `"logid"`) || !strings.Contains(r.Rule.MatchJSON, "0100044546") {
		t.Fatalf("syslog should key on logid: %s", r.Rule.MatchJSON)
	}
	if r.Rule.Priority != fp-1 {
		t.Fatalf("syslog priority should be firing-1 (%d), got %d", fp-1, r.Rule.Priority)
	}
	mustCompile(t, r.Rule.MatchJSON)

	// Generic vendor, no KV → message-contains fallback on the prefix-stripped raw.
	r2 := SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeSyslogAlert, DeviceID: 7, DeviceName: "fw-01",
		Vendor: "generic", MetricName: "Syslog sev0-2",
		Message: "[Syslog sev0-2] fw-01: kernel panic on line card",
	})
	if !strings.Contains(r2.Rule.MatchJSON, `"contains"`) || strings.Contains(r2.Rule.MatchJSON, "[Syslog sev0-2]") {
		t.Fatalf("syslog fallback should be a prefix-stripped message-contains: %s", r2.Rule.MatchJSON)
	}
	mustCompile(t, r2.Rule.MatchJSON)
}

func TestSuggestRule_SyslogEmptyAndPriorityClamp(t *testing.T) {
	// Empty log content (prefix strips to nothing, no KV) → unsupported, NOT a
	// {contains message ""} matcher that would silence all syslog.
	r := SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeSyslogCritical, DeviceID: 7, Vendor: "generic",
		MetricName: "Syslog sev0-2", Message: "[Syslog sev0-2] fw-01: ",
	})
	if r.Supported {
		t.Fatalf("empty syslog content should be unsupported, got %+v", r.Rule)
	}

	// Firing rule at priority 0 → suggestion clamps to 0 (not -1).
	zero := 0
	r2 := SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeSyslogCritical, DeviceID: 7, Vendor: "fortigate",
		MetricName: "R", Message: "[R] fw-01: logid=1 subtype=x", FiringRulePriority: &zero,
	})
	if !r2.Supported || r2.Rule.Priority != 0 {
		t.Fatalf("priority should clamp to 0, got %+v", r2.Rule)
	}
}

func TestIsSyslogRuleAlertType(t *testing.T) {
	if !IsSyslogRuleAlertType(models.AlertTypeSyslogCritical) || !IsSyslogRuleAlertType(models.AlertTypeLogRuleMatch) {
		t.Fatal("syslog types should report true")
	}
	if IsSyslogRuleAlertType(models.AlertTypeCPUHigh) || IsSyslogRuleAlertType(models.AlertTypeInterfaceDown) {
		t.Fatal("non-syslog types must report false (MetricName is a resource key, not a rule name)")
	}
}

func TestSuggestRule_FlowSecurity(t *testing.T) {
	// A per-source sFlow-security alert → a temporary flow_security suppress rule
	// matching the attacker IP (the unified replacement for Silence Source).
	r := SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeSFlowSecurity, DeviceID: 7, SourceAddr: "198.51.100.9"})
	if !r.Supported || r.Rule == nil {
		t.Fatalf("SFLOW_SECURITY with a source should be supported; got %+v", r)
	}
	if r.Rule.Source != "flow_security" || r.Rule.Action != "suppress" {
		t.Errorf("want flow_security/suppress, got %s/%s", r.Rule.Source, r.Rule.Action)
	}
	if r.Rule.ExpiresHours != 24 {
		t.Errorf("suppress-a-source should default to a 24h temporary rule, got %d", r.Rule.ExpiresHours)
	}
	if !strings.Contains(r.Rule.MatchJSON, `"source_ip"`) || !strings.Contains(r.Rule.MatchJSON, "198.51.100.9") {
		t.Errorf("match should key on source_ip=198.51.100.9, got %s", r.Rule.MatchJSON)
	}
	// The storm DIGEST (no single source) is NOT auto-suppressed blanket.
	d := SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeSFlowSecurityDigest, DeviceID: 0})
	if d.Supported || d.Alternative != "per_source" {
		t.Errorf("digest without a source should guide to per-source, got %+v", d)
	}
}

func TestSuggestRule_Unsupported(t *testing.T) {
	cases := []struct {
		at  models.AlertType
		alt string
	}{
		{models.AlertTypeSFlowCapacity, "maintenance"},
		{models.AlertTypeDeviceOffline, "maintenance"},
		{models.AlertTypeSSHHostKeyChanged, "maintenance"},
		{models.AlertTypeProbeDataLag, "maintenance"},
		{models.AlertTypeInterfaceErrors, "maintenance"},
	}
	for _, tc := range cases {
		r := SuggestRuleForAlert(SuggestInput{AlertType: tc.at, DeviceID: 7})
		if r.Supported {
			t.Errorf("%s should be unsupported", tc.at)
		}
		if r.Reason == "" || r.Alternative != tc.alt {
			t.Errorf("%s: reason=%q alt=%q want alt %q", tc.at, r.Reason, r.Alternative, tc.alt)
		}
	}
}
