package alerts

import (
	"strings"
	"testing"

	"firewall-mon/internal/detect"
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

// TestSuggestRule_FlowDetectionTypes pins the v0.11.111 coverage extension:
// EVERY per-detection SFLOW_* alert type gets a flow_security suggestion —
// detector-scoped, narrowed to the subject IP when the alert carries one,
// device-scoped by default.
func TestSuggestRule_FlowDetectionTypes(t *testing.T) {
	// Cleartext without a source: detector-scoped, device-scoped, permanent.
	r := SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeSFlowCleartext, DeviceID: 7, DeviceName: "edge-1"})
	if !r.Supported || r.Rule == nil {
		t.Fatalf("SFLOW_CLEARTEXT must be supported; got %+v", r)
	}
	if r.Rule.Source != "flow_security" {
		t.Errorf("want source flow_security, got %s", r.Rule.Source)
	}
	if !strings.Contains(r.Rule.MatchJSON, `"detector"`) || !strings.Contains(r.Rule.MatchJSON, "cleartext") {
		t.Errorf("match should key on detector=cleartext, got %s", r.Rule.MatchJSON)
	}
	if r.Rule.DeviceID == nil || *r.Rule.DeviceID != 7 {
		t.Errorf("detector-scoped suggestion should stay device-scoped, got %+v", r.Rule.DeviceID)
	}
	if r.Rule.ExpiresHours != 0 {
		t.Errorf("detector-only suppress should default permanent, got %dh", r.Rule.ExpiresHours)
	}

	// denied_then_allowed WITH a source: detector AND source_ip, 24h temporary.
	r = SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeSFlowDeniedThenAllowed, DeviceID: 3, SourceAddr: "172.69.130.140"})
	if !r.Supported || r.Rule == nil {
		t.Fatalf("SFLOW_DENIED_THEN_ALLOWED must be supported; got %+v", r)
	}
	if !strings.Contains(r.Rule.MatchJSON, "denied_then_allowed") || !strings.Contains(r.Rule.MatchJSON, "172.69.130.140") {
		t.Errorf("match should key on detector+source_ip, got %s", r.Rule.MatchJSON)
	}
	if r.Rule.ExpiresHours != 24 {
		t.Errorf("subject-scoped suppress should default to 24h temporary, got %d", r.Rule.ExpiresHours)
	}

	// Victim-keyed DDoS: alert.SourceAddr carries the victim; same shape.
	r = SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeSFlowDDoSVolumetric, DeviceID: 3, SourceAddr: "10.0.0.9"})
	if !r.Supported || r.Rule == nil || !strings.Contains(r.Rule.MatchJSON, "ddos_volumetric") {
		t.Fatalf("SFLOW_DDOS_VOLUMETRIC must be supported with a detector matcher; got %+v", r)
	}
}

// TestSuggestRule_FlowRuleMatch pins the FLOW_RULE_MATCH path: the suppress
// suggestion reuses the firing flow rule's matcher one priority above it, and
// customize opens the firing rule via ExistingRuleID.
func TestSuggestRule_FlowRuleMatch(t *testing.T) {
	pri := 40
	rid := uint(9)
	r := SuggestRuleForAlert(SuggestInput{
		AlertType: models.AlertTypeFlowRuleMatch, DeviceID: 7, MetricName: "Big transfers",
		FiringRulePriority: &pri, ExistingRuleID: &rid,
		FiringRuleMatchJSON: `{"op":"eq","field":"dst_port","value":"445"}`,
	})
	if !r.Supported || r.Rule == nil {
		t.Fatalf("FLOW_RULE_MATCH with a loaded firing rule must be supported; got %+v", r)
	}
	if r.Rule.Source != "flow" || r.Rule.MatchJSON != `{"op":"eq","field":"dst_port","value":"445"}` {
		t.Errorf("suppress must reuse the firing rule's matcher on source flow, got %s / %s", r.Rule.Source, r.Rule.MatchJSON)
	}
	if r.Rule.Priority != 39 {
		t.Errorf("suppress must run one priority above the firing rule (39), got %d", r.Rule.Priority)
	}
	if r.ExistingRuleID == nil || *r.ExistingRuleID != 9 {
		t.Errorf("customize must open the firing rule, got %+v", r.ExistingRuleID)
	}
	// Firing rule not loaded (renamed/deleted): no matcher to reuse.
	nr := SuggestRuleForAlert(SuggestInput{AlertType: models.AlertTypeFlowRuleMatch, DeviceID: 7, MetricName: "gone"})
	if nr.Supported {
		t.Errorf("FLOW_RULE_MATCH without the firing rule should be unsupported, got %+v", nr)
	}
}

// TestRuleSource_CoversEveryDetector is the "all alerts must be suppressible"
// guardrail: every registered flow detector's auto-derived alert type
// (SFLOW_<UPPER(name)>) must map to the flow_security rule source. A future
// detector that would ship without rule coverage fails here.
func TestRuleSource_CoversEveryDetector(t *testing.T) {
	for _, d := range detect.Registry() {
		at := models.AlertType("SFLOW_" + strings.ToUpper(d.Name()))
		if got := ruleSourceForAlertType(at); got != "flow_security" {
			t.Errorf("detector %q → alert type %s maps to rule source %q, want flow_security", d.Name(), at, got)
		}
		r := SuggestRuleForAlert(SuggestInput{AlertType: at, DeviceID: 1, DeviceName: "d"})
		if !r.Supported {
			t.Errorf("alert type %s must be rule-suppressible; got unsupported (%s)", at, r.Reason)
		}
	}
}
