package alerts

import "testing"

// Phase 5b: the alert-config overview handler reuses ParseMetricDampen to pull a
// metric Event Rule's threshold instead of re-declaring the dampen schema.
func TestParseMetricDampen_5b(t *testing.T) {
	t.Parallel()

	th, cl, k, mode, ok := ParseMetricDampen(`{"threshold":85,"clear_threshold":80,"zscore_k":2.5,"mode":"zscore"}`)
	if !ok || th != 85 || cl != 80 || k != 2.5 || mode != "zscore" {
		t.Fatalf("full parse: got th=%v cl=%v k=%v mode=%q ok=%v", th, cl, k, mode, ok)
	}

	// Valid JSON with no threshold parses (ok=true) but threshold 0 (inherit).
	if th, _, _, mode, ok := ParseMetricDampen(`{"mode":"static"}`); !ok || th != 0 || mode != "static" {
		t.Fatalf("no-threshold: got th=%v mode=%q ok=%v, want 0 static true", th, mode, ok)
	}

	// Empty and malformed → ok=false.
	if _, _, _, _, ok := ParseMetricDampen(""); ok {
		t.Fatal("empty dampen should not parse")
	}
	if _, _, _, _, ok := ParseMetricDampen("{not json"); ok {
		t.Fatal("malformed dampen should not parse")
	}

	// Event-type ↔ AlertType mapping used to label rows.
	if MetricAlertTypeForEvent(MetricEventCPU) != "CPU_HIGH" || MetricAlertTypeForEvent("nope") != "" {
		t.Fatal("MetricAlertTypeForEvent mapping wrong")
	}
	if !IsMetricAlertType("DISK_HIGH") || IsMetricAlertType("INTERFACE_DOWN") {
		t.Fatal("IsMetricAlertType wrong")
	}
}
