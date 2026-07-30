package ipsectelemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
)

func testTime() time.Time { return time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC) }

// A truncated result is invalid JSON. Without an explicit check the failure
// surfaces as an unexplained parse error — and it would recur on every poll,
// writing nothing, until the tunnel silently aged out three hours later. The
// message has to name truncation so the cause is readable from the log alone.
func TestIngest_TruncationIsReportedNotInferred(t *testing.T) {
	// Build a result the way CompleteProbeCommand would after cutting it.
	// A mid-JSON cut leaves the body unterminated, exactly as a real truncation would.
	truncated := `{"vendor":"opnsense","steps":[{"path":"/api/ipsec/sessions/searchPhase1","body":"` +
		strings.Repeat("x", 128) +
		"\n[truncated: result exceeded the stored-result cap]"

	if !database.ProbeCommandResultTruncated(truncated) {
		t.Fatal("fixture is not recognised as truncated — the marker changed")
	}

	_, err := Ingest(nil, 5, truncated, testTime())
	if err == nil {
		t.Fatal("truncated result parsed without error — the silent-zero-rows failure")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error %q does not mention truncation; the operator would see a generic "+
			"JSON syntax error and look at the device instead of the cap", err)
	}
}

// The documents are matched by PATH, not by position. Feeding SPD in where SAD
// is expected would parse cleanly and produce quietly wrong counters, which is
// far worse than an error.
func TestReportView_DocumentsMatchedByPath(t *testing.T) {
	raw := `{"vendor":"opnsense","steps":[
		{"path":"/api/ipsec/sad/search","body":"SAD"},
		{"path":"/api/ipsec/sessions/searchPhase1","body":"P1"},
		{"path":"/api/ipsec/spd/search","body":"SPD"}]}`
	var rv reportView
	if err := json.Unmarshal([]byte(raw), &rv); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ suffix, want string }{
		{"searchPhase1", "P1"}, {"spd/search", "SPD"}, {"sad/search", "SAD"},
	} {
		got, ok := rv.bodyFor(c.suffix)
		if !ok || got != c.want {
			t.Errorf("bodyFor(%q) = %q,%v — want %q. Order in the response must not "+
				"decide which document is which.", c.suffix, got, ok, c.want)
		}
	}
}

// A report missing a document must fail loudly rather than parse a partial set.
func TestIngest_MissingDocumentIsAnError(t *testing.T) {
	raw := `{"vendor":"opnsense","steps":[{"path":"/api/ipsec/sessions/searchPhase1","body":"{}"}]}`
	if _, err := Ingest(nil, 5, raw, testTime()); err == nil {
		t.Error("a report with only one of three documents was accepted")
	}
}

// The collector's own error must surface rather than being parsed past.
func TestIngest_CollectorErrorSurfaces(t *testing.T) {
	raw := `{"vendor":"opnsense","error":"dial tcp: connection refused","steps":[]}`
	_, err := Ingest(nil, 5, raw, testTime())
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("collector error not surfaced, got %v", err)
	}
}

// The three steps must all be GET. The collector hard-refuses any other method
// on this channel, so a POST here would fail every cycle — and it is exactly
// why searchPhase2 cannot be used.
func TestOPNsenseSteps_AllGET(t *testing.T) {
	if len(OPNsenseSteps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(OPNsenseSteps))
	}
	for _, s := range OPNsenseSteps {
		if s.Method != "GET" {
			t.Errorf("step %q is %s; the collector refuses non-GET status steps", s.Path, s.Method)
		}
	}
}

// Vendors with no session telemetry must yield nothing rather than an error —
// most report VPN state over SNMP and need nothing from this path.
func TestStepsFor_UnknownVendorIsQuiet(t *testing.T) {
	for _, v := range []string{"fortigate", "cisco_asa", "", "paloalto"} {
		if got := StepsFor(v); got != nil {
			t.Errorf("StepsFor(%q) returned %d steps; expected none", v, len(got))
		}
	}
	if len(StepsFor("opnsense")) == 0 {
		t.Error("StepsFor(opnsense) returned nothing")
	}
}
