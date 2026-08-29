package handlers

import (
	"testing"

	_ "firewall-mon/internal/ipsec/vendors"
)

// previewHasBlock reports whether the preview response carries ANY blocking
// finding (severity "block").
func previewHasBlock(data map[string]any) bool {
	raw, _ := data["validation"].([]any)
	for _, f := range raw {
		if m, ok := f.(map[string]any); ok && m["severity"] == "block" {
			return true
		}
	}
	return false
}

// AUDIT-274/275: PreviewIPSecTunnel/PreviewIPSecIntent called ipsec.Validate but
// NEVER conformance.Validate, while DeployIPSecTunnel runs conformance and 400s
// on any violation. So a FortiGate end whose child lifetime is 60s — below the
// device's 120s keylifeseconds floor, which ipsec.Validate does not bound —
// previewed GREEN and then failed conformance on deploy, leaving the tunnel
// undeployable via the wizard. Preview must now surface the same blocking
// conformance finding the deploy would.
func TestPreview_FortiGateChildLifetimeBelowFloorBlocks(t *testing.T) {
	h, _ := setupTestHandler(t)

	in := validPreviewIntent("")
	in.Ends[0].ChildLifetimeSecs = 60 // FortiGate keylifeseconds floor is 120

	code, data, body := postPreview(t, h, in)
	if code != 200 {
		t.Fatalf("status = %d; body: %s", code, body)
	}
	f := findingByCode(t, data, "conformance")
	if f == nil {
		t.Fatalf("a below-floor FortiGate child lifetime must surface a blocking conformance finding in preview "+
			"(deploy would 400 on it); validation = %v", data["validation"])
	}
	if f["severity"] != "block" {
		t.Errorf("conformance finding severity = %v, want block", f["severity"])
	}
	if f["end"] != float64(0) {
		t.Errorf("conformance finding must anchor to end A (the FortiGate end); got end = %v", f["end"])
	}
}

// AUDIT-274/275: the same preview↔deploy gap via the tunnel-level DPD delay —
// 120s exceeds FortiGate's dpd-retryinterval [1,60] ceiling, which ipsec.Validate
// never bounds but conformance rejects on deploy.
func TestPreview_FortiGateDPDDelayAboveCeilingBlocks(t *testing.T) {
	h, _ := setupTestHandler(t)

	in := validPreviewIntent("")
	in.DPD.DelaySecs = 120 // FortiGate dpd-retryinterval ceiling is 60

	_, data, _ := postPreview(t, h, in)
	if findingByCode(t, data, "conformance") == nil {
		t.Fatalf("a FortiGate DPD delay above the device ceiling must block in preview "+
			"(deploy would reject it); validation = %v", data["validation"])
	}
}

// The over-blocking guard: a currently-valid FortiGate⇄OPNsense config must STILL
// preview green after conformance is added to the preview path — conformance must
// not reject a config both vendors accept (it is a no-op for a specless vendor and
// mirrors exactly what deploy already enforces).
func TestPreview_ValidConfigStillGreenAfterConformance(t *testing.T) {
	h, _ := setupTestHandler(t)

	_, data, _ := postPreview(t, h, validPreviewIntent(""))
	if previewHasBlock(data) {
		t.Fatalf("a valid FG⇄OPNsense config must preview green (no over-blocking); validation = %v", data["validation"])
	}
}
