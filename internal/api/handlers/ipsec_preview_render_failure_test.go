package handlers

import (
	"testing"

	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors"
)

// The preview exists to explain what is wrong with an intent, and a bad intent
// is exactly when the driver cannot render it — so returning 400 on a render
// failure threw away the findings that name the offending field. The wizard
// anchors each finding to the control that caused it; with a 400 it showed a
// dismissible toast and anchored nothing.
//
// The live trigger is the ordinary one: a tunnel with no LAN interface ticked
// yet. Render fail-fasts on an empty interface list (a deliberate guard added
// with multi-LAN support), so lan_missing — the very finding that tells the
// operator what to do — was the one guaranteed to be swallowed.

func findingByCode(t *testing.T, data map[string]any, code string) map[string]any {
	t.Helper()
	raw, _ := data["validation"].([]any)
	for _, f := range raw {
		if m, ok := f.(map[string]any); ok && m["code"] == code {
			return m
		}
	}
	return nil
}

// THE REGRESSION, end to end through the real endpoint.
func TestPreview_RenderFailureStillReturnsTheFindingsThatExplainIt(t *testing.T) {
	h, _ := setupTestHandler(t)

	in := validPreviewIntent("")
	in.Ends[0].LANIface = "" // no LAN ticked yet: blocks validation AND fails render
	in.Ends[0].LANIfaces = nil

	code, data, body := postPreview(t, h, in)
	if code != 200 {
		t.Fatalf("status = %d, want 200 — a render failure must not swallow the findings "+
			"that tell the operator which field to fix; body: %s", code, body)
	}
	if f := findingByCode(t, data, "lan_missing"); f == nil {
		t.Errorf("lan_missing must reach the client so the wizard can anchor it to the LAN "+
			"picker; validation was %v", data["validation"])
	}
	// Nothing renderable exists yet. That is honest, not an error.
	if ends, _ := data["ends"].([]any); len(ends) != 0 {
		t.Errorf("ends = %v, want empty when rendering failed", ends)
	}
}

// unrenderable builds an intent no driver can render, without tripping any
// validation rule — the shape that exposes a validation gap.
func unrenderable() *ipsec.TunnelIntent {
	in := validPreviewIntent(ipsecPreviewPlaceholderPSK)
	in.Ends[0].Vendor = "no-such-vendor"
	return &in
}

// A render failure with NO blocking finding means the intent passed every
// linter yet cannot become config. Swallowing that would leave the client with
// zero blocking findings, which ENABLES Save — letting the operator store a
// tunnel that can never deploy. It becomes a blocking finding of its own.
func TestRenderPreviewEnds_UnrenderableButValidGetsASyntheticBlock(t *testing.T) {
	previews, findings := renderPreviewEnds(unrenderable(), nil)

	if len(previews) != 0 {
		t.Errorf("previews = %v, want none", previews)
	}
	if !ipsec.HasBlock(findings) {
		t.Fatalf("an unrenderable intent with no other finding must produce a blocking one, "+
			"or the client enables Save on a tunnel that cannot deploy; got %v", findings)
	}
	f := findings[len(findings)-1]
	if f.Code != "render_failed" {
		t.Errorf("Code = %q, want render_failed", f.Code)
	}
	// Tunnel-level: it belongs to no single endpoint, and claiming one would make
	// the UI anchor it to an arbitrary side of a problem that is not there.
	if f.End != nil {
		t.Errorf("render_failed must not claim an end; got %d", *f.End)
	}
	if f.Message == "" {
		t.Error("the synthetic finding must carry the render error, or the operator " +
			"sees a blocked Save with no stated reason")
	}
}

// When validation already explained the problem, the synthetic finding would be
// noise restating a symptom next to its cause.
func TestRenderPreviewEnds_NoSyntheticWhenValidationAlreadyBlocks(t *testing.T) {
	existing := []ipsec.Finding{{Severity: ipsec.SeverityBlock, Code: "lan_missing", Message: "x"}}

	_, findings := renderPreviewEnds(unrenderable(), existing)

	if len(findings) != 1 {
		t.Fatalf("want the original finding only, got %d: %v", len(findings), findings)
	}
	if findings[0].Code != "lan_missing" {
		t.Errorf("the actionable finding must survive unchanged, got %q", findings[0].Code)
	}
}

// Warnings are not blocks: a warn-only intent that cannot render still needs the
// synthetic finding, or Save stays enabled.
func TestRenderPreviewEnds_WarningsDoNotSuppressTheSyntheticBlock(t *testing.T) {
	warn := []ipsec.Finding{{Severity: ipsec.SeverityWarn, Code: "lan_subnet_mismatch", Message: "x"}}

	_, findings := renderPreviewEnds(unrenderable(), warn)

	if !ipsec.HasBlock(findings) {
		t.Errorf("a warning must not stand in for the blocking render failure; got %v", findings)
	}
}

// The happy path must be untouched.
func TestPreview_ValidIntentStillRendersBothEnds(t *testing.T) {
	h, _ := setupTestHandler(t)

	code, data, body := postPreview(t, h, validPreviewIntent(""))
	if code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", code, body)
	}
	if ends, _ := data["ends"].([]any); len(ends) != 2 {
		t.Errorf("a valid intent must still render both ends, got %d", len(ends))
	}
}
