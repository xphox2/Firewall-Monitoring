package handlers

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// D-34: DeployIPSecTunnel refuses an intent with a blocking finding before it
// renders anything; the stateless preview rendered it anyway and returned the
// device config text. The preview must apply the same HasBlock gate: findings
// back, no ends.
func TestPreviewIPSecIntent_BlockingFindingsAreNotRendered(t *testing.T) {
	h, _ := setupTestHandler(t)

	in := validPreviewIntent("")
	// Renderable, but the reserved substitution token is a blocking finding —
	// the value must never reach a driver.
	in.Ends[0].LocalID.Value = "site-a<uuid:evil>"

	code, data, body := postPreview(t, h, in)
	if code != 200 {
		t.Fatalf("status = %d, want 200 (findings, not an error); body: %s", code, body)
	}
	if f := findingByCode(t, data, "reserved_token"); f == nil {
		t.Fatalf("reserved_token must still reach the client; validation was %v", data["validation"])
	}
	if ends, _ := data["ends"].([]any); len(ends) != 0 {
		t.Fatalf("an intent with a blocking finding must not be rendered; got %d ends", len(ends))
	}
	if strings.Contains(body, "<uuid:evil>") && strings.Contains(body, "\"preview\"") {
		t.Fatalf("rendered config for a blocked intent leaked into the response: %s", body)
	}
}

// The gate lives in renderPreviewEnds, which the stored-tunnel preview shares:
// a renderable intent plus any blocking finding yields no previews and the
// findings unchanged.
func TestRenderPreviewEnds_BlockingFindingSkipsRender(t *testing.T) {
	in := validPreviewIntent(ipsecPreviewPlaceholderPSK)
	caps, err := resolveCaps(&in)
	if err != nil {
		t.Fatal(err)
	}
	ipsec.NormalizeIdentities(&in, caps)
	hydrateDerived(&in)
	if previews, _ := renderPreviewEnds(&in, nil); len(previews) != 2 {
		t.Fatalf("precondition: the intent must render cleanly, got %d previews", len(previews))
	}
	block := []ipsec.Finding{{Severity: ipsec.SeverityBlock, Code: "lan_missing", Message: "x"}}
	previews, findings := renderPreviewEnds(&in, block)
	if len(previews) != 0 {
		t.Fatalf("previews = %d, want none behind a blocking finding", len(previews))
	}
	if len(findings) != 1 || findings[0].Code != "lan_missing" {
		t.Fatalf("findings must pass through unchanged, got %v", findings)
	}
}
