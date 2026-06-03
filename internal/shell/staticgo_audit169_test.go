package shell

import (
	"os"
	"strings"
	"testing"
)

// TestStaticGo_HasLayeringDocComment_AUDIT169 — the audit's
// recommendation was "Acceptable as-is. Document the choice."
// This test pins the documentation: any future agent who deletes
// the long comment block from cmd/api/static.go fails here, and
// the failure message points at the audit so they know to either
// re-add the comment or move the embed to internal/ (which the
// comment also documents as the right next step if a second
// consumer ever appears).
func TestStaticGo_HasLayeringDocComment_AUDIT169(t *testing.T) {
	const path = "../../cmd/api/static.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cmd/api/static.go not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// The doc comment must mention the audit ID and the layering
	// decision. We don't pin the full text (so a future edit to
	// clarify doesn't fail the test) but the canonical signals
	// must be present:
	//   - "AUDIT-169" (so the decision is traceable)
	//   - "staticFiles" (so the doc is about THIS file, not a
	//     copy-paste from elsewhere)
	//   - one of "Acceptable as-is" / "internal/" (the two
	//     branches of the decision)
	requiredSignals := []string{
		"AUDIT-169",
		"staticFiles",
		"internal/", // the migration target if a second consumer appears
	}
	for _, sig := range requiredSignals {
		if !strings.Contains(body, sig) {
			t.Errorf("cmd/api/static.go doc comment missing the %q signal (AUDIT-169: the layering decision must be documented in-place, not in a commit message that gets lost). The comment should mention AUDIT-169, name the staticFiles variable, and reference the `internal/` migration target.", sig)
		}
	}
}
