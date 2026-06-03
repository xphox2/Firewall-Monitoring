package shell

import (
	"os"
	"strings"
	"testing"
)

// TestAdminControls_DocumentsRouterLimitation_AUDIT127 is a static
// regression for the audit: `admin-controls.js` uses
// `history.replaceState` for filter changes, which means the
// browser back button doesn't restore the previous filter state
// — each page is a separate URL and back navigates between pages,
// not between filter states within a page.
//
// The audit's recommendation was "Implement minimal hash-based or
// History API router. Or accept the limitation and document."
// We chose the second option (a meaningful router refactor is its
// own work, see the deferred section in the doc comment) and
// document the trade-off in-place. The documentation must include:
//
//  1. The `AUDIT-127` signal (so the decision is traceable)
//  2. An explanation of WHY back doesn't restore filter state
//     (the design intent)
//  3. A forward-pointer to the future router work (so a future
//     agent picking this up knows what to do)
//
// A future agent who deletes the documentation (or shortens it
// to the pre-fix one-liner) fails here immediately, with a
// message pointing at the audit.
func TestAdminControls_DocumentsRouterLimitation_AUDIT127(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-controls.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-controls.js not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	requiredSignals := []string{
		"AUDIT-127",          // traceability
		"history.back",       // the limitation is named
		"replaceState",       // the design choice
		"minimal hash-based", // the future improvement
	}
	for _, sig := range requiredSignals {
		if !strings.Contains(body, sig) {
			t.Errorf("admin-controls.js doc block missing the %q signal (AUDIT-127: the back-button / filter-state limitation must be documented in-place, not in a commit message that gets lost). The doc should mention AUDIT-127, the history.back() limitation, the replaceState design choice, and the future hash-router work as the upgrade path.", sig)
		}
	}
}
