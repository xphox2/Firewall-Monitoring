package shell

import (
	"os"
	"strings"
	"testing"
)

// TestProbesModal_UsesActiveClass_AUDIT046 is a static regression for the
// audit: `web/admin/probes.html` had an inline rule
// `.modal:not(.hidden) { display: flex; }`. Because neither `#probe-modal`
// nor `#deploy-modal` ever carries a `.hidden` class (AdminCommon.openModal
// toggles `.active`, not `.hidden`), that rule (specificity 0,2,0) beat the
// base `.modal { display: none }` from admin-shared.css and forced both
// modals visible on first paint.
//
// The fix removed the negated-hidden rule. As of AUDIT-054 the inline
// `.modal.active` duplicate was also removed, so probes.html now relies on
// admin-shared.css for modal display. The enduring AUDIT-046 invariant is:
// probes.html must NOT carry a `:not(.hidden)` rule, and the canonical
// `.modal.active` rule must live in admin-shared.css. A future edit that
// reintroduces the `:not(.hidden)` form (or drops the AUDIT-046 marker) fails.
func TestProbesModal_UsesActiveClass_AUDIT046(t *testing.T) {
	const path = "../../web/admin/probes.html"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("probes.html not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	if strings.Contains(body, ".modal:not(.hidden)") {
		t.Errorf("probes.html still contains the buggy `.modal:not(.hidden)` rule (AUDIT-046): modals never carry a .hidden class, so this forces them visible on first paint. Modal display must come from admin-shared.css `.modal.active`.")
	}
	if !strings.Contains(body, "AUDIT-046") {
		t.Errorf("probes.html missing the AUDIT-046 marker (traceability): the comment documenting the modal-display convention must reference the audit ID.")
	}

	// The canonical `.modal.active` rule must live in admin-shared.css
	// (AUDIT-054 made it the single source of truth).
	const sharedPath = "../../cmd/api/static/css/admin-shared.css"
	shared, err := os.ReadFile(sharedPath)
	if err != nil {
		t.Skipf("admin-shared.css not found at %s; err: %v", sharedPath, err)
	}
	if !strings.Contains(string(shared), ".modal.active {") {
		t.Errorf("admin-shared.css is missing the canonical `.modal.active` rule (AUDIT-046/054): probes.html relies on it for modal display.")
	}
}
