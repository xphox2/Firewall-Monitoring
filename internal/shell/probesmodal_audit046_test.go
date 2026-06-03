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
// The fix replaces the rule with `.modal.active { display: flex; }`, matching
// the admin-shared.css convention. A future edit that reintroduces the
// `:not(.hidden)` form (or drops the AUDIT-046 marker) fails here.
func TestProbesModal_UsesActiveClass_AUDIT046(t *testing.T) {
	const path = "../../web/admin/probes.html"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("probes.html not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	if strings.Contains(body, ".modal:not(.hidden)") {
		t.Errorf("probes.html still contains the buggy `.modal:not(.hidden)` rule (AUDIT-046): modals never carry a .hidden class, so this forces them visible on first paint. Use `.modal.active { display: flex; }` instead.")
	}
	for _, sig := range []string{
		"AUDIT-046",                     // traceability
		".modal.active { display: flex", // the fix (matches admin-shared.css convention)
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("probes.html missing the %q signal (AUDIT-046): the modal display rule must use the `.active` convention and reference the audit ID in a comment.", sig)
		}
	}
}
