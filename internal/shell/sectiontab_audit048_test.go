package shell

import (
	"os"
	"strings"
	"testing"
)

// TestSectionTab_HiddenOverride_AUDIT048 is a static regression for the audit:
// connection-detail.html's inline `.section-tab { display: inline-block }`
// loads after admin-shared.css and (equal specificity, later cascade) beats
// the `.hidden { display: none }` that admin-connection-detail.js toggles on
// #tab-phase2 / #tab-flows. The v0.10.230 classList.toggle('hidden', ...) fix
// therefore produced no visual change. The fix adds a higher-specificity
// `.section-tab.hidden { display: none !important; }` rule to the same inline
// block. A future edit that drops it (or the audit marker) fails here.
func TestSectionTab_HiddenOverride_AUDIT048(t *testing.T) {
	const path = "../../web/admin/connection-detail.html"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("connection-detail.html not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	for _, sig := range []string{
		"AUDIT-048", // traceability
		".section-tab.hidden { display: none !important; }", // the fix
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("connection-detail.html missing the %q signal (AUDIT-048): the inline .section-tab rule must be overridden for the hidden state so the JS toggle actually hides #tab-phase2 / #tab-flows.", sig)
		}
	}
}
