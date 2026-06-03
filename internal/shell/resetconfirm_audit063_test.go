package shell

import (
	"os"
	"strings"
	"testing"
)

// TestResetConfirm_AUDIT063 is a static regression for the audit: the public
// dashboard "Reset Layout" button wiped the operator's saved widget layout
// (localStorage) with no confirmation — a single misclick destroyed it. The
// fix guards resetLayout with a confirm() before clearing localStorage.
func TestResetConfirm_AUDIT063(t *testing.T) {
	const path = "../../cmd/api/static/js/public-dashboard.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("public-dashboard.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-063") {
		t.Errorf("public-dashboard.js missing the AUDIT-063 marker.")
	}
	// The confirm guard must appear before the layout is cleared.
	idxConfirm := strings.Index(body, "window.confirm(")
	idxRemove := strings.Index(body, "localStorage.removeItem(LAYOUT_KEY)")
	if idxConfirm < 0 {
		t.Errorf("public-dashboard.js resetLayout must guard with window.confirm() (AUDIT-063).")
	}
	if idxConfirm >= 0 && idxRemove >= 0 && idxConfirm > idxRemove {
		t.Errorf("public-dashboard.js confirm() must come BEFORE clearing the saved layout (AUDIT-063).")
	}
}
