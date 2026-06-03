package shell

import (
	"os"
	"strings"
	"testing"
)

// TestPrintCss_AUDIT060 is a static regression for the audit: admin-shared.css
// had no `@media print` rule, so Ctrl+P on an admin page printed the sidebar,
// mobile header, toasts, and any `.no-print` element (the class was dead). The
// fix adds a print block hiding the interactive chrome.
func TestPrintCss_AUDIT060(t *testing.T) {
	const path = "../../cmd/api/static/css/admin-shared.css"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-shared.css not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-060") {
		t.Errorf("admin-shared.css missing the AUDIT-060 marker.")
	}
	if !strings.Contains(body, "@media print") {
		t.Errorf("admin-shared.css has no `@media print` rule (AUDIT-060): printing must hide the admin chrome.")
	}
	// The print block must reference the chrome it hides.
	for _, sel := range []string{".sidebar", ".no-print", ".mobile-header", ".toast-container"} {
		if !strings.Contains(body, sel) {
			t.Errorf("admin-shared.css print rule should cover %q (AUDIT-060).", sel)
		}
	}
}
