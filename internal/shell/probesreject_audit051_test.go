package shell

import (
	"os"
	"strings"
	"testing"
)

// TestProbesReject_UsesModal_AUDIT051 is a static regression for the audit:
// `cmd/api/static/js/admin-probes.js` rejected a probe via the native
// `window.prompt('Enter rejection reason:')`, inconsistent with the styled
// reject modal convention. The fix adds a #reject-modal
// to probes.html and routes rejection through AC.openModal / a form submit,
// matching the AdminCommon modal convention.
func TestProbesReject_UsesModal_AUDIT051(t *testing.T) {
	jsPath := "../../cmd/api/static/js/admin-probes.js"
	js, err := os.ReadFile(jsPath)
	if err != nil {
		t.Skipf("admin-probes.js not found at %s; err: %v", jsPath, err)
	}
	jsBody := string(js)

	// The native prompt() must be gone.
	if strings.Contains(jsBody, "prompt('Enter rejection reason:')") {
		t.Errorf("admin-probes.js still uses window.prompt() for reject (AUDIT-051): use the styled #reject-modal instead.")
	}
	for _, sig := range []string{
		"AUDIT-051",                    // traceability
		"AC.openModal('reject-modal')", // modal-based reject
		"function submitReject",        // form submit handler
	} {
		if !strings.Contains(jsBody, sig) {
			t.Errorf("admin-probes.js missing the %q signal (AUDIT-051).", sig)
		}
	}

	htmlPath := "../../web/admin/probes.html"
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Skipf("probes.html not found at %s; err: %v", htmlPath, err)
	}
	htmlBody := string(html)
	for _, sig := range []string{
		"AUDIT-051",
		`id="reject-modal"`,
		`id="reject-form"`,
		`id="reject-reason"`,
		`data-action="close-reject-modal"`,
	} {
		if !strings.Contains(htmlBody, sig) {
			t.Errorf("probes.html missing the %q signal (AUDIT-051): the reject modal markup must be present.", sig)
		}
	}
}
