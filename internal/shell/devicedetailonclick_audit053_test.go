package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDeviceDetail_NoInlineOnclick_AUDIT053 is a static regression for the
// audit: `cmd/api/static/js/admin-device-detail.js` built buttons with inline
// onclick="..." attributes (config-history View/Download/Delete and the config
// modal close buttons). These work only because the CSP still allows
// script-src 'unsafe-inline'; they block any future CSP tightening and are
// inconsistent with the file's data-action delegation pattern. The fix
// converts all five to data-action + data-id handled by AC.delegateEvent.
func TestDeviceDetail_NoInlineOnclick_AUDIT053(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-device-detail.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-device-detail.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	// No inline onclick attribute may remain (the marker comment is worded to
	// avoid the literal `onclick=` token).
	if strings.Contains(body, "onclick=") {
		t.Errorf("admin-device-detail.js still contains an inline `onclick=` attribute (AUDIT-053): convert it to data-action delegation so the page survives a future CSP tightening.")
	}
	for _, sig := range []string{
		"AUDIT-053", // traceability
		"data-action=\"view-config-revision\"",
		"data-action=\"close-config-modal\"",
		"'view-config-revision': function", // delegated handler
		"'close-config-modal': function",
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("admin-device-detail.js missing the %q signal (AUDIT-053): the inline handlers must be replaced by data-action delegation.", sig)
		}
	}
}
