package shell

import (
	"os"
	"strings"
	"testing"
)

// TestAriaExpanded_AUDIT070 is a static regression for the audit: the mobile
// menu button's aria-expanded never updated — the old inline admin.html toggle
// only flipped the .open classes. As of AUDIT-055 the hamburger and its toggle
// live in AdminCommon.renderMobileChrome(), whose open/close handler keeps
// aria-expanded in sync. This test pins that the button is created with
// aria-expanded="false" and that the handler updates it.
func TestAriaExpanded_AUDIT070(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-common.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-common.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-070") {
		t.Errorf("admin-common.js missing the AUDIT-070 marker.")
	}
	if !strings.Contains(body, `aria-expanded="false"`) {
		t.Errorf("renderMobileChrome must create the menu button with aria-expanded=\"false\" (AUDIT-070).")
	}
	if !strings.Contains(body, `setAttribute('aria-expanded', open ? 'true' : 'false')`) {
		t.Errorf("renderMobileChrome's toggle handler must keep aria-expanded in sync with the open state (AUDIT-070).")
	}
}
