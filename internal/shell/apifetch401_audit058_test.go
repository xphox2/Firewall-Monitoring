package shell

import (
	"os"
	"strings"
	"testing"
)

// TestApiFetch401_TopFrame_AUDIT058 is a static regression for the audit:
// apiFetch's 401/302 handler did `window.location.href = '/admin/login'`. When
// the failing request came from the Reports preview iframe, that navigated the
// IFRAME to /login, rendering the login page inside the report frame instead
// of redirecting the whole tab. The fix targets the top frame:
// `(window.top || window).location.href = '/admin/login'`.
func TestApiFetch401_TopFrame_AUDIT058(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-common.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-common.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-058") {
		t.Errorf("admin-common.js missing the AUDIT-058 marker.")
	}
	if !strings.Contains(body, "(window.top || window).location.href = '/admin/login'") {
		t.Errorf("admin-common.js apiFetch 401 redirect must target the top frame `(window.top || window).location.href` (AUDIT-058) so a 401 inside the Reports iframe doesn't navigate the iframe to /login.")
	}
}
