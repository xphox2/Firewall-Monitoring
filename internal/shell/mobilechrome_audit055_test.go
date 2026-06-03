package shell

import (
	"os"
	"strings"
	"testing"
)

// TestMobileChrome_OnAllPages_AUDIT055 is a static regression for the audit:
// only admin.html had the mobile sidebar chrome (mobile header, hamburger
// button, slide-in sidebar + overlay) — and it was inline. Every other admin
// page rendered a fixed 240px sidebar covering half a phone viewport with no
// way to collapse it. The fix moves the chrome CSS into admin-shared.css, adds
// AdminCommon.renderMobileChrome() to inject the markup + wire the toggle, and
// calls it on every admin page.
func TestMobileChrome_OnAllPages_AUDIT055(t *testing.T) {
	// 1) The shared method must exist and be exported.
	js, err := os.ReadFile("../../cmd/api/static/js/admin-common.js")
	if err != nil {
		t.Skipf("admin-common.js not found; err: %v", err)
	}
	jsBody := string(js)
	for _, sig := range []string{
		"AUDIT-055",
		"function renderMobileChrome",
		"renderMobileChrome: renderMobileChrome",
	} {
		if !strings.Contains(jsBody, sig) {
			t.Errorf("admin-common.js missing %q (AUDIT-055): renderMobileChrome must be defined and exported.", sig)
		}
	}

	// 2) The shared CSS must carry the mobile chrome.
	css, err := os.ReadFile("../../cmd/api/static/css/admin-shared.css")
	if err != nil {
		t.Skipf("admin-shared.css not found; err: %v", err)
	}
	cssBody := string(css)
	for _, sig := range []string{"AUDIT-055", ".mobile-header", ".sidebar.open", ".sidebar-overlay"} {
		if !strings.Contains(cssBody, sig) {
			t.Errorf("admin-shared.css missing %q (AUDIT-055): the shared mobile chrome CSS must be present.", sig)
		}
	}

	// 3) Every admin page must call renderMobileChrome().
	pages := []string{
		"admin.html", "connection-detail.html", "device-detail.html",
		"irc.html", "probe-pending.html", "probes.html", "sites.html",
	}
	for _, page := range pages {
		data, err := os.ReadFile("../../web/admin/" + page)
		if err != nil {
			t.Skipf("%s not found; err: %v", page, err)
		}
		if !strings.Contains(string(data), "AdminCommon.renderMobileChrome()") {
			t.Errorf("%s does not call AdminCommon.renderMobileChrome() (AUDIT-055): the mobile menu must be wired on every admin page.", page)
		}
	}
}
