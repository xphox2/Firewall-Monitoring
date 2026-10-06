package guardrails

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestArchiveStatusRouteAdminOnly: the raw archive status names the bucket,
// the parked chunks' errors and the database sessions holding an export, so
// it must stay in adminOnlyRoutes — RequireRole otherwise defaults a GET to
// the viewer role. Same source-scan pattern as
// TestFlowInternalNetworksRouteAdminOnly.
func TestArchiveStatusRouteAdminOnly(t *testing.T) {
	data, err := os.ReadFile("../../cmd/api/main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatal("adminOnlyRoutes marker not found")
	}
	end := strings.Index(body[start:], "))")
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")
	if !strings.Contains(adminOnly, `"/admin/api/archive/status":true`) {
		t.Error("/admin/api/archive/status must be in adminOnlyRoutes")
	}
	if !strings.Contains(body, `admin.GET("/api/archive/status", handler.GetArchiveStatus)`) {
		t.Error("the archive status route is not registered")
	}
}

// TestArchiveStatusCardCSPSafe: the Retention page's archive card binds its
// buttons through data-action (no inline handlers: the CSP forbids them) and
// only an admin's page fetches the admin-only status.
func TestArchiveStatusCardCSPSafe(t *testing.T) {
	main := readJS(t, "admin-main.js")
	for _, sub := range []string{
		"'archive-reset-chunk': function(el)",
		"'archive-reengage': function(el)",
		"if (!me || me.role !== 'admin') return null;",
		"apiFetch(API_BASE + '/archive/status')",
	} {
		if !strings.Contains(main, sub) {
			t.Errorf("admin-main.js is missing %q", sub)
		}
	}
	html, err := os.ReadFile("../../web/admin/admin.html")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(html), `id="settings-archive"`)
	if i < 0 {
		t.Fatal("the archive card is missing from the Retention section")
	}
	card := string(html)[strings.LastIndex(string(html)[:i], `<div class="card"`):i]
	if !strings.Contains(card, `data-min-role="admin"`) || strings.Contains(card, "onclick") {
		t.Errorf("archive card must be admin-only and carry no inline handler: %s", card)
	}
}

// TestArchiveStatusCardScript: the status card's renderer is loaded, writes
// no inline handler (CSP), escapes the server's strings, and refreshes only
// while the browser tab is visible (AdminCommon.pollWhenVisible) — admin-main
// hands it the admin-only fetch.
func TestArchiveStatusCardScript(t *testing.T) {
	html, err := os.ReadFile("../../web/admin/admin.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `<script defer src="/static/js/admin-archive-status.js"></script>`) {
		t.Error("admin-archive-status.js is not loaded")
	}
	js := readJS(t, "admin-archive-status.js")
	if regexp.MustCompile(`\bon[a-z]+\s*=`).MatchString(js) {
		t.Error("admin-archive-status.js writes an inline event handler")
	}
	for _, sub := range []string{
		"var esc = AC.escapeHtml;",
		"AC.pollWhenVisible(",
		"esc(e.error || '')",
		"esc(gr.error || '')",
		`data-action="archive-reset-chunk"`,
	} {
		if !strings.Contains(js, sub) {
			t.Errorf("admin-archive-status.js is missing %q", sub)
		}
	}
	if !strings.Contains(readJS(t, "admin-main.js"), "FwmonArchiveStatus.watch(host,") {
		t.Error("admin-main.js does not keep the archive status current")
	}
}
