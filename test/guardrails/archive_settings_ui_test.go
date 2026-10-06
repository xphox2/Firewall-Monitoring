package guardrails

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestArchiveSettingsRoutesAdminOnly (A-10): the archive settings carry the
// bucket keys and the test route connects to the bucket, so both stay in
// adminOnlyRoutes (RequireRole would otherwise give a GET to viewers), and
// the save goes through the login rate limiter like every step-up route.
func TestArchiveSettingsRoutesAdminOnly(t *testing.T) {
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
	for _, r := range []string{`"/admin/api/archive/settings":true`, `"/admin/api/archive/settings/test":true`} {
		if !strings.Contains(adminOnly, r) {
			t.Errorf("%s must be in adminOnlyRoutes", r)
		}
	}
	for _, reg := range []string{
		`admin.GET("/api/archive/settings", handler.GetArchiveSettings)`,
		`admin.POST("/api/archive/settings", middleware.LoginRateLimiter(), handler.SaveArchiveSettings)`,
		`admin.POST("/api/archive/settings/test", handler.TestArchiveSettings)`,
	} {
		if !strings.Contains(body, reg) {
			t.Errorf("route not registered as %s", reg)
		}
	}
}

// TestArchiveSettingsCardCSPSafe: the Raw Archive Settings card is admin-only,
// its script is loaded, and the module binds through addEventListener (the
// CSP forbids inline handlers), fetches only for an admin, and never puts a
// value into the secret's input.
func TestArchiveSettingsCardCSPSafe(t *testing.T) {
	html, err := os.ReadFile("../../web/admin/admin.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(html)
	i := strings.Index(page, `id="settings-archive-config"`)
	if i < 0 {
		t.Fatal("the archive settings card is missing")
	}
	card := page[strings.LastIndex(page[:i], `<div class="card"`):i]
	if !strings.Contains(card, `data-min-role="admin"`) || strings.Contains(card, "onclick") {
		t.Errorf("archive settings card must be admin-only with no inline handler: %s", card)
	}
	if !strings.Contains(page, `<script defer src="/static/js/admin-archive-settings.js"></script>`) {
		t.Error("admin-archive-settings.js is not loaded")
	}
	js := readJS(t, "admin-archive-settings.js")
	if regexp.MustCompile(`\bon(click|change|input|submit)\s*=`).MatchString(js) {
		t.Error("admin-archive-settings.js writes an inline event handler")
	}
	for _, sub := range []string{
		"el.addEventListener('click'",
		"if (!me || me.role !== 'admin') return null;",
		`autocomplete="new-password" placeholder=`,
		"apiFetch(API_BASE + '/archive/settings/test'",
	} {
		if !strings.Contains(js, sub) {
			t.Errorf("admin-archive-settings.js is missing %q", sub)
		}
	}
	if strings.Contains(js, `type="password" id="' + id + '" data-arch-key="' + f.key + '" value="' + `) {
		t.Error("the secret input must never be filled with a value")
	}
	main := readJS(t, "admin-main.js")
	if !strings.Contains(main, "FwmonArchiveSettings.render({ onSaved: renderArchiveStatus })") {
		t.Error("admin-main.js does not render the archive settings")
	}
}
