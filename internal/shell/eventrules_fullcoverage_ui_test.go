package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEventRulesFullCoverageUI pins the v0.11.119/120 full-coverage surface:
// the toggle matrix's per-type Rule bridge, the template-endpoint recreate
// path, the grouped rules table, and the dynamic alert-type select (the
// hardcoded 16-option list silently blanked alert_type when editing any rule
// of an uncovered type — a revert reintroduces data loss).
func TestEventRulesFullCoverageUI(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}

	profiles := read("../../cmd/api/static/js/admin-event-profiles.js")
	for _, pin := range []string{
		`data-ep-customize`,                // matrix per-type Rule button + delegate
		`event-rules/template?alert_type=`, // seed-deleted recreate path
		`openRuleModal(null, t.data`,       // template prefill BYPASSES openFromPrefill
	} {
		if !strings.Contains(profiles, pin) {
			t.Errorf("admin-event-profiles.js lost %q — the matrix→rule bridge regressed", pin)
		}
	}
	// The template prefill must never run through openFromPrefill, whose
	// force-enable/force-suppress would flip the disabled-by-design templates
	// live on recreate. Scan only openCustomize's BODY (up to the next
	// top-level function) so a legitimate openFromPrefill call added later
	// elsewhere in the file can't false-positive this pin.
	if idx := strings.Index(profiles, "function openCustomize"); idx >= 0 {
		body := profiles[idx:]
		if end := strings.Index(body[1:], "\n    function "); end >= 0 {
			body = body[:end+1]
		}
		if strings.Contains(body, "openFromPrefill(") {
			t.Error("openCustomize must not route template prefills through openFromPrefill (force-enable would activate disabled templates)")
		}
	} else {
		t.Error("openCustomize missing from admin-event-profiles.js")
	}

	rules := read("../../cmd/api/static/js/admin-event-rules.js")
	for _, pin := range []string{
		`data-er-group`,  // grouped collapsible rules table
		`'/alert-types'`, // dynamic er-alert-type select (blanking fix)
		`rebuildAlertTypeSelect`,
	} {
		if !strings.Contains(rules, pin) {
			t.Errorf("admin-event-rules.js lost %q — grouped table / dynamic type select regressed", pin)
		}
	}

	mainGo := read("../../cmd/api/main.go")
	for _, pin := range []string{
		`admin.GET("/api/event-rules/template"`,
		`"/admin/api/event-rules/template": true,`,
	} {
		if !strings.Contains(mainGo, pin) {
			t.Errorf("cmd/api/main.go lost %q — template endpoint route/RBAC regressed", pin)
		}
	}
}
