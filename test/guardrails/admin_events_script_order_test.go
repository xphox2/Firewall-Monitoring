package guardrails

import (
	"strings"
	"testing"
)

// TestAdminEventsScriptOrder pins the load order the Events page needs.
//
// admin-events.js reads window.AdminCommon (AC.escapeHtml, AC.apiFetch,
// AC.closeModal) at module load, not lazily, so its <script> tag must come
// after admin-common.js; it also renders int16 labels from window.FwmonEnums,
// so after enums.js; and admin-main.js calls FwmonEvents.init() when the page
// is shown, so admin-events.js must come before admin-main.js. Shipping the tag
// before admin-common.js makes the module throw at load and define nothing, so
// the page never renders and makes no API calls — a client-side failure that no
// CI lane catches (no browser), which is exactly what happened in v0.11.327
// before the v0.11.328 fix.
func TestAdminEventsScriptOrder(t *testing.T) {
	html := readRepoFile(t, "web/admin/admin.html")
	idx := func(file string) int {
		return strings.Index(html, `src="/static/js/`+file+`"`)
	}
	enums := idx("enums.js")
	common := idx("admin-common.js")
	events := idx("admin-events.js")
	main := idx("admin-main.js")
	for file, at := range map[string]int{
		"enums.js":        enums,
		"admin-common.js": common,
		"admin-events.js": events,
		"admin-main.js":   main,
	} {
		if at < 0 {
			t.Fatalf("admin.html no longer loads %s", file)
		}
	}
	if enums > events {
		t.Errorf("admin.html must load enums.js (index %d) before admin-events.js (index %d): the page renders window.FwmonEnums labels", enums, events)
	}
	if common > events {
		t.Errorf("admin.html must load admin-common.js (index %d) before admin-events.js (index %d): the module reads window.AdminCommon at load", common, events)
	}
	if events > main {
		t.Errorf("admin.html must load admin-events.js (index %d) before admin-main.js (index %d): loadPageData calls FwmonEvents.init()", events, main)
	}
}
