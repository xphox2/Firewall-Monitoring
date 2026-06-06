package shell

import (
	"os"
	"regexp"
	"testing"
)

// TestNoFaintTextColor_AUDIT066 pins the surgical fix: #484f58 must not be used
// as a foreground TEXT color (it fails WCAG AA ~2:1 on the dark background). It
// is still allowed for DECORATIVE use (borders, backgrounds, hover states, chart
// data-viz colors), so the test matches only the `color:` property — not
// `border-color`/`background-color` — via a "non-dash before color:" guard
// (Go's regexp has no lookbehind). The contrast fix that brightened these to
// #8b949e was reverted in v0.10.320 for flattening the hierarchy; this redo
// touches text only and uses #768390 (~4.6:1, passes AA) to keep a distinct
// faint tier.
func TestNoFaintTextColor_AUDIT066(t *testing.T) {
	// [^-] before "color:" excludes border-color/background-color but matches
	// standalone `color:` / `;color:` / `"color:` / `{color:`.
	textColor := regexp.MustCompile(`(?i)[^-]color: ?#484f58`)

	files := []string{
		"../../web/public/index.html",
		"../../cmd/api/static/css/admin-shared.css",
		"../../cmd/api/static/css/styles.css",
		"../../cmd/api/static/css/tailwind.css",
		"../../cmd/api/static/js/admin-connection-detail.js",
		"../../cmd/api/static/js/admin-device-detail.js",
		"../../cmd/api/static/js/admin-main.js",
		"../../cmd/api/static/js/diagram-panels.js",
		"../../cmd/api/static/js/public-dashboard.js",
	}
	sawFix := false
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		body := string(data)
		if loc := textColor.FindStringIndex(body); loc != nil {
			start := loc[0] - 20
			if start < 0 {
				start = 0
			}
			t.Errorf("%s still uses #484f58 as a TEXT color (fails WCAG AA) near: %q", f, body[start:loc[1]])
		}
		if regexp.MustCompile(`(?i)color: ?#768390`).MatchString(body) {
			sawFix = true
		}
	}
	if !sawFix {
		t.Error("none of the files contain the #768390 replacement — AUDIT-066 fix appears not applied")
	}
}
