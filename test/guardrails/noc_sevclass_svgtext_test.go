package guardrails

import (
	"regexp"
	"strings"
	"testing"
)

// TestNOCSevClassWhitelist pins L-1: admin-noc.js concatenates sevClass()'s
// result raw into class="…" on every site/device card, so a severity outside
// the known set must map to an empty string rather than reach the attribute. The lookup has
// to be an own-property check — SEV_RANK['constructor'] is non-null through the
// prototype, so a `!= null` test would still let it through.
func TestNOCSevClassWhitelist(t *testing.T) {
	js := readJS(t, "admin-noc.js")
	fn := regexp.MustCompile(`(?s)function sevClass\(sev\) \{(.*?)\n    \}`).FindStringSubmatch(js)
	if fn == nil {
		t.Fatal("admin-noc.js: sevClass(sev) not found")
	}
	if !strings.Contains(fn[1], "Object.prototype.hasOwnProperty.call(SEV_RANK, sev)") {
		t.Errorf("sevClass must whitelist the severity against SEV_RANK with an own-property check before building the class; body:%s", fn[1])
	}
	if strings.Contains(fn[1], "return sev ?") {
		t.Errorf("sevClass still builds the class from any truthy severity; body:%s", fn[1])
	}
}

// TestSVGLabelsStripBidi pins L-4: device names rendered into the connection
// bridge SVG <text> labels go through svgText, which strips bidi controls
// (U+202A–202E, U+2066–2069, U+200E/200F, U+061C) before truncating and escaping —
// escapeHtml alone leaves them, and they visually reorder the name.
func TestSVGLabelsStripBidi(t *testing.T) {
	common := readJS(t, "admin-common.js")
	for _, want := range []string{
		`var BIDI_CONTROLS = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;`,
		"function svgText(str, max)",
		".replace(BIDI_CONTROLS, '')",
		"svgText: svgText,",
		"window.svgText = svgText;",
	} {
		if !strings.Contains(common, want) {
			t.Errorf("admin-common.js is missing %q", want)
		}
	}

	for _, tc := range []struct{ file, want string }{
		{"admin-connection-detail.js", "AC.svgText(srcName, 16)"},
		{"admin-connection-detail.js", "AC.svgText(dstName, 16)"},
		{"diagram-panels.js", "${window.svgText(srcName, 16)}"},
		{"diagram-panels.js", "${window.svgText(dstName, 16)}"},
	} {
		js := readJS(t, tc.file)
		if !strings.Contains(js, tc.want) {
			t.Errorf("%s: SVG <text> label must render via %q (bidi-stripped)", tc.file, tc.want)
		}
		// No SVG <text> label may interpolate a name through escapeHtml alone.
		if regexp.MustCompile(`<text[^>]*>['"]? ?\+? ?(AC\.|window\.)?escapeHtml\(|<text[^>]*>\$\{window\.escapeHtml\(`).MatchString(js) {
			t.Errorf("%s: an SVG <text> label still uses escapeHtml directly (bidi controls pass through)", tc.file)
		}
	}
}
