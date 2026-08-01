package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The config-diff modal was rewritten from ~250 lines of string-concatenated
// inline styles into a class-based, token-driven layer. These tests pin the
// properties that made the rewrite worth doing, because each of them regressed
// silently in the original.
//
// Scoped to the CFGDIFF-UI:BEGIN/END sentinels in admin-device-detail.js so they
// assert on the diff UI only, not the rest of a 2000-line file.

const (
	cdJSPath   = "../../cmd/api/static/js/admin-device-detail.js"
	cdCSSPath  = "../../cmd/api/static/css/admin-config-diff.css"
	cdHTMLPath = "../../web/admin/device-detail.html"
)

// cfgdiffRegion returns the JS between the sentinels.
func cfgdiffRegion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(cdJSPath)
	if err != nil {
		t.Skipf("%s not found: %v", cdJSPath, err)
	}
	body := string(data)
	start := strings.Index(body, "CFGDIFF-UI:BEGIN")
	end := strings.Index(body, "CFGDIFF-UI:END")
	if start < 0 || end < 0 || end < start {
		t.Fatalf("CFGDIFF-UI:BEGIN/END sentinels missing from %s — the other tests in this file scope on them, so removing them silently disables the whole guard.", cdJSPath)
	}
	return body[start:end]
}

// TestConfigDiffUI_NoHexOrInlineStyle is the important one.
//
// The old renderer picked colour in JS — sevColor() returned a hex string and an
// opColor ternary chose another — which is precisely how it evaded
// TestNoThemeBlindInlineTextColor: that guard matches a literal `color:#hex`
// inside a style string, and a value routed through a variable never matches.
// Banning hex and inline styles outright inside this region closes the hole by
// construction rather than by discipline.
func TestConfigDiffUI_NoHexOrInlineStyle(t *testing.T) {
	region := cfgdiffRegion(t)

	hex := regexp.MustCompile(`#[0-9a-fA-F]{6}\b`)
	for _, m := range hex.FindAllString(region, -1) {
		t.Errorf("literal hex colour %q in the config-diff renderer — emit a data-sev/data-op state string and let admin-config-diff.css map it onto a token", m)
	}
	if strings.Contains(region, `style="`) {
		t.Error("inline style attribute in the config-diff renderer — styling belongs in admin-config-diff.css, or the day theme silently regresses")
	}
	for _, dead := range []string{"function sevColor", "var CD_ROW"} {
		if strings.Contains(region, dead) {
			t.Errorf("%q is back — it was removed because it selected colour in JS", dead)
		}
	}
}

// TestConfigDiffUI_NoConsole pins the repo-wide logging rule for this region.
func TestConfigDiffUI_NoConsole(t *testing.T) {
	region := cfgdiffRegion(t)
	if strings.Contains(region, "console.") {
		t.Error("console.* in the config-diff renderer — use fwmonLog.* (AUDIT-151)")
	}
	if !strings.Contains(region, "fwmonLog.") {
		t.Error("the config-diff renderer logs nothing via fwmonLog — the error paths should")
	}
}

// TestConfigDiffUI_AriaExpanded pins keyboard operability of the expanders.
//
// The old object cards used a <div data-action="cd-toggle">: not focusable, not
// announced, not operable by keyboard at all. AUDIT-070 covers only
// admin-common.js's mobile chrome, so nothing else would catch a regression.
func TestConfigDiffUI_AriaExpanded(t *testing.T) {
	region := cfgdiffRegion(t)

	for _, want := range []string{
		`<button type="button" class="cfgdiff-obj-head" data-action="cd-toggle"`,
		`aria-expanded=`,
		`aria-controls=`,
	} {
		if !strings.Contains(region, want) {
			t.Errorf("object-card expander missing %q — it must be a real button with aria-expanded/aria-controls", want)
		}
	}
	if !strings.Contains(region, `setAttribute('aria-expanded'`) {
		t.Error("the toggle handler never updates aria-expanded, so the announced state goes stale")
	}
	if !strings.Contains(region, `data-action="ld-expand"`) || !strings.Contains(region, `aria-controls="' + gid + '"`) {
		t.Error("the unchanged-run expander must carry aria-controls")
	}
}

// TestConfigDiffUI_TablistAria pins the view switches as real tabs.
func TestConfigDiffUI_TablistAria(t *testing.T) {
	region := cfgdiffRegion(t)
	for _, want := range []string{`role="tablist"`, `role="tab"`, `aria-selected=`} {
		if !strings.Contains(region, want) {
			t.Errorf("view switcher missing %q", want)
		}
	}
	if !strings.Contains(region, "function cdWireTablist") {
		t.Error("cdWireTablist is gone — arrow-key navigation between tabs is part of the tab contract")
	}
	if !strings.Contains(region, `aria-pressed`) {
		t.Error("severity filters must be toggles (aria-pressed), not tabs")
	}
}

// TestConfigDiffUI_VendorNeutral is what stops vendor-specific copy creeping
// back into a shared surface.
//
// The old footnote was hardcoded to "FortiOS encryption-IV churn" and rendered
// on every device, including OPNsense boxes that have never run FortiOS. The
// payload carries volatile_patterns and vendor; the renderer must use them.
func TestConfigDiffUI_VendorNeutral(t *testing.T) {
	region := cfgdiffRegion(t)
	html, err := os.ReadFile(cdHTMLPath)
	if err != nil {
		t.Skipf("%s not found: %v", cdHTMLPath, err)
	}

	// Scope the HTML check to the diff modal block.
	body := string(html)
	start := strings.Index(body, `id="config-diff-modal"`)
	if start < 0 {
		t.Fatal("config-diff modal missing from device-detail.html")
	}
	end := strings.Index(body[start:], "</div>\n            </div>")
	modalBlock := body[start:]
	if end > 0 {
		modalBlock = body[start : start+end]
	}

	// Check rendered code, not commentary: naming a vendor while EXPLAINING why
	// the copy must not name one is correct, and banning that would push the
	// rationale out of the file.
	code := stripLineComments(region)

	for _, vendor := range []string{"FortiOS", "FortiGate", "OPNsense", "pfSense", "PAN-OS", "Palo Alto"} {
		if strings.Contains(code, vendor) {
			t.Errorf("vendor name %q in the shared config-diff renderer — the volatile legend must be built from data.volatile_patterns, not hardcoded for one vendor", vendor)
		}
		if strings.Contains(modalBlock, vendor) {
			t.Errorf("vendor name %q in the config-diff modal markup", vendor)
		}
	}
	if !strings.Contains(region, "volatile_patterns") {
		t.Error("the renderer ignores data.volatile_patterns — that field is what makes the legend vendor-neutral")
	}
}

// stripLineComments removes `//` comments so a check can target emitted code
// rather than the commentary around it. Crude by design: it does not attempt to
// respect `//` inside a string literal, which would only ever make the check
// stricter than intended, never looser.
func stripLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// TestConfigDiffUI_StylesheetSlot pins the new stylesheet into the load order.
func TestConfigDiffUI_StylesheetSlot(t *testing.T) {
	if _, err := os.Stat(cdCSSPath); err != nil {
		t.Fatalf("admin-config-diff.css is missing: %v", err)
	}
	data, err := os.ReadFile(cdHTMLPath)
	if err != nil {
		t.Skipf("%s not found: %v", cdHTMLPath, err)
	}
	body := string(data)

	ds := strings.Index(body, "admin-design-system.css")
	cd := strings.Index(body, "admin-config-diff.css")
	br := strings.LastIndex(body, "admin-tw-bridge.css")
	if cd < 0 {
		t.Fatal("device-detail.html does not link admin-config-diff.css")
	}
	if !(ds < cd && cd < br) {
		t.Errorf("stylesheet order wrong: design-system(%d) < config-diff(%d) < tw-bridge(%d) must hold, or the tokens the diff UI depends on are not defined yet when it loads", ds, cd, br)
	}
}

// TestConfigDiffUI_ResponsiveAndPrint pins the narrow-viewport and print rules,
// and the theme-flip trap.
func TestConfigDiffUI_ResponsiveAndPrint(t *testing.T) {
	data, err := os.ReadFile(cdCSSPath)
	if err != nil {
		t.Skipf("%s not found: %v", cdCSSPath, err)
	}
	css := string(data)

	for _, want := range []string{
		"@media (max-width: 900px)",
		"@media (max-width: 640px)",
		"@media print",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("admin-config-diff.css is missing %q", want)
		}
	}

	// Chromium pins var() across a theme flip, so a transitioned `color` freezes
	// on the old theme's ink. Only background-color/border-color/box-shadow/
	// opacity may be transitioned.
	transition := regexp.MustCompile(`transition:[^;]*`)
	for _, m := range transition.FindAllString(css, -1) {
		if regexp.MustCompile(`(^|[^-\w])color\b`).MatchString(m) {
			t.Errorf("transition includes `color` (%q) — it freezes on the old theme across a day/night flip", strings.TrimSpace(m))
		}
	}
}
