package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The IPSec wizard's path list grows as the PRODUCT of both ends' subnet counts
// — five subnets a side is twenty-five rows. It used to live in fixed chrome
// above the form, which meant the two competed for height: at 1440x800 the head
// took 56% of the dialog and left the form a 190px window onto 614px of content.
//
// v0.11.187 managed that with a 132px cap and a collapse toggle. The diagram now
// has its OWN full-height view instead, which removes the competition rather
// than rationing it — so the cap and the toggle are gone, and what has to be
// pinned is the structure that makes them unnecessary.

func readWizardAsset(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// The invariant the old cap was really protecting: fixed chrome must not grow
// with the configuration. The header carries a one-line summary and nothing that
// enumerates pairs; the list lives in the panel and scrolls itself.
func TestIPSecWizard_HeaderCannotGrowWithTheConfiguration(t *testing.T) {
	html := readWizardAsset(t, "../../web/admin/admin.html")
	css := readWizardAsset(t, "../../cmd/api/static/css/admin-ipsec.css")

	head := regexp.MustCompile(`(?s)<header class="ipsec-wiz-head">(.*?)</header>`).FindStringSubmatch(html)
	if head == nil {
		t.Fatal("wizard header not found")
	}
	for _, id := range []string{"ipsec-schematic", "ipsec-paths"} {
		if strings.Contains(head[1], `id="`+id+`"`) {
			t.Errorf("#%s is back in the header. It grows with the number of subnet pairs, "+
				"and fixed chrome that grows is what squeezed the form to a 190px window.", id)
		}
	}
	if !strings.Contains(head[1], `id="ipsec-summary"`) {
		t.Error("no bounded summary line in the header — the operator loses live feedback " +
			"while typing on the Design view")
	}

	// The list must scroll on its own; if it did not, the rows past the fold
	// would be clipped and unreachable.
	block := regexp.MustCompile(`(?s)\.ipsec-paths\s*\{(.*?)\}`).FindStringSubmatch(css)
	if block == nil {
		t.Fatal(".ipsec-paths rule not found")
	}
	if !strings.Contains(block[1], "overflow-y: auto") {
		t.Error(".ipsec-paths does not scroll — with more pairs than fit, the tail is clipped")
	}
	if strings.Contains(block[1], "max-height") {
		t.Error(".ipsec-paths has a max-height again. It is supposed to take the height the " +
			"panel gives it; a cap here re-creates the cramped strip this view replaced.")
	}
}

// The height chain is the whole feature, and it fails SILENTLY: with no definite
// height anywhere above it, `flex:1` and `height:100%` resolve against nothing,
// the list grows to content, and `overflow:hidden` on the body then removes the
// only working scroll container. Each link is pinned because dropping any one of
// them reproduces that.
func TestIPSecWizard_DiagramPhaseHasARealHeightChain(t *testing.T) {
	css := readWizardAsset(t, "../../cmd/api/static/css/admin-ipsec.css")

	// Two classes, not one: admin.html's inline <style> loads AFTER this sheet,
	// so a single-class .ipsec-wiz loses every shared property to .modal-content.
	// Match the block that CARRIES the shell (max-height + padding), not merely
	// any rule wearing that selector — the 480px block uses it too, so a bare
	// substring check passes even with the base rule reverted.
	shell := regexp.MustCompile(`(?s)\.modal-content\.ipsec-wiz \{([^}]*)\}`).FindStringSubmatch(css)
	if shell == nil || !strings.Contains(shell[1], "max-height: 92vh") {
		t.Error("the shell block is not .modal-content.ipsec-wiz — at (0,1,0) it loses to the " +
			"inline .modal-content rule, which is why the wizard ran at 85vh with 24px " +
			"padding for so long despite this file saying otherwise")
	}
	if !strings.Contains(css, ".modal-content.ipsec-wiz.phase-diagram { height: 92vh; }") {
		t.Error("no definite height for the diagram phase; max-height alone leaves the dialog " +
			"content-sized and every flex child below collapses to auto")
	}

	form := regexp.MustCompile(`(?s)\.ipsec-wiz-form\s*\{(.*?)\}`).FindStringSubmatch(css)
	if form == nil || !strings.Contains(form[1], "flex: 1 1 auto") {
		t.Error(".ipsec-wiz-form must stretch (flex: 1 1 auto) — without it the chain stops " +
			"here and the panel below has no height to fill")
	}

	for _, want := range []string{
		".ipsec-wiz.phase-diagram .ipsec-wiz-body",
		".ipsec-panel-diagram",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("%s rule missing — the body must hand its height to the panel", want)
		}
	}

	// Mobile: media queries add NO specificity, so the 480px override needs the
	// same (0,3,0) as the phase rule or it loses to our own 92vh and leaves a
	// gap behind a supposedly edge-to-edge sheet.
	mobile := regexp.MustCompile(`(?s)@media \(max-width: 480px\) \{(.*?)\n\}`).FindStringSubmatch(css)
	if mobile == nil {
		t.Fatal("480px media block not found")
	}
	if !strings.Contains(mobile[1], ".modal-content.ipsec-wiz.phase-diagram") {
		t.Error("the 480px block does not override the phase-diagram height at equal " +
			"specificity; on a phone the dialog would resolve to min(92vh, 100dvh)")
	}
}

// Deleting #ipsec-schematic is fatal in two ways: refreshDerived uses its
// presence as the mount guard for the ENTIRE live-render pipeline, and
// openWizard writes to it unguarded. It moved into the diagram panel; it must
// never simply go away.
func TestIPSecWizard_SchematicElementStillExists(t *testing.T) {
	html := readWizardAsset(t, "../../web/admin/admin.html")
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	if !strings.Contains(html, `id="ipsec-schematic"`) {
		t.Fatal("#ipsec-schematic is gone. refreshDerived guards on it (so every live update " +
			"stops silently) and openWizard writes to it unguarded (so the wizard throws " +
			"on open).")
	}
	if !strings.Contains(js, `if (!$('ipsec-schematic')) return;`) {
		t.Error("refreshDerived's mount guard changed — if it no longer guards, the unguarded " +
			"writes below it become the crash instead")
	}
}

// The total is the one number that says whether the tunnel is what the operator
// intended. Group headers scroll away with their group and show only per-group
// counts, so the total has to live outside the scroller.
func TestIPSecWizard_TotalCountIsOutsideTheScrollingList(t *testing.T) {
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	fn := regexp.MustCompile(`(?s)function renderSummary\(\)\s*\{(.*?)\n    \}`).FindStringSubmatch(js)
	if fn == nil {
		t.Fatal("renderSummary() not found — the header summary is where the total lives")
	}
	if !strings.Contains(fn[1], "child SA") {
		t.Error("the header summary does not report the child-SA count; scrolling the path " +
			"list would then hide the only total on screen")
	}
	if !strings.Contains(js, "$('ipsec-summary')") {
		t.Error("renderSummary does not target #ipsec-summary")
	}
}

// Rows are real buttons. Two independent reasons, and losing either is a bug:
// nothing else in this codebase makes a clickable row keyboard-reachable, and a
// <button> without type="button" SUBMITS the form it sits in.
func TestIPSecWizard_PathRowsAreAccessibleButtons(t *testing.T) {
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	fn := regexp.MustCompile(`(?s)function renderPaths\(\)\s*\{(.*?)\n    \}`).FindStringSubmatch(js)
	if fn == nil {
		t.Fatal("renderPaths() not found")
	}
	body := fn[1]

	if strings.Contains(body, `type="checkbox"`) {
		t.Error("path rows still render a checkbox; the row itself is the control now")
	}
	// Anchored on the closing quote: "ipsec-paths-head" starts with "ipsec-path",
	// so a prefix match is satisfied by the GROUP header even when the rows have
	// lost their type attribute entirely.
	if !regexp.MustCompile(`'<button type="button" class="ipsec-path'`).MatchString(body) {
		t.Error(`path rows are not <button type="button">. Without the type they submit ` +
			`#ipsec-wizard-form on every click — a navigation that discards the wizard — ` +
			`and without a real button they are not keyboard reachable at all.`)
	}
	if !strings.Contains(body, `aria-pressed="`) {
		t.Error("path rows carry no aria-pressed, so the on/off state is conveyed by colour alone")
	}
	if !strings.Contains(body, `class="ipsec-paths-head" aria-pressed="`) {
		t.Error("group headers are not aria-pressed buttons")
	}
	// A partly-enabled group is genuinely neither on nor off.
	if !strings.Contains(body, `'mixed'`) {
		t.Error(`no "mixed" group state — a half-disabled group would claim to be fully on or off`)
	}

	// Colour must come from tokens: a literal rgba here is dark-tuned and
	// near-invisible in Day.
	css := readWizardAsset(t, "../../cmd/api/static/css/admin-ipsec.css")
	states := regexp.MustCompile(`(?s)\.ipsec-path\[aria-pressed="(?:true|false)"\]\s*\{(.*?)\}`).FindAllStringSubmatch(css, -1)
	if len(states) < 2 {
		t.Fatal("expected both aria-pressed state rules for .ipsec-path")
	}
	for _, st := range states {
		if regexp.MustCompile(`rgba?\(`).MatchString(st[1]) {
			t.Errorf("a path state rule uses a literal rgba: %q. Use a --fwmon-* token or a "+
				"color-mix over one, or it will be near-invisible in the Day theme.", strings.TrimSpace(st[1]))
		}
	}
}

// FortiOS policies are interface-scoped by construction — a body with
// "srcintf": [] is rejected outright — so the port genuinely has to be named in
// the config. That is not a reason to make a human work out WHICH port.
func TestIPSecWizard_InsidePortsDeriveFromSubnets(t *testing.T) {
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	if !strings.Contains(js, "function autoTickLANFromSubnets") {
		t.Fatal("no derivation of inside ports from the protected subnets — the operator is " +
			"left to match interface addressing against subnets by eye")
	}

	fn := regexp.MustCompile(`(?s)function autoTickLANFromSubnets\(pfx\) \{(.*?)\n    \}`).FindStringSubmatch(js)
	if fn == nil {
		t.Fatal("autoTickLANFromSubnets() body not found")
	}
	// ADD only: a port may carry a subnet routed downstream of it, invisible to
	// the address table, so unticking on the wizard's authority deletes a
	// correct manual choice.
	if regexp.MustCompile(`\.checked\s*=\s*false`).MatchString(fn[1]) {
		t.Error("the derivation unticks boxes; it must only ever ADD")
	}
	if !strings.Contains(fn[1], "lanUnticked[pfx][cb.value]") {
		t.Error("the derivation ignores explicitly unticked ports — it would re-tick them " +
			"on every keystroke and make the control unusable")
	}
	if !strings.Contains(fn[1], "uses_lan_iface === false") {
		t.Error("the derivation does not exempt vendors that never name an interface")
	}

	// Bound to the textarea, never the form: a restore sets .value
	// programmatically and fires no input event, which is what stops a saved
	// tunnel's port selection being rewritten just by being reopened.
	bind := regexp.MustCompile(`(?s)sb\.addEventListener\('input',\s*function\s*\(\)\s*\{(.*?)\}\);`).FindStringSubmatch(js)
	if bind == nil {
		t.Error("subnet-driven derivation is not bound to the subnets textarea's input event")
	} else if !strings.Contains(bind[1], "autoTickLANFromSubnets(pfx)") {
		t.Error("the subnets textarea's input handler no longer derives the inside ports")
	}
}

// The selective-path rules that survive the redesign.
func TestIPSecWizard_SelectivePathRules(t *testing.T) {
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	// Keys must mirror the server: canonical, so reformatting a subnet keeps a
	// path disabled rather than quietly re-enabling it.
	if !strings.Contains(js, "function canonNet") || !strings.Contains(js, "function pathKey") {
		t.Error("no canonical path-key construction — a raw key would fail OPEN when the " +
			"operator reformats a subnet, silently re-enabling a path they switched off")
	}

	// The count must never claim more children than the device will hold.
	if !strings.Contains(js, "childCount: on") {
		t.Error("childCount is not restricted to ENABLED lanes; the caption would overstate " +
			"what the device holds")
	}

	// Route-based negotiates one 0.0.0.0/0 selector; a per-path control there
	// would do nothing on the device.
	paths := regexp.MustCompile(`(?s)function renderPaths\(\)\s*\{(.*?)\n    \}`).FindStringSubmatch(js)
	if paths == nil {
		t.Fatal("renderPaths() not found")
	}
	if !strings.Contains(paths[1], "if (m.routed)") {
		t.Error("renderPaths does not special-case route-based mode, so it would offer " +
			"per-path toggles against a device that holds ONE 0.0.0.0/0 selector")
	}

	// The selection has to reach the server.
	if !strings.Contains(js, "disabled_paths: Object.keys(disabledPaths)") {
		t.Error("the disabled paths are never sent — the wizard would show a path as off " +
			"while the device carries it")
	}
}

// Nothing may vanish. Disabled paths must stay put and remain clickable, so the
// wizard must not delete a subnet — and with it, its rows — once every path
// using it is off.
func TestIPSecWizard_NothingIsRemovedWhenPathsAreDisabled(t *testing.T) {
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	if strings.Contains(js, "pruneFullyDisabledSubnets") {
		t.Error("the auto-removal is back. Turning off the last path for a subnet must not " +
			"delete the subnet, or its rows disappear and cannot be clicked back on — " +
			"which is exactly what the operator asked to stop happening.")
	}
	if strings.Contains(js, "lanAutoTicked") {
		t.Error("lanAutoTicked survives; it existed only to let the removed propagation " +
			"release ports it had ticked itself")
	}
}
