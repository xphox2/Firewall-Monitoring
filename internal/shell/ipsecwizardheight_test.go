package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The IPSec wizard's schematic is FIXED chrome — it never scrolls away — while
// the form below it is the only scrolling region. That is fine until the
// schematic grows, and it grows with the configuration it describes: one lane
// per subnet pair, so two subnets a side is four lanes, three a side is nine.
//
// Measured at 1440x800 with two subnets a side, before the fix: the head took
// 379px of a 680px dialog (56%), leaving the form a 190px window onto 614px of
// content. The wizard was effectively unusable at laptop height — the operator
// could not reach the fields they had opened it to fill in.
//
// Two independent protections, because either alone leaves a hole: the lane
// list is CAPPED (bounds the pathological case even when expanded), and the
// whole diagram is COLLAPSIBLE (lets the operator reclaim the space outright,
// and is the default where the viewport cannot afford it).

func readWizardAsset(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// The lane list must not be free to grow without limit inside chrome that never
// shrinks. Without a cap, enough subnet pairs push the form off screen entirely.
func TestIPSecWizard_LaneListIsHeightCapped(t *testing.T) {
	css := readWizardAsset(t, "../../cmd/api/static/css/admin-ipsec.css")

	block := regexp.MustCompile(`(?s)\.ipsec-lanes\s*\{(.*?)\}`).FindStringSubmatch(css)
	if block == nil {
		t.Fatal(".ipsec-lanes rule not found — the schematic's lane list must keep a bounded height")
	}
	body := block[1]

	if !strings.Contains(body, "max-height") {
		t.Error(".ipsec-lanes has no max-height. One lane per subnet pair, in chrome that " +
			"never shrinks, means a large tunnel squeezes the form until it cannot be " +
			"filled in: at 1440x800 with two subnets a side the form got 190px of 614px.")
	}
	// A cap with no way to reach the overflowed rows just hides configuration.
	if !strings.Contains(body, "overflow-y: auto") && !strings.Contains(body, "overflow: auto") {
		t.Error(".ipsec-lanes is capped but not scrollable — lanes beyond the cap would be " +
			"silently unreachable, which is worse than the crowding it fixes")
	}
}

// The pair count must live OUTSIDE the scrolling lane list, or scrolling the
// lanes hides how many there are in total — the one number that says whether
// the tunnel is what the operator intended.
func TestIPSecWizard_PairCountIsOutsideTheScrollingList(t *testing.T) {
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	// The count must not be concatenated INTO the lanes markup.
	if regexp.MustCompile(`lanes\s*\+=\s*'<div class="ipsec-lane-count"`).MatchString(js) {
		t.Error("the lane count is appended into the lanes string, so it renders INSIDE " +
			"the scrolling .ipsec-lanes box and scrolls out of view with the rows it counts")
	}
	if !strings.Contains(js, `'<div class="ipsec-lanes">' + lanes + '</div>' + laneCount`) {
		t.Error("expected the lane count to be emitted as a SIBLING of .ipsec-lanes so it " +
			"stays visible however the list is scrolled")
	}
}

// The diagram must be collapsible, and collapsing must not hide that there is
// anything to look at.
func TestIPSecWizard_DiagramCanBeCollapsed(t *testing.T) {
	html := readWizardAsset(t, "../../web/admin/admin.html")
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")
	css := readWizardAsset(t, "../../cmd/api/static/css/admin-ipsec.css")

	if !strings.Contains(html, `data-action="ipsec-schematic-toggle"`) {
		t.Error("no schematic collapse control in the wizard markup")
	}
	// renderSchematic() replaces #ipsec-schematic's innerHTML on every edit, so a
	// toggle nested inside it would be destroyed as the operator types.
	schematic := regexp.MustCompile(`(?s)<div id="ipsec-schematic".*?</div>`).FindString(html)
	if strings.Contains(schematic, "ipsec-schematic-toggle") {
		t.Error("the collapse control is inside #ipsec-schematic, whose innerHTML is " +
			"rewritten on every keystroke — the button would vanish mid-edit")
	}
	if !strings.Contains(js, `'ipsec-schematic-toggle': function`) {
		t.Error("the collapse control is not wired to any handler")
	}
	if !strings.Contains(css, ".ipsec-wiz.schematic-collapsed .ipsec-schematic") {
		t.Error("no CSS rule actually hides the schematic when collapsed")
	}
	// Collapsed, the button carries the pair count — otherwise hiding the
	// diagram also hides that the tunnel has lanes worth checking.
	if !strings.Contains(js, "'Show diagram'") || !strings.Contains(js, "pair") {
		t.Error("the collapsed label should still report the pair count, so collapsing " +
			"never conceals that there is configuration to review")
	}
}

// An explicit choice must outrank the viewport-derived default in BOTH
// directions. If the stored value were read as a bare truthiness check, an
// operator who deliberately expanded the diagram on a laptop would find it
// collapsed again on the next open.
func TestIPSecWizard_StoredChoiceBeatsViewportDefault(t *testing.T) {
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	fn := regexp.MustCompile(`(?s)function schematicHidden\(\)\s*\{(.*?)\n    \}`).FindStringSubmatch(js)
	if fn == nil {
		t.Fatal("schematicHidden() not found")
	}
	body := fn[1]

	if !strings.Contains(body, `=== '1'`) || !strings.Contains(body, `=== '0'`) {
		t.Error("schematicHidden() must honour BOTH stored states explicitly. Checking only " +
			"the hidden case makes a deliberate 'keep it open' indistinguishable from " +
			"'never chose', so the viewport default silently overrides the operator.")
	}
	if !strings.Contains(body, "window.innerHeight") {
		t.Error("no viewport-derived default — the wizard would open unusable at laptop " +
			"height for anyone who has not found the toggle")
	}
}

// FortiOS policies are interface-scoped by construction — a body with
// "srcintf": [] is rejected outright — so the port genuinely has to be named in
// the config. That is not a reason to make a human work out WHICH port: the
// wizard already holds every interface's networks and the protected subnets,
// and prints them side by side. Matching them by eye is redoing arithmetic the
// page has already done, and getting it wrong is silent — the tunnel comes up
// and traffic for the unnamed port is dropped.
func TestIPSecWizard_InsidePortsDeriveFromSubnets(t *testing.T) {
	js := readWizardAsset(t, "../../cmd/api/static/js/admin-ipsec.js")

	if !strings.Contains(js, "function autoTickLANFromSubnets") {
		t.Fatal("no derivation of inside ports from the protected subnets — the operator is " +
			"left to match interface addressing against subnets by eye")
	}

	// ADD only. A port may carry a subnet routed downstream of it, which no
	// address table can show, so unticking on the wizard's own authority would
	// delete a correct choice the operator made deliberately.
	fn := regexp.MustCompile(`(?s)function autoTickLANFromSubnets\(pfx\) \{(.*?)\n    \}`).FindStringSubmatch(js)
	if fn == nil {
		t.Fatal("autoTickLANFromSubnets() body not found")
	}
	if regexp.MustCompile(`\.checked\s*=\s*false`).MatchString(fn[1]) {
		t.Error("the derivation unticks boxes. It must only ever ADD: a subnet routed " +
			"downstream of a port is invisible to the address table, so an untick here " +
			"silently discards a correct manual selection.")
	}

	// A deliberate untick must survive the next keystroke.
	if !strings.Contains(fn[1], "lanUnticked[pfx][cb.value]") {
		t.Error("the derivation ignores explicitly unticked ports — it would re-tick them " +
			"on every keystroke and make the control unusable")
	}

	// Bound to the textarea, never the form: a restore sets .value
	// programmatically and fires no input event, so binding here is what stops a
	// saved tunnel's port selection being rewritten just by being reopened.
	//
	// Matched structurally rather than as one exact line — the handler has since
	// grown a second call, and a literal pin would fail on a change that keeps
	// the property intact.
	bind := regexp.MustCompile(`(?s)sb\.addEventListener\('input',\s*function\s*\(\)\s*\{(.*?)\}\);`).FindStringSubmatch(js)
	if bind == nil {
		t.Error("subnet-driven derivation is not bound to the subnets textarea's input event")
	} else if !strings.Contains(bind[1], "autoTickLANFromSubnets(pfx)") {
		t.Error("the subnets textarea's input handler no longer derives the inside ports")
	}

	// Vendors whose rules name no interface must be left alone.
	if !strings.Contains(fn[1], "uses_lan_iface === false") {
		t.Error("the derivation does not exempt vendors that never name an interface " +
			"(OPNsense's rules are floating and subnet-scoped) — it would tick a control " +
			"that vendor does not even show")
	}
}

// Selective subnet paths: the wizard's own rules, which the Go tests cannot see.
//
// The tunnel otherwise carries the full cross product of both ends' subnets, so
// switching a path off is a security control. These pin the parts where getting
// it wrong is silent.
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
			"what the device holds — the UI-lies-about-the-device failure this area exists to avoid")
	}

	// Route-based negotiates one 0.0.0.0/0 selector; a per-path control there
	// would do nothing on the device.
	if !strings.Contains(js, "var tog = m.routed ? ''") {
		t.Error("per-path toggles are not suppressed in route-based mode")
	}

	// Propagation must only ever release a port the wizard itself ticked.
	prune := regexp.MustCompile(`(?s)function pruneFullyDisabledSubnets\(\)\s*\{(.*?)\n    \}`).FindStringSubmatch(js)
	if prune == nil {
		t.Fatal("pruneFullyDisabledSubnets() not found")
	}
	// Pin the GUARD, not merely a mention. The function also DELETEs from
	// lanAutoTicked, so a substring check anywhere in the body passes even with
	// the guard removed — the exact way a test can look green while the
	// protection is gone.
	guard := regexp.MustCompile(`if \(!cb\.checked \|\|([^)]*)\) \{ return; \}`).FindStringSubmatch(prune[1])
	if guard == nil {
		t.Fatal("the untick guard in pruneFullyDisabledSubnets() is not in the expected shape")
	}
	if !strings.Contains(guard[1], "lanAutoTicked") {
		t.Error("the untick guard does not consult lanAutoTicked — propagation could untick " +
			"a port the operator chose by hand, which may serve a subnet routed downstream " +
			"of it that no address table can show")
	}
	if !strings.Contains(guard[1], "still[cb.value]") {
		t.Error("the untick guard does not check whether another live subnet still needs the " +
			"port; autoTickLANFromSubnets would tick it straight back on the next keystroke")
	}
	// Dispatching change here would record the wizard's own untick as the
	// operator's and permanently suppress auto-ticking for that port.
	if regexp.MustCompile(`cb\.checked = false;\s*\n\s*cb\.dispatchEvent`).MatchString(prune[1]) {
		t.Error("propagation dispatches a change event when unticking, which records it as " +
			"an OPERATOR untick and suppresses future auto-ticking for that port")
	}

	// The selection has to reach the server.
	if !strings.Contains(js, "disabled_paths: Object.keys(disabledPaths)") {
		t.Error("the disabled paths are never sent — the wizard would show a path as off " +
			"while the device carries it")
	}
}
