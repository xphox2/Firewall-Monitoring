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
