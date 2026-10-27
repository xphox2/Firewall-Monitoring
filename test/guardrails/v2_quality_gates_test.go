package guardrails

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The V2 console's quality gates.
//
// Three things were true before this PR that should not be true again:
//
//   - **The vitest suite never ran on the server.** Every assertion in it
//     was checked locally and nowhere else, so a regression could land on
//     master and be green.
//   - **Every browser spec ran at the desktop width.** A page that broke
//     at the phone or tablet size was not noticed, and the mobile card
//     stack of thirteen tables was missing its actions entirely.
//   - **Nothing checked the console's contrast, its focus indicators or
//     its focus trap**.
//
// The tests below pin the gates themselves: a gate that has been quietly
// removed is worse than no gate, because it looks like one.

const (
	ciWorkflow  = ".github/workflows/ci.yml"
	uiV2Package = "ui-v2/package.json"
)

// TestV2TheWorkflowActionPinsAreWellFormed pins the action pins.
//
// The workflow pins every action to a commit SHA, which is right. But a
// mistyped SHA is a 39-character string that looks right in a diff and
// fails the whole job at "Set up job" — before a single step runs, with an
// error that says nothing about which line was wrong.
//
// So: every pin is a full 40-character SHA, and the same action always
// uses the same one.
func TestV2TheWorkflowActionPinsAreWellFormed(t *testing.T) {
	root, _ := hygieneRepoFiles(t)
	data, err := os.ReadFile(filepath.Join(root, ciWorkflow))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	uses := regexp.MustCompile(`uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@([0-9a-fA-F]+)`)
	seen := map[string]string{}
	for _, m := range uses.FindAllStringSubmatch(string(data), -1) {
		action, sha := m[1], m[2]
		if len(sha) != 40 {
			t.Errorf("%s pins %s to %q — that is %d characters, not a 40-character commit SHA, and the job will fail at 'Set up job' with an error that does not say which line is wrong", ciWorkflow, action, sha, len(sha))
		}
		if prev, ok := seen[action]; ok && prev != sha {
			t.Errorf("%s pins %s to two different SHAs (%s and %s) — one of them is wrong", ciWorkflow, action, prev, sha)
		}
		seen[action] = sha
	}
	if len(seen) == 0 {
		t.Error("the workflow pins no actions — the check is not reading the file")
	}
}

// TestV2TheUnitTestsRunInCI pins that the console's unit tests execute on
// the server.
func TestV2TheUnitTestsRunInCI(t *testing.T) {
	root, _ := hygieneRepoFiles(t)
	data, err := os.ReadFile(filepath.Join(root, ciWorkflow))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	ci := string(data)

	// The job has to RUN the suite, not merely mention it. The pattern is
	// anchored on the whole step, so `npm run test:e2e` — the browser job —
	// does not satisfy it.
	unitStep := regexp.MustCompile(`(?m)^\s*run: npm (run )?test\s*$`)
	if !unitStep.MatchString(ci) {
		t.Error("the CI workflow never runs the console's unit tests — every assertion in the vitest suite is checked locally and nowhere else")
	}
	// And the typecheck: the suite's imports are only checked by tsc.
	if !regexp.MustCompile(`(?m)^\s*run: npm run typecheck\s*$`).MatchString(ci) {
		t.Error("the CI workflow does not run the console's typecheck")
	}
	// The job has to be a MERGE GATE, so it must be on the pull-request
	// event rather than only on a push to master.
	if !strings.Contains(ci, "ui-v2-unit") {
		t.Error("the CI workflow has no ui-v2-unit job")
	}
}

// TestV2TheBrowserSuiteRunsAtThreeWidths pins the viewport matrix.
//
// Every browser spec used to run at the desktop width, so a page that
// broke at the phone or tablet size was not noticed — and thirteen tables'
// mobile cards were missing their row actions entirely.
func TestV2TheBrowserSuiteRunsAtThreeWidths(t *testing.T) {
	config := readRepoFile(t, "ui-v2/playwright.config.ts")
	for _, name := range []string{"mobile", "tablet", "desktop"} {
		if !strings.Contains(config, "name: '"+name+"'") {
			t.Errorf("the Playwright config has no %q project — a page that breaks at that width is not noticed", name)
		}
	}
	// The widths have to be the real ones, not placeholders.
	for _, width := range []string{"390", "820", "1440"} {
		if !strings.Contains(config, "width: "+width) {
			t.Errorf("the Playwright config has no %spx viewport", width)
		}
	}
}

// TestV2TheOverflowCheckExists pins the sideways-scroll spec.
//
// The console's shell is a fixed viewport with a scrollable content area,
// so the DOCUMENT must never scroll sideways. Without the check, a table
// that is wider than the phone is invisible to the gate.
func TestV2TheOverflowCheckExists(t *testing.T) {
	spec := readRepoFile(t, "ui-v2/e2e/responsive.spec.ts")
	// The check has to be on the GEOMETRY, not on the document's scroll
	// width: the shell sets `overflow-x: hidden` on html and body, so the
	// document never scrolls sideways however far the content reaches — an
	// assertion on `scrollWidth` passes on every page, whatever is hanging
	// off the edge.
	if !strings.Contains(spec, "getBoundingClientRect") {
		t.Error("the responsive spec does not measure the geometry — the document's scrollWidth is always equal to its clientWidth, because the shell clips the overflow, so an assertion on it passes on every page")
	}
	if !strings.Contains(spec, "overflowX") {
		t.Error("the responsive spec does not skip the intentionally scrollable strips — every wide table would be reported")
	}
	// And there has to be a self-test: a check that cannot fail is
	// decoration.
	if !strings.Contains(spec, "fwmon-overflow-probe") {
		t.Error("the responsive spec has no self-test — a check that cannot fail is decoration")
	}
}

// TestV2TheAccessibilityCheckExists pins the axe spec.
func TestV2TheAccessibilityCheckExists(t *testing.T) {
	spec := stripComments(readRepoFile(t, "ui-v2/e2e/accessibility.spec.ts"))
	if !strings.Contains(spec, "@axe-core/playwright") {
		t.Error("the accessibility spec does not use axe — the console's contrast, names and landmarks are not checked")
	}
	// The bar has to be serious and critical: a moderate finding is often a
	// deliberate choice, and failing the build on those would make the gate
	// something people route around.
	for _, needle := range []string{"serious", "critical"} {
		if !strings.Contains(spec, needle) {
			t.Errorf("the accessibility spec does not consider %q violations", needle)
		}
	}
	// And the dependency has to be declared, or `npm ci` on the server
	// cannot install it.
	pkg := readRepoFile(t, "ui-v2/package.json")
	if !strings.Contains(pkg, "@axe-core/playwright") {
		t.Error("ui-v2/package.json does not declare @axe-core/playwright — the CI install would not have it")
	}
}

// TestV2TheKeyboardSpecsExist pins the keyboard specs.
//
// The console is a NOC surface: an operator drives it from a keyboard with
// the console next to the screen. The drawer had no focus trap, the sort
// was mouse-only and the tab strips could not be reached with the arrow
// keys — none of which a typecheck or a unit test can see.
func TestV2TheKeyboardSpecsExist(t *testing.T) {
	spec := stripComments(readRepoFile(t, "ui-v2/e2e/keyboard.spec.ts"))
	for _, needle := range []string{
		"focus indicator", // a visible focus ring on every focused control
		"traps the focus", // the drawer's focus trap
		"Escape",          // Escape closes the drawer and the palette
		"aria-sort",       // the sort announces its state
	} {
		if !strings.Contains(spec, needle) {
			t.Errorf("the keyboard spec does not assert %q — the behaviour is not being checked", needle)
		}
	}
}

// TestV2TheMobileCardCarriesTheActions pins the structural fix.
//
// The shared data view renders both a mobile card stack and a desktop
// table, and CSS hides one of them. Thirteen tables had an actions column
// that the mobile card DID NOT — so on a phone an operator could not
// approve a collector, disable a user, reset a password, delete a flow or
// open a connection.
//
// The fix is structural: the actions and the selection column are rendered
// into the card FROM THE COLUMNS, so a table cannot forget them. A check
// that a table's card happens to carry the buttons would have to be
// written per table, and the next one would forget again.
func TestV2TheMobileCardCarriesTheActions(t *testing.T) {
	view := readV2(t, "components/ui/responsive-data-view.tsx")
	// The card renders the carried cells.
	if !strings.Contains(view, "getVisibleCells()") {
		t.Error("the shared data view does not read the row's cells — the mobile card cannot carry the actions column")
	}
	for _, column := range []string{"'actions'", "'select'"} {
		if !strings.Contains(view, "cell.column.id === "+column) {
			t.Errorf("the shared data view does not carry the %s column into the mobile card — a phone cannot operate the row", column)
		}
	}
	// And every table that HAS an actions column must have one with that
	// id, or the shared component cannot find it.
	columnsWithActions := 0
	for _, rel := range v2SourceFiles(t) {
		src := readV2(t, rel)
		if strings.Contains(src, "id: 'actions'") {
			columnsWithActions++
		}
	}
	if columnsWithActions == 0 {
		t.Error("no table has an actions column — the shared component cannot find one to carry")
	}
}

// TestV2TheContrastTokensExist pins the accent split.
//
// axe found two real contrast failures: white on the solid accent was
// 3.2:1 (WCAG AA wants 4.5:1 for text this size), and the accent as text
// on an accent-tinted background was 3.5:1. Both are fixed by splitting
// the accent into a solid background, a label on it, and a text colour for
// the tinted chips.
func TestV2TheContrastTokensExist(t *testing.T) {
	css := readV2(t, "styles/globals.css")
	for _, token := range []string{
		"--fwmon-on-accent",   // the label on a solid accent
		"--fwmon-accent-text", // the accent as text on a tinted background
		"--color-on-accent",   // the Tailwind alias
		"--color-accent-text", // the Tailwind alias
	} {
		if !strings.Contains(css, token) {
			t.Errorf("styles/globals.css has no %s — the accent's contrast failures are back", token)
		}
	}
	// And every theme has to define them, or one theme falls back to the
	// other's value.
	lightAt := strings.Index(css, ":root[data-theme=\"light\"]")
	if lightAt < 0 {
		t.Fatal("styles/globals.css has no light theme block — the tokens cannot be per-theme")
	}
	// The DARK theme's label on the solid accent must be the DARK one: the
	// original was white, which is 3.2:1 against the accent and fails AA.
	dark := css[:lightAt]
	if strings.Contains(dark, "--fwmon-on-accent: #ffffff;") {
		t.Error("the dark theme's label on the solid accent is white — white on the accent is 3.2:1, below the 4.5:1 that WCAG AA requires")
	}
	// And the LIGHT theme's label must be white: its accent is dark.
	light := css[lightAt:]
	if !strings.Contains(light, "--fwmon-on-accent: #ffffff;") {
		t.Error("the light theme's label on the solid accent is not white — the light accent is dark, so the label has to be light")
	}
}

// TestV2TheSortAnnouncesItsState pins the aria-sort.
//
// It was only present on a column that was ALREADY the sorted one, so a
// screen reader could not hear that a column could be sorted at all. The
// ARIA spec asks for aria-sort on every sortable header.
func TestV2TheSortAnnouncesItsState(t *testing.T) {
	view := readV2(t, "components/ui/responsive-data-view.tsx")
	if !strings.Contains(view, "aria-sort") {
		t.Error("the shared data view has no aria-sort — the sort state is not announced")
	}
	// "none" for a sortable column that is not the sorted one.
	if !regexp.MustCompile(`'none'`).MatchString(view) {
		t.Error("the shared data view does not mark an unsorted sortable column with aria-sort=\"none\" — a screen reader cannot hear that the column can be sorted")
	}
}
