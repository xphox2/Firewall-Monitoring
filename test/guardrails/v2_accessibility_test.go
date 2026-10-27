package guardrails

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The V2 console was written without a design system and without an
// accessibility pass. The audit found:
//
//   - 71 `<label>` elements with no `htmlFor` that did not wrap their
//     control, and 103 more that used a `<span>` as a pseudo-label. Every
//     one of those was announced with no idea what it labelled.
//   - 15 async error surfaces with no `role="alert"`, so a failed load was
//     invisible to a screen reader.
//   - a table sort that was an `onClick` on the `<th>`: mouse-only, with no
//     accessible name and no sort state.
//   - a hand-rolled mobile navigation drawer with no `role="dialog"`, no
//     `aria-modal`, no focus trap, no Escape and no scroll lock.
//   - tab strips with `role="tablist"` but no `role="tabpanel"`, no
//     `aria-controls` and no arrow-key handling.
//   - a topology map with sixteen hardcoded dark-theme colours that never
//     restyled when the theme changed.
//
// The tests below pin the fixes so they cannot come back.

// v2SourceFiles returns every V2 source file, relative to ui-v2/src.
func v2SourceFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	root := v2Src
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".tsx") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk the V2 sources: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no V2 source files were found — the guardrail would pass on nothing")
	}
	return out
}

// stripComments removes the JSX and line comments from a source file.
//
// Without it the checks match their own documentation: a comment that says
// "a wrapping <label> does not name a <button>" reads as an orphaned
// label, and a comment that names a control satisfies a control check.
func stripComments(src string) string {
	// The block comments: {/* ... */}
	out := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, " ")
	// The line comments. A `//` inside a string is rare enough in this
	// codebase that the simple form is safe, and the damage from a false
	// strip is a missed match, not a false failure.
	out = regexp.MustCompile(`(?m)//[^\n]*`).ReplaceAllString(out, " ")
	return out
}

// The patterns, compiled once. They were compiled inside the per-file loop
// before, which made the whole guardrail take 51 seconds under the race
// detector — and the race suite runs on every CI job.
var (
	reLabelOpen    = regexp.MustCompile(`<label[\s>]`)
	reLabelClose   = regexp.MustCompile(`</label>`)
	reLabelWithFor = regexp.MustCompile(`<label[^>]*htmlFor=`)
	reAnyControl   = regexp.MustCompile(`(?i)<(input|select|textarea|button)\b`)
	reLabelText    = regexp.MustCompile(`<span[^>]*className="[^"]*mb-1 block text-xs font-medium text-text-dim`)
	reControl      = regexp.MustCompile(`(?i)<(input|select|textarea)\b`)
	reHardColour   = regexp.MustCompile(`color: '#[0-9A-Fa-f]{6}'`)
)

// labelBalance answers "is this position inside an unclosed <label>?" for
// every position of a file at once.
//
// The naive form — recount the opens and closes before each position — is
// quadratic, and under the race detector it took the guardrail package from
// three seconds to fifty-two. CI runs the race suite on every job, so the
// positions are collected once and the balance is a binary search.
type labelBalance struct {
	opens  []int
	closes []int
}

// balanceAt returns the label nesting depth at a position: positive inside
// an open <label>, zero outside one.
func (b labelBalance) balanceAt(pos int) int {
	opens := sort.SearchInts(b.opens, pos)
	closes := sort.SearchInts(b.closes, pos)
	return opens - closes
}

// newLabelBalance collects the <label> and </label> positions of a source.
func newLabelBalance(src string) labelBalance {
	var b labelBalance
	for _, m := range reLabelOpen.FindAllStringIndex(src, -1) {
		b.opens = append(b.opens, m[0])
	}
	for _, m := range reLabelClose.FindAllStringIndex(src, -1) {
		b.closes = append(b.closes, m[0])
	}
	return b
}

// alertOnContainingElement reports whether the element that contains the
// text at pos carries role="alert" — or, one level out, its parent.
//
// The search is for the nearest opening tag above the text, because the
// message is usually the only content of the element that carries the
// role. A sibling's role does not count: it would announce the wrong
// thing.
func alertOnContainingElement(src string, pos int) bool {
	head := src[:pos]
	checked := 0
	for checked < 3 {
		i := strings.LastIndex(head, "<")
		if i < 0 {
			return false
		}
		// A closing tag is not a container.
		if strings.HasPrefix(head[i:], "</") {
			head = head[:i]
			continue
		}
		tagEnd := strings.Index(head[i:], ">")
		if tagEnd < 0 {
			return false
		}
		tag := head[i : i+tagEnd]
		// A self-closing element cannot contain the text, so it is not a
		// level — it is simply skipped.
		if !strings.HasSuffix(strings.TrimSpace(tag), "/>") {
			checked++
			if strings.Contains(tag, `role="alert"`) {
				return true
			}
		}
		head = head[:i]
	}
	return false
}

// TestV2EveryLabelIsAssociated pins that every `<label>` in the console is
// associated with its control.
//
// A label is associated if it carries an `htmlFor`, or if it WRAPS the
// control — the implicit association, which needs no id and therefore cannot
// collide. A `<label>` that does neither is announced as a bare string, and
// the control it belongs to is announced with no name.
//
// The `<span>` pseudo-label is the same bug wearing a different hat: a span
// is not a label at all, so it never associates with anything.
func TestV2EveryLabelIsAssociated(t *testing.T) {
	for _, rel := range v2SourceFiles(t) {
		src := stripComments(readV2(t, rel))
		for _, m := range reLabelOpen.FindAllStringIndex(src, -1) {
			// The tag's own attributes.
			tagEnd := strings.Index(src[m[0]:], ">")
			if tagEnd < 0 {
				continue
			}
			tag := src[m[0] : m[0]+tagEnd]
			if reLabelWithFor.MatchString(tag) {
				continue
			}
			// The body, up to the matching </label>.
			bodyStart := m[0] + tagEnd + 1
			closeIdx := strings.Index(src[bodyStart:], "</label>")
			if closeIdx < 0 {
				continue
			}
			body := src[bodyStart : bodyStart+closeIdx]
			if reAnyControl.MatchString(body) {
				continue
			}
			// `field.tsx` is the primitive: its <label> wraps {children}.
			if strings.HasSuffix(rel, filepath.Join("components", "ui", "field.tsx")) {
				continue
			}
			line := strings.Count(src[:m[0]], "\n") + 1
			t.Errorf("%s:%d has a <label> with no htmlFor that does not wrap its control — a screen reader announces the text and the control with no name", rel, line)
		}
	}
}

// TestV2NoSpanPseudoLabels pins that a `<span>` is not used as a label.
//
// The console used a `<span>` with the label's class string beside a
// control. A span is not a label, so it never associates with anything:
// the control was announced with no name at all.
func TestV2NoSpanPseudoLabels(t *testing.T) {
	// The label text class. A <span> carrying it is a pseudo-label.
	for _, rel := range v2SourceFiles(t) {
		src := stripComments(readV2(t, rel))
		balance := newLabelBalance(src)
		for _, m := range reLabelText.FindAllStringIndex(src, -1) {
			// A span inside a label is not an orphan: the label wraps the
			// control and associates it.
			if balance.balanceAt(m[0]) > 0 {
				continue
			}
			// The next control within a short window.
			window := src[m[1]:]
			if len(window) > 600 {
				window = window[:600]
			}
			if !reControl.MatchString(window) {
				continue
			}
			line := strings.Count(src[:m[0]], "\n") + 1
			t.Errorf("%s:%d uses a <span> with the label class beside a control — a span is not a label, so the control has no accessible name", rel, line)
		}
	}
}

// TestV2EveryLoadFailureIsAnnounced pins that an async load failure is
// announced.
//
// A failed load replaced the content with a "Could not load …" block. It
// was invisible to a screen reader: the operator had no way to know the
// data was missing, only that the panel was blank.
func TestV2EveryLoadFailureIsAnnounced(t *testing.T) {
	failure := regexp.MustCompile(`Could not load`)
	for _, rel := range v2SourceFiles(t) {
		src := stripComments(readV2(t, rel))
		for _, m := range failure.FindAllStringIndex(src, -1) {
			// The role has to be on the element that CONTAINS the message.
			// A window search would accept a sibling's role, which would
			// announce the wrong thing.
			if alertOnContainingElement(src, m[0]) {
				continue
			}
			line := strings.Count(src[:m[0]], "\n") + 1
			t.Errorf("%s:%d has a load failure whose element carries no role=\"alert\" — the message is invisible to a screen reader", rel, line)
		}
	}
}

// TestV2TheTableSortIsOperable pins the sort.
//
// The sort used to be an `onClick` on the `<th>`: it could not be reached
// with the keyboard, it had no accessible name, and the sort state was not
// exposed at all. It is now a real button inside a `<th scope="col">`, and
// the header carries `aria-sort`.
func TestV2TheTableSortIsOperable(t *testing.T) {
	view := stripComments(readV2(t, "components/ui/responsive-data-view.tsx"))
	for _, needle := range []string{
		`aria-sort=`,
		`scope="col"`,
		`getToggleSortingHandler()`,
	} {
		if !strings.Contains(view, needle) {
			t.Errorf("responsive-data-view.tsx is missing %q — the table sort has to be a real button inside a <th scope=\"col\">, with the sort state on the header", needle)
		}
	}
	// The sort handler has to be on a BUTTON, not on the header cell.
	buttonOpen := regexp.MustCompile(`<button[^>]*onClick=\{header\.column\.getToggleSortingHandler\(\)\}`)
	if !buttonOpen.MatchString(view) {
		t.Error("responsive-data-view.tsx does not put the sort handler on a <button> — the sort was mouse-only")
	}
	// And the mobile card rows have to be reachable with the keyboard.
	if !strings.Contains(view, "tabIndex={onRowClick ? 0 : undefined}") {
		t.Error("responsive-data-view.tsx does not make the mobile card rows focusable — they were mouse-only")
	}
	if !strings.Contains(view, "event.key === 'Enter'") {
		t.Error("responsive-data-view.tsx does not handle Enter on the mobile card rows — they were mouse-only")
	}
}

// TestV2TheMobileDrawerIsADialog pins that the mobile navigation uses the
// shared drawer.
//
// It was hand-rolled: no `role="dialog"`, no `aria-modal`, no focus trap,
// no Escape and no scroll lock — so the page behind it stayed scrollable
// and the keyboard walked straight out of the menu.
func TestV2TheMobileDrawerIsADialog(t *testing.T) {
	shell := stripComments(readV2(t, "components/layout/AppShell.tsx"))
	if !strings.Contains(shell, "<SlideOverDrawer") {
		t.Error("AppShell.tsx does not use the shared SlideOverDrawer for the mobile navigation — the hand-rolled drawer had no focus trap, no Escape and no scroll lock")
	}
	// The hand-rolled shape is gone.
	for _, needle := range []string{
		"fixed inset-0 z-50 lg:hidden flex",
	} {
		if strings.Contains(shell, needle) {
			t.Errorf("AppShell.tsx still contains the hand-rolled mobile drawer (%q) — it has no role=\"dialog\", no focus trap and no Escape", needle)
		}
	}
	// And the drawer itself is a Radix dialog.
	drawer := stripComments(readV2(t, "components/ui/slide-over-drawer.tsx"))
	for _, needle := range []string{"Dialog.Content", "Dialog.Title"} {
		if !strings.Contains(drawer, needle) {
			t.Errorf("slide-over-drawer.tsx is missing %q — the drawer must be a Radix dialog for the focus trap and the Escape handling to work", needle)
		}
	}
}

// TestV2TheTabStripsAreRealTabs pins the tab strips.
//
// They carried `role="tablist"` and `role="tab"` but no `role="tabpanel"`,
// no `aria-controls` and no arrow-key handling: the strip could only be
// reached with the mouse.
func TestV2TheTabStripsAreRealTabs(t *testing.T) {
	drawer := stripComments(readV2(t, "components/ui/slide-over-drawer.tsx"))
	for _, needle := range []string{
		`'tabpanel'`,
		"aria-controls=",
		"tabIndex={isActive ? 0 : -1}",
		"ArrowRight",
		"ArrowLeft",
		"Home",
		"End",
	} {
		if !strings.Contains(drawer, needle) {
			t.Errorf("slide-over-drawer.tsx is missing %q — the tab strip needs the panel role, the wiring, the roving tabindex and the arrow keys", needle)
		}
	}
}

// TestV2TheFocusRingSurvives pins the focus indicator.
//
// Safari draws NO focus ring on a `<button>` or an `<input>` unless the
// author provides one, so a keyboard user in Safari had no way to see where
// the focus was.
//
// The subtlety: `focus:outline-hidden` sets `--tw-outline-style: none`, and
// `focus-visible:outline-2` reads that variable — so the two together
// cancel out and the ring never appears. The `focus-visible:outline-solid`
// is what makes it work, and it has to be there.
func TestV2TheFocusRingSurvives(t *testing.T) {
	// The shared primitives carry the ring explicitly.
	for _, f := range []string{
		"components/ui/button.tsx",
		"components/ui/input.tsx",
	} {
		src := readV2(t, f)
		if !strings.Contains(src, "focus-visible:outline-") {
			t.Errorf("%s has no focus-visible ring — Safari draws no focus ring on a button or an input unless the author provides one", f)
		}
		if strings.Contains(src, "focus:outline-hidden") && !strings.Contains(src, "focus-visible:outline-solid") {
			t.Errorf("%s uses focus:outline-hidden without focus-visible:outline-solid — the hidden rule sets --tw-outline-style: none, which the focus-visible rule then reads, so the ring never appears", f)
		}
	}

	// And the global baseline, which is what gives the controls that were
	// NOT migrated a ring. Without it the console has controls with no
	// focus indicator at all.
	css := readV2(t, "styles/globals.css")
	if !strings.Contains(css, ":focus-visible") {
		t.Error("styles/globals.css has no :focus-visible rule — the controls that were not migrated onto the primitives would have no focus indicator, because Safari draws none for a button or an input")
	}

	// NO file may repeat the broken combination. The primitives are not
	// the only place a control carries these classes: a hand-written one
	// is exactly how the combination got back in.
	broken := regexp.MustCompile(`focus:outline-hidden[^"\x27]*focus-visible:outline-2`)
	solid := regexp.MustCompile(`focus-visible:outline-solid`)
	for _, rel := range v2SourceFiles(t) {
		src := stripComments(readV2(t, rel))
		for _, m := range broken.FindAllStringIndex(src, -1) {
			// The class string around the match. The window is BOUNDED:
			// an unbounded one ran past the end of the file and panicked.
			from := m[0] - 200
			if from < 0 {
				from = 0
			}
			to := m[1] + 200
			if to > len(src) {
				to = len(src)
			}
			window := src[from:to]
			if solid.MatchString(window) {
				continue
			}
			line := strings.Count(src[:m[0]], "\n") + 1
			t.Errorf("%s:%d combines focus:outline-hidden with focus-visible:outline-2 and no focus-visible:outline-solid — the hidden rule sets --tw-outline-style: none, which the focus-visible rule reads, so the ring never appears", rel, line)
		}
	}
}

// TestV2TheMapFollowsTheTheme pins the map's colours.
//
// The graph had sixteen hardcoded dark-theme colours and the Cytoscape
// instance was created ONCE, so in light mode it rendered dark-theme
// colours on a white card and never corrected itself.
func TestV2TheMapFollowsTheTheme(t *testing.T) {
	mapFile := stripComments(readV2(t, "components/topology/topology-map.tsx"))
	for _, needle := range []string{
		"mapStyle(",
		"readMapColours()",
		"cy.style(mapStyle(",
	} {
		if !strings.Contains(mapFile, needle) {
			t.Errorf("topology-map.tsx is missing %q — the graph's colours have to be resolved from the theme and re-applied when it changes", needle)
		}
	}
	// The stylesheet must read the resolved colours, not a literal.
	if !strings.Contains(mapFile, "'background-color': colours.siteBg") {
		t.Error("topology-map.tsx still hardcodes the site node's background colour — it is a dark-theme colour and renders wrong in light mode")
	}

	// The chart series colours come from the tokens.
	lib := stripComments(readV2(t, "lib/topology.ts"))
	if !strings.Contains(lib, "LinkPalette") {
		t.Error("lib/topology.ts has no LinkPalette — the link colours have to come from the theme")
	}
}

// TestV2TheChartsUseTheSeriesTokens pins the chart series colours.
//
// The theme defines eight series colours (`--fwmon-series-1..8`) for
// exactly this purpose, and the charts ignored them in favour of hardcoded
// hex, so a chart looked the same in both themes and the tokens were dead.
func TestV2TheChartsUseTheSeriesTokens(t *testing.T) {
	chart := readV2(t, "components/charts/time-series-chart.tsx")
	if !strings.Contains(chart, "resolveColour") {
		t.Error("time-series-chart.tsx does not resolve a CSS-variable colour — a series colour written as var(--fwmon-series-N) cannot be read by the canvas")
	}
	// No chart may still carry a hardcoded hex series colour.
	for _, rel := range v2SourceFiles(t) {
		src := stripComments(readV2(t, rel))
		for _, m := range reHardColour.FindAllStringIndex(src, -1) {
			line := strings.Count(src[:m[0]], "\n") + 1
			t.Errorf("%s:%d has a hardcoded chart colour — the theme has eight series tokens for exactly this", rel, line)
		}
	}
}
