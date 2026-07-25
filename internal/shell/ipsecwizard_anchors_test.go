package shell

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The IPSec wizard anchors each server finding next to the control that caused
// it, instead of dumping everything into one div at the bottom. That contract
// lives across three files — validation.go emits the code, admin-ipsec.js maps
// code to slot, admin.html provides the slot — and every way it can break is
// SILENT: the finding quietly falls back to the summary, which looks exactly
// like the old behaviour and is invisible to a browser walkthrough.
//
// These tests pin the two failure modes that produce no error anywhere.

// stripJSComments removes // line comments and /* */ blocks so a rule can search
// for a bad code pattern without tripping over the comment that warns about it.
func stripJSComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
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

func readWizardFiles(t *testing.T) (js, html string) {
	t.Helper()
	j, err := os.ReadFile("../../cmd/api/static/js/admin-ipsec.js")
	if err != nil {
		t.Fatalf("read admin-ipsec.js: %v", err)
	}
	h, err := os.ReadFile("../../web/admin/admin.html")
	if err != nil {
		t.Fatalf("read admin.html: %v", err)
	}
	return string(j), string(h)
}

// THE FALSY-ZERO TRAP. End A is index 0. `if (f.end)` is the natural thing to
// write and it drops every end-A finding — half of them, on the end that is
// usually the FortiGate — while end B keeps working, so the bug looks like "some
// findings don't anchor" rather than "the guard is wrong".
func TestIPSecWizard_EndGuardIsTypeofNotTruthiness(t *testing.T) {
	js, _ := readWizardFiles(t)

	// Both directions scan CODE, not comments: the positive check would otherwise
	// be satisfied by the comment that explains the rule, leaving the test green
	// with the guard deleted.
	code := stripJSComments(js)
	if !strings.Contains(code, "typeof f.end === 'number'") {
		t.Error("the end guard must be `typeof f.end === 'number'`: end A is 0, which is falsy, " +
			"so a truthiness check silently drops every end-A anchor")
	}
	// Catch a regression to any truthiness form on the same field. Comments are
	// stripped first: the code documents this exact trap by NAMING the bad form,
	// and matching that would fail the test for explaining itself.
	for _, bad := range []string{"if (f.end)", "f.end &&", "!f.end ", "f.end ?"} {
		if strings.Contains(code, bad) {
			t.Errorf("found truthiness test %q on f.end — end A is 0 and would be dropped", bad)
		}
	}
}

// THE SLOT CONTRACT. The JS builds an anchor id as "<a|b>-<slot>" and queries
// [data-anchor="..."]. A slot named in the map with no matching element in the
// markup means those findings silently fall through to the summary forever.
func TestIPSecWizard_EveryAnchorSlotExistsInMarkup(t *testing.T) {
	js, html := readWizardFiles(t)

	// Pull the slot names out of the ANCHOR map: `code: 'slot',`
	start := strings.Index(js, "var ANCHOR = {")
	if start < 0 {
		t.Fatal("ANCHOR map not found — the finding-to-field mapping is the whole feature")
	}
	end := strings.Index(js[start:], "};")
	if end < 0 {
		t.Fatal("ANCHOR map is not terminated")
	}
	body := js[start : start+end]

	slotRe := regexp.MustCompile(`:\s*'([a-z]+)'`)
	slots := map[string]bool{}
	for _, m := range slotRe.FindAllStringSubmatch(body, -1) {
		slots[m[1]] = true
	}
	if len(slots) == 0 {
		t.Fatal("no slots parsed out of the ANCHOR map")
	}

	// Scoped to the wizard form: the JS queries
	// `#ipsec-wizard-form .ipsec-anchor[data-anchor=...]`, so an element that
	// exists elsewhere on the page would satisfy a whole-file search while the
	// real lookup returns null and the finding falls through to the summary.
	form := wizardForm(t, html)

	var missing []string
	for slot := range slots {
		// 'psk' is tunnel-level and unprefixed; every other slot is per-end.
		ids := []string{"a-" + slot, "b-" + slot}
		if slot == "psk" {
			ids = []string{"psk"}
		}
		for _, id := range ids {
			if !strings.Contains(form, `data-anchor="`+id+`"`) {
				missing = append(missing, id)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("ANCHOR maps findings to slots with no [data-anchor] element inside #ipsec-wizard-form: %v\n"+
			"Those findings fall back to the summary silently — the UI looks fine and the "+
			"operator never sees them next to the field they must edit.", missing)
	}
}

// wizardForm returns the markup between <form id="ipsec-wizard-form"> and its
// closing tag, which is the subtree the JS actually queries.
func wizardForm(t *testing.T, html string) string {
	t.Helper()
	start := strings.Index(html, `<form id="ipsec-wizard-form"`)
	if start < 0 {
		t.Fatal(`<form id="ipsec-wizard-form"> not found — it is the invalidation backbone ` +
			`(form-level input/change bubbling) and every anchor lookup is scoped to it`)
	}
	end := strings.Index(html[start:], "</form>")
	if end < 0 {
		t.Fatal("wizard form is not closed")
	}
	return html[start : start+end]
}

// A mapped code that the server never emits is dead weight; the reverse — a real
// per-field code with no mapping — silently falls back to the summary, which is
// the behaviour this whole feature replaced. Codes drift as validation grows, so
// pin the direction that actually hurts: every code in the map must be real.
func TestIPSecWizard_EveryMappedCodeIsEmittedByTheServer(t *testing.T) {
	js, _ := readWizardFiles(t)
	v, err := os.ReadFile("../../internal/ipsec/validation.go")
	if err != nil {
		t.Fatalf("read validation.go: %v", err)
	}
	h, err := os.ReadFile("../../internal/api/handlers/handlers_ipsec.go")
	if err != nil {
		t.Fatalf("read handlers_ipsec.go: %v", err)
	}
	server := string(v) + string(h)

	start := strings.Index(js, "var ANCHOR = {")
	end := strings.Index(js[start:], "};")
	if start < 0 || end < 0 {
		t.Fatal("ANCHOR map not found")
	}
	body := stripJSComments(js[start : start+end])

	// Every `code: 'slot'` pair, not just the first on each line — the map packs
	// several entries per line, so an anchored `^\s*` regex silently checks about
	// a third of them.
	codeRe := regexp.MustCompile(`([a-z_]+)\s*:\s*'`)
	var dead []string
	for _, m := range codeRe.FindAllStringSubmatch(body, -1) {
		if !strings.Contains(server, `"`+m[1]+`"`) {
			dead = append(dead, m[1])
		}
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Errorf("ANCHOR maps codes the server never emits: %v\n"+
			"These entries are dead — and their presence disguises the fact that the real "+
			"code for that field is unmapped and falling through to the summary.", dead)
	}
}

// The server must actually send what the client anchors on. If Finding loses
// either field the whole mapping degrades to summary-only with nothing failing.
func TestIPSecWizard_FindingCarriesEndAndSubject(t *testing.T) {
	b, err := os.ReadFile("../../internal/ipsec/validation.go")
	if err != nil {
		t.Fatalf("read validation.go: %v", err)
	}
	src := string(b)

	// End must be a POINTER: a plain int makes "end A" (0) and "not set"
	// identical on the wire, which is the same falsy-zero trap one layer down.
	// Matched by regex because gofmt aligns struct fields, so the gap between the
	// name and the type is whatever the widest field in the block dictates.
	if !regexp.MustCompile(`\bEnd\s+\*int\b`).MatchString(src) {
		t.Error("Finding.End must be *int — a value int cannot distinguish end A (0) from unset")
	}
	if !strings.Contains(src, `json:"end,omitempty"`) {
		t.Error(`Finding.End must be tagged json:"end,omitempty"`)
	}
	if !strings.Contains(src, `json:"subject,omitempty"`) {
		t.Error("Finding.Subject must be on the wire: (code, end) alone cannot distinguish " +
			"two mismatches on the same end, so the UI could not tell which lane to paint")
	}
}
