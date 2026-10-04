package guardrails

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestVendorDefaultGuard keeps "no vendor means FortiGate" from coming back.
//
// Until 0.11.289 an empty device vendor was silently FortiGate in six places
// (the model's column default, the create handler, the deny projection, the
// SNMP resolver, a startup UPDATE …) and each one drifted on its own. Since
// 0.11.290 an empty or unknown vendor is "generic" everywhere, resolved by
// handlers.deviceVendor. This test walks every tracked non-test Go file plus
// the admin JS/HTML and fails on a line that assigns, defaults to, or falls
// back to "fortigate" for a vendor. A vendor COMPARISON (`vendor ==
// "fortigate"`, `case "fortigate":`) is dispatch, not a default, and is not
// matched.
//
// Exceptions go in vendorDefaultAllow keyed by file and the exact trimmed
// line, each with a reason; an entry no line uses any more fails the test so
// the list cannot outlive the code it excuses.
var vendorDefaultPatterns = []*regexp.Regexp{
	// vendor := "fortigate" / vendor = "fortigate" / device.Vendor = "fortigate"
	regexp.MustCompile(`(?i)vendor\s*:?=\s*"fortigate"`),
	// gorm:"default:fortigate"
	regexp.MustCompile(`default:fortigate`),
	// case "fortigate", "": / case "", "fortigate": — "" sharing the FortiGate arm
	regexp.MustCompile(`case\s+"fortigate"\s*,\s*""`),
	regexp.MustCompile(`case\s+""\s*,\s*"fortigate"`),
	// JS: d.vendor || 'fortigate'
	regexp.MustCompile(`(?i)vendor[^|\n]*\|\|\s*['"]fortigate['"]`),
	// HTML: the device form's pre-selected vendor
	regexp.MustCompile(`value="fortigate"\s+selected`),
}

// vendorDefaultAllow: file → exact trimmed line → reason.
var vendorDefaultAllow = map[string]map[string]string{
	"internal/api/handlers/handlers_event_rules.go": {
		`vendor = "fortigate" // the only extracting vendor today`: "rule-tester default; S-1c resolves each message's device vendor instead (drop this entry with that change)",
	},
}

func TestVendorDefaultGuard(t *testing.T) {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not inside a git work tree: %v", err)
	}
	root := strings.TrimSpace(string(top))
	cmd := exec.Command("git", "ls-files", "--full-name", "-z", "--", "*.go", "*.js", "*.html")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	used := map[string]map[string]bool{}
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" || strings.HasSuffix(f, "_test.go") || hygieneSkip[f] {
			continue
		}
		for _, hit := range vendorDefaultHits(t, filepath.Join(root, f)) {
			if reason := vendorDefaultAllow[f][hit.line]; reason != "" {
				if used[f] == nil {
					used[f] = map[string]bool{}
				}
				used[f][hit.line] = true
				continue
			}
			t.Errorf("%s:%d: %q defaults a vendor to FortiGate — an empty or unknown vendor is \"generic\" (handlers.deviceVendor); use that, or add the exact line to vendorDefaultAllow in vendor_default_guard_test.go with a reason", f, hit.n, hit.line)
		}
	}
	// The allowlist must stay as small as the tree needs.
	files := make([]string, 0, len(vendorDefaultAllow))
	for f := range vendorDefaultAllow {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		for line, reason := range vendorDefaultAllow[f] {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("vendorDefaultAllow[%q][%q] has no reason", f, line)
			}
			if !used[f][line] {
				t.Errorf("vendorDefaultAllow[%q][%q] matches no line any more — remove it", f, line)
			}
		}
	}
}

type vendorDefaultHit struct {
	n    int
	line string
}

// vendorDefaultHits returns the trimmed lines of path that match any
// vendorDefaultPatterns entry, with their 1-based line numbers.
func vendorDefaultHits(t *testing.T, path string) []vendorDefaultHit {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer fh.Close()
	var hits []vendorDefaultHit
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		for _, re := range vendorDefaultPatterns {
			if re.MatchString(line) {
				hits = append(hits, vendorDefaultHit{n, strings.TrimSpace(line)})
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return hits
}

// TestVendorDefaultGuard_Patterns pins what the guard does and does not
// match, so a future pattern edit cannot silently widen it onto dispatch
// arms or narrow it off the shapes it exists for.
func TestVendorDefaultGuard_Patterns(t *testing.T) {
	for _, tc := range []struct {
		line string
		hit  bool
	}{
		{`vendor := "fortigate"`, true},
		{`vendor = "fortigate" // comment`, true},
		{`device.Vendor = "fortigate"`, true},
		{`Vendor string ` + "`" + `json:"vendor" gorm:"default:fortigate"` + "`", true},
		{`case "fortigate", "":`, true},
		{`case "", "fortigate":`, true},
		{`var v = d.vendor || 'fortigate';`, true},
		{`<option value="fortigate" selected>FortiGate</option>`, true},
		{`vendor == "fortigate"`, false},
		{`return vendor == "fortigate" || vendor == "opnsense"`, false},
		{`case "fortigate":`, false},
		{`Vendor: "fortigate",`, false},
		{`vendor := "generic"`, false},
		{`if vendor === 'fortigate') {`, false},
	} {
		got := false
		for _, re := range vendorDefaultPatterns {
			if re.MatchString(tc.line) {
				got = true
				break
			}
		}
		if got != tc.hit {
			t.Errorf("%q: matched=%v, want %v", tc.line, got, tc.hit)
		}
	}
}
