package guardrails

import (
	"bufio"
	"os"
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
	// cmp.Or(vendor, "fortigate") — the stdlib way to spell a default
	regexp.MustCompile(`cmp\.Or\([^)]*"fortigate"`),
	// GetVendorProfile("fortigate") as a fallback (the registry lookup by a
	// literal; the FortiGate profile's own file registers, never looks up)
	regexp.MustCompile(`GetVendorProfile\("fortigate"\)`),
	// vendor == "" || vendor == "fortigate" — "" sharing the FortiGate branch
	regexp.MustCompile(`==\s*""\s*\|\|[^|]*==\s*"fortigate"`),
	// flag.String("vendor", "fortigate", …) — a CLI default
	regexp.MustCompile(`flag\.String\("vendor",\s*"fortigate"`),
	// JS: || 'fortigate' anywhere (d.vendor || 'fortigate', also after
	// toLowerCase()), ?? 'fortigate', cond ? 'fortigate' : … / cond ? … :
	// 'fortigate', and sel.value = 'fortigate'
	regexp.MustCompile(`\|\|\s*['"]fortigate['"]`),
	regexp.MustCompile(`\?\??\s*['"]fortigate['"]`),
	regexp.MustCompile(`\?[^?:\n]*:\s*['"]fortigate['"]`),
	regexp.MustCompile(`\.value\s*=\s*['"]fortigate['"]`),
	// HTML: the device form's pre-selected vendor
	regexp.MustCompile(`value="fortigate"\s+selected`),
}

// vendorDefaultAllow: file → exact trimmed line → reason.
var vendorDefaultAllow = map[string]map[string]string{
	"internal/api/handlers/handlers_event_rules.go": {
		`vendor = "fortigate" // the only extracting vendor today`: "rule-tester default; S-1c resolves each message's device vendor instead (drop this entry with that change)",
	},
	"internal/api/handlers/handlers.go": {
		`const legacySNMPVendor = "fortigate"`: "the legacy single-device SNMP_HOST client predates the vendor column and has only ever polled a FortiGate; explicit so the generic default does not change what that (mostly dead) path returns",
	},
	"cmd/configcheck/main.go": {
		`vendor := flag.String("vendor", "fortigate", "device vendor (fortigate, paloalto, cisco_asa, ...)")`: "developer CLI for diffing two config files; the flag names the vendor being inspected and FortiGate is the normalizer most worked on — not a device default",
	},
}

// vendorDefaultFile reports whether a tracked path is one the guard scans:
// non-test Go, and the admin JS / HTML.
func vendorDefaultFile(f string) bool {
	switch {
	case strings.HasSuffix(f, "_test.go"):
		return false
	case strings.HasSuffix(f, ".go"), strings.HasSuffix(f, ".js"), strings.HasSuffix(f, ".html"):
		return true
	}
	return false
}

func TestVendorDefaultGuard(t *testing.T) {
	root, files := hygieneRepoFiles(t)
	used := map[string]map[string]bool{}
	for _, f := range files {
		if !vendorDefaultFile(f) {
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
	allowed := make([]string, 0, len(vendorDefaultAllow))
	for f := range vendorDefaultAllow {
		allowed = append(allowed, f)
	}
	sort.Strings(allowed)
	for _, f := range allowed {
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

// TestVendorDefaultGuard_DeviceFormFirstOptionIsGeneric: the device form's
// <select id="device-vendor"> lists Generic first (form.reset() and a browser
// with no `selected` both land on the first option).
func TestVendorDefaultGuard_DeviceFormFirstOptionIsGeneric(t *testing.T) {
	data, err := os.ReadFile("../../web/admin/admin.html")
	if err != nil {
		t.Fatalf("read admin.html: %v", err)
	}
	sel := regexp.MustCompile(`(?s)<select id="device-vendor">\s*<option value="([a-z_]+)"`)
	m := sel.FindSubmatch(data)
	if m == nil {
		t.Fatal(`admin.html: <select id="device-vendor"> with an <option> not found`)
	}
	if string(m[1]) != "generic" {
		t.Errorf("admin.html: first #device-vendor option is %q, want generic", m[1])
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
		{`var v = (d.vendor || '').toLowerCase() || 'fortigate';`, true},
		{`var v = d.vendor ?? 'fortigate';`, true},
		{`var v = d.vendor ? d.vendor : 'fortigate';`, true},
		{`sel.value = 'fortigate';`, true},
		{`document.getElementById('device-vendor').value = "fortigate";`, true},
		{`vendor := cmp.Or(dev.Vendor, "fortigate")`, true},
		{`profile = GetVendorProfile("fortigate")`, true},
		{`if vendor == "" || vendor == "fortigate" {`, true},
		{`vendor := flag.String("vendor", "fortigate", "device vendor")`, true},
		{`<option value="fortigate" selected>FortiGate</option>`, true},
		{`vendor == "fortigate"`, false},
		{`return vendor == "fortigate" || vendor == "opnsense"`, false},
		{`case "fortigate":`, false},
		{`Vendor: "fortigate",`, false},
		{`vendor := "generic"`, false},
		{`if vendor === 'fortigate') {`, false},
		{`var supported = vendor === 'fortigate' || vendor === 'opnsense';`, false},
		{`hint = vendor === 'fortigate' ? 'FortiGate: …' : 'OPNsense: …';`, false},
		{`RegisterVendor(&FortiGateProfile{})`, false},
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
