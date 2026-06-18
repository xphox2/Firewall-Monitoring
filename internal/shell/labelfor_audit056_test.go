package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestLabelFor_AUDIT056 is a static regression for the audit: form <label>
// elements across the admin pages lacked `for=""`, so screen readers couldn't
// pair a label with its control. The sweep (scripts/audit056_labels.py) added
// `for="<input id>"` to every non-wrapping label whose adjacent control has an
// id. This test pins two invariants:
//  1. Every `<label for="X">` resolves to an `id="X"` in the same file (no
//     broken or mis-targeted association).
//  2. Each page has at least a minimum number of associated labels, so a future
//     edit that strips the for= attributes wholesale fails here.
func TestLabelFor_AUDIT056(t *testing.T) {
	labelFor := regexp.MustCompile(`<label\s+for="([^"]+)"`)
	idAttr := regexp.MustCompile(`\bid="([^"]+)"`)

	cases := []struct {
		file   string
		minFor int
	}{
		{"../../web/admin/probes.html", 4},
		{"../../web/admin/sites.html", 6},
		{"../../web/admin/irc.html", 20},
		{"../../web/admin/admin.html", 50},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Skipf("%s not found; err: %v", tc.file, err)
			continue
		}
		body := string(data)

		ids := map[string]bool{}
		for _, m := range idAttr.FindAllStringSubmatch(body, -1) {
			ids[m[1]] = true
		}
		fors := labelFor.FindAllStringSubmatch(body, -1)
		if len(fors) < tc.minFor {
			t.Errorf("%s has %d `<label for=>` associations, want >= %d (AUDIT-056).", tc.file, len(fors), tc.minFor)
		}
		for _, m := range fors {
			if !ids[m[1]] {
				t.Errorf("%s: <label for=%q> has no matching id in the file (AUDIT-056) — broken association.", tc.file, m[1])
			}
		}
	}

	// Traceability marker lives in admin.html (the primary form file).
	admin, err := os.ReadFile("../../web/admin/admin.html")
	if err == nil && !strings.Contains(string(admin), "AUDIT-056") {
		t.Errorf("admin.html missing the AUDIT-056 marker comment.")
	}
}
