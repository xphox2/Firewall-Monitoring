package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEscapeHtml_NullishGuard_AUDIT059 is a static regression for the audit:
// escapeHtml in admin-common.js and admin-irc.js guarded with `if (!str)` /
// `if (!text)`, which treats numeric 0 (and false, ”) as empty — so a
// "0 bytes in" field rendered blank. The fix is a nullish-only check
// (`== null`). A future edit that reverts to the falsy guard fails here.
func TestEscapeHtml_NullishGuard_AUDIT059(t *testing.T) {
	cases := []struct {
		path  string
		guard string // the correct nullish guard for that file's param name
		falsy string // the old falsy guard that must be gone
	}{
		{"../../cmd/api/static/js/admin-common.js", "if (str == null) return '';", "if (!str) return '';"},
		{"../../cmd/api/static/js/admin-irc.js", "if (text == null) return '';", "if (!text) return '';"},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Skipf("%s not found; err: %v", tc.path, err)
			continue
		}
		body := string(data)
		if !strings.Contains(body, "AUDIT-059") {
			t.Errorf("%s missing the AUDIT-059 marker.", tc.path)
		}
		if !strings.Contains(body, tc.guard) {
			t.Errorf("%s escapeHtml must use the nullish guard %q (AUDIT-059).", tc.path, tc.guard)
		}
		if strings.Contains(body, tc.falsy) {
			t.Errorf("%s escapeHtml still uses the falsy guard %q (AUDIT-059): it blanks numeric 0.", tc.path, tc.falsy)
		}
	}
}
