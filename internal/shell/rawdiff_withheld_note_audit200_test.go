package shell

import (
	"os"
	"strings"
	"testing"
)

// TestRawDiffWithheldNote_AUDIT200 is a static guardrail for the fail-closed
// masking path's UI half: DiffLines returns a WITHHELD diff as zero rows plus
// Truncated+Note, and renderRawDiff's empty-rows early return used to fire
// before the note banner — rendering an affirmative "No differences found" for
// a diff that was deliberately withheld (a false statement during incident
// review). The empty-rows branch must render the truncated note when one is
// present, i.e. the `ld.truncated && ld.note` check must appear BEFORE the
// "No differences found" placeholder in the source.
func TestRawDiffWithheldNote_AUDIT200(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-device-detail.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-device-detail.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	// Anchor on the placeholder MARKUP, not the bare phrase — the phrase also
	// appears in the explanatory comment above the check.
	noteIdx := strings.Index(body, "ld.truncated && ld.note")
	placeholderIdx := strings.Index(body, `cfgdiff-placeholder">No differences found`)
	if noteIdx < 0 {
		t.Fatalf("admin-device-detail.js missing the withheld-note branch (ld.truncated && ld.note) in renderRawDiff (AUDIT-200).")
	}
	if placeholderIdx < 0 {
		t.Fatalf("admin-device-detail.js missing the 'No differences found' placeholder — renderRawDiff restructured? Update this guardrail.")
	}
	if noteIdx > placeholderIdx {
		t.Errorf("the withheld-note check must precede the 'No differences found' placeholder — otherwise a withheld diff (rows empty, note set) renders as an affirmative no-change statement (AUDIT-200).")
	}
	// The note must render escaped, matching the existing banner.
	if !strings.Contains(body, "esc(ld.note)") {
		t.Errorf("the withheld-note branch must escape ld.note with esc() (AUDIT-200).")
	}
}
