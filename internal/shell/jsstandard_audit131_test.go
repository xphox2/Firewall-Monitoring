package shell

import (
	"os"
	"strings"
	"testing"
)

// TestJSStandardDocumented_AUDIT131 pins that the admin JS directory documents
// a single language standard. The audit flagged the inconsistency of ES6
// admin-irc.js amid otherwise ES5-style code with no stated convention; the
// resolution is to declare ES2020 the target (justified by the AUDIT-168
// evergreen browser baseline) so the ES6 code is correct and new ES5
// workarounds are discouraged.
func TestJSStandardDocumented_AUDIT131(t *testing.T) {
	const path = "../../cmd/api/static/js/README.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/static/js/README.md not found (AUDIT-131): %v", err)
	}
	body := string(data)

	if !strings.Contains(body, "ES2020") {
		t.Error("the JS conventions doc does not name a standard (ES2020) (AUDIT-131).")
	}
	// It should tie the decision to the browser baseline and flag the legacy
	// ['catch'] workaround as not-to-be-extended (the AUDIT-132 cleanup).
	for _, kw := range []string{"AUDIT-168", "['catch']", "AUDIT-132"} {
		if !strings.Contains(body, kw) {
			t.Errorf("the JS conventions doc is missing %q (AUDIT-131): tie the standard to the baseline and flag the legacy workaround.", kw)
		}
	}
}
