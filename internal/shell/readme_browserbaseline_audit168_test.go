package shell

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeBrowserBaseline_AUDIT168 pins that the README documents a
// browser support baseline. The frontend uses the CSS `:has()` selector
// (AUDIT-132) and ES2020, which excludes older browsers — without a stated
// baseline, an operator on an old Safari/Chrome can't tell whether a broken
// layout is a bug or an unsupported browser.
func TestReadmeBrowserBaseline_AUDIT168(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Skipf("README.md not found; err: %v", err)
	}
	body := string(data)

	if !strings.Contains(body, "Browser Support") {
		t.Error("README.md has no `Browser Support` section (AUDIT-168).")
	}
	// The baseline must name concrete minimum versions for the three engines.
	for _, kw := range []string{"Chrome", "Safari", "Firefox"} {
		if !strings.Contains(body, kw) {
			t.Errorf("README browser baseline does not mention %q (AUDIT-168): name a concrete minimum version per engine.", kw)
		}
	}
}
