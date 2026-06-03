package shell

import (
	"os"
	"testing"
)

// TestColorContrast_NoDarkText6e_AUDIT067 pins that #6e7681 — which only meets
// WCAG AA for LARGE text on the dark backgrounds (≈4.07:1) — is no longer used
// as small foreground text (stat labels, muted/secondary text). All such uses
// were lifted to #8b949e (≈5.3:1). Decorative uses (chart ticks as quoted
// '#6e7681', borders/icons) are left as-is. Reuses textContextHits /
// servedStyleFiles from the AUDIT-066 test (same package).
func TestColorContrast_NoDarkText6e_AUDIT067(t *testing.T) {
	for _, path := range servedStyleFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s not found; err: %v", path, err)
			continue
		}
		if hits := textContextHits(string(data), "#6e7681"); hits > 0 {
			t.Errorf("%s still uses #6e7681 as foreground text in %d place(s) (AUDIT-067): lift to #8b949e for any text < 18pt regular / 14pt bold.", path, hits)
		}
	}
}
