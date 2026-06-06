package shell

import (
	"os"
	"strings"
	"testing"
)

// TestCodeownersExists_AUDIT163 pins that .github/CODEOWNERS exists and has
// a catch-all default owner. The HANDOFF noted the CHANGELOG referenced this
// file before it actually existed on disk; this guards against it going
// missing again and ensures the catch-all line is present (without a `*`
// rule, paths with no specific owner get no auto-review).
func TestCodeownersExists_AUDIT163(t *testing.T) {
	const path = "../../.github/CODEOWNERS"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf(".github/CODEOWNERS not found at %s (AUDIT-163): %v", path, err)
	}

	hasCatchAll := false
	hasOwner := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Errorf("CODEOWNERS line has no owner: %q (AUDIT-163: each pattern needs at least one owner).", line)
			continue
		}
		if fields[0] == "*" {
			hasCatchAll = true
		}
		for _, owner := range fields[1:] {
			if strings.HasPrefix(owner, "@") {
				hasOwner = true
			}
		}
	}
	if !hasCatchAll {
		t.Error("CODEOWNERS has no `*` catch-all rule (AUDIT-163): paths without a specific owner would get no default reviewer.")
	}
	if !hasOwner {
		t.Error("CODEOWNERS has no @owner entries (AUDIT-163).")
	}
}
