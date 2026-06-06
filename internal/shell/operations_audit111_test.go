package shell

import (
	"os"
	"strings"
	"testing"
)

// TestOperationsRunbook_AUDIT111 pins that docs/OPERATIONS.md exists and
// covers the operational procedures the audit enumerated (first-24h, failure
// modes, debug logging, password reset, JWT rotation, backup/restore,
// upgrade, scale, DR), and is linked from the README.
func TestOperationsRunbook_AUDIT111(t *testing.T) {
	const path = "../../docs/OPERATIONS.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("docs/OPERATIONS.md not found (AUDIT-111): %v", err)
	}
	body := strings.ToLower(string(data))

	for _, section := range []string{
		"first-24h",
		"failure mode",
		"debug logging",
		"password reset",
		"jwt secret rotation",
		"backup & restore",
		"upgrade",
		"scale",
		"disaster recovery",
	} {
		if !strings.Contains(body, section) {
			t.Errorf("docs/OPERATIONS.md is missing a %q section (AUDIT-111).", section)
		}
	}

	readme, err := os.ReadFile("../../README.md")
	if err == nil && !strings.Contains(string(readme), "docs/OPERATIONS.md") {
		t.Error("README.md does not link docs/OPERATIONS.md (AUDIT-111): the runbook should be discoverable.")
	}
}
