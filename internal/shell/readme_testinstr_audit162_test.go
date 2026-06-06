package shell

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeHasTestInstructions_AUDIT162 pins that the README tells a
// contributor how to run the test suite. Pre-fix the README documented
// build/deploy but never mentioned `go test`, so a newcomer had no signal
// that tests exist or how to run them before opening a PR.
func TestReadmeHasTestInstructions_AUDIT162(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Skipf("README.md not found; err: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "go test ./...") {
		t.Error("README.md does not document `go test ./...` (AUDIT-162): contributors need a documented way to run the suite.")
	}
}
