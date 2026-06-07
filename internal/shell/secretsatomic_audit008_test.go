package shell

import (
	"os"
	"strings"
	"testing"
)

// TestSecretsAtomicPublish_AUDIT008 pins the concurrent-start fix (v0.10.386).
// LoadOrGenerate must publish the secret file atomically by writing a temp file
// and hard-linking it into place (os.CreateTemp + os.Link), NOT by creating an
// empty file with O_CREATE|O_EXCL and writing to it as a separate step — that
// two-step pattern let a racing process read the file created-but-empty (the
// flaky "secret file empty after concurrent write" / TestLoadOrGenerate_
// ConcurrentRaceSafe failure). The live gate is the -race test in
// internal/secrets; this is a fast static backstop against a regression.
func TestSecretsAtomicPublish_AUDIT008(t *testing.T) {
	const path = "../../internal/secrets/secrets.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("secrets.go not found at %s (AUDIT-008): %v", path, err)
	}
	body := string(data)

	for _, r := range []struct{ needle, why string }{
		{"os.CreateTemp(", "must stage the secret in a temp file before publishing (AUDIT-008 atomic publish)"},
		{"os.Link(", "must publish the secret by hard-linking the temp file into place — atomic, never empty (AUDIT-008)"},
	} {
		if !strings.Contains(body, r.needle) {
			t.Errorf("secrets.go missing %q: %s", r.needle, r.why)
		}
	}

	// The racy two-step "create empty then write" must NOT come back.
	if strings.Contains(body, "O_CREATE|os.O_EXCL") || strings.Contains(body, "O_EXCL, 0o600") {
		t.Error("secrets.go must not O_CREATE|O_EXCL the final secret file then write separately — that publishes an empty file a racer can read (AUDIT-008); use temp+os.Link")
	}
}
