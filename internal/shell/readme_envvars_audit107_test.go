package shell

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeEnvVarDocs_AUDIT107 pins that the README documents the
// configuration surface beyond the original 6 lines: it must point at
// config.env.example as the authoritative reference and name the
// previously-undocumented families (ENCRYPTION_KEY, RETENTION_*, PROBE_*,
// REPORT_*, the server timeouts). Pre-fix an operator had to read the source
// to find these even existed.
func TestReadmeEnvVarDocs_AUDIT107(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Skipf("README.md not found; err: %v", err)
	}
	body := string(data)

	if !strings.Contains(body, "config.env.example") {
		t.Error("README.md does not reference config.env.example as the authoritative config reference (AUDIT-107).")
	}
	for _, kw := range []string{"ENCRYPTION_KEY", "RETENTION_", "PROBE_", "REPORT_", "SERVER_READ_TIMEOUT", "DB_MAX_OPEN_CONNS"} {
		if !strings.Contains(body, kw) {
			t.Errorf("README.md does not document %q (AUDIT-107): these env-var families were undocumented before the fix.", kw)
		}
	}
}
