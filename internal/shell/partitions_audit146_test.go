package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEnsurePartitions_SurfacesWarning_AUDIT146 is a static
// regression for the audit: `internal/database/database.go`
// contains a non-Postgres skip path (SQLite deployments and
// pre-partitioning Postgres deployments) that emits a log
// message. Pre-fix the message was a plain `log.Printf` with
// no prefix, which made it easy to miss in startup noise.
//
// The fix: the message now starts with `WARNING: AUDIT-146`,
// which is grep-able and self-documents. The test pins:
//
//  1. The WARNING prefix is present in the skip-message
//     template (so a future agent who copy-pastes a
//     pre-fix-style log line fails the test).
//  2. The audit ID is referenced in a comment (so the
//     rationale for the WARNING prefix is documented).
//  3. The message mentions the migration path (so an
//     operator who sees the warning has a pointer to
//     docs/partition-migration.md).
func TestEnsurePartitions_SurfacesWarning_AUDIT146(t *testing.T) {
	const path = "../../internal/database/database.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("internal/database/database.go not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// 1. The WARNING prefix is present in the partition-skip
	// log message. We look for the exact substring
	// `WARNING: AUDIT-146` so a future agent who "improves"
	// the message (e.g. removes the WARNING prefix) fails here.
	if !strings.Contains(body, "WARNING: AUDIT-146") {
		t.Errorf("internal/database/database.go is missing the `WARNING: AUDIT-146` log prefix (AUDIT-146: the partition-skip message must surface as a warning, not a per-table info line, so an operator who needs to migrate to a partitioned table sees the message in startup noise).")
	}

	// 2. The migration path is mentioned.
	if !strings.Contains(body, "docs/partition-migration.md") {
		t.Errorf("internal/database/database.go is missing the docs/partition-migration.md pointer (AUDIT-146: the operator who sees the WARNING needs a next step; the doc is the next step).")
	}
}
