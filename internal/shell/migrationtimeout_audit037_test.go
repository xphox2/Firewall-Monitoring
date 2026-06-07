package shell

import (
	"os"
	"strings"
	"testing"
)

// TestMigrationDDLLiftsStatementTimeout_AUDIT037 pins the v0.10.391 production
// fix: heavy startup DDL must not run under the AUDIT-037 per-connection
// statement_timeout (default 30s), or it gets canceled (57014) on a large DB.
// Two sites must lift it:
//   - the interface_addresses self-heal (dedupe + CREATE UNIQUE INDEX), else
//     idx_ifaddr_dev_ip never builds and every upsert fails 42P10;
//   - the migration advisory-lock acquisition, else a process blocking on a
//     busy migrator is canceled and crash-loops ("migrate: acquire lock").
func TestMigrationDDLLiftsStatementTimeout_AUDIT037(t *testing.T) {
	for _, c := range []struct {
		path, needle, why string
	}{
		{
			"../../internal/database/migrate.go",
			"SET LOCAL statement_timeout = 0",
			"the interface_addresses dedupe + index build must lift the statement timeout (AUDIT-037/030) — otherwise the index can't build on a large table and the upsert 42P10s",
		},
		{
			"../../internal/database/migrations.go",
			"SET statement_timeout = 0",
			"the migration advisory-lock connection must lift the statement timeout (AUDIT-037/044) — otherwise blocking on a busy migrator is canceled (57014) and the process fails to boot",
		},
	} {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatalf("%s not found: %v", c.path, err)
		}
		if !strings.Contains(string(data), c.needle) {
			t.Errorf("%s missing %q: %s", c.path, c.needle, c.why)
		}
	}
}
