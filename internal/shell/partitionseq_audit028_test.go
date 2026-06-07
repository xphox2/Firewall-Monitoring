package shell

import (
	"os"
	"strings"
	"testing"
)

// TestPartitionSequenceReown_AUDIT028 pins the fix for the fresh-Postgres
// partition migration crash (v0.10.384). convertEmptyTableToPartitioned builds
// the partitioned parent with `CREATE TABLE ... (LIKE <t>_prepart INCLUDING
// DEFAULTS)`, which copies the id serial's nextval() default; the sequence is
// still OWNED BY <t>_prepart.id, so the new parent depends on it and a plain
// DROP TABLE <t>_prepart fails with SQLSTATE 2BP01. The drop must be preceded by
// re-pointing the sequence ownership to the new parent (resolved via
// pg_get_serial_sequence), and must NOT use CASCADE (which would drop the
// still-needed sequence). The live gate is the AUDIT-118 integration-postgres
// CI job; this is a fast static backstop against a regression.
func TestPartitionSequenceReown_AUDIT028(t *testing.T) {
	const path = "../../internal/database/migrate.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("migrate.go not found at %s (AUDIT-028): %v", path, err)
	}
	body := string(data)

	for _, r := range []struct{ needle, why string }{
		{"pg_get_serial_sequence(", "must resolve the id sequence name at runtime before re-owning it (AUDIT-028 2BP01 fix)"},
		{"ALTER SEQUENCE", "must re-point the id sequence ownership before dropping the old table (AUDIT-028 2BP01 fix)"},
		{"OWNED BY", "the sequence must be re-owned by the new partitioned parent so DROP TABLE _prepart succeeds (AUDIT-028 2BP01 fix)"},
	} {
		if !strings.Contains(body, r.needle) {
			t.Errorf("migrate.go missing %q: %s", r.needle, r.why)
		}
	}

	// A CASCADE drop here would drop the still-needed id sequence — guard against
	// someone "fixing" 2BP01 the wrong way.
	if strings.Contains(body, "_prepart`, table)") && strings.Contains(body, "DROP TABLE %s_prepart CASCADE") {
		t.Error("convertEmptyTableToPartitioned must NOT DROP TABLE _prepart CASCADE — that drops the sequence the new parent depends on (AUDIT-028)")
	}
}
