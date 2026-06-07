package shell

import (
	"os"
	"strings"
	"testing"
)

// TestPartitionTables_AUDIT028 pins the partitioning of the 6 high-volume tables
// (AUDIT-028: interface_stats/system_status; AUDIT-146: the four syslog/trap/flow
// tables): the shared partition list names all six, a v2 migration is registered
// to convert empty tables, cleanup can drop old partitions, and the operator
// runbook the warning references exists.
func TestPartitionTables_AUDIT028(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}

	mig := read("../../internal/database/migrate.go")
	for _, tbl := range []string{"interface_stats", "system_status", "syslog_messages", "syslog_summaries", "trap_events", "flow_samples"} {
		if !strings.Contains(mig, `{"`+tbl+`", "timestamp"}`) {
			t.Errorf("partitionTables is missing %q (AUDIT-028/146).", tbl)
		}
	}
	if !strings.Contains(mig, "func (d *Database) migratePartitionHighVolume()") ||
		!strings.Contains(mig, "PARTITION BY RANGE") {
		t.Error("migrate.go missing the empty-table partition conversion (AUDIT-028).")
	}

	migr := read("../../internal/database/migrations.go")
	if !strings.Contains(migr, `name: "partition_high_volume"`) {
		t.Error("the partition_high_volume v2 migration is not registered (AUDIT-028).")
	}

	cl := read("../../internal/database/cleanup.go")
	if !strings.Contains(cl, "func (d *Database) dropPartitionsOlderThan(") {
		t.Error("cleanup.go missing dropPartitionsOlderThan (AUDIT-028).")
	}

	if _, err := os.Stat("../../docs/partition-migration.md"); err != nil {
		t.Error("docs/partition-migration.md is missing (AUDIT-028): the EnsurePartitions warning references it.")
	}
}
