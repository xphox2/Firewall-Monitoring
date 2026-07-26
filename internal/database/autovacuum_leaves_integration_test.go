//go:build integration

// Storage parameters do NOT propagate from a partitioned parent to its children,
// and Postgres rejects them on the parent outright. ConfigureAutovacuum used to
// address only the parent and log-and-continue on failure, so the aggressive
// AUDIT-147 settings SILENTLY stopped applying the moment a table was
// partitioned — every leaf ran at the 20% default scale factor instead of 1%.
//
// This can only be tested against real Postgres: ConfigureAutovacuum early-
// returns on SQLite, so the unit lane cannot see the bug or the fix. Reverting
// the fix is otherwise test-invisible.
package database

import (
	"strings"
	"testing"
)

func TestAutovacuumIntegration_SettingsReachLeafPartitions(t *testing.T) {
	d := NewIntegrationDB(t)

	// syslog_messages is BOTH in defaultAutovacuumTables and converted to a
	// partitioned parent by migration v2 on a fresh schema — the combination this
	// test needs. (An earlier version asserted on denied_events, which is
	// partitioned but was absent from the autovacuum list, so it proved nothing.)
	var isPartitioned bool
	if err := d.db.Raw(`SELECT EXISTS (
		SELECT 1 FROM pg_partitioned_table pt
		JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = 'syslog_messages')`).
		Scan(&isPartitioned).Error; err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !isPartitioned {
		t.Skip("syslog_messages is not partitioned on this schema; nothing to assert")
	}

	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	if err := d.ConfigureAutovacuum(); err != nil {
		t.Fatalf("ConfigureAutovacuum: %v", err)
	}

	var leaves []struct {
		Relname    string
		Reloptions string
	}
	if err := d.db.Raw(`
		SELECT c.relname, coalesce(array_to_string(c.reloptions, ','), '') AS reloptions
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = 'syslog_messages'`).Scan(&leaves).Error; err != nil {
		t.Fatalf("read leaf reloptions: %v", err)
	}
	if len(leaves) == 0 {
		t.Fatal("syslog_messages has no child partitions — EnsurePartitions did not run")
	}

	var missing []string
	for _, leaf := range leaves {
		if !strings.Contains(leaf.Reloptions, "autovacuum_vacuum_scale_factor=0.01") {
			missing = append(missing, leaf.Relname+"["+leaf.Reloptions+"]")
		}
	}
	if len(missing) > 0 {
		t.Errorf("leaf partitions without the aggressive autovacuum settings: %v\n"+
			"Storage parameters do not inherit from a partitioned parent, so addressing "+
			"only the parent leaves every leaf at the 20%% default scale factor. That is "+
			"load-bearing: a monthly partition only stays near its live size because "+
			"retention-freed pages get reused by later inserts into that same partition, "+
			"which requires vacuum to keep up.", missing)
	}
}
