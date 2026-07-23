//go:build integration

// AUDIT AL-M2 (Postgres-only): migration v52 must add the `source` column to the
// partitioned system_status parent AND propagate it to every child partition, so
// the alert engine can read the collector's per-writer source stamp.
package database

import (
	"testing"
)

func TestV52_SystemStatusSourceColumn(t *testing.T) {
	d := NewIntegrationDB(t) // runs migrations incl. v52
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	if !pgIsPartitioned(t, d, "system_status") {
		t.Fatal("system_status is not partitioned")
	}

	// The column exists on the parent...
	colExists := func(table string) bool {
		var ok bool
		if err := d.Gorm().Raw(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name = ? AND column_name = 'source')`, table).Scan(&ok).Error; err != nil {
			t.Fatalf("column probe %s: %v", table, err)
		}
		return ok
	}
	if !colExists("system_status") {
		t.Fatal("AUDIT AL-M2: migration v52 did not add system_status.source")
	}

	// ...and on at least one child partition (the ADD propagated).
	var child string
	if err := d.Gorm().Raw(`
		SELECT c.relname FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = 'system_status' LIMIT 1`).Scan(&child).Error; err != nil {
		t.Fatalf("find child partition: %v", err)
	}
	if child == "" {
		t.Fatal("no child partition of system_status found")
	}
	if !colExists(child) {
		t.Fatalf("AUDIT AL-M2: source column did not propagate to partition %q", child)
	}
}
