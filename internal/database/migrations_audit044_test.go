//go:build !production

package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestRunMigrations_BaselineRecordedOnce pins that RunMigrations creates the
// schema_migrations table, records the v1 baseline exactly once, and is a no-op
// on re-run (AUDIT-044). NewDatabaseForTesting gives a DB whose schema already
// exists but has no migration records — i.e. the "existing prod" case — so this
// also proves the baseline is idempotent there.
func TestRunMigrations_BaselineRecordedOnce(t *testing.T) {
	d := NewDatabaseForTesting(t)

	if err := d.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	// Expect every registered migration recorded, in order. v1 = baseline,
	// v2 = partition_high_volume (a no-op on SQLite but still recorded).
	want := registeredMigrations
	rows := appliedMigrations(t, d)
	if len(rows) != len(want) {
		t.Fatalf("after first run, want %d recorded migrations, got %d (%+v)", len(want), len(rows), rows)
	}
	for i, m := range want {
		if rows[i].Version != m.version || rows[i].Name != m.name {
			t.Fatalf("recorded migration %d = {%d %q}, want {%d %q}", i, rows[i].Version, rows[i].Name, m.version, m.name)
		}
	}

	// Re-run must be a no-op (skip the already-applied versions).
	if err := d.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations (2nd): %v", err)
	}
	if rows := appliedMigrations(t, d); len(rows) != len(want) {
		t.Fatalf("re-run should not add rows; want %d, got %d", len(want), len(rows))
	}
}

// TestRunMigrations_AppliesNewSkipsApplied pins that the runner applies an
// un-applied migration exactly once and skips already-recorded ones, via the
// injectable runMigrationList core.
func TestRunMigrations_AppliesNewSkipsApplied(t *testing.T) {
	d := NewDatabaseForTesting(t)

	ran := 0
	list := []migration{
		{version: 1, name: "baseline", run: (*Database).migrateBaseline},
		{version: 2, name: "fake", run: func(*Database) error { ran++; return nil }},
	}

	if err := d.runMigrationList(list); err != nil {
		t.Fatalf("runMigrationList: %v", err)
	}
	if ran != 1 {
		t.Fatalf("fake migration ran %d times, want 1", ran)
	}
	if rows := appliedMigrations(t, d); len(rows) != 2 {
		t.Fatalf("want 2 recorded migrations, got %d (%+v)", len(rows), rows)
	}

	// Re-run: both are recorded, so nothing should execute again.
	if err := d.runMigrationList(list); err != nil {
		t.Fatalf("runMigrationList (2nd): %v", err)
	}
	if ran != 1 {
		t.Fatalf("fake migration re-ran (ran=%d); recorded migrations must be skipped", ran)
	}
	if rows := appliedMigrations(t, d); len(rows) != 2 {
		t.Fatalf("re-run changed the recorded set; want 2, got %d", len(rows))
	}
}

func appliedMigrations(t *testing.T, d *Database) []models.SchemaMigration {
	t.Helper()
	var rows []models.SchemaMigration
	if err := d.Gorm().Order("version").Find(&rows).Error; err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	return rows
}
