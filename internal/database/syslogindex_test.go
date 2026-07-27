package database

import (
	"strings"
	"testing"
)

// The per-severity retention deletes filter on `severity IN (…) AND timestamp < ?`,
// which needs a (severity, timestamp) composite. Getting that index CREATED is
// the whole point, and it is easy to get wrong in a way that leaves no trace:
//
//   - a gorm `index:` tag is applied only by migrateBaseline's AutoMigrate loop,
//     and runMigrationList skips versions already recorded, so on any existing
//     database the tag does nothing at all;
//   - AutoMigrate runs on a connection carrying the 30s statement_timeout and
//     SWALLOWS failures as warnings while the migration is still recorded as
//     applied — so a timed-out build looks like success.
//
// These assert on the resulting schema rather than on the migration returning
// nil, because "ran without error" is exactly what both failure modes look like.

func TestSyslogIndex_MigrationActuallyCreatesTheIndex(t *testing.T) {
	d := NewDatabaseForTesting(t)

	// Drop what the test harness's AutoMigrate created from the model tag.
	// Without this the test passes against a migration that does nothing —
	// which is the precise illusion this guards against, because AutoMigrate is
	// the one path that never runs on an existing production database.
	if err := d.db.Exec(`DROP INDEX IF EXISTS idx_syslog_sev_ts`).Error; err != nil {
		t.Fatalf("drop tag-created index: %v", err)
	}

	if err := d.migrateSyslogSeverityIndex(); err != nil {
		t.Fatalf("migration: %v", err)
	}

	var names []string
	if err := d.db.Raw(
		`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='syslog_messages'`).
		Scan(&names).Error; err != nil {
		t.Fatalf("read indexes: %v", err)
	}
	var found bool
	for _, n := range names {
		if n == "idx_syslog_sev_ts" {
			found = true
		}
	}
	if !found {
		t.Errorf("idx_syslog_sev_ts absent after the migration ran; indexes = %v.\n"+
			"A migration that returns nil without creating the index is the exact "+
			"failure this replaced — the per-severity deletes would have no index to use", names)
	}
}

func TestSyslogIndex_MigrationIsIdempotent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	for i := 0; i < 2; i++ {
		if err := d.migrateSyslogSeverityIndex(); err != nil {
			t.Fatalf("run %d: %v — the migration must be safe to re-run, since a "+
				"failed run is retried on the next boot", i+1, err)
		}
	}
}

// The index must not be left to the model tag. A tag-only change is invisible on
// every existing deployment, which is what made this a real bug rather than a
// theoretical one.
func TestSyslogIndex_IsCreatedByARegisteredMigration(t *testing.T) {
	var found *migration
	for i := range registeredMigrations {
		if strings.Contains(registeredMigrations[i].name, "syslog_severity") {
			found = &registeredMigrations[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no registered migration creates the syslog severity index — relying on the " +
			"model's gorm tag means the index is never created on an existing database, " +
			"because migrateBaseline only runs on a fresh one")
	}
	if found.version <= 1 {
		t.Errorf("the index migration is version %d; it must be a NEW version, since already-"+
			"recorded versions are skipped on existing databases", found.version)
	}
}

// The old severity-only index is superseded by the composite's leading prefix and
// is pure dead weight (673 MB on production) once the composite exists.
func TestSyslogIndex_SupersededIndexIsDropped(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_syslog_severity ON syslog_messages (severity)`).Error; err != nil {
		t.Fatalf("seed old index: %v", err)
	}
	if err := d.migrateSyslogSeverityIndex(); err != nil {
		t.Fatalf("migration: %v", err)
	}
	var n int64
	d.db.Raw(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_syslog_severity'`).Scan(&n)
	if n != 0 {
		t.Error("idx_syslog_severity survived; the composite covers it as a leading prefix, " +
			"so leaving it costs space and write throughput for nothing")
	}
}
