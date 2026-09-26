package database

import (
	"strings"
	"testing"
)

// v67 adds idx_vpn_status_timestamp. The model tag gives it to fresh installs;
// the migration is what reaches existing databases, where the baseline never
// runs again — so the test removes the tag-created index first and proves the
// migration puts it back.

func vpnTimestampIndexExists(t *testing.T, d *Database) bool {
	t.Helper()
	var n int64
	if err := d.db.Raw(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_vpn_status_timestamp'`).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestVPNStatusTimestampIndex_MigrationCreatesIt(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if !vpnTimestampIndexExists(t, d) {
		t.Fatal("the model tag must create idx_vpn_status_timestamp on a fresh schema")
	}
	if err := d.db.Exec(`DROP INDEX IF EXISTS idx_vpn_status_timestamp`).Error; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := d.migrateVPNStatusTimestampIndex(); err != nil {
			t.Fatalf("run %d: %v — the migration must be safe to re-run", i+1, err)
		}
	}
	if !vpnTimestampIndexExists(t, d) {
		t.Fatal("migration did not create idx_vpn_status_timestamp")
	}
}

func TestVPNStatusTimestampIndex_IsARegisteredMigration(t *testing.T) {
	for _, m := range registeredMigrations {
		if strings.Contains(m.name, "vpn_status_timestamp") {
			if m.version <= 1 {
				t.Fatalf("version %d: must be a new version; recorded versions are skipped on existing databases", m.version)
			}
			return
		}
	}
	t.Fatal("no registered migration creates idx_vpn_status_timestamp; a tag alone never reaches an existing database")
}
