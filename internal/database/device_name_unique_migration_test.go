package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// deviceIndexSQL returns name → CREATE statement for every index on devices
// (SQLite catalog; the harness is SQLite-only).
func deviceIndexSQL(t *testing.T, d *Database) map[string]string {
	t.Helper()
	var rows []struct {
		Name string
		SQL  string
	}
	if err := d.db.Raw(`SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='devices' AND sql IS NOT NULL`).
		Scan(&rows).Error; err != nil {
		t.Fatalf("list devices indexes: %v", err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Name] = r.SQL
	}
	return out
}

// installGlobalUniqueNameIndex puts the devices table back into its pre-v63
// shape: no partial index, idx_devices_name a GLOBAL unique index (what the
// old `uniqueIndex` model tag produced on every install).
func installGlobalUniqueNameIndex(t *testing.T, d *Database) {
	t.Helper()
	for _, stmt := range []string{
		`DROP INDEX IF EXISTS idx_devices_name_active`,
		`DROP INDEX IF EXISTS idx_devices_name`,
		`CREATE UNIQUE INDEX idx_devices_name ON devices (name)`,
	} {
		if err := d.db.Exec(stmt).Error; err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

// TestMigrateDeviceNameUniqueAmongActive runs the v63 body on a database that
// still carries the old global unique idx_devices_name and asserts the swap:
// idx_devices_name becomes a plain index, idx_devices_name_active is the
// partial unique index, a retired + active pair may share a name, a second
// active row may not, and a rerun is a no-op.
func TestMigrateDeviceNameUniqueAmongActive(t *testing.T) {
	d := NewDatabaseForTesting(t)
	installGlobalUniqueNameIndex(t, d)

	old := &models.Device{Name: "FW", IPAddress: "10.0.0.1", Enabled: true}
	if err := d.CreateDevice(old); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.RetireDevice(old.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	// Under the old index the retired name still blocks a re-add.
	if err := d.CreateDevice(&models.Device{Name: "FW", IPAddress: "10.0.0.2"}); !IsUniqueViolation(err) {
		t.Fatalf("pre-migration re-add err = %v, want a unique violation (test setup)", err)
	}

	if err := d.migrateDeviceNameUniqueAmongActive(); err != nil {
		t.Fatalf("migrate v63: %v", err)
	}
	idx := deviceIndexSQL(t, d)
	if sql, ok := idx["idx_devices_name"]; !ok || strings.Contains(strings.ToUpper(sql), "UNIQUE") {
		t.Errorf("idx_devices_name after v63 = %q, want a plain (non-unique) index", sql)
	}
	if sql, ok := idx["idx_devices_name_active"]; !ok || !strings.Contains(strings.ToUpper(sql), "UNIQUE") || !strings.Contains(sql, "retired_at IS NULL") {
		t.Errorf("idx_devices_name_active after v63 = %q, want a unique partial index on retired_at IS NULL", sql)
	}

	repl := &models.Device{Name: "FW", IPAddress: "10.0.0.2", Enabled: true}
	if err := d.CreateDevice(repl); err != nil {
		t.Fatalf("post-migration re-add of a retired name: %v", err)
	}
	if err := d.CreateDevice(&models.Device{Name: "FW", IPAddress: "10.0.0.3"}); !IsUniqueViolation(err) {
		t.Fatalf("second active FW err = %v, want a unique violation", err)
	}

	// Idempotent rerun: same index shape, rows untouched.
	if err := d.migrateDeviceNameUniqueAmongActive(); err != nil {
		t.Fatalf("rerun v63: %v", err)
	}
	if again := deviceIndexSQL(t, d); again["idx_devices_name"] != idx["idx_devices_name"] || again["idx_devices_name_active"] != idx["idx_devices_name_active"] {
		t.Errorf("rerun changed the index shape: %v vs %v", again, idx)
	}
	var n int64
	d.db.Model(&models.Device{}).Where("name = ?", "FW").Count(&n)
	if n != 2 {
		t.Errorf("rows named FW = %d after rerun, want 2", n)
	}
}

// TestMigrateDeviceNameUniqueAmongActive_RefusesActiveDuplicates: with two
// ACTIVE rows sharing a name (only possible on a hand-edited database) the
// migration returns an error naming them and applies nothing — the global
// unique index is still in place afterwards.
func TestMigrateDeviceNameUniqueAmongActive_RefusesActiveDuplicates(t *testing.T) {
	d := NewDatabaseForTesting(t)
	for _, stmt := range []string{`DROP INDEX IF EXISTS idx_devices_name_active`, `DROP INDEX IF EXISTS idx_devices_name`} {
		if err := d.db.Exec(stmt).Error; err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	now := time.Now()
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		if err := d.CreateDevice(&models.Device{Name: "DUP", IPAddress: ip, Enabled: true, LastPolled: now}); err != nil {
			t.Fatalf("seed duplicate: %v", err)
		}
	}
	if err := d.db.Exec(`CREATE INDEX idx_devices_name ON devices (name)`).Error; err != nil {
		t.Fatalf("recreate lookup index: %v", err)
	}
	// Retired namesakes never count.
	r := &models.Device{Name: "DUP", IPAddress: "10.0.0.3", Enabled: true}
	if err := d.CreateDevice(r); err != nil {
		t.Fatalf("seed retired: %v", err)
	}
	if err := d.RetireDevice(r.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}

	err := d.migrateDeviceNameUniqueAmongActive()
	if err == nil || !strings.Contains(err.Error(), `"DUP" (2 active rows)`) {
		t.Fatalf("migrate v63 with active duplicates err = %v, want an error naming DUP", err)
	}
	if idx := deviceIndexSQL(t, d); idx["idx_devices_name_active"] != "" {
		t.Errorf("partial index was created despite the refusal: %q", idx["idx_devices_name_active"])
	}
}
