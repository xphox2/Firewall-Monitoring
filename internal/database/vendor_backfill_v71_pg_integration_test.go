//go:build integration

package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestVendorBackfillV71Postgres runs v71 against real Postgres (TEST_PG_DSN;
// skipped otherwise): empty and NULL vendors become "fortigate" once, other
// rows are untouched, a re-run changes nothing, the column default is
// 'generic' afterwards, and an INSERT that omits vendor gets it.
func TestVendorBackfillV71Postgres(t *testing.T) {
	d := newPGForTest(t) // RunMigrations has applied v71 on an empty schema

	t.Run("BackfillOnceThenIdempotent", func(t *testing.T) {
		seed := []struct {
			name   string
			ip     string
			vendor interface{} // nil = SQL NULL
		}{
			{"fw-example-01", "192.0.2.1", ""},
			{"fw-example-02", "192.0.2.2", nil},
			{"fw-example-03", "192.0.2.3", "opnsense"},
			{"fw-example-04", "192.0.2.4", "generic"},
		}
		for _, s := range seed {
			if err := d.Gorm().Exec(`INSERT INTO devices (name, ip_address, vendor, created_at, updated_at) VALUES (?, ?, ?, now(), now())`,
				s.name, s.ip, s.vendor).Error; err != nil {
				t.Fatalf("seed %s: %v", s.name, err)
			}
		}
		// Simulate an upgrade: v71 not yet recorded, rows in the pre-0.11.290
		// shape, and the column default the old model tag created.
		for _, stmt := range []string{
			`DELETE FROM schema_migrations WHERE version = 71`,
			`ALTER TABLE devices ALTER COLUMN vendor SET DEFAULT 'fortigate'`,
		} {
			if err := d.Gorm().Exec(stmt).Error; err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		if err := d.RunMigrations(); err != nil {
			t.Fatalf("RunMigrations (applies v71): %v", err)
		}
		if err := d.migrateVendorBackfillFinal(); err != nil {
			t.Fatalf("v71 re-run: %v", err)
		}
		want := map[string]string{
			"fw-example-01": "fortigate",
			"fw-example-02": "fortigate",
			"fw-example-03": "opnsense",
			"fw-example-04": "generic",
		}
		var rows []models.Device
		if err := d.Gorm().Order("name").Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(want) {
			t.Fatalf("%d devices, want %d", len(rows), len(want))
		}
		for _, r := range rows {
			if r.Vendor != want[r.Name] {
				t.Errorf("%s vendor = %q, want %q", r.Name, r.Vendor, want[r.Name])
			}
		}
		var recorded int64
		d.Gorm().Raw(`SELECT count(*) FROM schema_migrations WHERE version = 71 AND name = 'vendor_backfill_final'`).Scan(&recorded)
		if recorded != 1 {
			t.Fatalf("v71 recorded %d times, want 1", recorded)
		}
	})

	t.Run("ColumnDefaultIsGeneric", func(t *testing.T) {
		var def string
		d.Gorm().Raw(`SELECT column_default FROM information_schema.columns WHERE table_name = 'devices' AND column_name = 'vendor'`).Scan(&def)
		if def != "'generic'::character varying" && def != "'generic'::text" {
			t.Fatalf("devices.vendor default = %q, want 'generic'", def)
		}
		if err := d.Gorm().Exec(`INSERT INTO devices (name, ip_address, created_at, updated_at) VALUES ('fw-example-05', '192.0.2.5', now(), now())`).Error; err != nil {
			t.Fatal(err)
		}
		var v string
		d.Gorm().Raw(`SELECT vendor FROM devices WHERE name = 'fw-example-05'`).Scan(&v)
		if v != "generic" {
			t.Fatalf("vendor of an INSERT without vendor = %q, want generic", v)
		}
	})
}
