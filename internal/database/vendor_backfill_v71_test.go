package database

import (
	"fmt"
	"testing"

	"firewall-mon/internal/models"
)

// TestMigrateV71_Idempotent (SQLite): v71 sets every empty / NULL vendor to
// "fortigate" exactly once — the value the removed startup backfill would have
// given those rows — leaves every other row alone, and a re-run changes
// nothing. The Postgres twin (vendor_backfill_v71_pg_integration_test.go)
// also checks the column default.
func TestMigrateV71_Idempotent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seed := []struct {
		name   string
		vendor interface{} // nil = SQL NULL
	}{
		{"fw-example-01", ""},
		{"fw-example-02", nil},
		{"fw-example-03", "opnsense"},
		{"fw-example-04", "generic"},
	}
	for i, s := range seed {
		if err := d.db.Exec(`INSERT INTO devices (name, ip_address, vendor, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			s.name, fmt.Sprintf("192.0.2.%d", i+1), s.vendor).Error; err != nil {
			t.Fatalf("seed %s: %v", s.name, err)
		}
	}
	want := map[string]string{
		"fw-example-01": "fortigate",
		"fw-example-02": "fortigate",
		"fw-example-03": "opnsense",
		"fw-example-04": "generic",
	}
	for run := 1; run <= 2; run++ {
		if err := d.migrateVendorBackfillFinal(); err != nil {
			t.Fatalf("v71 run %d: %v", run, err)
		}
		var rows []models.Device
		if err := d.db.Order("name").Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(want) {
			t.Fatalf("run %d: %d devices, want %d", run, len(rows), len(want))
		}
		for _, r := range rows {
			if r.Vendor != want[r.Name] {
				t.Errorf("run %d: %s vendor = %q, want %q", run, r.Name, r.Vendor, want[r.Name])
			}
		}
	}

	// The model's column default is generic: a device created without a
	// vendor is stored as such (GORM omits the zero-valued field).
	dev := &models.Device{Name: "fw-example-05", IPAddress: "192.0.2.5"}
	if err := d.CreateDevice(dev); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetDevice(dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Vendor != "generic" {
		t.Errorf("new device vendor = %q, want generic (model default)", got.Vendor)
	}
}

// TestRegisteredMigrations_V71IsLast pins the version number the plan and
// CHANGELOG cite.
func TestRegisteredMigrations_V71IsLast(t *testing.T) {
	last := registeredMigrations[len(registeredMigrations)-1]
	if last.version != 71 || last.name != "vendor_backfill_final" {
		t.Fatalf("last migration = {%d %q}, want {71 vendor_backfill_final}", last.version, last.name)
	}
}
