package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestEnsureInterfaceAddrUniqueIndex_RepairsLegacyDuplicates is the
// regression for the production 42P10 failure.
//
// AUDIT-030's UPSERT targets the unique index idx_ifaddr_dev_ip. On a
// deployment that predates AUDIT-030, the table already held duplicate
// (device_id, ip_address) rows, so AutoMigrate could not create the
// index (CREATE UNIQUE INDEX fails on duplicate values) and silently
// logged a warning. The absent index then made every UPSERT fail with
// "no unique or exclusion constraint matching the ON CONFLICT
// specification" (SQLSTATE 42P10), 500ing the probe endpoint each poll.
//
// This test reconstructs that broken state — index dropped, duplicate
// rows inserted via raw SQL that bypasses the index — runs the repair,
// and asserts the index is back, duplicates collapsed to the newest row
// per pair, and a subsequent SaveInterfaceAddresses UPSERT succeeds.
func TestEnsureInterfaceAddrUniqueIndex_RepairsLegacyDuplicates(t *testing.T) {
	d := NewDatabaseForTesting(t)

	// Simulate the legacy broken state: drop the unique index so we can
	// insert duplicate (device_id, ip_address) rows the way a pre-fix
	// deployment did.
	if err := d.db.Exec(`DROP INDEX IF EXISTS idx_ifaddr_dev_ip`).Error; err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if d.db.Migrator().HasIndex(&models.InterfaceAddress{}, "idx_ifaddr_dev_ip") {
		t.Fatal("precondition failed: index still present after drop")
	}

	older := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	newer := older.Add(30 * time.Second)
	// Three rows for the same (1, "10.0.0.1") pair (the duplicate buildup)
	// plus one distinct pair that must survive untouched.
	if err := d.db.Exec(`INSERT INTO interface_addresses (timestamp, device_id, if_index, ip_address, net_mask) VALUES
		(?, 1, 0, '10.0.0.1', '255.255.255.0'),
		(?, 1, 0, '10.0.0.1', '255.255.255.0'),
		(?, 1, 1, '10.0.0.1', '255.255.255.0'),
		(?, 2, 0, '10.0.0.2', '255.255.255.0')`,
		older, older, newer, newer).Error; err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}

	// Run the repair.
	d.ensureInterfaceAddrUniqueIndex()

	// The index must now exist.
	if !d.db.Migrator().HasIndex(&models.InterfaceAddress{}, "idx_ifaddr_dev_ip") {
		t.Fatal("repair did not create idx_ifaddr_dev_ip")
	}

	// Duplicates for device 1 must collapse to a single row — the newest
	// (highest id), which carries if_index 1.
	var dev1 []models.InterfaceAddress
	if err := d.Gorm().Where("device_id = ?", 1).Find(&dev1).Error; err != nil {
		t.Fatalf("query device 1: %v", err)
	}
	if len(dev1) != 1 {
		t.Fatalf("device 1 rows after repair = %d, want 1 (duplicates should collapse to the newest)", len(dev1))
	}
	if dev1[0].IfIndex != 1 {
		t.Errorf("kept row if_index = %d, want 1 (the highest-id / most-recent duplicate)", dev1[0].IfIndex)
	}

	// The distinct device-2 pair must be untouched.
	var total int64
	if err := d.Gorm().Model(&models.InterfaceAddress{}).Count(&total).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 2 {
		t.Errorf("total rows after repair = %d, want 2 (one per distinct pair)", total)
	}

	// The whole point: the UPSERT path must now work instead of 42P10ing.
	if err := d.SaveInterfaceAddresses([]models.InterfaceAddress{{
		DeviceID: 1, IfIndex: 2, IPAddress: "10.0.0.1", NetMask: "255.255.255.0", Timestamp: newer.Add(time.Minute),
	}}); err != nil {
		t.Fatalf("UPSERT after repair failed (index still wrong?): %v", err)
	}
	var dev1After int64
	if err := d.Gorm().Model(&models.InterfaceAddress{}).Where("device_id = ?", 1).Count(&dev1After).Error; err != nil {
		t.Fatalf("recount device 1: %v", err)
	}
	if dev1After != 1 {
		t.Errorf("device 1 rows after post-repair UPSERT = %d, want 1 (UPSERT must update, not append)", dev1After)
	}
}

// TestEnsureInterfaceAddrUniqueIndex_Idempotent verifies the common
// path: when the index already exists (every fresh install), the repair
// is a no-op and does not touch existing rows.
func TestEnsureInterfaceAddrUniqueIndex_Idempotent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	if err := d.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: 1, IfIndex: 0, IPAddress: "10.0.0.1", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: 2, IfIndex: 0, IPAddress: "10.0.0.2", NetMask: "255.255.255.0", Timestamp: now},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Index is present from AutoMigrate — repair must do nothing.
	d.ensureInterfaceAddrUniqueIndex()

	var count int64
	if err := d.Gorm().Model(&models.InterfaceAddress{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Errorf("rows after no-op repair = %d, want 2 (repair must not alter data when the index exists)", count)
	}
}
