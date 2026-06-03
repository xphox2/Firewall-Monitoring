package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestSaveInterfaceAddresses_DedupsOnPoll_AUDIT030 is the regression
// for the audit: pre-fix SaveInterfaceAddresses was a plain
// `Create` that appended a row on every probe poll, even when the
// (device_id, ip_address) pair was unchanged. With 50 devices ×
// 4 polls/min × 90 days the table grew to ~25M rows of mostly-
// redundant data.
//
// The fix is a portable UPSERT: GORM's `clause.OnConflict` emits
// `INSERT ... ON CONFLICT (device_id, ip_address) DO UPDATE SET
// ...` on Postgres, and the equivalent UPSERT on SQLite. The
// conflict target is the unique index `idx_ifaddr_dev_ip` (declared
// on the model).
//
// The test seeds the same address twice (simulating two polls),
// then asserts that the table has exactly ONE row, with the
// LATEST timestamp / if_index / net_mask. A pre-fix run would
// have produced two rows.
func TestSaveInterfaceAddresses_DedupsOnPoll_AUDIT030(t *testing.T) {
	d := NewDatabaseForTesting(t)

	firstPoll := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	secondPoll := firstPoll.Add(15 * time.Second) // a probe polls every 15s

	// First poll: device 1, interface 0, IP 10.0.0.1/24.
	if err := d.SaveInterfaceAddresses([]models.InterfaceAddress{{
		DeviceID: 1, IfIndex: 0, IPAddress: "10.0.0.1", NetMask: "255.255.255.0",
		Timestamp: firstPoll,
	}}); err != nil {
		t.Fatalf("first poll: %v", err)
	}

	// Second poll: same device, same IP, slightly later, with
	// updated if_index (the device moved the IP to interface 1
	// between polls — a real scenario) and net_mask unchanged.
	if err := d.SaveInterfaceAddresses([]models.InterfaceAddress{{
		DeviceID: 1, IfIndex: 1, IPAddress: "10.0.0.1", NetMask: "255.255.255.0",
		Timestamp: secondPoll,
	}}); err != nil {
		t.Fatalf("second poll: %v", err)
	}

	// Assert: exactly one row, with the latest values.
	var rows []models.InterfaceAddress
	if err := d.Gorm().Find(&rows).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("after two polls of the same address, expected 1 row, got %d (AUDIT-030: the unique index on (device_id, ip_address) + UPSERT should collapse to a single row)", len(rows))
	}
	got := rows[0]
	if !got.Timestamp.Equal(secondPoll) {
		t.Errorf("timestamp = %v, want %v (latest poll's value)", got.Timestamp, secondPoll)
	}
	if got.IfIndex != 1 {
		t.Errorf("if_index = %d, want 1 (latest poll's value — the address moved interfaces)", got.IfIndex)
	}
	if got.IPAddress != "10.0.0.1" {
		t.Errorf("ip_address = %q, want \"10.0.0.1\"", got.IPAddress)
	}
}

// TestSaveInterfaceAddresses_PerDeviceDedup_AUDIT030 is the
// defensive sibling: dedup is per (device_id, ip_address), NOT
// per ip_address alone. Two devices with the same IP (a common
// pattern — both ends of a /30 link) must produce two rows.
func TestSaveInterfaceAddresses_PerDeviceDedup_AUDIT030(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	// Same IP, different devices.
	addrs := []models.InterfaceAddress{
		{DeviceID: 1, IfIndex: 0, IPAddress: "10.0.0.1", NetMask: "255.255.255.252", Timestamp: now},
		{DeviceID: 2, IfIndex: 0, IPAddress: "10.0.0.1", NetMask: "255.255.255.252", Timestamp: now},
	}
	if err := d.SaveInterfaceAddresses(addrs); err != nil {
		t.Fatalf("save: %v", err)
	}

	var rows []models.InterfaceAddress
	if err := d.Gorm().Order("device_id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("after saving the same IP for two devices, expected 2 rows, got %d (AUDIT-030: the unique index is on (device_id, ip_address), not ip_address alone)", len(rows))
	}
	if rows[0].DeviceID != 1 || rows[1].DeviceID != 2 {
		t.Errorf("row devices: got %d and %d, want 1 and 2", rows[0].DeviceID, rows[1].DeviceID)
	}
}

// TestSaveInterfaceAddresses_MultipleAddressesSameCall_AUDIT030
// — a single Save call with three different (device, ip) tuples
// must produce three rows. Defends against a future regression
// where someone "optimizes" the function by deduping in-process
// (which would be correct, but the unique-index test above is
// the source of truth — and a future agent might remove the
// in-Go dedup and rely on the DB).
func TestSaveInterfaceAddresses_MultipleAddressesSameCall_AUDIT030(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	addrs := []models.InterfaceAddress{
		{DeviceID: 1, IfIndex: 0, IPAddress: "10.0.0.1", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: 1, IfIndex: 1, IPAddress: "10.0.0.2", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: 2, IfIndex: 0, IPAddress: "10.0.0.1", NetMask: "255.255.255.0", Timestamp: now},
	}
	if err := d.SaveInterfaceAddresses(addrs); err != nil {
		t.Fatalf("save: %v", err)
	}

	var count int64
	if err := d.Gorm().Model(&models.InterfaceAddress{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 rows for 3 distinct (device, ip) tuples, got %d", count)
	}
}
