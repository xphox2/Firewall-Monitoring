package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// GetAllLatestInterfaces was rewritten from an unbounded
// `INNER JOIN (SELECT device_id, MAX(timestamp) ... GROUP BY device_id)` — which
// production measured as a Parallel Seq Scan reading 423,092 buffers ~4x/minute,
// making interface_stats the single largest source of read I/O in the database —
// into a correlated subquery driven from the small devices table (60 buffers,
// 0.836ms).
//
// A time bound was the obvious alternative and was rejected: three of the four
// poller callers need a window wider than any value that helps, and
// detectOverlayConnections has no freshness gate at all, so a bound would delete
// live edges. These tests pin the properties that made the correlated form the
// safe choice.

// TestGetAllLatestInterfaces_ReturnsWholeNewestSnapshotPerDevice is the core
// equivalence property: one row per interface for each device's most recent
// poll, and nothing from any earlier poll.
func TestGetAllLatestInterfaces_ReturnsWholeNewestSnapshotPerDevice(t *testing.T) {
	d := NewDatabaseForTesting(t)

	old := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC)

	for _, dev := range []models.Device{{Name: "fw-a"}, {Name: "fw-b"}} {
		if err := d.db.Create(&dev).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}

	rows := []models.InterfaceStats{
		// Device 1: two interfaces in the old poll, three in the newest.
		{DeviceID: 1, Timestamp: old, Name: "old1", Index: 1},
		{DeviceID: 1, Timestamp: old, Name: "old2", Index: 2},
		{DeviceID: 1, Timestamp: newer, Name: "new1", Index: 1},
		{DeviceID: 1, Timestamp: newer, Name: "new2", Index: 2},
		{DeviceID: 1, Timestamp: newer, Name: "new3", Index: 3},
		// Device 2: only an old poll — it must still be reported. This is the
		// case a time bound would silently drop.
		{DeviceID: 2, Timestamp: old, Name: "quiet1", Index: 1},
	}
	for i := range rows {
		if err := d.db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed stats: %v", err)
		}
	}

	got, err := d.GetAllLatestInterfaces()
	if err != nil {
		t.Fatalf("GetAllLatestInterfaces: %v", err)
	}

	byDev := map[uint][]string{}
	for _, r := range got {
		byDev[r.DeviceID] = append(byDev[r.DeviceID], r.Name)
	}
	if len(byDev[1]) != 3 {
		t.Errorf("device 1 returned %d interfaces (%v), want the 3 from its newest poll", len(byDev[1]), byDev[1])
	}
	for _, n := range byDev[1] {
		if n == "old1" || n == "old2" {
			t.Errorf("device 1 returned %q from a superseded poll", n)
		}
	}
	if len(byDev[2]) != 1 {
		t.Errorf("device 2 returned %d interfaces, want 1 — a device whose newest poll is old must still report; "+
			"this is exactly what a `since` bound would drop, breaking VPN/overlay/L2 detection", len(byDev[2]))
	}
}

// TestGetAllLatestInterfaces_IncludesRetiredDevices guards the scoping trap.
// The old query grouped over interface_stats and so included retired devices;
// the poller filters separately via GetActiveDevices. Adding ActiveDevices to
// the driving scan here would silently remove a retired-but-still-reporting
// device's interfaces from link detection.
func TestGetAllLatestInterfaces_IncludesRetiredDevices(t *testing.T) {
	d := NewDatabaseForTesting(t)

	retiredAt := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	dev := models.Device{Name: "fw-retired", RetiredAt: &retiredAt}
	if err := d.db.Create(&dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	st := models.InterfaceStats{DeviceID: dev.ID, Timestamp: time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC), Name: "wan1"}
	if err := d.db.Create(&st).Error; err != nil {
		t.Fatalf("seed stats: %v", err)
	}

	got, err := d.GetAllLatestInterfaces()
	if err != nil {
		t.Fatalf("GetAllLatestInterfaces: %v", err)
	}
	if len(got) != 1 || got[0].DeviceID != dev.ID {
		t.Fatalf("retired device's interfaces were dropped (got %d rows); the driving devices scan must NOT be scoped to active devices", len(got))
	}
}

// TestGetAllLatestInterfaces_DropsOrphanedTelemetry documents the one accepted
// behaviour delta. The old query derived its device set from interface_stats, so
// rows whose device_id has no devices row (device_id 0, or a legacy hard delete
// before the purge job existed) were returned with no device. The rewrite is
// driven by devices and drops them. That is the desirable direction, but it is a
// difference and is pinned so it stays deliberate.
func TestGetAllLatestInterfaces_DropsOrphanedTelemetry(t *testing.T) {
	d := NewDatabaseForTesting(t)

	dev := models.Device{Name: "fw-real"}
	if err := d.db.Create(&dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	ts := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	for _, r := range []models.InterfaceStats{
		{DeviceID: dev.ID, Timestamp: ts, Name: "wan1"},
		{DeviceID: 0, Timestamp: ts, Name: "orphan-zero"},
		{DeviceID: 9999, Timestamp: ts, Name: "orphan-deleted"},
	} {
		if err := d.db.Create(&r).Error; err != nil {
			t.Fatalf("seed stats: %v", err)
		}
	}

	got, err := d.GetAllLatestInterfaces()
	if err != nil {
		t.Fatalf("GetAllLatestInterfaces: %v", err)
	}
	for _, r := range got {
		if r.DeviceID != dev.ID {
			t.Errorf("orphaned telemetry for device_id %d leaked into the result", r.DeviceID)
		}
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1 (only the real device)", len(got))
	}
}

// TestGetLatestInterfaceAddresses_NewestPerDevice covers the sibling rewrite.
func TestGetLatestInterfaceAddresses_NewestPerDevice(t *testing.T) {
	d := NewDatabaseForTesting(t)

	dev := models.Device{Name: "fw-a"}
	if err := d.db.Create(&dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	old := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC)
	for _, a := range []models.InterfaceAddress{
		{DeviceID: dev.ID, Timestamp: old, IPAddress: "10.0.0.1"},
		{DeviceID: dev.ID, Timestamp: newer, IPAddress: "10.0.0.2"},
		{DeviceID: dev.ID, Timestamp: newer, IPAddress: "10.0.0.3"},
	} {
		if err := d.db.Create(&a).Error; err != nil {
			t.Fatalf("seed addr: %v", err)
		}
	}

	got, err := d.GetLatestInterfaceAddresses()
	if err != nil {
		t.Fatalf("GetLatestInterfaceAddresses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d addresses, want the 2 from the newest snapshot", len(got))
	}
	for _, a := range got {
		if a.IPAddress == "10.0.0.1" {
			t.Error("returned an address from a superseded snapshot")
		}
	}
}
