package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// These tests pin the VPN evidence horizon introduced to fix a rolled-back tunnel
// (fwm-t7) that kept rendering on the connection map for days after it was deleted
// from the device, and the mirror-image bug the same investigation uncovered: a
// live tunnel (fwm-t9) hidden from its own device page.
//
// Root cause of BOTH: "latest" was device-wide MAX(timestamp) with no age bound.
// A device that stops reporting freezes its snapshot forever (dead tunnels live
// on); and when two writers report at different cadences — SNMP ~60s vs the
// FortiGate SSH path at 900s — the slower writer's tunnels are masked by the
// faster writer's newer rows (live tunnels vanish). The fix is per-tunnel MAX
// bounded by VPNEvidenceGrace.

func vpnFreshnessDB(t *testing.T) *Database {
	t.Helper()
	d := NewDatabaseForTesting(t)
	if err := d.Gorm().AutoMigrate(&models.Device{}, &models.DeviceConnection{}, &models.VPNStatus{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

func mkVPN(t *testing.T, d *Database, deviceID uint, name, status string, ts time.Time) {
	t.Helper()
	if err := d.Gorm().Create(&models.VPNStatus{
		DeviceID: deviceID, TunnelName: name, Status: status, Timestamp: ts,
	}).Error; err != nil {
		t.Fatalf("create vpn_status %s: %v", name, err)
	}
}

func mkDev(t *testing.T, d *Database, name, ip string) *models.Device {
	t.Helper()
	dev := &models.Device{Name: name, IPAddress: ip}
	if err := d.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device %s: %v", name, err)
	}
	return dev
}

// The regression that motivated the horizon: a device whose whole snapshot froze
// (every tunnel deleted, so the collector posts nothing at all) must stop being
// served as current state.
func TestGetAllLatestVPNStatuses_ExpiresFrozenSnapshot(t *testing.T) {
	d := vpnFreshnessDB(t)
	now := time.Now().UTC()
	frozen := mkDev(t, d, "frozen", "10.0.0.1")
	live := mkDev(t, d, "live", "10.0.0.2")

	mkVPN(t, d, frozen.ID, "fwm-t7", "down", now.Add(-48*time.Hour))
	mkVPN(t, d, live.ID, "tun1", "up", now.Add(-1*time.Minute))

	got, err := d.GetAllLatestVPNStatuses()
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	for _, s := range got {
		if s.DeviceID == frozen.ID {
			t.Errorf("tunnel %q from a 48h-frozen snapshot must not be returned as current state", s.TunnelName)
		}
	}
	if len(got) != 1 || got[0].TunnelName != "tun1" {
		t.Errorf("want only the live tunnel, got %+v", got)
	}
}

// The mirror-image regression: two writers at different cadences on ONE device.
// Under the old device-wide MAX the slow writer's tunnel was masked entirely.
func TestGetAllLatestVPNStatuses_SlowWriterNotMaskedByFast(t *testing.T) {
	d := vpnFreshnessDB(t)
	now := time.Now().UTC()
	dev := mkDev(t, d, "fgt", "10.0.0.1")

	// Fast writer (SNMP, ~60s) and slow writer (SSH, ~900s), both well inside grace.
	mkVPN(t, d, dev.ID, "dialup-peer", "up", now.Add(-1*time.Minute))
	mkVPN(t, d, dev.ID, "fwm-t9", "up", now.Add(-20*time.Minute))
	// An older row for the SAME slow tunnel must not be returned alongside it.
	mkVPN(t, d, dev.ID, "fwm-t9", "down", now.Add(-40*time.Minute))

	got, err := d.GetAllLatestVPNStatuses()
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	byName := map[string]models.VPNStatus{}
	for _, s := range got {
		if prev, dup := byName[s.TunnelName]; dup {
			t.Errorf("tunnel %q returned twice (%v and %v) — per-tunnel MAX should yield one row",
				s.TunnelName, prev.Timestamp, s.Timestamp)
		}
		byName[s.TunnelName] = s
	}
	if _, ok := byName["fwm-t9"]; !ok {
		t.Error("the slow writer's tunnel is missing — a faster writer's newer row must not mask it")
	}
	if _, ok := byName["dialup-peer"]; !ok {
		t.Error("the fast writer's tunnel is missing")
	}
	if got := byName["fwm-t9"].Status; got != "up" {
		t.Errorf("fwm-t9 status = %q, want the NEWEST row's value 'up'", got)
	}
}

// Per-device isolation: one device expiring must not affect another.
func TestGetAllLatestVPNStatuses_GraceBoundary(t *testing.T) {
	d := vpnFreshnessDB(t)
	now := time.Now().UTC()
	dev := mkDev(t, d, "d", "10.0.0.1")

	mkVPN(t, d, dev.ID, "inside", "up", now.Add(-VPNEvidenceGrace).Add(time.Minute))
	mkVPN(t, d, dev.ID, "outside", "up", now.Add(-VPNEvidenceGrace).Add(-time.Minute))

	got, err := d.GetAllLatestVPNStatuses()
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	names := map[string]bool{}
	for _, s := range got {
		names[s.TunnelName] = true
	}
	if !names["inside"] {
		t.Error("a tunnel just inside the grace horizon must be returned")
	}
	if names["outside"] {
		t.Error("a tunnel just outside the grace horizon must be expired")
	}
}

// Device-scoped reader must expire the same way — this is the device-detail page.
func TestGetLatestVPNStatuses_ExpiresAndUnmasks(t *testing.T) {
	d := vpnFreshnessDB(t)
	now := time.Now().UTC()
	dev := mkDev(t, d, "fgt", "10.0.0.1")

	mkVPN(t, d, dev.ID, "dialup-peer", "up", now.Add(-1*time.Minute))
	mkVPN(t, d, dev.ID, "fwm-t9", "up", now.Add(-20*time.Minute))
	mkVPN(t, d, dev.ID, "fwm-t4", "unknown", now.Add(-48*time.Hour))

	got, err := d.GetLatestVPNStatuses(dev.ID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	names := map[string]bool{}
	for _, s := range got {
		names[s.TunnelName] = true
	}
	if !names["fwm-t9"] {
		t.Error("live tunnel on the slow writer must appear on the device page (the fwm-t9 regression)")
	}
	if names["fwm-t4"] {
		t.Error("a tunnel dead for 48h must not appear on the device page")
	}
	if !names["dialup-peer"] {
		t.Error("the fast writer's tunnel must still appear")
	}
}

// A device whose entire snapshot is beyond grace returns empty, not an error —
// callers treat nil error + empty as "no current tunnels".
func TestGetLatestVPNStatuses_AllExpiredReturnsEmpty(t *testing.T) {
	d := vpnFreshnessDB(t)
	dev := mkDev(t, d, "frozen", "10.0.0.1")
	mkVPN(t, d, dev.ID, "fwm-t7", "down", time.Now().UTC().Add(-48*time.Hour))

	got, err := d.GetLatestVPNStatuses(dev.ID)
	if err != nil {
		t.Fatalf("want nil error for an all-expired device, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no tunnels, got %+v", got)
	}
}

// The horizon must bound SNAPSHOT SELECTION only. LastUpAt is a historical
// annotation of a current tunnel and must still see older history.
func TestGetLatestVPNStatuses_EnrichmentStillSeesHistory(t *testing.T) {
	d := vpnFreshnessDB(t)
	now := time.Now().UTC()
	dev := mkDev(t, d, "d", "10.0.0.1")

	lastUp := now.Add(-2 * time.Hour)
	mkVPN(t, d, dev.ID, "tun1", "up", lastUp)                // inside grace, older
	mkVPN(t, d, dev.ID, "tun1", "down", now)                 // current state
	mkVPN(t, d, dev.ID, "tun1", "up", now.Add(-5*time.Hour)) // beyond grace

	got, err := d.GetLatestVPNStatuses(dev.ID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly the current snapshot row, got %d: %+v", len(got), got)
	}
	if got[0].Status != "down" {
		t.Errorf("current status = %q, want down (newest row)", got[0].Status)
	}
	if got[0].LastUpAt == nil {
		t.Fatal("LastUpAt must still be populated from history within the snapshot scan")
	}
	if got[0].LastUpAt.Before(lastUp.Add(-time.Minute)) {
		t.Errorf("LastUpAt = %v, want the most recent up (%v)", got[0].LastUpAt, lastUp)
	}
}

// The badge counts must agree with the device page rather than counting every
// tunnel the device ever reported (they previously used an unbounded per-tunnel
// MAX and kept counting tunnels dead for days).
func TestGetVPNTunnelCounts_ExcludesExpired(t *testing.T) {
	d := vpnFreshnessDB(t)
	now := time.Now().UTC()
	dev := mkDev(t, d, "d", "10.0.0.1")

	mkVPN(t, d, dev.ID, "fwm-t9", "up", now.Add(-2*time.Minute))
	mkVPN(t, d, dev.ID, "quiet", "unknown", now.Add(-3*time.Minute))
	mkVPN(t, d, dev.ID, "fwm-t4", "unknown", now.Add(-48*time.Hour))
	mkVPN(t, d, dev.ID, "fwm-t6", "down", now.Add(-48*time.Hour))

	up, total, err := d.GetVPNTunnelCounts(dev.ID)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	// "unknown" is present on the device, so it counts toward total but not up.
	if total != 2 {
		t.Errorf("total = %d, want 2 (the two tunnels inside the horizon)", total)
	}
	if up != 1 {
		t.Errorf("up = %d, want 1 (unknown is not up)", up)
	}
}
