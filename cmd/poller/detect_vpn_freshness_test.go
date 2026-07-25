package main

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The bug these pin: a tunnel deleted from a device kept rendering on the
// connection map for days. The device stopped reporting VPN rows entirely, so its
// snapshot froze; the detector re-derived the pair from that frozen snapshot every
// cycle and re-stamped last_check, which starved the existing
// CleanupStaleAutoConnectionsBefore sweep so it never became a candidate.
//
// The fix is the same up -> stale -> deleted staircase the L2 detector uses.

func freshnessFixture(t *testing.T) (*Poller, *database.Database, models.Device, models.Device) {
	t.Helper()
	p, db := newTestPoller(t)
	site := &models.Site{Name: "S"}
	if err := db.CreateSite(site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	mk := func(name, ip string) models.Device {
		d := models.Device{Name: name, IPAddress: ip, Vendor: "fortigate", Enabled: true, SiteID: &site.ID}
		if err := db.CreateDevice(&d); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return d
	}
	return p, db, mk("A", "198.51.100.1"), mk("B", "203.0.113.1")
}

// seedPair writes a mutual pair of tunnel rows (each pointing at the other's mgmt
// IP) at the given age, which is what the ip_match strategy keys on.
func seedPair(t *testing.T, db *database.Database, a, b models.Device, status string, age time.Duration) {
	t.Helper()
	ts := time.Now().UTC().Add(-age)
	if err := db.SaveVPNStatuses([]models.VPNStatus{
		{DeviceID: a.ID, TunnelName: "tunA", RemoteIP: b.IPAddress, Status: status, Timestamp: ts},
		{DeviceID: b.ID, TunnelName: "tunB", RemoteIP: a.IPAddress, Status: status, Timestamp: ts},
	}); err != nil {
		t.Fatalf("seed vpn statuses: %v", err)
	}
}

func onlyConn(t *testing.T, db *database.Database) *models.DeviceConnection {
	t.Helper()
	conns, err := db.GetAllConnections()
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("want exactly 1 connection, got %d", len(conns))
	}
	return &conns[0]
}

// Fresh evidence must still produce a normal up/down edge — the gate must not
// suppress live data.
func TestDetectVPN_FreshEvidenceIsTrusted(t *testing.T) {
	p, db, a, b := freshnessFixture(t)
	seedPair(t, db, a, b, "up", time.Minute)

	n, ok := p.detectVPNConnections([]models.Device{a, b})
	if !ok || n != 1 {
		t.Fatalf("detect returned (%d, %t), want (1, true)", n, ok)
	}
	if got := onlyConn(t, db).Status; got != "up" {
		t.Errorf("status = %q, want up", got)
	}
}

// "Device reports it DOWN" is not the same as "device stopped reporting it".
// A fresh down row must render as down, never be reaped.
func TestDetectVPN_FreshDownIsNotReaped(t *testing.T) {
	p, db, a, b := freshnessFixture(t)
	seedPair(t, db, a, b, "down", time.Minute)

	if _, ok := p.detectVPNConnections([]models.Device{a, b}); !ok {
		t.Fatal("detect reported a failed read")
	}
	c := onlyConn(t, db)
	if c.Status != "down" {
		t.Errorf("status = %q, want down (a reported-down tunnel still exists)", c.Status)
	}
	if db.CleanupStaleAutoConnectionsBefore(time.Now().Add(-time.Second)) != 0 {
		t.Error("a freshly-refreshed connection must not be swept")
	}
}

// Between fresh and grace the connection is HELD as "stale": same row, same ID,
// last_check advanced so the sweep leaves it alone — the amber middle step.
func TestDetectVPN_StaleEvidenceHoldsConnection(t *testing.T) {
	p, db, a, b := freshnessFixture(t)
	seedPair(t, db, a, b, "up", database.VPNEvidenceFresh+30*time.Minute)

	cycleStart := time.Now()
	n, ok := p.detectVPNConnections([]models.Device{a, b})
	if !ok || n != 1 {
		t.Fatalf("detect returned (%d, %t), want (1, true) — a held pair still counts", n, ok)
	}
	c := onlyConn(t, db)
	if c.Status != "stale" {
		t.Errorf("status = %q, want stale — evidence is too old to assert up/down", c.Status)
	}
	if c.LastCheck.Before(cycleStart) {
		t.Error("a held connection must have last_check advanced so the sweep spares it")
	}
	if removed := db.CleanupStaleAutoConnectionsBefore(cycleStart); removed != 0 {
		t.Errorf("sweep removed %d held connection(s); a hold must survive its own cycle", removed)
	}
}

// Past grace the rows stop being served as state at all, so the pair is never
// re-derived, last_check stops advancing, and the EXISTING sweep reaps it. This is
// the reported symptom end to end.
func TestDetectVPN_ExpiredEvidenceIsReaped(t *testing.T) {
	p, db, a, b := freshnessFixture(t)
	// Pre-seed the ghost exactly as a previous cycle would have left it.
	if err := db.UpsertAutoConnection(a.ID, b.ID, "down", "tunA", "A ↔ B", "ipsec", "ip_match"); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	seedPair(t, db, a, b, "down", database.VPNEvidenceGrace+time.Hour)

	cycleStart := time.Now()
	n, ok := p.detectVPNConnections([]models.Device{a, b})
	if !ok {
		t.Fatal("detect reported a failed read")
	}
	if n != 0 {
		t.Errorf("detect re-derived %d pair(s) from expired evidence; it must derive none", n)
	}
	if removed := db.CleanupStaleAutoConnectionsBefore(cycleStart); removed != 1 {
		t.Fatalf("sweep removed %d connection(s), want 1 — the ghost must be reaped", removed)
	}
	conns, err := db.GetAllConnections()
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("ghost survived: %+v", conns)
	}
}

// A manually-created connection is the operator's, not the detector's, and must
// survive expired evidence untouched.
func TestDetectVPN_ManualConnectionNeverReaped(t *testing.T) {
	p, db, a, b := freshnessFixture(t)
	manual := &models.DeviceConnection{
		Name: "operator link", SourceDeviceID: a.ID, DestDeviceID: b.ID,
		ConnectionType: "ipsec", Status: "up", AutoDetected: false,
		LastCheck: time.Now().Add(-72 * time.Hour),
	}
	if err := db.Gorm().Create(manual).Error; err != nil {
		t.Fatalf("create manual connection: %v", err)
	}
	seedPair(t, db, a, b, "down", database.VPNEvidenceGrace+time.Hour)

	if _, ok := p.detectVPNConnections([]models.Device{a, b}); !ok {
		t.Fatal("detect reported a failed read")
	}
	db.CleanupStaleAutoConnectionsBefore(time.Now())

	var got models.DeviceConnection
	if err := db.Gorm().First(&got, manual.ID).Error; err != nil {
		t.Fatalf("manual connection was deleted: %v", err)
	}
	if got.Status != "up" {
		t.Errorf("manual connection status = %q, want untouched up", got.Status)
	}
}
