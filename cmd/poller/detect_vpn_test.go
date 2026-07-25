package main

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestDetectVPNConnections_TunnelOverlay verifies that hub-and-spoke IPSec is
// mapped from the tunnel-interface overlay subnet alone, with NO fgVpnTunTable /
// VPNStatus rows present (the real-world case: dial-up spokes expose no tunnel
// table). The hub carries 192.168.255.1/24 on its tunnel interface and the spoke
// 192.168.255.2/32 on its own — a /32 inside the hub's /24 — and they are in
// different sites (IPSec is cross-site).
func TestDetectVPNConnections_TunnelOverlay(t *testing.T) {
	p, db := newTestPoller(t)

	hubSite := &models.Site{Name: "DC"}
	spokeSite := &models.Site{Name: "Branch"}
	if err := db.CreateSite(hubSite); err != nil {
		t.Fatalf("create hub site: %v", err)
	}
	if err := db.CreateSite(spokeSite); err != nil {
		t.Fatalf("create spoke site: %v", err)
	}
	mk := func(name, ip string, site *models.Site) models.Device {
		d := models.Device{Name: name, IPAddress: ip, Vendor: "fortigate", Enabled: true, SiteID: &site.ID}
		if err := db.CreateDevice(&d); err != nil {
			t.Fatalf("create device %s: %v", name, err)
		}
		return d
	}
	hub := mk("hub", "198.51.100.1", hubSite)
	spoke := mk("spoke", "203.0.113.1", spokeSite)

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: hub.ID, Index: 22, Name: "SPOKES", TypeName: "tunnel", Status: "up", Timestamp: now},
		{DeviceID: spoke.ID, Index: 20, Name: "HUB", TypeName: "tunnel", Status: "up", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface stats: %v", err)
	}
	if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: hub.ID, IfIndex: 22, IPAddress: "192.168.255.1", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: spoke.ID, IfIndex: 20, IPAddress: "192.168.255.2", NetMask: "255.255.255.255", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface addresses: %v", err)
	}

	n, ok := p.detectVPNConnections([]models.Device{hub, spoke})
	if !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}
	if n != 1 {
		t.Fatalf("detectVPNConnections found %d connections, want 1", n)
	}

	conns, err := db.GetAllConnections()
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("got %d connection rows, want 1", len(conns))
	}
	c := conns[0]
	if c.ConnectionType != "ipsec" {
		t.Errorf("connection_type = %q, want ipsec", c.ConnectionType)
	}
	if c.MatchMethod != "tunnel_overlay" {
		t.Errorf("match_method = %q, want tunnel_overlay", c.MatchMethod)
	}
	pair := map[uint]bool{c.SourceDeviceID: true, c.DestDeviceID: true}
	if !pair[hub.ID] || !pair[spoke.ID] {
		t.Errorf("connection between %d and %d, want hub %d and spoke %d", c.SourceDeviceID, c.DestDeviceID, hub.ID, spoke.ID)
	}
}

// TestDetectVPNConnections_SpokesNotLinkedToEachOther confirms two spokes, each a
// /32 host address inside the hub's overlay, are linked to the hub but NOT to one
// another (their /32s never contain each other).
func TestDetectVPNConnections_SpokesNotLinkedToEachOther(t *testing.T) {
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
	hub := mk("hub", "198.51.100.1")
	s1 := mk("spoke1", "203.0.113.1")
	s2 := mk("spoke2", "203.0.113.2")

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: hub.ID, Index: 1, Name: "SPOKES", TypeName: "tunnel", Status: "up", Timestamp: now},
		{DeviceID: s1.ID, Index: 1, Name: "HUB", TypeName: "tunnel", Status: "up", Timestamp: now},
		{DeviceID: s2.ID, Index: 1, Name: "HUB", TypeName: "tunnel", Status: "up", Timestamp: now},
	}); err != nil {
		t.Fatalf("save stats: %v", err)
	}
	if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: hub.ID, IfIndex: 1, IPAddress: "192.168.255.1", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: s1.ID, IfIndex: 1, IPAddress: "192.168.255.2", NetMask: "255.255.255.255", Timestamp: now},
		{DeviceID: s2.ID, IfIndex: 1, IPAddress: "192.168.255.3", NetMask: "255.255.255.255", Timestamp: now},
	}); err != nil {
		t.Fatalf("save addrs: %v", err)
	}

	p.detectVPNConnections([]models.Device{hub, s1, s2}) //nolint:errcheck // count/ok not asserted here

	conns, err := db.GetAllConnections()
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	// hub<->s1 and hub<->s2, but NOT s1<->s2 => exactly 2.
	if len(conns) != 2 {
		t.Fatalf("got %d connections, want 2 (hub-spoke only, no spoke-to-spoke)", len(conns))
	}
	for _, c := range conns {
		if c.SourceDeviceID != hub.ID && c.DestDeviceID != hub.ID {
			t.Errorf("connection %d<->%d does not involve the hub (spoke-to-spoke false positive)", c.SourceDeviceID, c.DestDeviceID)
		}
	}
}
