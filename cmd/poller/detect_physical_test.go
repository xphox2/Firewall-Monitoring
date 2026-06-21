package main

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestDetectPhysicalConnections_FortiGateSwitchInterface is a regression guard
// for the real-world case observed on two FortiGates sharing a LAN: one carries
// the subnet IP on a plain Ethernet port, the other on its "internal" hardware
// switch, which SNMP reports as ifType 209 (bridge). The subnet detector must
// pair them even though one side is not a bare ethernet/lag interface — bridge,
// l2vlan and propVirtual are all valid LAN-segment interface types.
func TestDetectPhysicalConnections_FortiGateSwitchInterface(t *testing.T) {
	p, db := newTestPoller(t, nil)

	site := &models.Site{Name: "HQ"}
	if err := db.CreateSite(site); err != nil {
		t.Fatalf("create site: %v", err)
	}

	mk := func(name, ip string) models.Device {
		d := models.Device{Name: name, IPAddress: ip, Vendor: "fortigate", Enabled: true, SiteID: &site.ID}
		if err := db.CreateDevice(&d); err != nil {
			t.Fatalf("create device %s: %v", name, err)
		}
		return d
	}
	vm := mk("fw-vm", "192.168.25.1")         // LAN IP on port3 (ethernet)
	existing := mk("fw-01", "192.168.25.254") // LAN IP on internal (bridge)

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: vm.ID, Index: 3, Name: "port3", TypeName: "ethernet", Status: "up", Timestamp: now},
		{DeviceID: existing.ID, Index: 6, Name: "internal", TypeName: "bridge", Status: "up", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface stats: %v", err)
	}
	if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: vm.ID, IfIndex: 3, IPAddress: "192.168.25.1", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: existing.ID, IfIndex: 6, IPAddress: "192.168.25.254", NetMask: "255.255.255.0", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface addresses: %v", err)
	}

	n := p.detectPhysicalConnections([]models.Device{vm, existing})
	if n != 1 {
		t.Fatalf("detectPhysicalConnections created %d connections, want 1", n)
	}

	conns, err := db.GetAllConnections()
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("got %d connection rows, want 1", len(conns))
	}
	c := conns[0]
	if c.MatchMethod != "subnet_match" {
		t.Errorf("match_method = %q, want subnet_match", c.MatchMethod)
	}
	if c.ConnectionType != "ethernet" {
		t.Errorf("connection_type = %q, want ethernet", c.ConnectionType)
	}
	pair := map[uint]bool{c.SourceDeviceID: true, c.DestDeviceID: true}
	if !pair[vm.ID] || !pair[existing.ID] {
		t.Errorf("connection is between %d and %d, want %d and %d", c.SourceDeviceID, c.DestDeviceID, vm.ID, existing.ID)
	}
}

// TestDetectPhysicalConnections_ExcludesTunnelAndCrossSite locks in the
// boundaries: tunnel/loopback interfaces are never LAN segments, and a shared
// subnet across different sites must not be paired.
func TestDetectPhysicalConnections_ExcludesTunnelAndCrossSite(t *testing.T) {
	p, db := newTestPoller(t, nil)

	siteA := &models.Site{Name: "A"}
	siteB := &models.Site{Name: "B"}
	if err := db.CreateSite(siteA); err != nil {
		t.Fatalf("create site A: %v", err)
	}
	if err := db.CreateSite(siteB); err != nil {
		t.Fatalf("create site B: %v", err)
	}

	mk := func(name, ip string, site *models.Site) models.Device {
		d := models.Device{Name: name, IPAddress: ip, Vendor: "fortigate", Enabled: true, SiteID: &site.ID}
		if err := db.CreateDevice(&d); err != nil {
			t.Fatalf("create device %s: %v", name, err)
		}
		return d
	}
	// Same subnet but DIFFERENT sites -> must not pair.
	a := mk("a", "10.0.0.1", siteA)
	b := mk("b", "10.0.0.2", siteB)
	// Same site, but the shared subnet is on tunnel interfaces -> must not pair.
	c := mk("c", "10.1.1.1", siteA)
	d := mk("d", "10.1.1.2", siteA)

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: a.ID, Index: 1, Name: "port1", TypeName: "ethernet", Status: "up", Timestamp: now},
		{DeviceID: b.ID, Index: 1, Name: "port1", TypeName: "ethernet", Status: "up", Timestamp: now},
		{DeviceID: c.ID, Index: 9, Name: "tun0", TypeName: "tunnel", Status: "up", Timestamp: now},
		{DeviceID: d.ID, Index: 9, Name: "tun0", TypeName: "tunnel", Status: "up", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface stats: %v", err)
	}
	if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: a.ID, IfIndex: 1, IPAddress: "10.0.0.1", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: b.ID, IfIndex: 1, IPAddress: "10.0.0.2", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: c.ID, IfIndex: 9, IPAddress: "10.1.1.1", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: d.ID, IfIndex: 9, IPAddress: "10.1.1.2", NetMask: "255.255.255.0", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface addresses: %v", err)
	}

	p.detectPhysicalConnections([]models.Device{a, b, c, d})

	conns, err := db.GetAllConnections()
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 0 {
		t.Fatalf("got %d connection rows, want 0 (cross-site and tunnel must not pair)", len(conns))
	}
}
