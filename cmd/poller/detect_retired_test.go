package main

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// A retired device must never be linked. In production a retired FortiGate's
// provisioned tunnel (status rollback_failed) re-created "? ↔ OPNsense" every
// cycle: RetireDevice deleted the row, the VPN detector wrote it back, and the
// map could not draw it because one end was not an active device.
//
// Each test asserts TWO things. No row may exist (counted UNSCOPED, so the
// active-only read paths cannot hide one), and the database backstop must not
// have fired, which proves the poller dropped the pair itself. The backstop
// alone would also leave no row, so without the second check these tests
// would pass with the poller filter removed.

// rawConnCount counts rows for a device pair, bypassing ActiveConnections.
func rawConnCount(t *testing.T, db *database.Database, a, b uint) int64 {
	t.Helper()
	var n int64
	if err := db.Gorm().Model(&models.DeviceConnection{}).
		Where("(source_device_id = ? AND dest_device_id = ?) OR (source_device_id = ? AND dest_device_id = ?)", a, b, b, a).
		Count(&n).Error; err != nil {
		t.Fatalf("count connections: %v", err)
	}
	return n
}

func assertNoRetiredLink(t *testing.T, db *database.Database, a, b uint) {
	t.Helper()
	if n := rawConnCount(t, db, a, b); n != 0 {
		t.Errorf("%d connection row(s) link device %d and retired device %d; want none", n, a, b)
	}
	if n := db.AutoConnectionSkipCount(); n != 0 {
		t.Errorf("the database backstop refused %d upsert(s): the detector offered a pair with a retired device instead of dropping it", n)
	}
}

func activeDevices(t *testing.T, db *database.Database) []models.Device {
	t.Helper()
	devs, err := db.GetActiveDevices()
	if err != nil {
		t.Fatalf("active devices: %v", err)
	}
	return devs
}

// THE REPORTED BUG. Phase 0 pairs from ipsec_tunnels, which keep a retired
// endpoint by design (other consumers rely on it), so the poller must drop it.
func TestDetectVPN_RetiredProvisionedEndpointIsNotLinked(t *testing.T) {
	f := newMapFixture(t)
	f.provision(t, "fwm-t12", f.fgt, f.opn, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})
	// The surviving peer still reports the provisioned tunnel.
	if err := f.db.SaveVPNStatuses([]models.VPNStatus{
		{DeviceID: f.opn.ID, TunnelName: "fwm-t12", TunnelType: "ipsec", Status: "down", Timestamp: time.Now()},
		// The retired device's own rows are still inside the grace window.
		parentRow(f.fgt.ID, "fwm-t12"),
		dialupRow(f.fgt.ID, "192.168.13.0/24", "192.168.50.0/32"),
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}
	if err := f.db.RetireDevice(f.fgt.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// A ghost row written by an older version, with an old last_check.
	ghost := models.DeviceConnection{
		Name: "? ↔ OPNsense", SourceDeviceID: f.fgt.ID, DestDeviceID: f.opn.ID,
		ConnectionType: "ipsec", Status: "down", AutoDetected: true,
		MatchMethod: "provisioned", LastCheck: time.Now().Add(-time.Hour),
	}
	if err := f.db.Gorm().Create(&ghost).Error; err != nil {
		t.Fatalf("seed ghost: %v", err)
	}

	cycleStart := time.Now()
	if _, ok := f.p.detectVPNConnections(activeDevices(t, f.db)); !ok {
		t.Fatal("detectVPNConnections reported a failed cycle; the stale sweep would be skipped and the ghost kept")
	}
	// The monitoring cycle sweeps what no detector refreshed (main.go).
	f.db.CleanupStaleAutoConnectionsBefore(cycleStart)
	assertNoRetiredLink(t, f.db, f.opn.ID, f.fgt.ID)

	// The shared provisioned-pair lookup is untouched: the surviving device's
	// VPN panel and chart grouping still resolve the tunnel.
	pairs, err := f.db.GetProvisionedTunnelPairs()
	if err != nil {
		t.Fatalf("provisioned pairs: %v", err)
	}
	if len(pairs) == 0 {
		t.Error("GetProvisionedTunnelPairs no longer returns the tunnel; its other consumers depend on it")
	}
}

// Phase 2 (tunnel_indirect) builds its pair without getPair, from latest VPN
// rows that still include a device retired inside the grace window.
func TestDetectVPN_RetiredDeviceRowsInGraceAreNotLinked(t *testing.T) {
	f := newMapFixture(t)
	// The retired FortiGate's tunnel name carries the surviving peer's name and
	// its remote IP resolves to no device: exactly the tunnel_indirect shape.
	if err := f.db.SaveVPNStatuses([]models.VPNStatus{
		{DeviceID: f.fgt.ID, TunnelName: "TO_OPNSENSE", TunnelType: "ipsec", RemoteIP: "198.51.100.9", Status: "up", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}

	// Sanity: while both are active, the row does produce the pair, so the
	// assertion below is about retirement and not a fixture that links nothing.
	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detect (active) reported a failed cycle")
	}
	if c := f.connFor(t, f.fgt.ID, f.opn.ID); c == nil || c.MatchMethod != "tunnel_indirect" {
		t.Fatalf("fixture did not produce a tunnel_indirect pair while both devices were active: %+v", c)
	}

	if err := f.db.RetireDevice(f.fgt.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, ok := f.p.detectVPNConnections(activeDevices(t, f.db)); !ok {
		t.Fatal("detectVPNConnections reported a failed cycle")
	}
	assertNoRetiredLink(t, f.db, f.opn.ID, f.fgt.ID)
}

// The overlay detector reads every latest interface, retired devices included.
func TestDetectOverlay_RetiredDeviceInterfacesAreNotLinked(t *testing.T) {
	p, db := newTestPoller(t)
	site := l2TestSite(t, db)
	a := l2TestDevice(t, db, "HUB-FW", "10.1.0.1", &site.ID)
	r := l2TestDevice(t, db, "OLD-FW", "10.2.0.1", &site.ID)

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: a.ID, Index: 40, Name: "vlan700", TypeName: "l3ipvlan", Status: "up", Timestamp: now},
		{DeviceID: r.ID, Index: 41, Name: "vlan700", TypeName: "l3ipvlan", Status: "up", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interfaces: %v", err)
	}
	// Latest interface addresses are read unscoped, so the retired device's
	// address still resolves to it (as it does in production).
	if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: r.ID, IfIndex: 41, IPAddress: "203.0.113.41", NetMask: "255.255.255.0", Timestamp: now},
	}); err != nil {
		t.Fatalf("save addr: %v", err)
	}
	// The hub's up tunnel points at that address, which is what verifies an
	// overlay's direct link.
	if err := db.SaveVPNStatuses([]models.VPNStatus{
		{DeviceID: a.ID, TunnelName: "TO_OLD", TunnelType: "ipsec", RemoteIP: "203.0.113.41", Status: "up", Timestamp: now},
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}

	// Sanity: while both are active, the overlay pair forms.
	if n, ok := p.detectOverlayConnections([]models.Device{a, r}); !ok || n != 1 {
		t.Fatalf("fixture: overlay detector created %d pair(s) (ok=%t) while both devices were active, want 1", n, ok)
	}

	if err := db.RetireDevice(r.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, ok := p.detectOverlayConnections(activeDevices(t, db)); !ok {
		t.Fatal("detectOverlayConnections reported a failed cycle")
	}
	assertNoRetiredLink(t, db, a.ID, r.ID)
}

// The L2 detector indexes MAC owners from unscoped interfaces, so a retired
// device can be a target; sameSite drops it because the retired id is not in
// the active index. Pinned so a change there cannot reopen the path.
func TestDetectL2_RetiredMACOwnerIsNotLinked(t *testing.T) {
	p, db := newTestPoller(t)
	site := l2TestSite(t, db)
	core := l2TestDevice(t, db, "fw-core", "192.168.5.1", &site.ID)
	branch := l2TestDevice(t, db, "fw-branch", "192.168.5.107", &site.ID)

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: core.ID, Index: 5, Name: "port5", TypeName: "ethernet", Status: "up", MACAddress: "AA:BB:CC:00:00:05", Timestamp: now},
		{DeviceID: branch.ID, Index: 3, Name: "lan3", TypeName: "ethernet", Status: "up", MACAddress: "AA:BB:CC:00:01:03", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface stats: %v", err)
	}
	if err := db.SaveTopologyEntriesSnapshot([]models.TopologyEntry{
		{DeviceID: core.ID, EntryType: "fdb", IfIndex: 5, MACAddress: "aa:bb:cc:00:01:03", VlanID: 10, Timestamp: now, Source: "snmp"},
		{DeviceID: branch.ID, EntryType: "fdb", IfIndex: 3, MACAddress: "aa:bb:cc:00:00:05", VlanID: 10, Timestamp: now, Source: "snmp"},
	}); err != nil {
		t.Fatalf("save topology: %v", err)
	}
	if err := db.RetireDevice(branch.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, ok := p.detectL2Links(activeDevices(t, db)); !ok {
		t.Fatal("detectL2Links reported a read failure")
	}
	assertNoRetiredLink(t, db, core.ID, branch.ID)
}
