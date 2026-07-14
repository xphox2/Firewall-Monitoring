package main

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

func l2TestSite(t *testing.T, db *database.Database) *models.Site {
	t.Helper()
	site := &models.Site{Name: "HQ"}
	if err := db.CreateSite(site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	return site
}

func l2TestDevice(t *testing.T, db *database.Database, name, ip string, siteID *uint) models.Device {
	t.Helper()
	d := models.Device{Name: name, IPAddress: ip, Vendor: "fortigate", Enabled: true, SiteID: siteID}
	if err := db.CreateDevice(&d); err != nil {
		t.Fatalf("create device %s: %v", name, err)
	}
	return d
}

// TestDetectL2Links_FDBCreatesPortLink: bidirectional FDB evidence creates
// ONE port-level link with both interface names, fdb_match method, and port
// columns populated. Interface MACs are seeded UPPERCASE (as the collector's
// interface-stats formatter sends them) against lowercase topology rows —
// the normalization boundary must hold end-to-end.
func TestDetectL2Links_FDBCreatesPortLink(t *testing.T) {
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

	n := p.detectL2Links([]models.Device{core, branch})
	if n != 1 {
		t.Fatalf("detectL2Links created %d links, want 1", n)
	}
	conns, err := db.GetAllConnections()
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("got %d connection rows, want 1", len(conns))
	}
	c := conns[0]
	if c.MatchMethod != "fdb_match" || c.ConnectionType != "ethernet" || c.Status != "up" {
		t.Errorf("method/type/status wrong: %+v", c)
	}
	if c.SourceIfName != "port5" || c.DestIfName != "lan3" || c.SourceIfIndex != 5 || c.DestIfIndex != 3 {
		t.Errorf("port attribution wrong: src=%s(%d) dst=%s(%d)", c.SourceIfName, c.SourceIfIndex, c.DestIfName, c.DestIfIndex)
	}
	if c.VLANIDs != "10" {
		t.Errorf("vlan_ids = %q, want 10", c.VLANIDs)
	}
	if !strings.Contains(c.TunnelNames, "port5") || !strings.Contains(c.TunnelNames, "lan3") {
		t.Errorf("tunnel_names = %q, want both port names", c.TunnelNames)
	}
	if !strings.Contains(c.Name, "fw-core:port5") || !strings.Contains(c.Name, "fw-branch:lan3") {
		t.Errorf("name = %q, want port-labeled", c.Name)
	}
}

// TestDetectL2Links_NoSubnetGuess is the REQUIRED regression for the feature:
// two same-site devices sharing a subnet, both reporting fresh non-trivial
// FDB snapshots that do NOT contain each other's MACs → NO link is created.
// (The old detector would have drawn one from the shared subnet alone.)
func TestDetectL2Links_NoSubnetGuess(t *testing.T) {
	p, db := newTestPoller(t)
	site := l2TestSite(t, db)
	fw1 := l2TestDevice(t, db, "fw1", "10.0.0.1", &site.ID)
	fw2 := l2TestDevice(t, db, "fw2", "10.0.0.2", &site.ID)

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: fw1.ID, Index: 1, Name: "internal", TypeName: "bridge", Status: "up", MACAddress: "AA:BB:CC:00:10:01", Timestamp: now},
		{DeviceID: fw2.ID, Index: 1, Name: "internal", TypeName: "bridge", Status: "up", MACAddress: "AA:BB:CC:00:20:01", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface stats: %v", err)
	}
	// Shared subnet — the old heuristic's trigger.
	if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: fw1.ID, IfIndex: 1, IPAddress: "10.0.0.1", NetMask: "255.255.255.0", Timestamp: now},
		{DeviceID: fw2.ID, IfIndex: 1, IPAddress: "10.0.0.2", NetMask: "255.255.255.0", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface addresses: %v", err)
	}
	// Fresh FDB on both devices, but with only unrelated host MACs — the
	// devices are NOT actually adjacent.
	if err := db.SaveTopologyEntriesSnapshot([]models.TopologyEntry{
		{DeviceID: fw1.ID, EntryType: "fdb", IfIndex: 1, MACAddress: "11:11:11:11:11:11", Timestamp: now, Source: "snmp"},
		{DeviceID: fw2.ID, EntryType: "fdb", IfIndex: 1, MACAddress: "22:22:22:22:22:22", Timestamp: now, Source: "snmp"},
	}); err != nil {
		t.Fatalf("save topology: %v", err)
	}

	if n := p.detectL2Links([]models.Device{fw1, fw2}); n != 0 {
		t.Fatalf("detectL2Links created %d links, want 0 (no L2 evidence of adjacency)", n)
	}
	conns, _ := db.GetAllConnections()
	if len(conns) != 0 {
		t.Fatalf("got %d connection rows, want 0 — the subnet guess must be gone", len(conns))
	}
}

// TestDetectL2Links_CrossSiteIgnored: perfect FDB evidence across different
// sites must not pair (same boundary as every other detector).
func TestDetectL2Links_CrossSiteIgnored(t *testing.T) {
	p, db := newTestPoller(t)
	siteA := l2TestSite(t, db)
	siteB := &models.Site{Name: "B"}
	if err := db.CreateSite(siteB); err != nil {
		t.Fatalf("create site B: %v", err)
	}
	a := l2TestDevice(t, db, "a", "10.0.0.1", &siteA.ID)
	b := l2TestDevice(t, db, "b", "10.0.0.2", &siteB.ID)

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: a.ID, Index: 1, Name: "port1", TypeName: "ethernet", Status: "up", MACAddress: "AA:BB:CC:00:30:01", Timestamp: now},
		{DeviceID: b.ID, Index: 1, Name: "port1", TypeName: "ethernet", Status: "up", MACAddress: "AA:BB:CC:00:40:01", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface stats: %v", err)
	}
	if err := db.SaveTopologyEntriesSnapshot([]models.TopologyEntry{
		{DeviceID: a.ID, EntryType: "fdb", IfIndex: 1, MACAddress: "aa:bb:cc:00:40:01", Timestamp: now, Source: "snmp"},
	}); err != nil {
		t.Fatalf("save topology: %v", err)
	}

	if n := p.detectL2Links([]models.Device{a, b}); n != 0 {
		t.Fatalf("cross-site link created (%d), want 0", n)
	}
}

// TestDetectL2Links_StalenessTransitions: fresh evidence → up; older than the
// fresh window but within grace → status "stale"; older than grace → not
// upserted, and the cycle sweep deletes the previous row.
func TestDetectL2Links_StalenessTransitions(t *testing.T) {
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

	seed := func(age time.Duration) {
		t.Helper()
		if err := db.SaveTopologyEntriesSnapshot([]models.TopologyEntry{
			{DeviceID: core.ID, EntryType: "fdb", IfIndex: 5, MACAddress: "aa:bb:cc:00:01:03", Timestamp: now.Add(-age), Source: "snmp"},
		}); err != nil {
			t.Fatalf("save topology: %v", err)
		}
	}

	// Fresh → up.
	seed(time.Minute)
	if n := p.detectL2Links([]models.Device{core, branch}); n != 1 {
		t.Fatalf("fresh: created %d, want 1", n)
	}
	conns, _ := db.GetAllConnections()
	if len(conns) != 1 || conns[0].Status != "up" {
		t.Fatalf("fresh link wrong: %+v", conns)
	}

	// Within grace but past fresh → stale (same row, same ID).
	prevID := conns[0].ID
	seed(time.Hour)
	if n := p.detectL2Links([]models.Device{core, branch}); n != 1 {
		t.Fatalf("stale window: created %d, want 1", n)
	}
	conns, _ = db.GetAllConnections()
	if len(conns) != 1 || conns[0].Status != "stale" || conns[0].ID != prevID {
		t.Fatalf("stale transition wrong: %+v", conns)
	}

	// Past grace → not refreshed → swept by the cycle cleanup.
	seed(4 * time.Hour)
	cycleStart := time.Now()
	if n := p.detectL2Links([]models.Device{core, branch}); n != 0 {
		t.Fatalf("past grace: created %d, want 0", n)
	}
	db.CleanupStaleAutoConnectionsBefore(cycleStart)
	conns, _ = db.GetAllConnections()
	if len(conns) != 0 {
		t.Fatalf("expired link not swept: %+v", conns)
	}
}

// TestUpsertAutoL2Connection_Semantics pins the upsert key and contracts:
// exact-port refresh keeps the row ID; a portless legacy row is adopted (ID
// survives); manual rows block auto rows; two one-sided links on different
// dest ports don't collide (dest_if_index is part of the key); direction
// normalization swaps the port fields with the device IDs.
func TestUpsertAutoL2Connection_Semantics(t *testing.T) {
	db := database.NewDatabaseForTesting(t)

	base := database.L2LinkUpsert{
		SourceID: 1, DestID: 2, Status: "up", Name: "a:p1 ↔ b:p2",
		ConnType: "ethernet", MatchMethod: "fdb_match",
		SourceIfIndex: 1, SourceIfName: "p1", DestIfIndex: 2, DestIfName: "p2",
	}
	if err := db.UpsertAutoL2Connection(base); err != nil {
		t.Fatalf("create: %v", err)
	}
	conns, _ := db.GetAllConnections()
	if len(conns) != 1 {
		t.Fatalf("got %d rows, want 1", len(conns))
	}
	id := conns[0].ID

	// Exact refresh → same row.
	base.Status = "down"
	if err := db.UpsertAutoL2Connection(base); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	conns, _ = db.GetAllConnections()
	if len(conns) != 1 || conns[0].ID != id || conns[0].Status != "down" {
		t.Fatalf("exact refresh wrong: %+v", conns)
	}

	// Different dest port on a one-sided sibling → NEW row, no collision.
	oneSided1 := database.L2LinkUpsert{
		SourceID: 3, DestID: 4, Status: "up", Name: "c ↔ d", ConnType: "ethernet",
		MatchMethod: "arp_match", DestIfIndex: 7, DestIfName: "p7",
	}
	oneSided2 := oneSided1
	oneSided2.DestIfIndex, oneSided2.DestIfName = 8, "p8"
	if err := db.UpsertAutoL2Connection(oneSided1); err != nil {
		t.Fatalf("one-sided 1: %v", err)
	}
	if err := db.UpsertAutoL2Connection(oneSided2); err != nil {
		t.Fatalf("one-sided 2: %v", err)
	}
	var n int64
	db.Gorm().Model(&models.DeviceConnection{}).Where("source_device_id = 3").Count(&n)
	if n != 2 {
		t.Fatalf("one-sided links collided: %d rows, want 2", n)
	}

	// Adoption: a portless legacy auto row is upgraded in place (ID kept).
	legacy := &models.DeviceConnection{
		Name: "e ↔ f", SourceDeviceID: 5, DestDeviceID: 6,
		ConnectionType: "ethernet", Status: "up", AutoDetected: true, MatchMethod: "ip_match",
	}
	if err := db.Gorm().Create(legacy).Error; err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	adopt := database.L2LinkUpsert{
		SourceID: 5, DestID: 6, Status: "up", Name: "e:p1 ↔ f:p2", ConnType: "ethernet",
		MatchMethod: "lldp_neighbor", SourceIfIndex: 1, SourceIfName: "p1", DestIfIndex: 2, DestIfName: "p2",
	}
	if err := db.UpsertAutoL2Connection(adopt); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	var adopted models.DeviceConnection
	db.Gorm().Where("source_device_id = 5").First(&adopted)
	if adopted.ID != legacy.ID || adopted.MatchMethod != "lldp_neighbor" || adopted.SourceIfName != "p1" {
		t.Fatalf("adoption failed: %+v (legacy id %d)", adopted, legacy.ID)
	}
	db.Gorm().Model(&models.DeviceConnection{}).Where("source_device_id = 5").Count(&n)
	if n != 1 {
		t.Fatalf("adoption duplicated the row: %d, want 1", n)
	}

	// Manual row blocks auto rows entirely.
	manual := &models.DeviceConnection{
		Name: "manual", SourceDeviceID: 7, DestDeviceID: 8,
		ConnectionType: "ethernet", Status: "up", AutoDetected: false,
	}
	if err := db.Gorm().Create(manual).Error; err != nil {
		t.Fatalf("seed manual: %v", err)
	}
	blocked := database.L2LinkUpsert{
		SourceID: 7, DestID: 8, Status: "up", Name: "x", ConnType: "ethernet",
		MatchMethod: "fdb_match", SourceIfIndex: 1, DestIfIndex: 2,
	}
	if err := db.UpsertAutoL2Connection(blocked); err != nil {
		t.Fatalf("blocked upsert errored: %v", err)
	}
	db.Gorm().Model(&models.DeviceConnection{}).Where("source_device_id = 7").Count(&n)
	if n != 1 {
		t.Fatalf("manual row did not block: %d rows, want 1", n)
	}
	var m models.DeviceConnection
	db.Gorm().Where("source_device_id = 7").First(&m)
	if m.Name != "manual" || m.AutoDetected {
		t.Fatalf("manual row touched: %+v", m)
	}

	// Direction normalization: reporter with the higher ID → ports swap.
	rev := database.L2LinkUpsert{
		SourceID: 10, DestID: 9, Status: "up", Name: "rev", ConnType: "ethernet",
		MatchMethod: "fdb_match", SourceIfIndex: 5, SourceIfName: "p5", DestIfIndex: 3, DestIfName: "p3",
	}
	if err := db.UpsertAutoL2Connection(rev); err != nil {
		t.Fatalf("rev: %v", err)
	}
	var norm models.DeviceConnection
	db.Gorm().Where("source_device_id = 9").First(&norm)
	if norm.SourceDeviceID != 9 || norm.DestDeviceID != 10 ||
		norm.SourceIfIndex != 3 || norm.SourceIfName != "p3" ||
		norm.DestIfIndex != 5 || norm.DestIfName != "p5" {
		t.Fatalf("direction normalization wrong: %+v", norm)
	}
}
