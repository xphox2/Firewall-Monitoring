package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func topoEntry(deviceID uint, entryType, mac string, ifIndex int) models.TopologyEntry {
	return models.TopologyEntry{
		Timestamp:  time.Now(),
		DeviceID:   deviceID,
		EntryType:  entryType,
		IfIndex:    ifIndex,
		MACAddress: mac,
		Source:     "snmp",
	}
}

func countTopo(t *testing.T, db *Database, deviceID uint, entryType string) int64 {
	t.Helper()
	var n int64
	q := db.Gorm().Model(&models.TopologyEntry{}).Where("device_id = ?", deviceID)
	if entryType != "" {
		q = q.Where("entry_type = ?", entryType)
	}
	if err := q.Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestSaveTopologyEntriesSnapshot_ReplacesNotAppends pins the state-table
// semantics: a second save for the same device REPLACES its rows — rows
// absent from the new snapshot (a MAC that moved / aged out) must disappear,
// or the link inference would keep drawing stale links.
func TestSaveTopologyEntriesSnapshot_ReplacesNotAppends(t *testing.T) {
	db := NewDatabaseForTesting(t)

	first := []models.TopologyEntry{
		topoEntry(1, "fdb", "aa:bb:cc:00:00:01", 3),
		topoEntry(1, "fdb", "aa:bb:cc:00:00:02", 3),
	}
	if err := db.SaveTopologyEntriesSnapshot(first); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if got := countTopo(t, db, 1, "fdb"); got != 2 {
		t.Fatalf("after first save: %d rows, want 2", got)
	}

	second := []models.TopologyEntry{topoEntry(1, "fdb", "aa:bb:cc:00:00:01", 5)}
	if err := db.SaveTopologyEntriesSnapshot(second); err != nil {
		t.Fatalf("second save: %v", err)
	}
	if got := countTopo(t, db, 1, "fdb"); got != 1 {
		t.Fatalf("snapshot appended instead of replacing: %d rows, want 1", got)
	}
	var row models.TopologyEntry
	if err := db.Gorm().Where("device_id = ? AND entry_type = ?", 1, "fdb").First(&row).Error; err != nil {
		t.Fatalf("read row: %v", err)
	}
	if row.IfIndex != 5 {
		t.Errorf("surviving row is stale: ifIndex=%d, want 5 (the moved port)", row.IfIndex)
	}
}

// TestSaveTopologyEntriesSnapshot_ScopedByDeviceAndType: device A's save must
// not touch device B's rows, and an ARP-only batch (the FortiGate SSH
// supplement) must not wipe the same device's FDB rows.
func TestSaveTopologyEntriesSnapshot_ScopedByDeviceAndType(t *testing.T) {
	db := NewDatabaseForTesting(t)

	seed := []models.TopologyEntry{
		topoEntry(1, "fdb", "aa:bb:cc:00:00:01", 3),
		topoEntry(1, "arp", "aa:bb:cc:00:00:02", 4),
		topoEntry(2, "fdb", "aa:bb:cc:00:00:03", 7),
	}
	if err := db.SaveTopologyEntriesSnapshot(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// ARP-only refresh for device 1.
	if err := db.SaveTopologyEntriesSnapshot([]models.TopologyEntry{
		topoEntry(1, "arp", "aa:bb:cc:00:00:09", 4),
	}); err != nil {
		t.Fatalf("arp refresh: %v", err)
	}

	if got := countTopo(t, db, 1, "fdb"); got != 1 {
		t.Errorf("device 1 FDB wiped by an ARP-only batch: %d rows, want 1", got)
	}
	if got := countTopo(t, db, 1, "arp"); got != 1 {
		t.Errorf("device 1 ARP not replaced: %d rows, want 1", got)
	}
	if got := countTopo(t, db, 2, ""); got != 1 {
		t.Errorf("device 2 rows touched by device 1's save: %d rows, want 1", got)
	}
}

// TestGetTopologyEntriesSince_CutoffAndMACFilter: the poller's reader filters
// by age and (pre-lowercased) MAC allow-list in SQL.
func TestGetTopologyEntriesSince_CutoffAndMACFilter(t *testing.T) {
	db := NewDatabaseForTesting(t)

	old := topoEntry(1, "fdb", "aa:bb:cc:00:00:01", 3)
	old.Timestamp = time.Now().Add(-4 * time.Hour)
	fresh := topoEntry(1, "fdb", "aa:bb:cc:00:00:02", 3)
	other := topoEntry(1, "fdb", "dd:ee:ff:00:00:03", 4)
	if err := db.SaveTopologyEntriesSnapshot([]models.TopologyEntry{old, fresh, other}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := db.GetTopologyEntriesSince(time.Now().Add(-3*time.Hour), "fdb", []string{"aa:bb:cc:00:00:02"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1 || got[0].MACAddress != "aa:bb:cc:00:00:02" {
		t.Fatalf("cutoff+MAC filter wrong: %+v", got)
	}

	// nil allow-list = no MAC filter.
	all, err := db.GetTopologyEntriesSince(time.Now().Add(-3*time.Hour), "", nil)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("nil filter: %d rows, want 2 (old row excluded by cutoff)", len(all))
	}
}

// TestSaveTopologyNeighborsSnapshot_ScopedByProtocol mirrors the entries test
// for the neighbor table's (device, protocol) scoping.
func TestSaveTopologyNeighborsSnapshot_ScopedByProtocol(t *testing.T) {
	db := NewDatabaseForTesting(t)

	seed := []models.TopologyNeighbor{
		{Timestamp: time.Now(), DeviceID: 1, Protocol: "lldp", RemoteChassisID: "aa:bb:cc:00:00:01"},
		{Timestamp: time.Now(), DeviceID: 1, Protocol: "cdp", RemoteChassisID: "switch-a"},
	}
	if err := db.SaveTopologyNeighborsSnapshot(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// LLDP-only refresh must leave the CDP row alone.
	if err := db.SaveTopologyNeighborsSnapshot([]models.TopologyNeighbor{
		{Timestamp: time.Now(), DeviceID: 1, Protocol: "lldp", RemoteChassisID: "aa:bb:cc:00:00:99"},
	}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var n int64
	db.Gorm().Model(&models.TopologyNeighbor{}).Where("device_id = 1").Count(&n)
	if n != 2 {
		t.Fatalf("neighbor rows = %d, want 2 (1 lldp replaced + 1 cdp untouched)", n)
	}
	var lldp models.TopologyNeighbor
	db.Gorm().Where("device_id = 1 AND protocol = 'lldp'").First(&lldp)
	if lldp.RemoteChassisID != "aa:bb:cc:00:00:99" {
		t.Errorf("lldp row not replaced: %+v", lldp)
	}
}

// TestGetConnectionDetail_L2Evidence: a direct fdb_match connection's detail
// carries the evidence rows that drew it (same l2infer logic), with the
// reporting device's name and a freshness flag.
func TestGetConnectionDetail_L2Evidence(t *testing.T) {
	db := NewDatabaseForTesting(t)

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
	core := mk("fw-core", "192.168.5.1")
	branch := mk("fw-branch", "192.168.5.107")

	now := time.Now()
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: core.ID, Index: 5, Name: "port5", TypeName: "ethernet", Status: "up", MACAddress: "AA:BB:CC:00:00:05", Timestamp: now},
		{DeviceID: branch.ID, Index: 3, Name: "lan3", TypeName: "ethernet", Status: "up", MACAddress: "AA:BB:CC:00:01:03", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interface stats: %v", err)
	}
	if err := db.SaveTopologyEntriesSnapshot([]models.TopologyEntry{
		{DeviceID: core.ID, EntryType: "fdb", IfIndex: 5, MACAddress: "aa:bb:cc:00:01:03", Timestamp: now, Source: "snmp"},
		{DeviceID: branch.ID, EntryType: "fdb", IfIndex: 3, MACAddress: "aa:bb:cc:00:00:05", Timestamp: now, Source: "snmp"},
	}); err != nil {
		t.Fatalf("save topology: %v", err)
	}
	if err := db.UpsertAutoL2Connection(L2LinkUpsert{
		SourceID: core.ID, DestID: branch.ID, Status: "up",
		Name: "fw-core:port5 ↔ fw-branch:lan3", ConnType: "ethernet", MatchMethod: "fdb_match",
		SourceIfIndex: 5, SourceIfName: "port5", DestIfIndex: 3, DestIfName: "lan3",
		TunnelNames: "port5, lan3",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	conns, _ := db.GetAllConnections()
	if len(conns) != 1 {
		t.Fatalf("got %d connections, want 1", len(conns))
	}

	detail, err := db.GetConnectionDetail(conns[0].ID)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if detail.Family != "direct" {
		t.Fatalf("family = %q, want direct", detail.Family)
	}
	if len(detail.Evidence) == 0 {
		t.Fatal("evidence empty for a fresh fdb_match connection")
	}
	sawCore := false
	for _, ev := range detail.Evidence {
		if ev.Tier != "fdb" {
			t.Errorf("tier = %q, want fdb", ev.Tier)
		}
		if !ev.Fresh {
			t.Errorf("fresh evidence flagged stale: %+v", ev)
		}
		if ev.DeviceID == core.ID {
			sawCore = true
			if ev.DeviceName != "fw-core" || ev.LocalIfName != "port5" || ev.RemoteMAC != "aa:bb:cc:00:01:03" {
				t.Errorf("core evidence wrong: %+v", ev)
			}
		}
	}
	if !sawCore {
		t.Error("no evidence row from the source device")
	}
}

// TestResolveL2EndpointInterfaces_NoCrossDeviceNameCollision pins the live
// finding: FortiGates share hardware port names (internal1, dmz), so the
// legacy name-list resolution paired UNRELATED same-named interfaces from
// both boxes into one segment (mismatched IPs under one title). Port-level
// links must resolve each side on its own device only.
func TestResolveL2EndpointInterfaces_NoCrossDeviceNameCollision(t *testing.T) {
	db := NewDatabaseForTesting(t)

	site := &models.Site{Name: "DC2"}
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
	fw2 := mk("FW-TECHNICAL_LABS", "192.168.5.1")
	fw1 := mk("FW-HOME", "192.168.5.2")

	now := time.Now()
	// BOTH FortiGates have an interface named internal1 — different roles.
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: fw2.ID, Index: 4, Name: "internal1", TypeName: "ethernet", Status: "up", Timestamp: now},
		{DeviceID: fw1.ID, Index: 23, Name: "port23", TypeName: "ethernet", Status: "up", Timestamp: now},
		{DeviceID: fw1.ID, Index: 4, Name: "internal1", TypeName: "ethernet", Status: "up", Timestamp: now},
	}); err != nil {
		t.Fatalf("save interfaces: %v", err)
	}
	// FW1's internal1 carries an unrelated subnet — the legacy resolver
	// would have dragged it into the link's interface list by name.
	if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: fw1.ID, IfIndex: 4, IPAddress: "10.10.10.1", NetMask: "255.255.255.0", Timestamp: now},
	}); err != nil {
		t.Fatalf("save addresses: %v", err)
	}

	if err := db.UpsertAutoL2Connection(L2LinkUpsert{
		SourceID: fw2.ID, DestID: fw1.ID, Status: "up",
		Name: "FW-TECHNICAL_LABS:internal1 ↔ FW-HOME:port23", ConnType: "ethernet",
		MatchMethod:   "lldp_neighbor",
		SourceIfIndex: 4, SourceIfName: "internal1",
		DestIfIndex: 23, DestIfName: "port23",
		TunnelNames: "internal1, port23",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	conns, _ := db.GetAllConnections()
	if len(conns) != 1 {
		t.Fatalf("got %d connections, want 1", len(conns))
	}

	detail, err := db.GetConnectionDetail(conns[0].ID)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if len(detail.Interfaces) != 2 {
		t.Fatalf("got %d interface refs, want exactly the 2 endpoints: %+v", len(detail.Interfaces), detail.Interfaces)
	}
	for _, r := range detail.Interfaces {
		if r.DeviceID == fw1.ID && r.IfName == "internal1" {
			t.Fatalf("FW1's unrelated internal1 leaked into the link's interfaces (cross-device name collision): %+v", detail.Interfaces)
		}
	}
	var sawFW2Internal1, sawFW1Port23 bool
	for _, r := range detail.Interfaces {
		if r.DeviceID == fw2.ID && r.IfName == "internal1" && r.IfIndex == 4 {
			sawFW2Internal1 = true
		}
		if r.DeviceID == fw1.ID && r.IfName == "port23" && r.IfIndex == 23 {
			sawFW1Port23 = true
		}
	}
	if !sawFW2Internal1 || !sawFW1Port23 {
		t.Fatalf("endpoint interfaces missing (fw2:internal1=%v fw1:port23=%v): %+v", sawFW2Internal1, sawFW1Port23, detail.Interfaces)
	}
}
