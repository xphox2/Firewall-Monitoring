package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetConnectionTraffic_VPNSingleEndpoint pins the v0.11.57 fix: a VPN tunnel
// is reported at BOTH endpoints (each device counts the same bytes on its own
// tunnel interface), so summing src+dst doubled the throughput. The traffic must
// aggregate ONE endpoint only (source preferred), matching the direct path's
// single-endpoint rule.
func TestGetConnectionTraffic_VPNSingleEndpoint(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.Create(&models.Device{ID: 1, Name: "HUB-FW1"}).Error; err != nil {
		t.Fatalf("dev1: %v", err)
	}
	if err := d.db.Create(&models.Device{ID: 2, Name: "SPOKE-FW1"}).Error; err != nil {
		t.Fatalf("dev2: %v", err)
	}
	conn := models.DeviceConnection{
		Name: "HUB-FW1 <-> SPOKE-FW1", SourceDeviceID: 1, DestDeviceID: 2,
		ConnectionType: "ipsec", Status: "up", TunnelNames: "tun1",
		MatchMethod: "name_match", AutoDetected: true,
	}
	if err := d.db.Create(&conn).Error; err != nil {
		t.Fatalf("conn: %v", err)
	}

	// One sample per 5-min bucket (24h window ⇒ minute buckets, so each sample
	// lands in its own bucket). Same cumulative counters on BOTH endpoints.
	base := time.Now().Add(-40 * time.Minute)
	seedTun := func(dev uint, samples []uint64) {
		for i, b := range samples {
			if err := d.db.Create(&models.VPNStatus{
				DeviceID: dev, TunnelName: "tun1", TunnelType: "ipsec", Status: "up",
				BytesIn: b, BytesOut: b / 2, PacketsIn: b / 10, PacketsOut: b / 10,
				Timestamp: base.Add(time.Duration(i) * 5 * time.Minute),
			}).Error; err != nil {
				t.Fatalf("seed tunnel dev %d: %v", dev, err)
			}
		}
	}
	seedTun(1, []uint64{100, 200, 300, 400}) // source: per-bucket deltas 100+100+100 = 300
	seedTun(2, []uint64{100, 200, 300, 400}) // dest: identical — must NOT be added

	rows, err := d.GetConnectionTraffic(conn.ID, "24h")
	if err != nil {
		t.Fatalf("GetConnectionTraffic: %v", err)
	}
	var aggIn, aggOut float64
	for _, r := range rows {
		aggIn += r.InBytes
		aggOut += r.OutBytes
	}
	// Source endpoint only: in = 300, out = (b/2 deltas) 50+50+50 = 150.
	// Pre-fix (both endpoints summed) this was 600 / 300.
	if !floatsClose(aggIn, 300) {
		t.Errorf("aggregate in_bytes = %v, want 300 (one endpoint; 600 = double-counted both ends)", aggIn)
	}
	if !floatsClose(aggOut, 150) {
		t.Errorf("aggregate out_bytes = %v, want 150 (one endpoint)", aggOut)
	}
}

// TestGetConnectionTraffic_DirectDropsOverlappingParent pins the v0.11.57 direct
// de-overlap: when a resolved set holds a bridge/parent AND its VLAN child, the
// parent's counter aggregates the child's octets, so summing both double-counts.
// The parent is dropped and only the leaf child is summed. (Distinct physical LAG
// members with no parent/child link still sum — covered by the port1/port2 case
// in TestGetConnectionTraffic_DirectUsesInterfaceStats.)
func TestGetConnectionTraffic_DirectDropsOverlappingParent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.Create(&models.Device{ID: 1, Name: "FW1", Vendor: "fortigate"}).Error; err != nil {
		t.Fatalf("dev1: %v", err)
	}
	if err := d.db.Create(&models.Device{ID: 2, Name: "FW2", Vendor: "fortigate"}).Error; err != nil {
		t.Fatalf("dev2: %v", err)
	}
	conn := models.DeviceConnection{
		Name: "FW1 <-> FW2", SourceDeviceID: 1, DestDeviceID: 2,
		ConnectionType: "l2vlan", Status: "up",
		TunnelNames: "internal, internal.100", MatchMethod: "name_match", AutoDetected: true,
	}
	if err := d.db.Create(&conn).Error; err != nil {
		t.Fatalf("conn: %v", err)
	}

	base := time.Now().Add(-40 * time.Minute)
	seedIface := func(name string, idx int, typeName string, vlan int, samples []uint64) {
		for i, b := range samples {
			if err := d.db.Create(&models.InterfaceStats{
				DeviceID: 1, Name: name, Index: idx, TypeName: typeName, VLANID: vlan, Status: "up",
				InBytes: b, OutBytes: b / 2, Timestamp: base.Add(time.Duration(i) * 5 * time.Minute),
			}).Error; err != nil {
				t.Fatalf("seed iface %s: %v", name, err)
			}
		}
	}
	// Bridge (parent) counter aggregates the VLAN child's traffic — summing both
	// would double count. Bridge deltas = 1000*3 = 3000; VLAN deltas = 100*3 = 300.
	seedIface("internal", 5, "bridge", 0, []uint64{1000, 2000, 3000, 4000})
	seedIface("internal.100", 6, "l2vlan", 200, []uint64{100, 200, 300, 400})
	// Config names the VLAN's parent (the parent/child relationship the drop keys on).
	cfg := "config system interface\n edit \"internal.100\"\n set interface \"internal\"\n set vlanid 200\n set type vlan\n next\nend\n"
	if err := d.db.Create(&models.DeviceConfigRevision{DeviceID: 1, Timestamp: time.Now(), ConfigText: cfg}).Error; err != nil {
		t.Fatalf("cfg: %v", err)
	}

	rows, err := d.GetConnectionTraffic(conn.ID, "24h")
	if err != nil {
		t.Fatalf("GetConnectionTraffic: %v", err)
	}
	var aggIn, aggOut float64
	for _, r := range rows {
		aggIn += r.InBytes
		aggOut += r.OutBytes
	}
	// Leaf VLAN only: in = 300, out = 150. Pre-fix (bridge+child) was 3300 / 1650.
	if !floatsClose(aggIn, 300) {
		t.Errorf("aggregate in_bytes = %v, want 300 (leaf only; 3300 = bridge+child double count)", aggIn)
	}
	if !floatsClose(aggOut, 150) {
		t.Errorf("aggregate out_bytes = %v, want 150 (leaf only)", aggOut)
	}
}
