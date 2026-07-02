package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetConnectionTraffic_DirectUsesInterfaceStats verifies the type-aware
// split: a direct link (ethernet/lag/l2vlan/bridge/wan) graphs interface_stats
// — keyed by the interface names in TunnelNames — instead of vpn_status, which
// has no rows for such links. It also checks the family classifier and that
// the per-interface buckets merge into the VPN chart shape (bucket_ms set).
//
// H10 of the 2026-07-01 audit: interface_stats counters are RAW CUMULATIVE,
// and the VPNChartBucket contract is per-bucket DELTAS (the tunnel path LAGs;
// both JS consumers divide in_bytes by the bucket interval for Mbps). The
// pre-fix version of this test asserted cumulative pass-through — pinning the
// bug. It now asserts per-interface consecutive-bucket deltas, clamped at 0
// on counter resets, with each interface's first (baseline) bucket dropped.
// Samples are seeded 5 minutes apart because the 24h window buckets at 5min
// (bucketUnitForWindow), putting each sample deterministically in its own
// bucket so the expected deltas are exact.
func TestGetConnectionTraffic_DirectUsesInterfaceStats(t *testing.T) {
	d := NewDatabaseForTesting(t)

	if err := d.db.Create(&models.Device{ID: 1, Name: "switch-a"}).Error; err != nil {
		t.Fatalf("seed device 1: %v", err)
	}
	if err := d.db.Create(&models.Device{ID: 2, Name: "switch-b"}).Error; err != nil {
		t.Fatalf("seed device 2: %v", err)
	}

	conn := models.DeviceConnection{
		Name: "switch-a <-> switch-b", SourceDeviceID: 1, DestDeviceID: 2,
		ConnectionType: "ethernet", Status: "up", TunnelNames: "port1, port2",
		MatchMethod: "subnet_match", AutoDetected: true,
	}
	if err := d.db.Create(&conn).Error; err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	// One sample per 5-min bucket (24h window ⇒ 5min buckets).
	base := time.Now().Add(-40 * time.Minute)
	seedIface := func(dev uint, name string, idx int, samples []uint64) {
		for i, b := range samples {
			if err := d.db.Create(&models.InterfaceStats{
				DeviceID: dev, Name: name, Index: idx, Status: "up", Speed: 1_000_000_000,
				InBytes: b, OutBytes: b / 2, InPackets: b / 100, OutPackets: b / 100,
				Timestamp: base.Add(time.Duration(i) * 5 * time.Minute),
			}).Error; err != nil {
				t.Fatalf("seed iface %s: %v", name, err)
			}
		}
	}
	// Source endpoint (device 1) has both member interfaces with stats.
	// port1: steadily growing counter → deltas 100+100+100 = 300.
	seedIface(1, "port1", 5, []uint64{100, 200, 300, 400})
	// port2: counter RESET mid-series (20 → 5) → deltas 10 + clamp(0) + 10 = 20.
	seedIface(1, "port2", 6, []uint64{10, 20, 5, 15})
	// Dest endpoint (device 2) also has port1 — must NOT be summed into the
	// source-perspective aggregate (would mix directions / double-count).
	// A large constant counter also proves cumulative values no longer leak
	// through: pre-fix this alone would have added 4×9000 to the aggregate.
	seedIface(2, "port1", 5, []uint64{9000, 9000, 9000, 9000})

	// Interface addresses let the UI pair the two ends by shared subnet.
	// dev1/port1 and dev2/port1 sit on 10.0.5.0/24 (the network joining them).
	addr := func(dev uint, ifIndex int, ip, mask string) {
		if err := d.db.Create(&models.InterfaceAddress{DeviceID: dev, IfIndex: ifIndex, IPAddress: ip, NetMask: mask, Timestamp: base}).Error; err != nil {
			t.Fatalf("seed addr %s: %v", ip, err)
		}
	}
	addr(1, 5, "10.0.5.1", "255.255.255.0")
	addr(1, 6, "10.0.6.1", "255.255.255.0")
	addr(2, 5, "10.0.5.2", "255.255.255.0")

	rows, err := d.GetConnectionTraffic(conn.ID, "24h")
	if err != nil {
		t.Fatalf("GetConnectionTraffic: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected interface-sourced buckets for a direct link, got none (still querying vpn_status?)")
	}

	var aggIn, aggOut float64
	for _, r := range rows {
		if r.BucketMs == 0 {
			t.Error("bucket_ms not populated on direct-link traffic bucket")
		}
		aggIn += r.InBytes
		aggOut += r.OutBytes
	}

	// Per-interface deltas, source endpoint only:
	//   port1 in: (200-100)+(300-200)+(400-300)            = 300
	//   port2 in: (20-10) + clamp(5-20 → 0) + (15-5)       = 20
	// Dest endpoint's port1 (constant 9000s) contributes nothing — and its
	// CUMULATIVE values must not appear either (pre-fix: +36000).
	const wantIn = 320.0
	if !floatsClose(aggIn, wantIn) {
		t.Errorf("aggregate in_bytes = %v, want %v (per-interface deltas, reset clamped, source endpoint only)", aggIn, wantIn)
	}
	//   port1 out (b/2: 50,100,150,200): deltas             = 150
	//   port2 out (b/2: 5,10,2,7): 5 + clamp(2-10 → 0) + 5  = 10
	const wantOut = 160.0
	if !floatsClose(aggOut, wantOut) {
		t.Errorf("aggregate out_bytes = %v, want %v", aggOut, wantOut)
	}

	// Detail must classify the family and expose the resolved interfaces.
	detail, err := d.GetConnectionDetail(conn.ID)
	if err != nil {
		t.Fatalf("GetConnectionDetail: %v", err)
	}
	if detail.Family != "direct" {
		t.Errorf("family = %q, want direct", detail.Family)
	}
	if len(detail.Interfaces) == 0 {
		t.Error("expected resolved interfaces in detail for a direct link")
	}
	if len(detail.SourceTunnels) != 0 || len(detail.DestTunnels) != 0 {
		t.Error("direct link must not carry tunnels")
	}

	// Each end must expose its IP + the shared network so the UI can pair them.
	var p1 *ConnInterfaceRef
	for i := range detail.Interfaces {
		if detail.Interfaces[i].DeviceID == 1 && detail.Interfaces[i].IfName == "port1" {
			p1 = &detail.Interfaces[i]
		}
	}
	if p1 == nil {
		t.Fatal("device 1 port1 not in resolved interfaces")
	}
	if p1.IPAddress != "10.0.5.1" {
		t.Errorf("port1 ip = %q, want 10.0.5.1", p1.IPAddress)
	}
	if p1.Subnet != "10.0.5.0/24" {
		t.Errorf("port1 subnet = %q, want 10.0.5.0/24 (the network pairing the two ends)", p1.Subnet)
	}
}

// TestResolveConnectionInterfaces_NormalizedBothEnds covers the "end not
// monitored" bug: a name_match L2 link (e.g. DC2-FW1 <-> DC2-FW2) where the two
// devices spell the interface differently and TunnelNames may list only one
// spelling. Both ends must still resolve via normalized matching.
func TestResolveConnectionInterfaces_NormalizedBothEnds(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.Create(&models.Device{ID: 1, Name: "DC2-FW1"}).Error; err != nil {
		t.Fatalf("dev1: %v", err)
	}
	if err := d.db.Create(&models.Device{ID: 2, Name: "DC2-FW2"}).Error; err != nil {
		t.Fatalf("dev2: %v", err)
	}
	conn := models.DeviceConnection{
		Name: "DC2-FW1 <-> DC2-FW2", SourceDeviceID: 1, DestDeviceID: 2,
		ConnectionType: "l2vlan", Status: "up",
		TunnelNames: "vlan100", // only one literal spelling stored
		MatchMethod: "name_match", AutoDetected: true,
	}
	if err := d.db.Create(&conn).Error; err != nil {
		t.Fatalf("conn: %v", err)
	}
	ts := time.Now().Add(-time.Minute)
	// Same logical interface, spelled differently per device.
	if err := d.db.Create(&models.InterfaceStats{DeviceID: 1, Name: "vlan100", Index: 7, Status: "up", Timestamp: ts}).Error; err != nil {
		t.Fatalf("if1: %v", err)
	}
	if err := d.db.Create(&models.InterfaceStats{DeviceID: 2, Name: "VLAN-100", Index: 9, Status: "up", Timestamp: ts}).Error; err != nil {
		t.Fatalf("if2: %v", err)
	}

	refs := d.resolveConnectionInterfaces(&conn)
	var haveSrc, haveDst bool
	for _, r := range refs {
		if r.DeviceID == 1 {
			haveSrc = true
		}
		if r.DeviceID == 2 {
			haveDst = true
		}
	}
	if !haveSrc {
		t.Error("source end (DC2-FW1 vlan100) did not resolve")
	}
	if !haveDst {
		t.Error("dest end (DC2-FW2 VLAN-100) did not resolve — normalized match failed (the 'end not monitored' bug)")
	}
}

// TestBuildOverlayInfo verifies an overlay (vxlan) connection is enriched from
// the device config (VNI, carrier iface, dstport, VTEPs) and SNMP (the overlay
// interface's own index/counters), surfaced on ConnectionDetailResult.Overlays.
func TestBuildOverlayInfo(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.Create(&models.Device{ID: 1, Name: "HUB-FW1", Vendor: "fortigate"}).Error; err != nil {
		t.Fatalf("dev1: %v", err)
	}
	if err := d.db.Create(&models.Device{ID: 2, Name: "SPOKE-FW1", Vendor: "fortigate"}).Error; err != nil {
		t.Fatalf("dev2: %v", err)
	}
	conn := models.DeviceConnection{
		Name: "HUB-FW1 <-> SPOKE-FW1", SourceDeviceID: 1, DestDeviceID: 2,
		ConnectionType: "vxlan", Status: "up", TunnelNames: "vxlan-ov",
		MatchMethod: "name_match", AutoDetected: true,
	}
	if err := d.db.Create(&conn).Error; err != nil {
		t.Fatalf("conn: %v", err)
	}
	cfg := "config system vxlan\n edit \"vxlan-ov\"\n set interface \"ipsec-hub\"\n set vxlan-id 7000\n set remote-ip \"198.51.100.9\"\n set dstport 4789\n next\nend\n"
	if err := d.db.Create(&models.DeviceConfigRevision{DeviceID: 1, Timestamp: time.Now(), ConfigText: cfg}).Error; err != nil {
		t.Fatalf("cfg rev: %v", err)
	}
	if err := d.db.Create(&models.InterfaceStats{DeviceID: 1, Name: "vxlan-ov", Index: 12, Status: "up", InBytes: 555, OutBytes: 222, Timestamp: time.Now().Add(-time.Minute)}).Error; err != nil {
		t.Fatalf("ifstat: %v", err)
	}

	detail, err := d.GetConnectionDetail(conn.ID)
	if err != nil {
		t.Fatalf("GetConnectionDetail: %v", err)
	}
	if detail.Family != "overlay" {
		t.Fatalf("family = %q, want overlay", detail.Family)
	}
	var hub *OverlayInfo
	for i := range detail.Overlays {
		if detail.Overlays[i].DeviceID == 1 {
			hub = &detail.Overlays[i]
		}
	}
	if hub == nil {
		t.Fatal("no overlay info for HUB-FW1")
	}
	if hub.VNI != 7000 {
		t.Errorf("VNI = %d, want 7000", hub.VNI)
	}
	if hub.CarrierIface != "ipsec-hub" {
		t.Errorf("carrier = %q, want ipsec-hub", hub.CarrierIface)
	}
	if hub.DestPort != 4789 {
		t.Errorf("dstport = %d, want 4789", hub.DestPort)
	}
	if len(hub.RemoteVTEPs) != 1 || hub.RemoteVTEPs[0] != "198.51.100.9" {
		t.Errorf("VTEPs = %v, want [198.51.100.9]", hub.RemoteVTEPs)
	}
	if hub.IfIndex != 12 || hub.InBytes != 555 || hub.OutBytes != 222 {
		t.Errorf("SNMP counters/index mismatch: %+v", hub)
	}
}

// TestResolveConnectionInterfaces_KindVlanParent verifies interfaces are
// enriched with kind (SNMP TypeName), VLAN id (SNMP, else config), and parent
// (config) so the UI can group a VLAN sub-interface with its parent bridge.
func TestResolveConnectionInterfaces_KindVlanParent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.Create(&models.Device{ID: 1, Name: "FW1", Vendor: "fortigate"}).Error; err != nil {
		t.Fatalf("dev: %v", err)
	}
	if err := d.db.Create(&models.Device{ID: 2, Name: "FW2", Vendor: "fortigate"}).Error; err != nil {
		t.Fatalf("dev2: %v", err)
	}
	conn := models.DeviceConnection{
		Name: "FW1 <-> FW2", SourceDeviceID: 1, DestDeviceID: 2,
		ConnectionType: "l2vlan", Status: "up",
		TunnelNames: "HOSTING-BLOCK-2, HOSTING_BLOCK-2", MatchMethod: "name_match", AutoDetected: true,
	}
	if err := d.db.Create(&conn).Error; err != nil {
		t.Fatalf("conn: %v", err)
	}
	ts := time.Now().Add(-time.Minute)
	// Bridge + its VLAN sub-interface on FW1.
	if err := d.db.Create(&models.InterfaceStats{DeviceID: 1, Name: "HOSTING-BLOCK-2", Index: 5, TypeName: "bridge", Status: "up", Timestamp: ts}).Error; err != nil {
		t.Fatalf("if bridge: %v", err)
	}
	if err := d.db.Create(&models.InterfaceStats{DeviceID: 1, Name: "HOSTING_BLOCK-2", Index: 6, TypeName: "l2vlan", VLANID: 200, Status: "up", Timestamp: ts}).Error; err != nil {
		t.Fatalf("if vlan: %v", err)
	}
	// Config gives the VLAN's parent (and would supply vlanid if SNMP lacked it).
	cfg := "config system interface\n edit \"HOSTING_BLOCK-2\"\n set interface \"HOSTING-BLOCK-2\"\n set vlanid 200\n set type vlan\n next\nend\n"
	if err := d.db.Create(&models.DeviceConfigRevision{DeviceID: 1, Timestamp: time.Now(), ConfigText: cfg}).Error; err != nil {
		t.Fatalf("cfg: %v", err)
	}

	refs := d.resolveConnectionInterfaces(&conn)
	var bridge, vlan *ConnInterfaceRef
	for i := range refs {
		switch refs[i].IfName {
		case "HOSTING-BLOCK-2":
			bridge = &refs[i]
		case "HOSTING_BLOCK-2":
			vlan = &refs[i]
		}
	}
	if bridge == nil || vlan == nil {
		t.Fatalf("expected both bridge and vlan refs, got %d refs", len(refs))
	}
	if bridge.Kind != "bridge" {
		t.Errorf("bridge kind = %q, want bridge", bridge.Kind)
	}
	if vlan.Kind != "l2vlan" || vlan.VlanID != 200 || vlan.Parent != "HOSTING-BLOCK-2" {
		t.Errorf("vlan enrichment wrong: kind=%q vlan=%d parent=%q", vlan.Kind, vlan.VlanID, vlan.Parent)
	}
}

func TestComputeNetworkCIDR(t *testing.T) {
	cases := []struct{ ip, mask, want string }{
		{"10.0.5.1", "255.255.255.0", "10.0.5.0/24"},
		{"192.168.1.55", "255.255.255.128", "192.168.1.0/25"},
		{"172.16.4.9", "255.255.0.0", "172.16.0.0/16"},
		{"10.0.0.1", "", ""},
		{"", "255.255.255.0", ""},
		{"not-an-ip", "255.255.255.0", ""},
	}
	for _, c := range cases {
		if got := computeNetworkCIDR(c.ip, c.mask); got != c.want {
			t.Errorf("computeNetworkCIDR(%q,%q) = %q, want %q", c.ip, c.mask, got, c.want)
		}
	}
}

func TestConnectionFamily(t *testing.T) {
	cases := map[string]string{
		"ipsec": "tunnel", "ssl": "tunnel", "gre": "tunnel", "tunnel": "tunnel",
		"vxlan": "overlay", "l3ipvlan": "overlay",
		"ethernet": "direct", "lag": "direct", "l2vlan": "direct", "bridge": "direct", "wan": "direct",
		"offnet": "offnet",
		"":       "tunnel", "weird": "tunnel", "ETHERNET": "direct",
	}
	for in, want := range cases {
		if got := connectionFamily(in); got != want {
			t.Errorf("connectionFamily(%q) = %q, want %q", in, got, want)
		}
	}
}

func floatsClose(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 0.001
}
