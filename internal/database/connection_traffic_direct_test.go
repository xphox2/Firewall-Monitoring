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
// the per-interface buckets merge into the VPN chart shape (bucket_ms set,
// aggregate == sum of the member interfaces on the source endpoint).
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

	base := time.Now().Add(-20 * time.Minute)
	seedIface := func(dev uint, name string, idx int, samples []uint64) {
		for i, b := range samples {
			if err := d.db.Create(&models.InterfaceStats{
				DeviceID: dev, Name: name, Index: idx, Status: "up", Speed: 1_000_000_000,
				InBytes: b, OutBytes: b / 2, InPackets: b / 100, OutPackets: b / 100,
				Timestamp: base.Add(time.Duration(i) * time.Minute),
			}).Error; err != nil {
				t.Fatalf("seed iface %s: %v", name, err)
			}
		}
	}
	// Source endpoint (device 1) has both member interfaces with stats.
	seedIface(1, "port1", 5, []uint64{100, 200, 300, 400})
	seedIface(1, "port2", 6, []uint64{10, 20, 30, 40})
	// Dest endpoint (device 2) also has port1 — must NOT be summed into the
	// source-perspective aggregate (would mix directions / double-count).
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

	var aggIn float64
	for _, r := range rows {
		if r.BucketMs == 0 {
			t.Error("bucket_ms not populated on direct-link traffic bucket")
		}
		aggIn += r.InBytes
	}

	// Aggregate must equal the sum of the two source-side interfaces only.
	to := time.Now()
	from := to.Add(-24 * time.Hour)
	wantIn := 0.0
	for _, idx := range []int{5, 6} {
		b, err := d.GetInterfaceChartWindow(1, idx, from, to)
		if err != nil {
			t.Fatalf("GetInterfaceChartWindow(%d): %v", idx, err)
		}
		for _, x := range b {
			wantIn += x.InBytes
		}
	}
	if !floatsClose(aggIn, wantIn) {
		t.Errorf("aggregate in_bytes = %v, want %v (sum of source ifaces port1+port2, excluding dest endpoint)", aggIn, wantIn)
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
