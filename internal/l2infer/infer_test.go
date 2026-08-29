package l2infer

import (
	"testing"
	"time"
)

var site1, site2 = uint(1), uint(2)

func twoDevices() []DeviceMeta {
	return []DeviceMeta{
		{ID: 1, Name: "fw-core", SiteID: &site1, IPs: []string{"192.168.5.1"}},
		{ID: 2, Name: "fw-branch.lab.local", SiteID: &site1, IPs: []string{"192.168.5.107"}},
	}
}

func twoDeviceIfaces() []Iface {
	return []Iface{
		{DeviceID: 1, IfIndex: 5, Name: "port5", MAC: "AA:BB:CC:00:00:05", Status: "up", TypeName: "ethernet"},
		{DeviceID: 1, IfIndex: 6, Name: "port6", MAC: "AA:BB:CC:00:00:06", Status: "up", TypeName: "ethernet"},
		{DeviceID: 2, IfIndex: 3, Name: "lan3", MAC: "aa:bb:cc:00:01:03", Status: "up", TypeName: "ethernet"},
		{DeviceID: 2, IfIndex: 4, Name: "lan4", MAC: "aa:bb:cc:00:01:04", Status: "up", TypeName: "ethernet"},
	}
}

func ts() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) }

// LLDP two-sided: mirrored neighbor rows collapse to ONE link with both ports.
func TestInferLinks_LLDPTwoSided(t *testing.T) {
	nbrs := []NeighborRow{
		{DeviceID: 1, LocalIfIndex: 5, ChassisID: "aa:bb:cc:00:01:03", PortID: "lan3", SysName: "fw-branch", Ts: ts()},
		{DeviceID: 2, LocalIfIndex: 3, ChassisID: "aa:bb:cc:00:00:05", PortID: "port5", SysName: "fw-core", Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), nil, nil, nbrs)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1: %+v", len(links), links)
	}
	l := links[0]
	if l.A != 1 || l.B != 2 || l.AIfName != "port5" || l.BIfName != "lan3" {
		t.Errorf("link wrong: %+v", l)
	}
	if l.Method != MethodLLDP || l.Sided != "both" || l.Status != "up" {
		t.Errorf("method/sided/status wrong: %+v", l)
	}
}

// LLDP sysname-only: chassis ID unknown (not a monitored MAC) but the sysname
// matches a device name — short-hostname matching included.
func TestInferLinks_LLDPSysnameOnly(t *testing.T) {
	nbrs := []NeighborRow{
		{DeviceID: 1, LocalIfIndex: 5, ChassisID: "unknown-chassis", PortID: "lan3", SysName: "FW-BRANCH", Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), nil, nil, nbrs)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1", len(links))
	}
	if links[0].B != 2 || links[0].BIfName != "lan3" {
		t.Errorf("sysname resolution failed: %+v", links[0])
	}
}

// FDB bidirectional through an unmanaged switch: A sees B's MAC on port5, B
// sees A's MAC on lan3 → one two-sided fdb link A:port5 ↔ B:lan3.
func TestInferLinks_FDBBidirectional(t *testing.T) {
	fdb := []FDBRow{
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", VLANID: 10, Ts: ts()},
		{DeviceID: 2, IfIndex: 3, MAC: "aa:bb:cc:00:00:05", VLANID: 10, Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, nil, nil)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1: %+v", len(links), links)
	}
	l := links[0]
	if l.AIfName != "port5" || l.BIfName != "lan3" || l.Method != MethodFDB || l.Sided != "both" {
		t.Errorf("link wrong: %+v", l)
	}
	if len(l.VLANIDs) != 1 || l.VLANIDs[0] != 10 {
		t.Errorf("vlans wrong: %v", l.VLANIDs)
	}
}

// One-sided FDB: only A reports → dest port unknown, Sided a_only.
func TestInferLinks_FDBOneSided(t *testing.T) {
	fdb := []FDBRow{{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", Ts: ts()}}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, nil, nil)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1", len(links))
	}
	l := links[0]
	if l.Sided != "a_only" || l.BIfIndex != 0 || l.BIfName != "" {
		t.Errorf("one-sided link wrong: %+v", l)
	}
}

// ARP-only, both directions: MAC-ownership matching attributes both ports.
func TestInferLinks_ARPBothDirections(t *testing.T) {
	arp := []ARPRow{
		{DeviceID: 1, IfIndex: 5, IP: "192.168.5.107", MAC: "aa:bb:cc:00:01:03", Ts: ts()},
		{DeviceID: 2, IfIndex: 3, IP: "192.168.5.1", MAC: "aa:bb:cc:00:00:05", Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), nil, arp, nil)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1: %+v", len(links), links)
	}
	l := links[0]
	if l.Method != MethodARP || l.Sided != "both" || l.AIfName != "port5" || l.BIfName != "lan3" {
		t.Errorf("arp link wrong: %+v", l)
	}
}

// ARP IP-fallback: the ARP MAC isn't any monitored device's interface MAC
// (e.g. unreported ifPhysAddress) but the IP belongs to device 2.
func TestInferLinks_ARPIPFallback(t *testing.T) {
	arp := []ARPRow{
		{DeviceID: 1, IfIndex: 5, IP: "192.168.5.107", MAC: "11:22:33:44:55:66", Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), nil, arp, nil)
	if len(links) != 1 || links[0].B != 2 {
		t.Fatalf("IP fallback failed: %+v", links)
	}
}

// SSH-sourced ARP rows carry interface NAMES; they must resolve to the ifIndex.
func TestInferLinks_ARPByIfName(t *testing.T) {
	arp := []ARPRow{
		{DeviceID: 1, IfName: "port5", IP: "192.168.5.107", MAC: "aa:bb:cc:00:01:03", Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), nil, arp, nil)
	if len(links) != 1 || links[0].AIfIndex != 5 || links[0].AIfName != "port5" {
		t.Fatalf("ifName resolution failed: %+v", links)
	}
}

// VLAN trunk: B's MACs on A:port5 under VLANs 10 and 20 → ONE link listing
// both VLANs (a link is a port pair, not a VLAN).
func TestInferLinks_VLANTrunkOneLink(t *testing.T) {
	fdb := []FDBRow{
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", VLANID: 10, Ts: ts()},
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:04", VLANID: 20, Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, nil, nil)
	if len(links) != 1 {
		t.Fatalf("trunk produced %d links, want 1", len(links))
	}
	if v := links[0].VLANIDs; len(v) != 2 || v[0] != 10 || v[1] != 20 {
		t.Errorf("vlans wrong: %v", v)
	}
}

// MAC move: B's MAC seen on two A-ports with different snapshot timestamps —
// the NEWEST port wins, deterministically, one link only.
func TestInferLinks_MACMoveNewestWins(t *testing.T) {
	older := ts().Add(-10 * time.Minute)
	fdb := []FDBRow{
		{DeviceID: 1, IfIndex: 6, MAC: "aa:bb:cc:00:01:03", Ts: older},
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, nil, nil)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1", len(links))
	}
	if links[0].AIfIndex != 5 {
		t.Errorf("newest port must win: got ifIndex %d, want 5", links[0].AIfIndex)
	}
}

// Mixed-case MACs: uppercase InterfaceStats MACs vs lowercase topology rows
// MUST still match (the case mismatch would silently kill the whole tier).
func TestInferLinks_MixedCaseMACsMatch(t *testing.T) {
	// twoDeviceIfaces already mixes cases (device 1 uppercase). Report the
	// FDB row uppercase too for good measure.
	fdb := []FDBRow{{DeviceID: 2, IfIndex: 3, MAC: "AA:BB:CC:00:00:05", Ts: ts()}}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, nil, nil)
	if len(links) != 1 {
		t.Fatalf("mixed-case MAC did not match: %+v", links)
	}
}

// VRRP/CARP virtual MACs must not anchor ownership: two devices both carrying
// the VRRP MAC must not get a link fabricated from it.
func TestInferLinks_VirtualMACExcluded(t *testing.T) {
	ifaces := append(twoDeviceIfaces(),
		Iface{DeviceID: 1, IfIndex: 9, Name: "vrrp1", MAC: "00:00:5e:00:01:01", Status: "up"},
		Iface{DeviceID: 2, IfIndex: 9, Name: "vrrp2", MAC: "00:00:5e:00:01:01", Status: "up"},
	)
	fdb := []FDBRow{{DeviceID: 1, IfIndex: 5, MAC: "00:00:5e:00:01:01", Ts: ts()}}
	links := InferLinks(twoDevices(), ifaces, fdb, nil, nil)
	if len(links) != 0 {
		t.Fatalf("virtual MAC fabricated a link: %+v", links)
	}
}

// FGCP virtual MACs (00:09:0f:09:xx:xx) stay OWNABLE — an HA FortiGate's
// ifPhysAddress reports them, and excluding them would kill its matching.
func TestInferLinks_FGCPMACOwnable(t *testing.T) {
	ifaces := []Iface{
		{DeviceID: 1, IfIndex: 5, Name: "port5", MAC: "aa:bb:cc:00:00:05", Status: "up"},
		{DeviceID: 2, IfIndex: 3, Name: "lan3", MAC: "00:09:0f:09:00:02", Status: "up"},
	}
	fdb := []FDBRow{{DeviceID: 1, IfIndex: 5, MAC: "00:09:0f:09:00:02", Ts: ts()}}
	links := InferLinks(twoDevices(), ifaces, fdb, nil, nil)
	if len(links) != 1 || links[0].B != 2 {
		t.Fatalf("FGCP MAC must resolve device 2: %+v", links)
	}
}

// A real MAC claimed by TWO devices (dual-monitored HA cluster) is ambiguous
// and dropped — no link may be fabricated from it.
func TestInferLinks_MultiOwnerMACDropped(t *testing.T) {
	ifaces := append(twoDeviceIfaces(),
		Iface{DeviceID: 1, IfIndex: 10, Name: "ha1", MAC: "00:09:0f:09:aa:aa", Status: "up"},
		Iface{DeviceID: 2, IfIndex: 10, Name: "ha2", MAC: "00:09:0f:09:aa:aa", Status: "up"},
	)
	fdb := []FDBRow{{DeviceID: 1, IfIndex: 5, MAC: "00:09:0f:09:aa:aa", Ts: ts()}}
	links := InferLinks(twoDevices(), ifaces, fdb, nil, nil)
	if len(links) != 0 {
		t.Fatalf("multi-owner MAC fabricated a link: %+v", links)
	}
}

// Cross-site pairs are ignored even with perfect evidence.
func TestInferLinks_CrossSiteIgnored(t *testing.T) {
	devs := twoDevices()
	devs[1].SiteID = &site2
	fdb := []FDBRow{
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", Ts: ts()},
		{DeviceID: 2, IfIndex: 3, MAC: "aa:bb:cc:00:00:05", Ts: ts()},
	}
	links := InferLinks(devs, twoDeviceIfaces(), fdb, nil, nil)
	if len(links) != 0 {
		t.Fatalf("cross-site link created: %+v", links)
	}
}

// LLDP-vs-FDB port conflict: LLDP says A:port5, FDB says A:port6 → single
// link on port5 (LLDP wins), FDB attached as discrepancy evidence.
func TestInferLinks_LLDPWinsPortConflict(t *testing.T) {
	nbrs := []NeighborRow{
		{DeviceID: 1, LocalIfIndex: 5, ChassisID: "aa:bb:cc:00:01:03", PortID: "lan3", SysName: "fw-branch", Ts: ts()},
	}
	fdb := []FDBRow{{DeviceID: 1, IfIndex: 6, MAC: "aa:bb:cc:00:01:03", Ts: ts()}}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, nil, nbrs)
	if len(links) != 1 {
		t.Fatalf("conflict spawned %d links, want 1: %+v", len(links), links)
	}
	l := links[0]
	if l.AIfIndex != 5 || l.Method != MethodLLDP {
		t.Errorf("LLDP must win the port conflict: %+v", l)
	}
	foundNote := false
	for _, ev := range l.Evidence {
		if ev.Note != "" && ev.Tier == TierFDB {
			foundNote = true
		}
	}
	if !foundNote {
		t.Error("conflicting FDB evidence must be attached with a discrepancy note")
	}
}

// Parallel links: two LLDP adjacencies on different port pairs (HA-sync +
// LAN) → two Link rows.
func TestInferLinks_ParallelLinks(t *testing.T) {
	nbrs := []NeighborRow{
		{DeviceID: 1, LocalIfIndex: 5, ChassisID: "aa:bb:cc:00:01:03", PortID: "lan3", SysName: "fw-branch", Ts: ts()},
		{DeviceID: 1, LocalIfIndex: 6, ChassisID: "aa:bb:cc:00:01:04", PortID: "lan4", SysName: "fw-branch", Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), nil, nil, nbrs)
	if len(links) != 2 {
		t.Fatalf("got %d links, want 2 parallel: %+v", len(links), links)
	}
	if links[0].AIfIndex == links[1].AIfIndex {
		t.Errorf("parallel links must sit on different ports: %+v", links)
	}
}

// AUDIT-279: mirrored LLDP rows where ONE side advertised the remote port by a
// name that doesn't resolve to any of the far device's interfaces (PortID !=
// interface Name → resolveRemotePort raw fallback portRef{0,name}) must still
// collapse to ONE link, not spawn a duplicate claiming the same local port. The
// far device's own row names that port authoritatively (ifIndex>0) and upgrades
// the raw fallback.
func TestInferLinks_LLDPRawRemoteFallbackDedups(t *testing.T) {
	nbrs := []NeighborRow{
		// fw-core sees fw-branch but advertises its remote port as "ge-0/0/3",
		// which is NOT one of fw-branch's interface names (lan3/lan4) → raw
		// fallback for the B side.
		{DeviceID: 1, LocalIfIndex: 5, ChassisID: "aa:bb:cc:00:01:03", PortID: "ge-0/0/3", SysName: "fw-branch", Ts: ts()},
		// fw-branch's mirrored row names its own port (lan3) and fw-core's port
		// (port5) correctly.
		{DeviceID: 2, LocalIfIndex: 3, ChassisID: "aa:bb:cc:00:00:05", PortID: "port5", SysName: "fw-core", Ts: ts()},
	}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), nil, nil, nbrs)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1 (raw-fallback remote must merge, not duplicate): %+v", len(links), links)
	}
	l := links[0]
	// The B side must resolve to fw-branch's authoritative port (lan3/ifIndex3),
	// not linger on the raw "ge-0/0/3" fallback.
	if l.AIfName != "port5" || l.BIfName != "lan3" || l.BIfIndex != 3 {
		t.Errorf("ports wrong: A=%s(%d) B=%s(%d), want port5/lan3(3)", l.AIfName, l.AIfIndex, l.BIfName, l.BIfIndex)
	}
	if l.Method != MethodLLDP || l.Sided != "both" {
		t.Errorf("method/sided wrong: %+v", l)
	}
}

// ARP must never spawn a second link when the pair already has one on a
// different port (logical VLAN subif vs the physical port is the same wire).
func TestInferLinks_ARPNeverSpawnsParallel(t *testing.T) {
	fdb := []FDBRow{{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", Ts: ts()}}
	arp := []ARPRow{{DeviceID: 1, IfIndex: 6, IP: "192.168.5.107", MAC: "aa:bb:cc:00:01:03", Ts: ts()}}
	links := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, arp, nil)
	if len(links) != 1 {
		t.Fatalf("ARP spawned a parallel link: %+v", links)
	}
	if links[0].AIfIndex != 5 {
		t.Errorf("FDB attribution must stand: %+v", links[0])
	}
}

// Down endpoint interface → link status down.
func TestInferLinks_StatusDown(t *testing.T) {
	ifaces := twoDeviceIfaces()
	ifaces[0].Status = "down" // port5 on device 1
	fdb := []FDBRow{{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", Ts: ts()}}
	links := InferLinks(twoDevices(), ifaces, fdb, nil, nil)
	if len(links) != 1 || links[0].Status != "down" {
		t.Fatalf("status must be down: %+v", links)
	}
}

// Determinism: repeated runs over the same inputs produce identical output.
func TestInferLinks_Deterministic(t *testing.T) {
	fdb := []FDBRow{
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", VLANID: 10, Ts: ts()},
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:04", VLANID: 20, Ts: ts()},
		{DeviceID: 2, IfIndex: 3, MAC: "aa:bb:cc:00:00:05", Ts: ts()},
	}
	arp := []ARPRow{{DeviceID: 2, IfIndex: 3, IP: "192.168.5.1", MAC: "aa:bb:cc:00:00:05", Ts: ts()}}
	first := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, arp, nil)
	for i := 0; i < 20; i++ {
		again := InferLinks(twoDevices(), twoDeviceIfaces(), fdb, arp, nil)
		if len(again) != len(first) {
			t.Fatalf("run %d: %d links vs %d", i, len(again), len(first))
		}
		for j := range again {
			if again[j].A != first[j].A || again[j].AIfIndex != first[j].AIfIndex ||
				again[j].BIfIndex != first[j].BIfIndex || again[j].Method != first[j].Method {
				t.Fatalf("run %d: link %d differs: %+v vs %+v", i, j, again[j], first[j])
			}
		}
	}
}
