package l2infer

import (
	"testing"
	"time"
)

// The live DC2 topology that surfaced the bug (2026-07-14): OPNsense →
// DC2-FW2 → DC2-FW1 daisy-chained on ONE broadcast domain. FW1's FDB
// legitimately contains OPNsense's MAC (learned through the FW2 uplink) and
// OPNsense's ARP contains FW1 — but OPNsense↔FW1 is not a cable.
func dc2Topology() ([]DeviceMeta, []Iface, []FDBRow, []ARPRow) {
	site := uint(1)
	devs := []DeviceMeta{
		{ID: 1, Name: "DC2-FW2", SiteID: &site, IPs: []string{"192.168.5.1"}},
		{ID: 2, Name: "DC2-FW1", SiteID: &site, IPs: []string{"192.168.5.2"}},
		{ID: 3, Name: "OPNsense", SiteID: &site, IPs: []string{"192.168.5.107"}},
	}
	ifaces := []Iface{
		// FW2: switch port to OPNsense (port3) + uplink to FW1 (port7)
		{DeviceID: 1, IfIndex: 3, Name: "port3", MAC: "AC:71:2E:6F:94:C8", Status: "up", TypeName: "ethernet"},
		{DeviceID: 1, IfIndex: 7, Name: "port7", MAC: "AC:71:2E:6F:94:C9", Status: "up", TypeName: "ethernet"},
		// FW1: one internal port toward FW2
		{DeviceID: 2, IfIndex: 4, Name: "internal", MAC: "E0:23:FF:6A:E5:D8", Status: "up", TypeName: "bridge"},
		// OPNsense LAN
		{DeviceID: 3, IfIndex: 2, Name: "lan", MAC: "E8:F6:D7:00:10:5B", Status: "up", TypeName: "ethernet"},
	}
	ts := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	fdb := []FDBRow{
		// FW2: OPNsense on the direct port, FW1 on the uplink — DIFFERENT ports.
		{DeviceID: 1, IfIndex: 3, MAC: "e8:f6:d7:00:10:5b", Ts: ts},
		{DeviceID: 1, IfIndex: 7, MAC: "e0:23:ff:6a:e5:d8", Ts: ts},
		// FW1: FW2 and OPNsense both through the SAME port (the FW2 cable).
		{DeviceID: 2, IfIndex: 4, MAC: "ac:71:2e:6f:94:c9", Ts: ts},
		{DeviceID: 2, IfIndex: 4, MAC: "e8:f6:d7:00:10:5b", Ts: ts},
	}
	arp := []ARPRow{
		// OPNsense sees both FortiGates on its single lan interface.
		{DeviceID: 3, IfIndex: 2, IP: "192.168.5.1", MAC: "ac:71:2e:6f:94:c8", Ts: ts},
		{DeviceID: 3, IfIndex: 2, IP: "192.168.5.2", MAC: "e0:23:ff:6a:e5:d8", Ts: ts},
	}
	return devs, ifaces, fdb, arp
}

// TestInferLinks_TransitiveSuppression: the daisy-chain yields exactly the
// two physical links; the OPNsense↔FW1 attribution (through monitored FW2)
// is suppressed.
func TestInferLinks_TransitiveSuppression(t *testing.T) {
	devs, ifaces, fdb, arp := dc2Topology()
	links := InferLinks(devs, ifaces, fdb, arp, nil)

	if len(links) != 2 {
		t.Fatalf("got %d links, want 2 (OPN↔FW2, FW2↔FW1): %+v", len(links), links)
	}
	for _, l := range links {
		if (l.A == 2 && l.B == 3) || (l.A == 3 && l.B == 2) {
			t.Fatalf("false transitive link OPNsense↔DC2-FW1 survived: %+v", l)
		}
	}
	// The surviving links carry the correct port attributions.
	var sawOPNFW2, sawFW1FW2 bool
	for _, l := range links {
		switch {
		case l.A == 1 && l.B == 3:
			sawOPNFW2 = true
			if l.AIfName != "port3" || l.BIfName != "lan" {
				t.Errorf("OPN↔FW2 ports wrong: %+v", l)
			}
		case l.A == 1 && l.B == 2:
			sawFW1FW2 = true
			if l.AIfName != "port7" || l.BIfName != "internal" {
				t.Errorf("FW2↔FW1 ports wrong: %+v", l)
			}
		}
	}
	if !sawOPNFW2 || !sawFW1FW2 {
		t.Errorf("expected both physical links present: %+v", links)
	}
}

// LLDP-confirmed adjacency is NEVER suppressed, even when the FDB pattern
// would call it transitive — the protocol's word beats the inference.
func TestInferLinks_TransitiveNeverSuppressesLLDP(t *testing.T) {
	devs, ifaces, fdb, arp := dc2Topology()
	nbrs := []NeighborRow{
		// A (hypothetical) direct LLDP adjacency OPNsense↔FW1.
		{DeviceID: 3, LocalIfIndex: 2, ChassisID: "e0:23:ff:6a:e5:d8", PortID: "internal", SysName: "DC2-FW1", Ts: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)},
	}
	links := InferLinks(devs, ifaces, fdb, arp, nbrs)
	found := false
	for _, l := range links {
		if l.A == 2 && l.B == 3 && l.Method == MethodLLDP {
			found = true
		}
	}
	if !found {
		t.Fatalf("LLDP-confirmed link was suppressed: %+v", links)
	}
}

// Partial middle-device data fails SAFE: without FW2's port attributions the
// suppression cannot prove FW2 is between, so the link stays (better a
// through-link than a hole).
func TestInferLinks_TransitivePartialDataKeepsLink(t *testing.T) {
	devs, ifaces, _, arp := dc2Topology()
	// No FDB at all — only OPNsense's ARP (sees both FWs on one port). FW2
	// has no attributions, so nothing proves it sits between.
	links := InferLinks(devs, ifaces, nil, arp, nil)
	found := false
	for _, l := range links {
		if (l.A == 2 && l.B == 3) || (l.A == 3 && l.B == 2) {
			found = true
		}
	}
	if !found {
		t.Fatalf("link suppressed without proof of a middle device: %+v", links)
	}
}

// Through an UNMANAGED switch the attribution stands: both devices see each
// other on dedicated ports and no monitored middle device exists.
func TestInferLinks_TransitiveUnmanagedSwitchUnaffected(t *testing.T) {
	site := uint(1)
	devs := []DeviceMeta{
		{ID: 1, Name: "fw-a", SiteID: &site},
		{ID: 2, Name: "fw-b", SiteID: &site},
	}
	ifaces := []Iface{
		{DeviceID: 1, IfIndex: 5, Name: "port5", MAC: "aa:bb:cc:00:00:05", Status: "up"},
		{DeviceID: 2, IfIndex: 3, Name: "lan3", MAC: "aa:bb:cc:00:01:03", Status: "up"},
	}
	ts := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	fdb := []FDBRow{
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", Ts: ts},
		{DeviceID: 2, IfIndex: 3, MAC: "aa:bb:cc:00:00:05", Ts: ts},
	}
	links := InferLinks(devs, ifaces, fdb, nil, nil)
	if len(links) != 1 || links[0].Method != MethodFDB {
		t.Fatalf("unmanaged-switch link affected by suppression: %+v", links)
	}
}
