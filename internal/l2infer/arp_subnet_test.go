package l2infer

import (
	"net"
	"testing"
)

// arpPair builds two same-site devices + one interface each carrying the given
// CIDR, plus mirrored ARP evidence between them. dev2IP is device 2's address
// (what device 1's ARP row resolves to).
func arpPair(net1, net2, dev1IP, dev2IP string) ([]DeviceMeta, []Iface, []ARPRow) {
	devs := []DeviceMeta{
		{ID: 1, Name: "fw-core", SiteID: &site1, IPs: []string{dev1IP}},
		{ID: 2, Name: "opnsense", SiteID: &site1, IPs: []string{dev2IP}},
	}
	ifaces := []Iface{
		{DeviceID: 1, IfIndex: 5, Name: "port5", MAC: "AA:BB:CC:00:00:05", Status: "up", TypeName: "ethernet", Networks: []string{net1}},
		{DeviceID: 2, IfIndex: 3, Name: "dtsec1", MAC: "aa:bb:cc:00:01:03", Status: "up", TypeName: "ethernet", Networks: []string{net2}},
	}
	arp := []ARPRow{
		{DeviceID: 1, IfIndex: 5, IP: dev2IP, MAC: "aa:bb:cc:00:01:03", Ts: ts()},
		{DeviceID: 2, IfIndex: 3, IP: dev1IP, MAC: "aa:bb:cc:00:00:05", Ts: ts()},
	}
	return devs, ifaces, arp
}

// TestInferLinks_ARPSharedSubnetSuppressed: the real DC2-FW1↔OPNsense case —
// both on a shared /24 with ARP-only evidence → NO link (a shared switch is
// not a point-to-point cable).
func TestInferLinks_ARPSharedSubnetSuppressed(t *testing.T) {
	devs, ifaces, arp := arpPair("192.168.5.0/24", "192.168.5.0/24", "192.168.5.1", "192.168.5.107")
	if links := InferLinks(devs, ifaces, nil, arp, nil); len(links) != 0 {
		t.Fatalf("shared /24 ARP must produce NO link, got %d: %+v", len(links), links)
	}
}

// TestInferLinks_ARPPointToPointKept: a genuine /30 (and /31) transit with
// ARP-only evidence still yields the link — suppression is scoped to
// multi-host subnets.
func TestInferLinks_ARPPointToPointKept(t *testing.T) {
	for _, tc := range []struct{ net, ip1, ip2 string }{
		{"10.0.0.0/30", "10.0.0.1", "10.0.0.2"},
		{"10.0.0.0/31", "10.0.0.0", "10.0.0.1"},
	} {
		devs, ifaces, arp := arpPair(tc.net, tc.net, tc.ip1, tc.ip2)
		links := InferLinks(devs, ifaces, nil, arp, nil)
		if len(links) != 1 || links[0].Method != MethodARP {
			t.Fatalf("%s P2P ARP must keep the link, got %d: %+v", tc.net, len(links), links)
		}
	}
}

// TestInferLinks_SharedSubnetFDBUnaffected: suppression is ARP-tier only — a
// shared /24 with FDB evidence still produces the (confirmed) link.
func TestInferLinks_SharedSubnetFDBUnaffected(t *testing.T) {
	devs, ifaces, _ := arpPair("192.168.5.0/24", "192.168.5.0/24", "192.168.5.1", "192.168.5.107")
	fdb := []FDBRow{
		{DeviceID: 1, IfIndex: 5, MAC: "aa:bb:cc:00:01:03", VLANID: 10, Ts: ts()},
		{DeviceID: 2, IfIndex: 3, MAC: "aa:bb:cc:00:00:05", VLANID: 10, Ts: ts()},
	}
	links := InferLinks(devs, ifaces, fdb, nil, nil)
	if len(links) != 1 || links[0].Method != MethodFDB {
		t.Fatalf("shared /24 with FDB must keep the confirmed link, got %d: %+v", len(links), links)
	}
}

// TestInferLinks_ARPTargetOutsideSubnetKept: precision guard — the reporter's
// interface is on a multi-host /24 but the target's IP is on a DIFFERENT
// network, so they don't actually share that segment → link kept.
func TestInferLinks_ARPTargetOutsideSubnetKept(t *testing.T) {
	// port5 on 192.168.5.0/24; device 2's only IP is 172.16.9.2 (elsewhere).
	devs, ifaces, arp := arpPair("192.168.5.0/24", "172.16.9.0/24", "192.168.5.1", "172.16.9.2")
	if links := InferLinks(devs, ifaces, nil, arp, nil); len(links) != 1 {
		t.Fatalf("ARP where target IP is outside the reporter subnet must keep the link, got %d: %+v", len(links), links)
	}
}

// TestInferLinks_ARPResolvedIPPrecision: a genuine /30 transit whose interface
// ALSO carries a secondary multi-host /24 must keep the link — suppression
// tests the exact resolved ARP IP (the /30 peer), not the target's unrelated
// /24 address.
func TestInferLinks_ARPResolvedIPPrecision(t *testing.T) {
	devs := []DeviceMeta{
		{ID: 1, Name: "fw-core", SiteID: &site1, IPs: []string{"10.0.0.1"}},
		// target owns both the /30 peer IP and a /24 mgmt IP.
		{ID: 2, Name: "opnsense", SiteID: &site1, IPs: []string{"10.0.0.2", "192.168.5.107"}},
	}
	ifaces := []Iface{
		// reporter's transit port carries the /30 AND a secondary /24.
		{DeviceID: 1, IfIndex: 5, Name: "port5", MAC: "AA:BB:CC:00:00:05", Status: "up", TypeName: "ethernet",
			Networks: []string{"10.0.0.0/30", "192.168.5.0/24"}},
		{DeviceID: 2, IfIndex: 3, Name: "dtsec1", MAC: "aa:bb:cc:00:01:03", Status: "up", TypeName: "ethernet",
			Networks: []string{"10.0.0.0/30"}},
	}
	// ARP resolved the /30 peer IP — the real transit adjacency.
	arp := []ARPRow{
		{DeviceID: 1, IfIndex: 5, IP: "10.0.0.2", MAC: "aa:bb:cc:00:01:03", Ts: ts()},
		{DeviceID: 2, IfIndex: 3, IP: "10.0.0.1", MAC: "aa:bb:cc:00:00:05", Ts: ts()},
	}
	if links := InferLinks(devs, ifaces, nil, arp, nil); len(links) != 1 {
		t.Fatalf("P2P /30 with a secondary /24 must keep the link (resolved IP is the /30 peer), got %d: %+v", len(links), links)
	}
}

// TestInferLinks_GarbageZeroMaskKept: a 0.0.0.0 netmask (→ /0) is garbage, not
// a shared segment — it must not blanket-suppress ARP inference.
func TestInferLinks_GarbageZeroMaskKept(t *testing.T) {
	devs, ifaces, arp := arpPair("0.0.0.0/0", "0.0.0.0/0", "10.9.9.1", "10.9.9.2")
	if links := InferLinks(devs, ifaces, nil, arp, nil); len(links) != 1 {
		t.Fatalf("/0 garbage mask must keep the link, got %d: %+v", len(links), links)
	}
}

// TestNetworkIsMultiHost pins the prefix boundary.
func TestNetworkIsMultiHost(t *testing.T) {
	mk := func(cidr string) bool {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		return networkIsMultiHost(n)
	}
	for _, c := range []string{"192.168.5.0/24", "10.0.0.0/29", "10.0.0.0/25"} {
		if !mk(c) {
			t.Errorf("%s should be multi-host", c)
		}
	}
	for _, c := range []string{"10.0.0.0/30", "10.0.0.0/31", "10.0.0.1/32"} {
		if mk(c) {
			t.Errorf("%s should be point-to-point (not multi-host)", c)
		}
	}
}
