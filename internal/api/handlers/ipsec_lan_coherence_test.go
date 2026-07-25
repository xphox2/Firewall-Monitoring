package handlers

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"
)

// The incident this guards: a tunnel was deployed with lan_iface=port3 while its
// protected subnet lived on port2. Validation passed, the deploy succeeded, both
// SAs came up, and no traffic moved — the policies named a port the traffic never
// touches. Nothing in the system objected.
//
// The check is deliberately narrow. It needs live device facts, so it warns
// rather than blocks, and it only fires when the subnet is disjoint from every
// SELECTED interface AND sits on some OTHER local one — a case that always has a
// nameable carrier. Anything vaguer would fire on legitimate topologies and get
// trained away.

// seedIfaces writes an interface + its addresses at one shared timestamp, which
// is what the latest-snapshot join keys on.
func seedIfaces(t *testing.T, db *database.Database, deviceID uint, ifaces []struct {
	Name     string
	Index    int
	TypeName string
	Addrs    [][2]string // {ip, mask}
}) {
	t.Helper()
	now := time.Now().UTC()
	for _, i := range ifaces {
		if err := db.SaveInterfaceStats([]models.InterfaceStats{{
			DeviceID: deviceID, Index: i.Index, Name: i.Name,
			TypeName: i.TypeName, Status: "up", Timestamp: now,
		}}); err != nil {
			t.Fatalf("save iface %s: %v", i.Name, err)
		}
		for _, a := range i.Addrs {
			if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{{
				DeviceID: deviceID, IfIndex: i.Index,
				IPAddress: a[0], NetMask: a[1], Timestamp: now,
			}}); err != nil {
				t.Fatalf("save addr %s: %v", a[0], err)
			}
		}
	}
}

type ifaceSeed = []struct {
	Name     string
	Index    int
	TypeName string
	Addrs    [][2]string
}

// twoPortFortiGate mirrors the real box: port2 = 192.168.25.0/24,
// port3 = 192.168.13.0/24.
func twoPortFortiGate(t *testing.T, db *database.Database, deviceID uint) {
	t.Helper()
	seedIfaces(t, db, deviceID, ifaceSeed{
		{Name: "port2", Index: 2, TypeName: "ethernet", Addrs: [][2]string{{"192.168.25.1", "255.255.255.0"}}},
		{Name: "port3", Index: 3, TypeName: "ethernet", Addrs: [][2]string{{"192.168.13.1", "255.255.255.0"}}},
	})
}

func coherenceIntent(lanIfaces []string, subnets []string) *ipsec.TunnelIntent {
	in := &ipsec.TunnelIntent{ID: 1, Name: "fwm-t1", Mode: ipsec.ModePolicyBased}
	in.Ends[0] = ipsec.EndpointSpec{
		DeviceID: 1, Vendor: "fortigate", EgressIface: "port1",
		LANIfaces: lanIfaces, ProtectedSubnets: subnets,
	}
	in.Ends[1] = ipsec.EndpointSpec{
		DeviceID: 2, Vendor: "opnsense", EgressIface: "wan",
		ProtectedSubnets: []string{"192.168.50.0/24"},
	}
	return in
}

func mismatchFinding(fs []ipsec.Finding) *ipsec.Finding {
	for i := range fs {
		if fs[i].Code == "lan_subnet_mismatch" {
			return &fs[i]
		}
	}
	return nil
}

// The reported bug: subnet on port2, only port3 selected.
func TestLANCoherence_WarnsAndNamesTheRealCarrier(t *testing.T) {
	h, db := setupTestHandler(t)
	twoPortFortiGate(t, db, 1)

	f := mismatchFinding(h.lanCoherenceFindings(db, coherenceIntent([]string{"port3"}, []string{"192.168.25.0/24"})))
	if f == nil {
		t.Fatal("a subnet on an unselected interface must warn — this is the exact incident")
	}
	if f.Severity != ipsec.SeverityWarn {
		t.Errorf("severity = %q, want warn — the check needs live device facts and must never block", f.Severity)
	}
	if !strings.Contains(f.Message, "port2") {
		t.Errorf("the finding must name the interface that actually carries the subnet; got %q", f.Message)
	}
}

// Everything legitimate must stay silent, or the warning gets trained away.
func TestLANCoherence_SilentOnLegitimateShapes(t *testing.T) {
	h, db := setupTestHandler(t)
	twoPortFortiGate(t, db, 1)

	cases := map[string]*ipsec.TunnelIntent{
		"subnet is on the selected interface": coherenceIntent([]string{"port3"}, []string{"192.168.13.0/24"}),
		"both interfaces selected":            coherenceIntent([]string{"port2", "port3"}, []string{"192.168.13.0/24", "192.168.25.0/24"}),
		// Routed via a downstream L3 device: on no local interface at all, so there
		// is no carrier to name and nothing is wrong.
		"subnet routed behind the LAN": coherenceIntent([]string{"port3"}, []string{"10.99.0.0/24"}),
		// A supernet legitimately aggregates the interface's network; containment in
		// either direction counts as a match.
		"supernet of the selected interface": coherenceIntent([]string{"port3"}, []string{"192.168.0.0/16"}),
		// Several subnets behind ONE port is a normal topology, not a mismatch.
		"many subnets on one selected port": coherenceIntent([]string{"port3"}, []string{"192.168.13.0/24", "10.20.0.0/24"}),
	}
	for name, in := range cases {
		if f := mismatchFinding(h.lanCoherenceFindings(db, in)); f != nil {
			t.Errorf("%s: expected silence, got %q", name, f.Message)
		}
	}
}

// A device that was never polled has no interface facts. Saying nothing is the
// only honest answer — a guessed warning would be worse than none.
func TestLANCoherence_SilentWithoutDeviceData(t *testing.T) {
	h, db := setupTestHandler(t)
	if f := mismatchFinding(h.lanCoherenceFindings(db, coherenceIntent([]string{"port3"}, []string{"192.168.25.0/24"}))); f != nil {
		t.Errorf("a never-polled device must produce no finding; got %q", f.Message)
	}
}

// OPNsense rules are floating and subnet-scoped — they never name an interface,
// so the whole question is meaningless for that end.
func TestLANCoherence_SkipsVendorsThatDoNotNameInterfaces(t *testing.T) {
	h, db := setupTestHandler(t)
	seedIfaces(t, db, 2, ifaceSeed{
		{Name: "lan", Index: 1, TypeName: "ethernet", Addrs: [][2]string{{"192.168.99.1", "255.255.255.0"}}},
	})
	in := coherenceIntent([]string{"port3"}, []string{"192.168.13.0/24"})
	in.Ends[1].LANIfaces = []string{"lan"}
	in.Ends[1].ProtectedSubnets = []string{"192.168.50.0/24"} // not on "lan"

	if f := mismatchFinding(h.lanCoherenceFindings(db, in)); f != nil {
		t.Errorf("the OPNsense end must be skipped entirely; got %q", f.Message)
	}
}

// The legacy singular must satisfy the check the same as a one-element list —
// otherwise every tunnel persisted before lan_ifaces existed warns on every read.
func TestLANCoherence_LegacySingularCounts(t *testing.T) {
	h, db := setupTestHandler(t)
	twoPortFortiGate(t, db, 1)

	in := coherenceIntent(nil, []string{"192.168.13.0/24"})
	in.Ends[0].LANIface = "port3"

	if f := mismatchFinding(h.lanCoherenceFindings(db, in)); f != nil {
		t.Errorf("a legacy intent must be judged on its effective interfaces; got %q", f.Message)
	}
}
