package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// Attribution must not credit a tunnel with traffic on a path the operator
// switched off — and, just as importantly, must still credit it for traffic on
// a path that is ON.
//
// The subtlety the shape has to survive: SelectorCovered is one-way containment
// (IKEv2 narrowing legitimately reports a configured /24 as a /32), and
// overlapping networks within one end stay legal. So a reported address can sit
// inside BOTH an enabled and a disabled entry. Testing the flat lists, or
// finding "the" covering pair and asking whether it is disabled, would reject a
// row that genuinely belongs to an enabled child.
func TestAttribution_ExistentialOverEnabledPaths(t *testing.T) {
	// End A holds an overlapping pair: a /16 and a /24 inside it.
	pp := ProvisionedTunnelPair{
		Name: "fwm-t7", A: 1, B: 2,
		ASubnets: []string{"10.0.0.0/16", "10.0.13.0/24"},
		BSubnets: []string{"192.168.50.0/24"},
		// 10.0.13.0/24 ↔ 50.0/24 is DISABLED; 10.0.0.0/16 ↔ 50.0/24 is enabled.
		EnabledPaths: [][2]string{{"10.0.0.0/16", "192.168.50.0/24"}},
		PathDetail:   true,
	}
	pairs := map[string]ProvisionedTunnelPair{"fwm-t7": pp}

	// A row narrowed to a host that sits inside BOTH entries. It belongs to the
	// enabled /16 child, so it must still attribute.
	row := models.VPNStatus{DeviceID: 1, LocalSubnet: "10.0.13.7/32", RemoteSubnet: "192.168.50.9/32"}
	if _, ok := MatchProvisionedBySubnets(pairs, row); !ok {
		t.Error("a row from the ENABLED overlapping /16 child was refused. The predicate " +
			"must ask whether ANY enabled pair covers it, not whether the most specific " +
			"covering entry happens to be disabled.")
	}

	// A row whose only covering pair is disabled must NOT attribute.
	only := ProvisionedTunnelPair{
		Name: "fwm-t8", A: 3, B: 4,
		ASubnets:     []string{"172.16.9.0/24"},
		BSubnets:     []string{"192.168.60.0/24"},
		EnabledPaths: nil,  // policy-based with every path off...
		PathDetail:   true, // ...which is NOT the same as "no pair detail"
	}
	off := map[string]ProvisionedTunnelPair{"fwm-t8": only}
	offRow := models.VPNStatus{DeviceID: 3, LocalSubnet: "172.16.9.5/32", RemoteSubnet: "192.168.60.5/32"}
	if _, ok := MatchProvisionedBySubnets(off, offRow); ok {
		t.Error("a row was attributed to a tunnel with no enabled paths")
	}
}

// Route-based tunnels carry no pair detail (one 0.0.0.0/0 selector is
// negotiated), so they must keep matching on the flat subnet lists exactly as
// they always have. Using the 0/0 path for attribution would match every row on
// the box.
func TestAttribution_RouteBasedFallsBackToLists(t *testing.T) {
	pp := ProvisionedTunnelPair{
		Name: "fwm-t9", A: 5, B: 6,
		ASubnets: []string{"10.10.0.0/24"},
		BSubnets: []string{"10.20.0.0/24"},
		// nil: no pair-level detail for route-based
	}
	pairs := map[string]ProvisionedTunnelPair{"fwm-t9": pp}
	row := models.VPNStatus{DeviceID: 5, LocalSubnet: "10.10.0.3/32", RemoteSubnet: "10.20.0.4/32"}
	if _, ok := MatchProvisionedBySubnets(pairs, row); !ok {
		t.Error("a route-based tunnel stopped attributing — the flat-list fallback is gone")
	}
}
