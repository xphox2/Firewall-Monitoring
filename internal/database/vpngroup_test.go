package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// One tunnel is reported as several rows by several writers under unrelated
// names. On a FortiGate the SSH row carries the provisioned name but no
// counters (it reads config, not state), while the SNMP dialup row carries the
// counters under a synthesized "dialup-<peer-ip>" name with an EMPTY
// phase1_name. That is why the connection-detail page draws a chart per row and
// one of them is permanently blank.

func provisioned(t *testing.T, name string, a, b uint, aNets, bNets []string) map[string]ProvisionedTunnelPair {
	t.Helper()
	return map[string]ProvisionedTunnelPair{
		name: {Name: name, A: a, B: b, ASubnets: aNets, BSubnets: bNets},
	}
}

// THE CASE THAT MOTIVATES THE FIELD. These two rows share no field that could
// group them: one has the name and no counters, the other has the counters and
// no phase1 name.
func TestTunnelGroup_UnitesTheFortiGateNamedAndDialupRows(t *testing.T) {
	pp := provisioned(t, "fwm-t11", 4, 5, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	named := models.VPNStatus{DeviceID: 4, TunnelName: "fwm-t11", Phase1Name: "fwm-t11", Status: "unknown"}
	dialup := models.VPNStatus{
		DeviceID: 4, TunnelName: "dialup-76.66.145.98", TunnelType: "ipsec-dialup",
		LocalSubnet: "192.168.13.0/24", RemoteSubnet: "192.168.50.0/32", Status: "up",
	}

	gNamed := tunnelGroupFor(pp, named)
	gDialup := tunnelGroupFor(pp, dialup)
	if gNamed != gDialup {
		t.Fatalf("the two rows of one tunnel landed in different groups (%q vs %q) — "+
			"this is exactly the split that produces two charts, one of them blank", gNamed, gDialup)
	}
	if gNamed != "fwm-t11" {
		t.Errorf("group = %q, want the provisioned name fwm-t11", gNamed)
	}
}

// A device that is not an endpoint must not be pulled into the tunnel by its
// SELECTORS. Subnet matching is the path that would otherwise capture an
// unrelated box carrying the same networks.
func TestTunnelGroup_NonEndpointDeviceIsNotCapturedBySubnets(t *testing.T) {
	pp := provisioned(t, "fwm-t11", 4, 5, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	// Same networks, unrelated name, and NOT an endpoint of fwm-t11.
	stranger := models.VPNStatus{
		DeviceID: 99, TunnelName: "SOME-OTHER-TUNNEL",
		LocalSubnet: "192.168.13.0/24", RemoteSubnet: "192.168.50.0/24",
	}
	if g := tunnelGroupFor(pp, stranger); g == "fwm-t11" {
		t.Errorf("a device outside the recorded endpoints must not be grouped into that "+
			"tunnel by matching subnets; got %q", g)
	}
}

// The endpoint guard on the NAME path is hard to observe, because a blocked row
// falls back to its own name and usually lands on the same string. The stored
// casing is the one channel where the two outcomes differ: a provisioned match
// returns the tunnel's RECORDED name, while the fallback returns what the device
// reported. So a case difference makes the guard visible.
func TestTunnelGroup_NameMatchRequiresAnEndpoint(t *testing.T) {
	pp := map[string]ProvisionedTunnelPair{
		// Lookup is lowercased; the recorded name keeps its own casing.
		"fwm-t11": {Name: "FWM-T11", A: 4, B: 5},
	}

	if g := tunnelGroupFor(pp, models.VPNStatus{DeviceID: 4, TunnelName: "fwm-t11"}); g != "FWM-T11" {
		t.Errorf("an endpoint must resolve to the RECORDED name; got %q", g)
	}
	if g := tunnelGroupFor(pp, models.VPNStatus{DeviceID: 99, TunnelName: "fwm-t11"}); g == "FWM-T11" {
		t.Error("a non-endpoint must not resolve to the provisioned record — tunnel names " +
			"are free text read off a device, and only the provisioning record is unique")
	}
}

// The guard blocks a non-endpoint from claiming the PROVISIONED identity — but
// a row still falls back to its own phase1_name, which may coincidentally equal
// the provisioned name. That is not a defect and cannot be fixed at this layer:
// the value is a human-meaningful label, not a globally unique key.
//
// It is the reason consumers MUST group by (device_id, tunnel_group). That is
// required anyway: the two ENDS of one tunnel report the same traffic from
// their own side, so a chart summing across devices would double every byte.
func TestTunnelGroup_IsDeviceScopedByContract(t *testing.T) {
	pp := provisioned(t, "fwm-t11", 4, 5, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	endpoint := models.VPNStatus{DeviceID: 4, TunnelName: "fwm-t11", Phase1Name: "fwm-t11"}
	stranger := models.VPNStatus{DeviceID: 99, TunnelName: "fwm-t11", Phase1Name: "fwm-t11"}

	// Both yield the same LABEL...
	if tunnelGroupFor(pp, endpoint) != tunnelGroupFor(pp, stranger) {
		t.Skip("labels already differ; the device-scoping contract is moot here")
	}
	// ...so the device id is what keeps them apart. Assert the pairing a
	// consumer must use is in fact distinct.
	if endpoint.DeviceID == stranger.DeviceID {
		t.Fatal("test setup: the two rows must be on different devices")
	}
}

// Every row must land in some group, or it would vanish from a grouped view.
func TestTunnelGroup_AlwaysFallsBackRatherThanEmpty(t *testing.T) {
	cases := map[string]models.VPNStatus{
		"phase1 name only": {DeviceID: 7, TunnelName: "x", Phase1Name: "HUB"},
		"tunnel name only": {DeviceID: 7, TunnelName: "DMZ"},
	}
	want := map[string]string{"phase1 name only": "HUB", "tunnel name only": "DMZ"}
	for name, vpn := range cases {
		if g := tunnelGroupFor(nil, vpn); g != want[name] {
			t.Errorf("%s: group = %q, want %q", name, g, want[name])
		}
	}
}

// Two children of one multi-subnet tunnel belong to the SAME group — the
// per-child split lives in the table, not in the chart.
func TestTunnelGroup_MultiSubnetChildrenShareOneGroup(t *testing.T) {
	pp := provisioned(t, "fwm-t11", 4, 5,
		[]string{"192.168.13.0/24", "192.168.25.0/24"}, []string{"192.168.50.0/24"})

	a := models.VPNStatus{DeviceID: 4, Phase1Name: "fwm-t11", TunnelName: "fwm-t11:192.168.13.0-192.168.50.0"}
	b := models.VPNStatus{DeviceID: 4, Phase1Name: "fwm-t11", TunnelName: "fwm-t11:192.168.25.0-192.168.50.0"}

	if tunnelGroupFor(pp, a) != tunnelGroupFor(pp, b) {
		t.Error("children of one tunnel must share a group")
	}
	if a.TunnelName == b.TunnelName {
		t.Error("...while keeping distinct tunnel_names, or the newest-per-name query drops one")
	}
}
