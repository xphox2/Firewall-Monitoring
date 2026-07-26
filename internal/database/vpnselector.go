package database

import (
	"strings"

	"firewall-mon/internal/models"
	"firewall-mon/internal/netclass"
)

// Selector matching for VPN telemetry attribution.
//
// These live here rather than in cmd/poller because they are coupled to
// ProvisionedTunnelPair (this package's type) and are needed by BOTH the
// poller's connection detection and the read paths that resolve a tunnel's
// identity for display. They were in package main, which no other package can
// import — the dependency was backwards.

// MatchProvisionedBySubnets identifies the provisioned tunnel an unnamed row
// belongs to, using the traffic it carries.
//
// A FortiGate dialup instance carries no usable tunnel name — the collector
// synthesizes one from the peer's observed address — so the selectors are the
// only self-describing thing on the row. Both must line up with the same
// tunnel's intent, from the reporting device's point of view.
//
// A tie is resolved by refusing to answer: attributing a tunnel to the wrong
// parent is worse than leaving it unattributed, because the result wears the
// "provisioned" label and looks authoritative.
func MatchProvisionedBySubnets(provPairs map[string]ProvisionedTunnelPair, vpn models.VPNStatus) (ProvisionedTunnelPair, bool) {
	if vpn.LocalSubnet == "" || vpn.RemoteSubnet == "" {
		return ProvisionedTunnelPair{}, false
	}
	var hit ProvisionedTunnelPair
	found := 0
	for _, pp := range provPairs {
		local, remote, ok := pp.SubnetsFor(vpn.DeviceID)
		if !ok {
			continue // this device is not an endpoint of that tunnel
		}
		if netclass.SelectorCovered(local, vpn.LocalSubnet) && netclass.SelectorCovered(remote, vpn.RemoteSubnet) {
			hit = pp
			found++
		}
	}
	if found != 1 {
		return ProvisionedTunnelPair{}, false
	}
	return hit, true
}

// resolveTunnelGroups labels each row with the LOGICAL tunnel it belongs to.
//
// One tunnel arrives as several rows from several writers under unrelated
// names. On a FortiGate the SSH row carries the provisioned name (`fwm-t11`)
// but no counters — `show ... phase1-interface` reads config, not state — while
// the SNMP dialup row carries the counters under a name the collector
// synthesizes from the peer's observed address, with an EMPTY phase1_name.
// No single existing field unites them, which is why the connection-detail page
// renders a chart per row and one of them is always blank.
//
// Precedence mirrors the connection map's, so the page and the map cannot give
// different answers about which rows are one tunnel:
//
//  1. the provisioned tunnel whose NAME the row reports (tunnel_name or
//     phase1_name), guarded so the reporting device is one of its endpoints;
//  2. failing that, the provisioned tunnel whose SELECTORS the row matches —
//     this is what catches the unnamed dialup child;
//  3. failing that, phase1_name, then tunnel_name, so a row is never groupless.
//
// A failed provisioning lookup is not fatal: the fallbacks still group rows
// that share a phase1 name, which is the pre-existing behaviour.
func (d *Database) resolveTunnelGroups(statuses []models.VPNStatus) {
	if len(statuses) == 0 {
		return
	}
	provPairs, err := d.GetProvisionedTunnelPairs()
	if err != nil {
		provPairs = nil
	}
	for i := range statuses {
		statuses[i].TunnelGroup = tunnelGroupFor(provPairs, statuses[i])
	}
}

func tunnelGroupFor(provPairs map[string]ProvisionedTunnelPair, vpn models.VPNStatus) string {
	for _, n := range []string{vpn.TunnelName, vpn.Phase1Name} {
		if n == "" {
			continue
		}
		// The reporting device must be an endpoint. vpn_status tunnel names are
		// free text read off a device and only ipsec_tunnels.name is unique, so
		// an unrelated box reporting a same-named tunnel must not join the group.
		if pp, ok := provPairs[strings.ToLower(n)]; ok &&
			(vpn.DeviceID == pp.A || vpn.DeviceID == pp.B) {
			return pp.Name
		}
	}
	if pp, ok := MatchProvisionedBySubnets(provPairs, vpn); ok {
		return pp.Name
	}
	if vpn.Phase1Name != "" {
		return vpn.Phase1Name
	}
	return vpn.TunnelName
}
