package database

import (
	"net"
	"strings"

	"firewall-mon/internal/models"
)

// Selector matching for VPN telemetry attribution.
//
// These live here rather than in cmd/poller because they are coupled to
// ProvisionedTunnelPair (this package's type) and are needed by BOTH the
// poller's connection detection and the read paths that resolve a tunnel's
// identity for display. They were in package main, which no other package can
// import — the dependency was backwards.

// vpnSelectorNet parses a selector as reported in vpn_status.
//
// Two formats occur, from two different code paths in the FortiGate SNMP
// profile: proper CIDR ("192.168.13.0/24") and an inclusive RANGE
// ("192.168.13.0 - 192.168.13.255") emitted where the MIB exposes begin/end
// addresses instead of addr/mask. A CIDR-only parse silently fails on the
// latter, which would leave a healthy tunnel unattributed and its edge red.
//
// A range is reduced to its first address, which is all the containment test
// below needs.
func vpnSelectorNet(s string) (net.IP, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if i := strings.Index(s, "-"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip, true
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip, true
	}
	return nil, false
}

// selectorCovered reports whether any of the intent's subnets contains the
// address the device reported for this selector. Containment rather than
// equality: FortiOS narrows a selector it has negotiated (a /24 in the intent
// is reported as a /32 for the specific host pair actually in use).
func selectorCovered(intentSubnets []string, reported string) bool {
	ip, ok := vpnSelectorNet(reported)
	if !ok {
		return false
	}
	for _, s := range intentSubnets {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

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
		if selectorCovered(local, vpn.LocalSubnet) && selectorCovered(remote, vpn.RemoteSubnet) {
			hit = pp
			found++
		}
	}
	if found != 1 {
		return ProvisionedTunnelPair{}, false
	}
	return hit, true
}
