// Package netclass holds the shared interface-classification + subnet-derivation
// heuristics used both by the poller's physical-connection auto-detect and by the
// IPSec wizard's "hints" endpoint, so the two can't drift.
package netclass

import (
	"fmt"
	"net"
	"strings"
)

// lanTypes are interface TypeNames that carry a LAN-segment (broadcast-domain) L3
// address. On FortiGate the LAN IP almost never sits on a bare Ethernet port: it
// lives on the hardware/software switch ("internal"/"lan", ifType 209 bridge) or
// a VLAN sub-interface (ifType 135 l2vlan); some setups use a software switch/zone
// (ifType 53 propVirtual). Tunnel/GRE/loopback/MPLS and overlay carriers
// (l3ipvlan, vxlan) are deliberately excluded — point-to-point/overlay, not LAN.
//
// Keys are lowercase because IsLANType lowercases its input. (The poller's earlier
// inline version keyed this map on camelCase "propVirtual" yet looked it up with a
// lowercased type name, so software-switch/zone interfaces silently never matched;
// extracting the heuristic here fixes that dead entry.)
var lanTypes = map[string]bool{
	"ethernet":    true,
	"lag":         true,
	"bridge":      true,
	"l2vlan":      true,
	"propvirtual": true,
}

// IsLANType reports whether an interface TypeName carries a LAN segment
// (case-insensitive; tolerates surrounding whitespace).
func IsLANType(typeName string) bool {
	return lanTypes[strings.ToLower(strings.TrimSpace(typeName))]
}

// vpnNamePrefixes are interface-NAME prefixes for VPN/overlay/tunnel carriers that
// must never count as a LAN segment even when their ifType looks LAN-ish. A Linux/
// BSD OpenVPN or WireGuard interface reports ifType 53 (propVirtual) — the same type
// as a FortiGate software switch — so type alone can't tell them apart; the name can.
var vpnNamePrefixes = []string{"tun", "tap", "wg", "vti", "ovpn", "gre", "gif", "ipsec", "l2tp", "wireguard"}

// IsVPNInterfaceName reports whether an interface NAME denotes a VPN/tunnel/overlay
// carrier (tun0, wg0, ovpns1, vti1, gif0, …) — a point-to-point/overlay link, never
// a broadcast LAN segment. Used alongside IsLANType so a propVirtual tun device is
// excluded from LAN-segment classification.
func IsVPNInterfaceName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, p := range vpnNamePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// IsFabricInterface reports a FortiLink/link-local (169.254.0.0/16) fabric link,
// which is a management/stacking link, not an inter-device LAN segment.
func IsFabricInterface(ifName, ipAddr string) bool {
	if strings.EqualFold(strings.TrimSpace(ifName), "fortilink") {
		return true
	}
	if ip := net.ParseIP(ipAddr); ip != nil {
		if v4 := ip.To4(); v4 != nil && v4[0] == 169 && v4[1] == 254 {
			return true
		}
	}
	return false
}

// SubnetCIDR derives the network CIDR (e.g. "10.10.10.0/24") from an IPv4 address
// + dotted netmask. ok=false for unparseable input OR a point-to-point/host prefix
// (/30, /31, /32) — those are WAN-link/host addresses, not a shared LAN segment.
func SubnetCIDR(ipAddr, netMask string) (cidr string, ok bool) {
	ip := net.ParseIP(ipAddr)
	mask := net.ParseIP(netMask)
	if ip == nil || mask == nil {
		return "", false
	}
	ip4 := ip.To4()
	mask4 := mask.To4()
	if ip4 == nil || mask4 == nil {
		return "", false
	}
	ones, bits := net.IPMask(mask4).Size()
	if bits == 32 && ones >= 30 {
		return "", false
	}
	network := ip4.Mask(net.IPMask(mask4))
	return fmt.Sprintf("%s/%d", network.String(), ones), true
}
