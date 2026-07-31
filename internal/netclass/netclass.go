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

// cgnat is the RFC 6598 carrier-grade-NAT shared space (100.64.0.0/10).
var _, cgnat, _ = net.ParseCIDR("100.64.0.0/10")

// IsPublicIP reports whether ip parses as a globally-routable address — i.e. not
// RFC1918 private, loopback, link-local, CGNAT (RFC 6598), unspecified, or
// multicast. Used to pick a firewall's real public WAN address out of its polled
// interface IPs. Unparseable input is not public.
func IsPublicIP(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return false
	}
	if p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsLinkLocalMulticast() ||
		p.IsMulticast() || p.IsUnspecified() {
		return false
	}
	return !cgnat.Contains(p)
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

// SelectorIP parses an IPSec traffic selector as devices actually report it and
// returns its first address.
//
// Two formats occur, from two different code paths in the FortiGate SNMP
// profile: proper CIDR ("192.168.13.0/24") and an inclusive RANGE
// ("192.168.13.0 - 192.168.13.255"), emitted where the MIB exposes begin/end
// addresses instead of addr/mask. A CIDR-only parse silently fails on the
// latter, which would leave a healthy tunnel unattributed.
//
// It lives here rather than beside either caller because both the telemetry
// parser and the connection detector need it, and it is pure net/strings logic
// with no database or vendor coupling.
func SelectorIP(s string) (net.IP, bool) {
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

// SelectorCovered reports whether any of the configured subnets contains the
// address a device reported for a selector.
//
// Containment rather than equality, because IKEv2 NARROWS: a /24 in the intent
// is legitimately reported as a /32 for the host pair actually in use. Note the
// direction is one-way on purpose — configured ⊇ reported. Treating it as
// symmetric would let a reported supernet match a narrower intent, which is not
// something a compliant peer can produce.
func SelectorCovered(configured []string, reported string) bool {
	ip, ok := SelectorIP(reported)
	if !ok {
		return false
	}
	for _, s := range configured {
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

// SelectorPrefixLen returns a selector's prefix length, for preferring the most
// specific of several candidate matches. Missing or unparseable prefixes sort
// as the least specific.
func SelectorPrefixLen(s string) int {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "-"); i >= 0 {
		return 0
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		ones, _ := n.Mask.Size()
		return ones
	}
	return 0
}

// NormalizeSelector rewrites a device-reported traffic selector into CIDR where
// that is possible WITHOUT changing what it means, so the two ends of a tunnel
// can be compared as strings even when their vendors serialise differently.
//
// A FortiGate emits three shapes (see snmp.vendor_fortigate): proper CIDR when
// the MIB exposes a mask; an inclusive RANGE "10.0.1.0 - 10.0.1.255" when it does
// not; and a BARE ADDRESS when there is no mask to build from, or when the
// range's end equals its begin. OPNsense emits CIDR throughout. So a host pair
// that IKEv2 narrowed reads "192.168.13.7" on one end and "192.168.13.7/32" on
// the other, and today those never compare equal.
//
// Three arms, and the third is the one that matters:
//
//   - an ALIGNED range becomes its CIDR;
//   - a bare address becomes /32;
//   - anything else is RETURNED UNCHANGED.
//
// That last arm is not a failure path, it is a guarantee. A non-aligned range
// has no CIDR form, and approximating it by its begin address would let a range
// selector collide with a host selector. Returning it verbatim also preserves
// the behaviour this function must not regress: two FortiGates mirroring the
// same range already match on exact string equality, and dropping or rewriting
// the value would take that away. Normalizing therefore only ever ADDS matches.
func NormalizeSelector(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "/") {
		return s
	}
	if i := strings.Index(s, " - "); i >= 0 {
		return normalizeRange(s, strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+3:]))
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return s + "/32"
	}
	return s
}

// normalizeRange converts begin-end to CIDR only when the range is exactly one
// aligned network: a power-of-two size, starting on a multiple of that size.
// Any other range keeps its original text.
func normalizeRange(original, begin, end string) string {
	b, e := net.ParseIP(begin), net.ParseIP(end)
	if b == nil || e == nil {
		return original
	}
	b4, e4 := b.To4(), e.To4()
	if b4 == nil || e4 == nil {
		return original
	}
	bi := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])
	ei := uint32(e4[0])<<24 | uint32(e4[1])<<16 | uint32(e4[2])<<8 | uint32(e4[3])
	if ei < bi {
		return original
	}
	size := uint64(ei) - uint64(bi) + 1
	if size&(size-1) != 0 { // not a power of two
		return original
	}
	if uint64(bi)%size != 0 { // not aligned to its own size
		return original
	}
	ones := 32
	for s := size; s > 1; s >>= 1 {
		ones--
	}
	return fmt.Sprintf("%s/%d", b4.String(), ones)
}
