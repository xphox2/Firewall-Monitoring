package classify

import (
	"net/netip"
	"sort"
)

// InternalSet is the operator's notion of "inside": the private ranges every
// deployment has (privateCIDRs, plus multicast, the limited broadcast and the
// unspecified address, as isInternal treats them) and the operator's own
// networks — the addresses and subnets of their monitored devices, and any
// ranges they list. Direction classifies a flow against it.
//
// Without the operator's networks, a public range the operator owns counts as
// "outside": on production 73% of a day's traffic read External, and a server
// on the operator's own /28 showed every flow as External.
//
// Prefixes are bucketed by length (the threatintel.Matcher layout), so a
// lookup costs one map probe per distinct length. Read-only once built; refresh
// by building a new set. A nil *InternalSet is valid and behaves exactly like
// Direction with revision 0.
type InternalSet struct {
	by4   map[int]map[netip.Prefix]struct{}
	lens4 []int
	by6   map[int]map[netip.Prefix]struct{}
	lens6 []int
	rev   uint16
}

// NewInternalSet builds a set from the operator's prefixes on top of the
// private defaults. rev is the classification revision rows stamped under this
// set carry (flow class_rev).
func NewInternalSet(prefixes []netip.Prefix, rev uint16) *InternalSet {
	s := &InternalSet{
		by4: map[int]map[netip.Prefix]struct{}{},
		by6: map[int]map[netip.Prefix]struct{}{},
		rev: rev,
	}
	for _, c := range privateCIDRs {
		s.add(netip.MustParsePrefix(c))
	}
	for _, p := range prefixes {
		s.add(p)
	}
	s.lens4 = sortedLens(s.by4)
	s.lens6 = sortedLens(s.by6)
	return s
}

func (s *InternalSet) add(p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	a := p.Addr()
	bits := p.Bits()
	if a.Is4In6() && bits >= 96 {
		a, bits = a.Unmap(), bits-96
	}
	p = netip.PrefixFrom(a, bits).Masked()
	by := s.by6
	if a.Is4() {
		by = s.by4
	}
	if by[bits] == nil {
		by[bits] = map[netip.Prefix]struct{}{}
	}
	by[bits][p] = struct{}{}
}

func sortedLens(by map[int]map[netip.Prefix]struct{}) []int {
	lens := make([]int, 0, len(by))
	for l := range by {
		lens = append(lens, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(lens)))
	return lens
}

// Rev is the classification revision; 0 for a nil set.
func (s *InternalSet) Rev() uint16 {
	if s == nil {
		return 0
	}
	return s.rev
}

// contains reports whether a (already unmapped) is inside the set.
func (s *InternalSet) contains(a netip.Addr) bool {
	if a.IsMulticast() || a.IsUnspecified() || a == limitedBroadcast {
		return true
	}
	by, lens := s.by6, s.lens6
	if a.Is4() {
		by, lens = s.by4, s.lens4
	}
	for _, l := range lens {
		p, err := a.Prefix(l)
		if err != nil {
			continue
		}
		if _, ok := by[l][p]; ok {
			return true
		}
	}
	return false
}

var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// parseFlowAddr parses a flow address the way net.ParseIP-based Direction
// does: no zones (net.ParseIP rejects "fe80::1%eth0"), and an IPv4-mapped IPv6
// address is its IPv4 address.
func parseFlowAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Direction classifies a flow against the set: inbound, outbound, internal or
// external, DirUnknown when either address does not parse. A nil set uses the
// private defaults only, exactly as the package-level Direction.
func (s *InternalSet) Direction(srcAddr, dstAddr string) uint8 {
	if s == nil {
		return Direction(srcAddr, dstAddr, 0, 0)
	}
	src, ok1 := parseFlowAddr(srcAddr)
	dst, ok2 := parseFlowAddr(dstAddr)
	if !ok1 || !ok2 {
		return DirUnknown
	}
	srcInt, dstInt := s.contains(src), s.contains(dst)
	switch {
	case srcInt && dstInt:
		return DirInternal
	case srcInt:
		return DirOutbound
	case dstInt:
		return DirInbound
	default:
		return DirExternal
	}
}

// defaultSet is the private-defaults-only set.
var defaultSet = NewInternalSet(nil, 0)

// DefaultInternal reports whether an address is inside even without any
// operator networks (private ranges, loopback, link-local, CGNAT, multicast,
// broadcast, unspecified).
func DefaultInternal(a netip.Addr) bool { return defaultSet.contains(a.Unmap()) }

// defaultPrefixes are the default-internal ranges as prefixes, including what
// contains() adds by method, for whole-prefix containment checks.
var defaultPrefixes = func() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(privateCIDRs)+5)
	for _, c := range append(append([]string{}, privateCIDRs...),
		"224.0.0.0/4", "ff00::/8", "255.255.255.255/32", "0.0.0.0/32", "::/128") {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

// DefaultCovers reports whether EVERY address of p is inside without any
// operator networks — p lies within one default range. Testing only p's first
// address would wrongly discard a wider range that merely starts inside one
// (192.168.0.0/13 begins in 192.168/16 but reaches 192.175.255.255).
func DefaultCovers(p netip.Prefix) bool {
	a := p.Addr()
	bits := p.Bits()
	if a.Is4In6() && bits >= 96 {
		a, bits = a.Unmap(), bits-96
	}
	for _, d := range defaultPrefixes {
		if bits >= d.Bits() && d.Contains(a) {
			return true
		}
	}
	return false
}
