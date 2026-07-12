package ipsec

import (
	"encoding/binary"
	"fmt"
	"net"
)

// vtiBase is the reserved link-local pool (169.254.0.0/16, RFC 3927) the wizard
// carves /30 transit networks from for route-based (VTI) tunnels. Link-local is
// never routed globally, so a transit /30 can't collide with real subnets.
const vtiBase uint32 = 0xA9FE0000 // 169.254.0.0

// AllocateVTI deterministically derives the /30 transit network and the two
// inner host IPs for a tunnel, from its ID. Deterministic so a redeploy of the
// same tunnel reuses the same addressing. The /16 holds 16384 /30s.
//
// Returns (cidr, innerA, innerB): innerA is Ends[0]'s VTI address, innerB is
// Ends[1]'s.
func AllocateVTI(tunnelID uint) (cidr, innerA, innerB string) {
	offset := uint32(tunnelID%16384) * 4
	network := vtiBase + offset
	cidr = fmt.Sprintf("%s/30", u32ToIP(network).String())
	innerA = u32ToIP(network + 1).String()
	innerB = u32ToIP(network + 2).String()
	return cidr, innerA, innerB
}

// NextFree returns the smallest integer >= start that is not present in taken.
// Used to allocate reqid / if_id / tunnel-number against the set already in use
// on a device (read live in the refresh_state step).
func NextFree(taken map[int]bool, start int) int {
	for n := start; ; n++ {
		if !taken[n] {
			return n
		}
	}
}

func u32ToIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b)
}
