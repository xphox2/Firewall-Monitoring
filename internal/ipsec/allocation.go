package ipsec

import (
	"encoding/binary"
	"fmt"
	"net"
)

// vtiBase starts at 169.254.1.0 — the link-local pool (169.254.0.0/16, RFC 3927)
// with the reserved first /24 (169.254.0.0/24) skipped. Link-local is never
// routed globally, so a transit /30 can't collide with a real subnet.
const vtiBase uint32 = 0xA9FE0100 // 169.254.1.0

// vtiUsable /30s: 169.254.1.0 .. 169.254.254.255 minus the metadata /24, ≈ 16192.
const vtiSpan uint32 = 253 * 64 // /30s across 169.254.1..253 (skip .0, .169, .254, .255)

// AllocateVTI deterministically derives the /30 transit network and the two
// inner host IPs for a tunnel, from its ID. Deterministic so a redeploy of the
// same tunnel reuses the same addressing. Reserved link-local ranges — the first
// /24, the last /24, and 169.254.169.0/24 (which contains the cloud metadata IP
// 169.254.169.254) — are skipped so cloud-hosted firewalls aren't broken.
//
// Returns (cidr, innerA, innerB): innerA is Ends[0]'s VTI address, innerB is
// Ends[1]'s.
func AllocateVTI(tunnelID uint) (cidr, innerA, innerB string) {
	id := uint32(tunnelID % uint(vtiSpan))
	// Map the ID onto the usable span, then skip the metadata /24 (169.254.169.x).
	third := 1 + id/64 // 1..253
	if third >= 169 {
		third++ // skip 169.254.169.0/24
	}
	fourth := (id % 64) * 4 // 0,4,...,252 within the /24
	network := (vtiBase & 0xFFFF0000) | third<<8 | fourth
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
