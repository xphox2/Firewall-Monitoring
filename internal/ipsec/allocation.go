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
const vtiSpan uint32 = 253 * 64 // /30s across 169.254.1..253 (skip .0 and .255 (RFC 3927 reserved), and .169 (metadata))

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

// FortiGate deterministic mkey allocation for fwm-managed router/static
// (seq-num) and firewall/policy (policyid). FortiOS auto-assigns these numeric
// keys, but a REST create can set them explicitly — so we choose them
// deterministically from the tunnel ID and a RESERVED HIGH base, letting
// RenderRemove DELETE exactly what Render created (stable across redeploys)
// without a read-back. The base is high (well above the low IDs a production
// box's existing routes/policies occupy) and each tunnel owns a stride-wide
// block; routes live in [block, block+fgPolicyOffset) and the two policies at
// block+fgPolicyOffset[..+1]. This bounds a tunnel at fgPolicyOffset (100)
// route objects — 2*N+1 for N protected subnets, i.e. N up to ~49.
//
// COLLISION NOTE: a fixed mkey can still collide with an operator's existing
// object in that high range. C2b's deploy MUST extend the preflight
// collision-check to these seq-nums/policyids before any write ships; C2a only
// renders them (no write), so a collision here is inert.
const (
	fgKeyBase      = 40000
	fgKeyStride    = 200
	fgPolicyOffset = 100
)

// MaxProtectedSubnetsPerEnd bounds a tunnel so its route keys never overrun the
// policy keys: routes occupy indices 0..2N (N subnet routes + N blackholes + 1
// optional peer /32), which must stay below fgPolicyOffset. Enforced in
// validation (too_many_subnets).
const MaxProtectedSubnetsPerEnd = (fgPolicyOffset - 1) / 2 // 49

// FGRouteKey returns the router/static seq-num for the index-th fwm route of a
// tunnel (subnet routes, then blackholes, then the optional peer /32).
func FGRouteKey(tunnelID uint, index int) int {
	return fgKeyBase + int(tunnelID)*fgKeyStride + index
}

// FGPolicyKey returns the firewall/policy policyid for the index-th fwm policy
// (0 = LAN→tunnel, 1 = tunnel→LAN).
func FGPolicyKey(tunnelID uint, index int) int {
	return fgKeyBase + int(tunnelID)*fgKeyStride + fgPolicyOffset + index
}

func u32ToIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b)
}
