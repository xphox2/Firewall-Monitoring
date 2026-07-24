package ipsec_test

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// TestValidate_PeerUnroutable_PrivateStaticVsPublicPeer is the fwm-t9 regression:
// a behind-NAT end (OPNsense, private 192.168.5.107) left as a STATIC peer while
// its far end is public (FortiGate 66.179.9.155) makes the private address the
// FortiGate's `remote-gw` — unroutable across the internet, a guaranteed dead
// tunnel. That must BLOCK, not merely warn. Marking the end dynamic (dialup)
// clears it; a genuine LAN-to-LAN pair (both private) stays a soft warn.
func TestValidate_PeerUnroutable_PrivateStaticVsPublicPeer(t *testing.T) {
	c := [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}

	// Canonical (End B dynamic/behind-NAT) is the correct config — no block.
	if fs := ipsec.Validate(canonicalIntent(), c); ipsec.HasBlock(fs) {
		t.Fatalf("canonical (B dynamic) must not block; got %+v", fs)
	}

	// The t9 breakage: End B (private) flipped to a STATIC peer while End A is
	// public → hard block with the actionable code.
	broken := canonicalIntent()
	broken.Ends[1].Dynamic = false // OPNsense now a static peer at 192.168.5.107
	fs := ipsec.Validate(broken, c)
	if !hasCode(fs, "peer_unroutable") {
		t.Fatalf("expected peer_unroutable block for private-static-vs-public-peer; got %+v", fs)
	}
	if !ipsec.HasBlock(fs) {
		t.Error("peer_unroutable must be a blocking finding, not a warning")
	}
	// It must NOT double-report as the softer peer_private warn.
	if hasCode(fs, "peer_private") {
		t.Error("private-vs-public should escalate to peer_unroutable, not also warn peer_private")
	}

	// Re-marking the behind-NAT end dynamic clears the block (the operator's fix).
	fixed := canonicalIntent()
	fixed.Ends[1].Dynamic = true
	if hasCode(ipsec.Validate(fixed, c), "peer_unroutable") {
		t.Error("a dynamic behind-NAT end must not be flagged unroutable")
	}

	// Giving the behind-NAT end its real public IP also clears the block.
	pub := canonicalIntent()
	pub.Ends[1].Dynamic = false
	pub.Ends[1].PeerIP = "76.66.145.98" // OPNsense's public NAT address
	if hasCode(ipsec.Validate(pub, c), "peer_unroutable") {
		t.Error("a public static endpoint must not be flagged unroutable")
	}

	// LAN-to-LAN (both ends private, static) stays the softer warn, never a block.
	lan := canonicalIntent()
	lan.Ends[0].Dynamic = false
	lan.Ends[0].PeerIP = "10.0.0.1" // FortiGate now also private
	lan.Ends[1].Dynamic = false
	lan.Ends[1].PeerIP = "10.0.0.2"
	lfs := ipsec.Validate(lan, c)
	if hasCode(lfs, "peer_unroutable") {
		t.Error("both-private LAN-to-LAN must not hard-block as unroutable")
	}
	if !hasCode(lfs, "peer_private") {
		t.Error("both-private LAN-to-LAN should still carry the soft peer_private warn")
	}
}

// TestValidate_FloatingPublicSubnetWarn: OPNsense's tunnel pass rule is floating
// (interface-agnostic), so a PUBLIC protected subnet warrants a WAN-antispoof
// warning; an all-private footprint (the common case) does not.
func TestValidate_FloatingPublicSubnetWarn(t *testing.T) {
	c := [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}

	// Canonical is all-private → no floating-subnet warning.
	if hasCode(ipsec.Validate(canonicalIntent(), c), "firewall_floating_public_subnet") {
		t.Error("all-private footprint must not warn about floating public subnets")
	}

	// A public protected subnet on the tunnel → warn (tied to the OPNsense end).
	pub := canonicalIntent()
	pub.Ends[0].ProtectedSubnets = []string{"203.0.113.0/24"} // FortiGate side public
	if !hasCode(ipsec.Validate(pub, c), "firewall_floating_public_subnet") {
		t.Error("a public protected subnet must warn that the OPNsense pass rule is interface-agnostic")
	}
}
