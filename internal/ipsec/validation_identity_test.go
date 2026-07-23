package ipsec_test

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// TestValidate_Identity covers the type-aware IKE identity validation: block any
// value that would fail phase-1 auth on a FortiGate⇄OPNsense tunnel, while
// allowing legitimate FQDN identities (including a single label like "TECHLABS"
// and an underscore, which both vendors accept).
func TestValidate_Identity(t *testing.T) {
	c := [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}

	withID := func(typ ipsec.IDType, val string) *ipsec.TunnelIntent {
		in := canonicalIntent()
		in.Ends[0].LocalID = ipsec.IKEIdentity{Type: typ, Value: val}
		return in
	}

	// --- FQDN type: values that MUST block (would fail the tunnel) ---
	blockFQDN := []struct{ val, code string }{
		{"192.168.5.1", "id_fqdn_is_ip"},          // IPv4 literal → strongSwan ID_IPV4_ADDR
		{"fe80::1", "id_fqdn_is_ip"},              // IPv6 literal
		{"10.0.0.1-10.0.0.9", "id_fqdn_is_range"}, // ip-ip range → ID_IPV4_ADDR_RANGE
		{"site:one", "id_fqdn_charset"},           // ':' → IPv6/KEY_ID/type-prefix
	}
	for _, tc := range blockFQDN {
		fs := ipsec.Validate(withID(ipsec.IDTypeFQDN, tc.val), c)
		if !hasCode(fs, tc.code) {
			t.Errorf("fqdn %q: expected block %q; got %+v", tc.val, tc.code, fs)
		}
		if sevOf(fs, tc.code) != ipsec.SeverityBlock {
			t.Errorf("fqdn %q: %q must be a block", tc.val, tc.code)
		}
	}

	// '@' is caught by the generic safeToken gate (unsafe_value) — still a block.
	if fs := ipsec.Validate(withID(ipsec.IDTypeFQDN, "fw@example.com"), c); !ipsec.HasBlock(fs) {
		t.Error("fqdn with '@' must block")
	}

	// Over-length (64 chars) → id_too_long.
	long := strings.Repeat("a", 64)
	if fs := ipsec.Validate(withID(ipsec.IDTypeFQDN, long), c); !hasCode(fs, "id_too_long") {
		t.Error("64-char identity must block id_too_long")
	}

	// --- FQDN type: values that MUST pass (they establish fine on both vendors) ---
	for _, val := range []string{"TECHLABS", "fw.technicallabs.org", "prince_1.test.com", "my-fw.example.com"} {
		if fs := ipsec.Validate(withID(ipsec.IDTypeFQDN, val), c); ipsec.HasBlock(fs) {
			t.Errorf("fqdn %q should be a valid identity, got blocks %+v", val, fs)
		}
	}

	// --- IP type: symmetric check ---
	if fs := ipsec.Validate(withID(ipsec.IDTypeIP, "not-an-ip"), c); !hasCode(fs, "id_ip_invalid") {
		t.Error("ip identity 'not-an-ip' must block id_ip_invalid")
	}
	if fs := ipsec.Validate(withID(ipsec.IDTypeIP, "203.0.113.7"), c); hasCode(fs, "id_ip_invalid") {
		t.Error("a valid IP identity must not be flagged")
	}
}
