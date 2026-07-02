package handlers

import "testing"

// TestCanonicalThreatCIDR_L22 pins the 2026-07-01 audit L22 fix: stored CIDR is
// canonicalized (masked) so the DB key, the displayed value, and the enforced
// prefix are identical.
func TestCanonicalThreatCIDR_L22(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9/24": "203.0.113.0/24",  // host bits dropped
		"203.0.113.0/24": "203.0.113.0/24",  // already canonical
		"203.0.113.9":    "203.0.113.9/32",  // bare IPv4 → /32
		"2001:db8::5/32": "2001:db8::/32",   // v6 host bits dropped
		"2001:db8::5":    "2001:db8::5/128", // bare IPv6 → /128
	}
	for in, want := range cases {
		if got := canonicalThreatCIDR(in); got != want {
			t.Errorf("canonicalThreatCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}
