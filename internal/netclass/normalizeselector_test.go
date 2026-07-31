package netclass

import "testing"

// NormalizeSelector exists so the two ends of a tunnel can be compared as text
// when their vendors serialise the same network differently. Its third arm —
// return the input unchanged — is a guarantee, not a failure path: two
// FortiGates mirroring a non-aligned range already match on exact equality, and
// rewriting or dropping such a value would take that away.
func TestNormalizeSelector(t *testing.T) {
	tests := []struct{ name, in, want string }{
		// Already CIDR — untouched.
		{"cidr passes through", "192.168.13.0/24", "192.168.13.0/24"},
		{"host cidr passes through", "192.168.13.7/32", "192.168.13.7/32"},
		{"default route passes through", "0.0.0.0/0", "0.0.0.0/0"},

		// Bare address -> /32. This is the arm that makes an IKEv2-narrowed host
		// pair comparable: FortiGate's buildCIDR refuses /30 and tighter, so it
		// emits the bare address where OPNsense emits /32.
		{"bare host becomes /32", "192.168.13.7", "192.168.13.7/32"},

		// Aligned ranges -> CIDR.
		{"aligned /24 range", "192.168.13.0 - 192.168.13.255", "192.168.13.0/24"},
		{"aligned /25 range", "10.0.0.0 - 10.0.0.127", "10.0.0.0/25"},
		{"aligned /31 range", "10.0.0.2 - 10.0.0.3", "10.0.0.2/31"},
		{"single-address range", "10.0.0.5 - 10.0.0.5", "10.0.0.5/32"},

		// Refusal is IDENTITY. A non-aligned range has no CIDR form; approximating
		// it by its begin address would let a range collide with a host selector,
		// and dropping it would remove a match that works today.
		{"unaligned start keeps its text", "10.0.0.1 - 10.0.0.254", "10.0.0.1 - 10.0.0.254"},
		{"non-power-of-two keeps its text", "10.0.0.0 - 10.0.0.99", "10.0.0.0 - 10.0.0.99"},
		{"reversed range keeps its text", "10.0.0.255 - 10.0.0.0", "10.0.0.255 - 10.0.0.0"},
		{"garbage keeps its text", "not-an-address", "not-an-address"},
		{"empty stays empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeSelector(tc.in); got != tc.want {
				t.Errorf("NormalizeSelector(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The property the phase-2 matcher depends on: normalizing can only ever ADD
// matches, never remove one.
//
// Two ends mirroring a selector this function cannot convert still have to
// match, and today they do — by exact equality of the identical raw text, which
// selectorMirrors documents as load-bearing for FortiGate range selectors. That
// survives only if refusal returns the input UNCHANGED. Returning "", or a
// best-effort approximation like the range's begin address, would silently drop
// a match that works in production.
func TestNormalizeSelector_RefusalIsIdentity(t *testing.T) {
	for _, s := range []string{
		"10.0.0.1 - 10.0.0.254", // non-aligned range: no CIDR form exists
		"10.0.0.0 - 10.0.0.99",  // not a power-of-two size
		"garbage",               // unparseable
		"2001:db8::/32",         // IPv6 — untouched, not mangled into IPv4
	} {
		if got := NormalizeSelector(s); got != s {
			t.Errorf("NormalizeSelector(%q) = %q, want it returned verbatim — a selector "+
				"this function cannot convert must still compare equal to the peer's "+
				"identical text, which is the only way those two ends match at all", s, got)
		}
	}
}
