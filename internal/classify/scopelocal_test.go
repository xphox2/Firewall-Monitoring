package classify

import "testing"

// TestScopeLocal pins the Flows-page noise filter: scope-local is link-local,
// multicast, broadcast, loopback, and the unspecified address (either endpoint),
// but NOT routed traffic — including RFC1918/ULA/CGNAT LAN hosts and portless
// routed protocols. Matching runs on canonical net.IP.String() forms.
func TestScopeLocal(t *testing.T) {
	// Each case fixes one endpoint to a routed public host so the result is
	// driven purely by the address under test.
	cases := []struct {
		name string
		addr string
		want bool
	}{
		// scope-local positives
		{"v6 link-local", "fe80::1", true},
		{"v6 link-local top of range", "febf::5", true},
		{"v6 multicast", "ff02::fb", true},
		{"v4 multicast low", "224.0.0.251", true},
		{"v4 multicast high", "239.255.255.250", true},
		{"v4 link-local", "169.254.1.1", true},
		{"v4 loopback", "127.0.0.1", true},
		{"v4 broadcast", "255.255.255.255", true},
		{"v4 unspecified", "0.0.0.0", true},
		{"v6 unspecified", "::", true},
		{"v6 loopback", "::1", true},
		// routed negatives — must stay visible
		{"rfc1918 10", "10.0.0.1", false},
		{"rfc1918 192.168", "192.168.1.1", false},
		{"ula", "fd00::1", false},
		{"cgnat", "100.64.0.1", false},
		{"public v4", "8.8.8.8", false},
		{"public v6", "2001:db8::1", false},
		{"site-local deprecated", "fec0::1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// as source, dst public
			if got := ScopeLocal(c.addr, "203.0.113.9"); got != c.want {
				t.Errorf("ScopeLocal(src=%s) = %v, want %v", c.addr, got, c.want)
			}
			// as destination, src public
			if got := ScopeLocal("203.0.113.9", c.addr); got != c.want {
				t.Errorf("ScopeLocal(dst=%s) = %v, want %v", c.addr, got, c.want)
			}
		})
	}

	// Unparseable addresses -> false (don't hide unknowns).
	if ScopeLocal("not-an-ip", "8.8.8.8") {
		t.Error("ScopeLocal with unparseable src should be false")
	}
	if ScopeLocal("8.8.8.8", "") {
		t.Error("ScopeLocal with empty dst should be false")
	}

	// Two routed hosts -> false; fe80->ff02 (both scope-local) -> true.
	if ScopeLocal("10.0.0.5", "203.0.113.9") {
		t.Error("routed-to-routed should not be scope-local")
	}
	if !ScopeLocal("fe80::1", "ff02::1") {
		t.Error("link-local -> multicast should be scope-local")
	}
}
