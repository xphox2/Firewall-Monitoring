package classify

import (
	"net/netip"
	"testing"
)

// flowAddrs covers every shape a flow address takes: private, public, loopback,
// link-local, CGNAT, multicast, broadcast, unspecified, IPv6, IPv4-mapped,
// zoned, and junk.
var flowAddrs = []string{
	"10.0.0.5", "172.16.3.4", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.9",
	"8.8.8.8", "66.179.9.156", "203.0.113.9", "224.0.0.251", "239.255.255.250",
	"255.255.255.255", "0.0.0.0", "fd00::1", "fe80::1", "::1", "2001:db8::1", "ff02::fb",
	"::", "::ffff:10.0.0.5", "::ffff:8.8.8.8", "fe80::1%eth0", "", "garbage", "1.2.3", "010.1.1.1",
}

// TestInternalSet_DefaultsMatchDirection: with no operator networks, the set
// classifies exactly like the package-level Direction on every pair — the
// reclassification job relies on that parity.
func TestInternalSet_DefaultsMatchDirection(t *testing.T) {
	for _, s := range []*InternalSet{nil, NewInternalSet(nil, 3)} {
		for _, a := range flowAddrs {
			for _, b := range flowAddrs {
				if got, want := s.Direction(a, b), Direction(a, b, 0, 0); got != want {
					t.Errorf("set(nil=%v).Direction(%q, %q) = %d, Direction = %d", s == nil, a, b, got, want)
				}
			}
		}
	}
}

func TestInternalSet_OwnNetworksAreInternal(t *testing.T) {
	s := NewInternalSet([]netip.Prefix{
		netip.MustParsePrefix("66.179.9.144/28"),
		netip.MustParsePrefix("66.9.166.120/32"),
		netip.MustParsePrefix("2001:db8:1::/48"),
		netip.MustParsePrefix("::ffff:198.51.100.0/120"), // an IPv4-mapped prefix means its IPv4 range
	}, 2)
	cases := []struct {
		src, dst string
		want     uint8
	}{
		{"66.179.9.156", "203.0.113.9", DirOutbound},
		{"203.0.113.9", "66.179.9.156", DirInbound},
		{"66.179.9.156", "10.0.0.5", DirInternal},
		{"66.179.9.160", "203.0.113.9", DirExternal}, // just outside the /28
		{"66.9.166.120", "8.8.8.8", DirOutbound},
		{"66.9.166.121", "8.8.8.8", DirExternal},
		{"2001:db8:1::5", "2001:db8:2::5", DirOutbound},
		{"::ffff:66.179.9.156", "8.8.8.8", DirOutbound}, // mapped form of an own address
		{"198.51.100.7", "8.8.8.8", DirOutbound},
		{"fe80::1%eth0", "66.179.9.156", DirUnknown},
	}
	for _, c := range cases {
		if got := s.Direction(c.src, c.dst); got != c.want {
			t.Errorf("Direction(%s, %s) = %s, want %s", c.src, c.dst, DirectionName(got), DirectionName(c.want))
		}
	}
	if s.Rev() != 2 || (*InternalSet)(nil).Rev() != 0 {
		t.Errorf("Rev = %d / nil %d, want 2 / 0", s.Rev(), (*InternalSet)(nil).Rev())
	}
}
