package classify

import "testing"

// TestDirection_MulticastBroadcastUnspecified_M6 pins the 2026-07-01 audit M6
// fix: multicast, limited broadcast, and the unspecified address are LAN-scope,
// not "external" — otherwise SSDP/mDNS/IPTV multicast and DHCP DISCOVER get
// stamped Outbound/External and feed false c2_beacon / data_exfil detections.
func TestDirection_MulticastBroadcastUnspecified_M6(t *testing.T) {
	cases := []struct {
		name, src, dst string
		want           uint8
	}{
		{"ssdp mDNS announce", "192.168.1.10", "239.255.255.250", DirInternal},
		{"ipv6 multicast", "fe80::1", "ff02::1", DirInternal},
		{"dhcp discover", "0.0.0.0", "255.255.255.255", DirInternal},
		{"ipv4 broadcast from lan", "192.168.1.5", "255.255.255.255", DirInternal},
		// Control: a genuine outbound flow to a public host is still Outbound.
		{"real outbound", "192.168.1.10", "8.8.8.8", DirOutbound},
		{"real inbound", "8.8.8.8", "192.168.1.10", DirInbound},
	}
	for _, c := range cases {
		if got := Direction(c.src, c.dst, 0, 0); got != c.want {
			t.Errorf("%s: Direction(%s→%s) = %s, want %s",
				c.name, c.src, c.dst, DirectionName(got), DirectionName(c.want))
		}
	}
}
