package classify

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name                       string
		proto                      uint8
		srcPort, dstPort, expected uint16 // expected stored as uint16 only for table brevity
		want                       Category
	}{
		{"https outbound", protoTCP, 51514, 443, 0, Web},
		{"http alt", protoTCP, 40000, 8080, 0, Web},
		{"dns udp", protoUDP, 33333, 53, 0, DNS},
		{"dns reply src", protoUDP, 53, 33333, 0, DNS},
		{"smtp", protoTCP, 50000, 25, 0, Email},
		{"smb", protoTCP, 49555, 445, 0, FileShare},
		{"ssh", protoTCP, 60000, 22, 0, RemoteAccess},
		{"rdp", protoTCP, 61000, 3389, 0, RemoteAccess},
		{"postgres", protoTCP, 51000, 5432, 0, Database},
		{"sip", protoUDP, 5060, 5060, 0, VoIP},
		{"ntp", protoUDP, 51000, 123, 0, Management},
		{"snmp", protoUDP, 51000, 161, 0, Management},
		{"bittorrent", protoTCP, 6881, 49000, 0, P2P},
		{"icmp", protoICMP, 0, 0, 0, ICMP},
		{"icmpv6", protoICMPv6, 0, 0, 0, ICMP},
		{"gre tunnel", protoGRE, 0, 0, 0, VPN},
		{"esp", protoESP, 0, 0, 0, VPN},
		{"ospf", protoOSPF, 0, 0, 0, Management},
		{"wireguard", protoUDP, 40000, 51820, 0, VPN},
		{"ephemeral both unknown", protoTCP, 40000, 41000, 0, Unknown},
		{"unknown proto", 200, 0, 0, 0, Unknown},
		{"lower-port wins when both known", protoTCP, 80, 443, 0, Web}, // both Web; 80 < 443
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.proto, tc.srcPort, tc.dstPort, 0); got != tc.want {
				t.Fatalf("Classify(%d, %d, %d) = %v (%s), want %v (%s)",
					tc.proto, tc.srcPort, tc.dstPort, got, got, tc.want, tc.want)
			}
		})
	}
}

func TestDirection(t *testing.T) {
	cases := []struct {
		name     string
		src, dst string
		want     uint8
	}{
		{"internal to internal", "10.0.0.5", "192.168.1.10", DirInternal},
		{"outbound", "10.0.0.5", "8.8.8.8", DirOutbound},
		{"inbound", "203.0.113.9", "192.168.1.10", DirInbound},
		{"external transit", "203.0.113.9", "8.8.8.8", DirExternal},
		{"cgnat is internal", "100.64.0.1", "10.0.0.1", DirInternal},
		{"ipv6 ula internal", "fc00::1", "fc00::2", DirInternal},
		{"ipv6 ula to public outbound", "fc00::1", "2606:4700:4700::1111", DirOutbound},
		{"link-local internal", "169.254.1.1", "10.0.0.1", DirInternal},
		{"unparseable src", "not-an-ip", "8.8.8.8", DirUnknown},
		{"empty", "", "", DirUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Direction(tc.src, tc.dst, 0, 0); got != tc.want {
				t.Fatalf("Direction(%q, %q) = %d (%s), want %d (%s)",
					tc.src, tc.dst, got, DirectionName(got), tc.want, DirectionName(tc.want))
			}
		})
	}
}

func TestCategoryNameStable(t *testing.T) {
	// Every defined category must have a non-empty, non-"Unknown" label except Unknown itself.
	for c := Web; c <= ICMP; c++ {
		if c.String() == "Unknown" {
			t.Errorf("category %d has no label", c)
		}
	}
	if Unknown.String() != "Unknown" {
		t.Errorf("Unknown label = %q", Unknown.String())
	}
}
