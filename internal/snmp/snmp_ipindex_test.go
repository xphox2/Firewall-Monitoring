package snmp

import "testing"

func TestIPv4FromTableIndex(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.25.1", "192.168.25.1"},         // clean 4-octet (newer FortiOS)
		{"192.168.25.254.1", "192.168.25.254"},   // FortiOS quirk: extra .1 sub-index
		{"10.25.25.1.1", "10.25.25.1"},           // quirk on a low-octet IP
		{"205.207.224.142.1", "205.207.224.142"}, // quirk on a public IP
		{"1.2.3", ""},                            // too short
		{"999.1.1.1", ""},                        // not a valid IPv4
		{"", ""},                                 // empty
	}
	for _, c := range cases {
		if got := ipv4FromTableIndex(c.in); got != c.want {
			t.Errorf("ipv4FromTableIndex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
