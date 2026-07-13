package netclass

import "testing"

func TestIsLANType(t *testing.T) {
	for _, tn := range []string{"ethernet", "lag", "bridge", "l2vlan", "propVirtual", "  L2VLAN ", "Ethernet"} {
		if !IsLANType(tn) {
			t.Errorf("IsLANType(%q) = false, want true (LAN-carrying type)", tn)
		}
	}
	// Point-to-point / overlay carriers are NOT LAN segments.
	for _, tn := range []string{"tunnel", "gre", "loopback", "l3ipvlan", "vxlan", "mplsTunnel", "", "softwareLoopback"} {
		if IsLANType(tn) {
			t.Errorf("IsLANType(%q) = true, want false (not a LAN segment)", tn)
		}
	}
}

func TestIsFabricInterface(t *testing.T) {
	cases := []struct {
		name, ip string
		want     bool
	}{
		{"fortilink", "10.255.1.1", true}, // named fabric link
		{"FortiLink", "1.2.3.4", true},    // case-insensitive
		{" fortilink ", "1.2.3.4", true},  // trims
		{"port1", "169.254.0.5", true},    // link-local (RFC 3927)
		{"port1", "169.254.255.9", true},  // 169.254/16
		{"internal", "10.10.10.1", false}, // ordinary LAN
		{"port1", "192.168.1.1", false},   // ordinary WAN
		{"", "169.254.1.1", true},         // empty name, link-local ip
		{"port1", "not-an-ip", false},     // unparseable ip, non-fabric name
		{"port1", "169.255.0.1", false},   // 169.255 is NOT link-local
	}
	for _, c := range cases {
		if got := IsFabricInterface(c.name, c.ip); got != c.want {
			t.Errorf("IsFabricInterface(%q,%q) = %v, want %v", c.name, c.ip, got, c.want)
		}
	}
}

func TestSubnetCIDR(t *testing.T) {
	ok := []struct {
		ip, mask, want string
	}{
		{"10.10.10.5", "255.255.255.0", "10.10.10.0/24"},
		{"192.168.1.130", "255.255.255.128", "192.168.1.128/25"},
		{"172.16.4.9", "255.255.0.0", "172.16.0.0/16"},
		{"10.0.0.1", "255.0.0.0", "10.0.0.0/8"},
	}
	for _, c := range ok {
		got, gotOK := SubnetCIDR(c.ip, c.mask)
		if !gotOK || got != c.want {
			t.Errorf("SubnetCIDR(%q,%q) = %q,%v; want %q,true", c.ip, c.mask, got, gotOK, c.want)
		}
	}
	// Rejected: point-to-point/host prefixes and unparseable input.
	bad := []struct{ ip, mask string }{
		{"10.0.0.1", "255.255.255.252"}, // /30 WAN link
		{"10.0.0.1", "255.255.255.254"}, // /31
		{"10.0.0.1", "255.255.255.255"}, // /32 host
		{"not-an-ip", "255.255.255.0"},
		{"10.0.0.1", "bogus"},
		{"", ""},
	}
	for _, c := range bad {
		if got, gotOK := SubnetCIDR(c.ip, c.mask); gotOK {
			t.Errorf("SubnetCIDR(%q,%q) = %q,true; want ok=false", c.ip, c.mask, got)
		}
	}
}
