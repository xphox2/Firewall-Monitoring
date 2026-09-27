package classify

import "testing"

// TestServicePort pins the service-side rule the Top services panel, the
// data_exfil gate and Classify all share.
func TestServicePort(t *testing.T) {
	cases := []struct {
		name     string
		proto    uint8
		src, dst uint16
		want     uint16
	}{
		{"client to https", protoTCP, 50000, 443, 443},
		{"https reply to client", protoTCP, 443, 50000, 443},
		{"alt-https reply", protoTCP, 50000, 8443, 8443},
		{"both known: lower wins", protoTCP, 80, 443, 80},
		{"both known, reversed", protoTCP, 443, 80, 80},
		{"unknown low port is a plausible listener", protoTCP, 1025, 30000, 1025},
		{"two ephemeral ports name no service", protoTCP, 40000, 41000, 0},
		{"zero port is absent", protoUDP, 0, 5000, 5000},
		{"zero port with an ephemeral other side", protoUDP, 0, 50000, 0},
		{"both zero", protoUDP, 0, 0, 0},
		{"dns reply", protoUDP, 53, 40000, 53},
		{"icmp has no ports", protoICMP, 0, 0, 0},
		{"gre has no ports", protoGRE, 1000, 2000, 0},
	}
	for _, c := range cases {
		if got := ServicePort(c.proto, c.src, c.dst); got != c.want {
			t.Errorf("%s: ServicePort(%d, %d, %d) = %d, want %d", c.name, c.proto, c.src, c.dst, got, c.want)
		}
	}
}

// TestClassifyAgreesWithServicePort: the category is always the service
// port's category, so the two can never name different sides.
func TestClassifyAgreesWithServicePort(t *testing.T) {
	ports := []uint16{0, 22, 53, 80, 443, 1025, 3389, 8443, 30000, 40000, 50000}
	for _, proto := range []uint8{protoTCP, protoUDP} {
		for _, s := range ports {
			for _, d := range ports {
				want := Unknown
				if c, ok := portCategory[ServicePort(proto, s, d)]; ok {
					want = c
				}
				if got := Classify(proto, s, d, 0); got != want {
					t.Errorf("Classify(%d,%d,%d) = %v, but ServicePort's category is %v", proto, s, d, got, want)
				}
			}
		}
	}
}

func TestServicePortFromDst(t *testing.T) {
	cases := []struct {
		proto uint8
		dst   uint16
		want  uint16
	}{
		{protoTCP, 443, 443},     // known service
		{protoTCP, 51820, 51820}, // known service above the ephemeral floor (WireGuard)
		{protoUDP, 1025, 1025},   // unknown but below the ephemeral range
		{protoTCP, 51234, 0},     // a client's ephemeral port: no service
		{protoTCP, 0, 0},
		{protoICMP, 443, 0},
	}
	for _, c := range cases {
		if got := ServicePortFromDst(c.proto, c.dst); got != c.want {
			t.Errorf("ServicePortFromDst(%d, %d) = %d, want %d", c.proto, c.dst, got, c.want)
		}
	}
}
