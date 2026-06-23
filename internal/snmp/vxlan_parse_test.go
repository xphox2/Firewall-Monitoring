package snmp

import "testing"

// TestParseFortiGateVxlanConfig_Details verifies the VXLAN config parser
// extracts VNI, carrier interface, UDP dstport, and the remote VTEP peer list
// — the fields the connection-detail overlay view surfaces.
func TestParseFortiGateVxlanConfig_Details(t *testing.T) {
	cfg := `
config system vxlan
    edit "vxlan-overlay"
        set interface "ipsec-hub"
        set vxlan-id 5000
        set ip-version ipv4-unicast
        set remote-ip "203.0.113.5" "203.0.113.6"
        set dstport 4789
    next
    edit "vxlan-b"
        set interface "wan2"
        set vxlan-id 42
    next
end
`
	vxlans := ParseFortiGateVxlanConfig(cfg)
	if len(vxlans) != 2 {
		t.Fatalf("got %d vxlans, want 2", len(vxlans))
	}
	a := vxlans[0]
	if a.Name != "vxlan-overlay" || a.Interface != "ipsec-hub" || a.VXLANID != 5000 || a.DestinationPort != 4789 {
		t.Errorf("vxlan A mismatch: %+v", a)
	}
	if len(a.RemoteIPs) != 2 || a.RemoteIPs[0] != "203.0.113.5" || a.RemoteIPs[1] != "203.0.113.6" {
		t.Errorf("vxlan A remote IPs = %v, want [203.0.113.5 203.0.113.6]", a.RemoteIPs)
	}
	b := vxlans[1]
	if b.Name != "vxlan-b" || b.VXLANID != 42 || len(b.RemoteIPs) != 0 {
		t.Errorf("vxlan B mismatch: %+v", b)
	}
}
