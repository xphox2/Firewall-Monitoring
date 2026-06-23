package snmp

import "testing"

// TestParseFortiGateInterfaceConfig verifies extraction of parent interface,
// vlanid, and type from `config system interface`, including correct handling
// of nested blocks (config ipv6/secondaryip) so they don't end the section early.
func TestParseFortiGateInterfaceConfig(t *testing.T) {
	cfg := `
config system interface
    edit "HOSTING-BLOCK-2"
        set type hard-switch
    next
    edit "HOSTING_BLOCK-2"
        set ip 10.0.0.1 255.255.255.0
        set interface "HOSTING-BLOCK-2"
        set vlanid 200
        set type vlan
        config ipv6
            set ip6-address 2001:db8::1/64
        end
    next
    edit "wan1"
        set type physical
    next
end
`
	ifs := ParseFortiGateInterfaceConfig(cfg)
	byName := map[string]FortiGateInterface{}
	for _, ic := range ifs {
		byName[ic.Name] = ic
	}
	if len(ifs) != 3 {
		t.Fatalf("got %d interfaces, want 3: %+v", len(ifs), ifs)
	}
	vlan := byName["HOSTING_BLOCK-2"]
	if vlan.Parent != "HOSTING-BLOCK-2" || vlan.VLANID != 200 || vlan.Type != "vlan" {
		t.Errorf("vlan sub-iface parsed wrong: %+v (nested config ipv6 may have broken parsing)", vlan)
	}
	if byName["HOSTING-BLOCK-2"].Type != "hard-switch" {
		t.Errorf("bridge type = %q, want hard-switch", byName["HOSTING-BLOCK-2"].Type)
	}
	if byName["wan1"].Type != "physical" {
		t.Errorf("wan1 type = %q, want physical", byName["wan1"].Type)
	}
}

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
