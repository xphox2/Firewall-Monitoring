package fortigate

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// TestRender_EmptyInnerIP_FailsFast pins the fwm-t4 guard: an intent with no
// VTI addressing (e.g. persisted before policy-mode allocation shipped) must
// ERROR at render time, never emit a system/interface step with a malformed
// empty "ip" the device would reject mid-apply (HTTP 500).
func TestRender_EmptyInnerIP_FailsFast(t *testing.T) {
	d, ok := ipsec.Driver("fortigate")
	if !ok {
		t.Fatal("fortigate driver not registered")
	}
	in := &ipsec.TunnelIntent{ID: 4, Name: "fwm-t4", Mode: ipsec.ModePolicyBased, PSK: "abcDEF012345678901234567890XYZ"}
	in.Ends[0] = ipsec.EndpointSpec{Vendor: "fortigate", PeerIP: "203.0.113.1", EgressIface: "port1", LANIface: "port3",
		LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "a"}, ProtectedSubnets: []string{"10.10.10.0/24"}}
	in.Ends[1] = ipsec.EndpointSpec{Vendor: "opnsense", PeerIP: "198.51.100.1", EgressIface: "wan", LANIface: "lan",
		LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "b"}, ProtectedSubnets: []string{"192.168.50.0/24"}}
	// No InnerIP on either end (pre-fix persisted shape).

	if _, err := d.Render(ipsec.ViewFor(in, 0)); err == nil {
		t.Fatal("render must fail fast on empty InnerIP (fwm-t4 guard)")
	} else if !strings.Contains(err.Error(), "VTI addressing") {
		t.Errorf("error should name the VTI addressing cause; got %v", err)
	}

	// Remove must STILL render (rollback of a partial deploy can't be blocked).
	if _, err := d.RenderRemove(ipsec.ViewFor(in, 0)); err != nil {
		t.Errorf("RenderRemove must not be gated on InnerIP: %v", err)
	}
}
