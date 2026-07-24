package fortigate

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// testView builds a minimal RenderView for ParseStatus tests: the tunnel name is
// what the parser matches against the monitor document.
func testView(name string) ipsec.RenderView {
	in := &ipsec.TunnelIntent{ID: 7, Name: name}
	in.Ends[0] = ipsec.EndpointSpec{Vendor: "fortigate", PeerIP: "203.0.113.1"}
	in.Ends[1] = ipsec.EndpointSpec{Vendor: "fortigate", PeerIP: "198.51.100.1"}
	return ipsec.ViewFor(in, 0)
}

// TestParseStatus_Up pins the happy path: our tunnel's entry is present with the
// connection-phase and a proxyid up — and ANOTHER tunnel's up entry must NOT
// count (the parser is tunnel-aware, not a bare substring match).
func TestParseStatus_Up(t *testing.T) {
	d, ok := ipsec.Driver("fortigate")
	if !ok {
		t.Fatal("fortigate driver not registered")
	}
	raw := `{"results":[
		{"name":"other-tunnel","connection-phase":"up","proxyid":[{"status":"up"}]},
		{"name":"fwm-t7","connection-phase":"up","proxyid":[{"status":"up"}]}
	]}`
	st, err := d.ParseStatus(raw, testView("fwm-t7"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUp || st.Child != ipsec.SAUp {
		t.Errorf("status = %+v, want ike/child up", st)
	}
}

// TestParseStatus_OurTunnelDown_OthersUp is the false-up guard: every OTHER
// tunnel is up but ours reports its proxyid down → down, never up.
func TestParseStatus_OurTunnelDown_OthersUp(t *testing.T) {
	d, _ := ipsec.Driver("fortigate")
	raw := `{"results":[
		{"name":"other-tunnel","connection-phase":"up","proxyid":[{"status":"up"}]},
		{"name":"fwm-t7","connection-phase":"up","proxyid":[{"status":"down"}]}
	]}`
	st, err := d.ParseStatus(raw, testView("fwm-t7"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.Child != ipsec.SADown {
		t.Errorf("child = %q, want down (our proxyid is down)", st.Child)
	}
	if st.IKE != ipsec.SAUp {
		t.Errorf("ike = %q, want up (connection-phase up, only phase2 down)", st.IKE)
	}
}

// TestParseStatus_DialupInstance is the real-world NAT/dialup case (fwm-t9): a
// peer behind NAT makes FortiOS split the tunnel into a bare parent
// (name==tunnel, empty proxyid) plus a per-peer instance ("<tunnel>_0",
// parent==tunnel) that carries the live phase2. The live proxyid lives on the
// instance, so matching the bare parent alone false-reports child-down. IKE is
// derived from the up child even with no connection-phase field (FortiOS omits
// it on the monitor document).
func TestParseStatus_DialupInstance(t *testing.T) {
	d, _ := ipsec.Driver("fortigate")
	raw := `{"results":[
		{"name":"fwm-t7_0","parent":"fwm-t7","proxyid":[{"status":"up"}]},
		{"name":"fwm-t7","proxyid":[]}
	]}`
	st, err := d.ParseStatus(raw, testView("fwm-t7"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUp || st.Child != ipsec.SAUp {
		t.Errorf("status = %+v, want ike/child up (dialup instance carries the up proxyid)", st)
	}
}

// TestParseStatus_DialupInstanceDown: the dialup instance's proxyid is down and
// the bare parent is empty — child is down, not falsely up from another tunnel.
func TestParseStatus_DialupInstanceDown(t *testing.T) {
	d, _ := ipsec.Driver("fortigate")
	raw := `{"results":[
		{"name":"other-tunnel_0","parent":"other-tunnel","proxyid":[{"status":"up"}]},
		{"name":"fwm-t7_0","parent":"fwm-t7","proxyid":[{"status":"down"}]},
		{"name":"fwm-t7","proxyid":[]}
	]}`
	st, err := d.ParseStatus(raw, testView("fwm-t7"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.Child != ipsec.SADown {
		t.Errorf("child = %q, want down (our instance proxyid is down)", st.Child)
	}
}

// TestParseStatus_TunnelAbsent: we just deployed this tunnel — its absence from
// the monitor list is a definitive not-established.
func TestParseStatus_TunnelAbsent(t *testing.T) {
	d, _ := ipsec.Driver("fortigate")
	raw := `{"results":[{"name":"other-tunnel","connection-phase":"up","proxyid":[{"status":"up"}]}]}`
	st, err := d.ParseStatus(raw, testView("fwm-t7"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SADown || st.Child != ipsec.SADown {
		t.Errorf("status = %+v, want down/down for an absent tunnel", st)
	}
	if st.RawError == "" {
		t.Error("RawError should name the absence for the operator")
	}
}

// TestParseStatus_Unparseable errors (the poll treats it as inconclusive).
func TestParseStatus_Unparseable(t *testing.T) {
	d, _ := ipsec.Driver("fortigate")
	if _, err := d.ParseStatus(`{"results": [`, testView("fwm-t7")); err == nil {
		t.Fatal("truncated document must error")
	}
}
