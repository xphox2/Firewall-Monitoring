package opnsense

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// testView builds a minimal RenderView: end 0 is OPNsense; its REMOTE peer
// (198.51.100.1) is what the parser matches session rows against.
func testView(remotePeer string) ipsec.RenderView {
	in := &ipsec.TunnelIntent{ID: 7, Name: "fwm-t7"}
	in.Ends[0] = ipsec.EndpointSpec{Vendor: "opnsense", PeerIP: "203.0.113.1"}
	in.Ends[1] = ipsec.EndpointSpec{Vendor: "fortigate", PeerIP: remotePeer}
	return ipsec.ViewFor(in, 0)
}

// TestParseStatus_Established pins the happy path: a session row referencing
// our peer reports ESTABLISHED. Rows for OTHER peers must not count.
func TestParseStatus_Established(t *testing.T) {
	d, ok := ipsec.Driver("opnsense")
	if !ok {
		t.Fatal("opnsense driver not registered")
	}
	raw := `{"rowCount":2,"rows":[
		{"ikeid":"3","local-addrs":"10.0.0.1","remote-addrs":"10.9.9.9","status":"ESTABLISHED"},
		{"ikeid":"4","local-addrs":"203.0.113.1","remote-addrs":"198.51.100.1","status":"ESTABLISHED"}
	]}`
	st, err := d.ParseStatus(raw, testView("198.51.100.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUp || st.Child != ipsec.SAUp {
		t.Errorf("status = %+v, want ike/child up (child mirrors ike for policy-based)", st)
	}
}

// TestParseStatus_ConnectedBool is the real sessions/searchPhase1 shape (fwm-t9):
// phase1 liveness is a BOOLEAN "connected", with no string status field. The
// row must be read as up — the string-only path misread it as unknown.
func TestParseStatus_ConnectedBool(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"total":1,"rowCount":1,"rows":[
		{"local-addrs":"%any","remote-addrs":"198.51.100.1","local-id":"opnsense","remote-id":"techlabs-fw-01","version":"IKEv2","connected":true,"install-time":"55","bytes-in":0,"bytes-out":0}
	]}`
	st, err := d.ParseStatus(raw, testView("198.51.100.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUp || st.Child != ipsec.SAUp {
		t.Errorf("status = %+v, want ike/child up (connected:true)", st)
	}
}

// TestParseStatus_ConnectedBoolFalse: a searchPhase1 row present but not yet
// connected is a definitive down, not unknown.
func TestParseStatus_ConnectedBoolFalse(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"rowCount":1,"rows":[{"remote-addrs":"198.51.100.1","connected":false}]}`
	st, err := d.ParseStatus(raw, testView("198.51.100.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SADown {
		t.Errorf("ike = %q, want down (connected:false)", st.IKE)
	}
}

// TestParseStatus_SwanctlPortSuffix: swanctl may render the peer with a port
// suffix ("1.2.3.4[4500]") — the match must tolerate it WITHOUT substring
// false-positives.
func TestParseStatus_SwanctlPortSuffix(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"rowCount":1,"rows":[{"ikeid":"4","remote-host":"198.51.100.1[4500]","state":"ESTABLISHED"}]}`
	st, err := d.ParseStatus(raw, testView("198.51.100.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUp {
		t.Errorf("ike = %q, want up (port-suffixed peer must match)", st.IKE)
	}
}

// TestParseStatus_NoFalsePositiveSubstring proves "198.51.100.1" does NOT match
// "198.51.100.11" (exact-match contract).
func TestParseStatus_NoFalsePositiveSubstring(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"rowCount":1,"rows":[{"ikeid":"4","remote-addrs":"198.51.100.11","status":"ESTABLISHED"}]}`
	st, err := d.ParseStatus(raw, testView("198.51.100.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SADown {
		t.Errorf("ike = %q, want down — .11 must not match .1", st.IKE)
	}
}

// TestParseStatus_NoMatchingRow: we just deployed — no session to our peer is a
// definitive not-established.
func TestParseStatus_NoMatchingRow(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"rowCount":1,"rows":[{"ikeid":"3","remote-addrs":"10.9.9.9","status":"ESTABLISHED"}]}`
	st, err := d.ParseStatus(raw, testView("198.51.100.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SADown || st.Child != ipsec.SADown {
		t.Errorf("status = %+v, want down/down with no session to our peer", st)
	}
}

// TestParseStatus_ConnectingIsDown: a row mid-negotiation reports a state that
// isn't up.
func TestParseStatus_ConnectingIsDown(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"rowCount":1,"rows":[{"ikeid":"4","remote-addrs":"198.51.100.1","status":"CONNECTING"}]}`
	st, err := d.ParseStatus(raw, testView("198.51.100.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SADown {
		t.Errorf("ike = %q, want down (CONNECTING is not established)", st.IKE)
	}
}

// TestParseStatus_HostnamePeerIsUnknown: a hostname peer appears in session rows
// only in RESOLVED form, so no safe match is possible — unknown, never a
// guessed down.
func TestParseStatus_HostnamePeerIsUnknown(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"rowCount":0,"rows":[]}`
	st, err := d.ParseStatus(raw, testView("vpn.example.com"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUnknown {
		t.Errorf("ike = %q, want unknown for a hostname peer", st.IKE)
	}
}

// TestParseStatus_Unparseable errors (the poll treats it as inconclusive).
func TestParseStatus_Unparseable(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	if _, err := d.ParseStatus(`{"rows": [`, testView("198.51.100.1")); err == nil {
		t.Fatal("truncated document must error")
	}
}
