package opnsense

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// Real sessions/searchPhase1 body captured from the live fwm-t9 probe (device 5).
func TestParseStatus_RealT9OPNsense(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"total":1,"rowCount":1,"current":1,"rows":[{"local-addrs":"%any","remote-addrs":"66.179.9.155","local-id":"opnsense","remote-id":"techlabs-fw-01","version":"IKEv2","routed":true,"local-class":"pre-shared key","remote-class":"pre-shared key","ikeid":"91f25bb5-f9c9-41e6-876b-6232560cc1f3","phase1desc":"fwm-t9","name":"91f25bb5-f9c9-41e6-876b-6232560cc1f3","connected":true,"install-time":"55","bytes-in":0,"bytes-out":0,"packets-in":0,"packets-out":0}]}`
	// End 1 is OPNsense; its remote peer is the FortiGate public IP.
	in := &ipsec.TunnelIntent{ID: 9, Name: "fwm-t9"}
	in.Ends[0] = ipsec.EndpointSpec{Vendor: "fortigate", PeerIP: "66.179.9.155"}
	in.Ends[1] = ipsec.EndpointSpec{Vendor: "opnsense", PeerIP: "76.66.145.98"}
	st, err := d.ParseStatus(raw, ipsec.ViewFor(in, 1))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUp || st.Child != ipsec.SAUp {
		t.Fatalf("REAL t9 OPNsense doc parsed %+v, want ike/child up", st)
	}
	t.Logf("REAL t9 OPNsense → %+v", st)
}
