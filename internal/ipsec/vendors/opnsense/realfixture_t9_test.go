package opnsense

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// A sessions/searchPhase1 response in the shape OPNsense emits for the fwm-t9
// tunnel (device 5).
func TestParseStatus_T9OPNsense(t *testing.T) {
	d, _ := ipsec.Driver("opnsense")
	raw := `{"total":1,"rowCount":1,"current":1,"rows":[{"local-addrs":"%any","remote-addrs":"198.19.9.155","local-id":"opnsense","remote-id":"osprey-fw-01","version":"IKEv2","routed":true,"local-class":"pre-shared key","remote-class":"pre-shared key","ikeid":"00000000-0000-4000-8000-000000000001","phase1desc":"fwm-t9","name":"00000000-0000-4000-8000-000000000001","connected":true,"install-time":"55","bytes-in":0,"bytes-out":0,"packets-in":0,"packets-out":0}]}`
	// End 1 is OPNsense; its remote peer is the FortiGate public IP.
	in := &ipsec.TunnelIntent{ID: 9, Name: "fwm-t9"}
	in.Ends[0] = ipsec.EndpointSpec{Vendor: "fortigate", PeerIP: "198.19.9.155"}
	in.Ends[1] = ipsec.EndpointSpec{Vendor: "opnsense", PeerIP: "198.19.76.98"}
	st, err := d.ParseStatus(raw, ipsec.ViewFor(in, 1))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUp || st.Child != ipsec.SAUp {
		t.Fatalf("t9 OPNsense doc parsed %+v, want ike/child up", st)
	}
	t.Logf("t9 OPNsense → %+v", st)
}
