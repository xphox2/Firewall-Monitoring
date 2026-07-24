package fortigate

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// Real monitor/vpn/ipsec body captured from the live fwm-t9 probe (device 4).
func TestParseStatus_RealT9FortiGate(t *testing.T) {
	d, _ := ipsec.Driver("fortigate")
	raw := `{"http_method":"GET","results":[{"proxyid":[{"proxy_src":[{"subnet":"192.168.25.0-192.168.25.255","port":0,"protocol":0,"protocol_name":""}],"proxy_dst":[{"subnet":"192.168.50.0-192.168.50.255","port":0,"protocol":0,"protocol_name":""}],"status":"up","p2name":"fwm-t9","p2serial":1,"expire":7131,"incoming_bytes":0,"outgoing_bytes":0}],"name":"fwm-t9_0","parent":"fwm-t9","comments":"","wizard-type":"custom","connection_count":1,"creation_time":54,"username":"opnsense","type":"dialup","incoming_bytes":0,"outgoing_bytes":0,"rgwy":"76.66.145.98","tun_id":"76.66.145.98","tun_id6":"::10.0.0.1","rport":64917,"dialup_index":0},{"proxyid":[],"name":"fwm-t9","comments":"","wizard-type":"custom","type":"","incoming_bytes":0,"outgoing_bytes":0,"rgwy":"0.0.0.0","tun_id":"10.0.0.10","tun_id6":"::10.0.0.10"}],"vdom":"root","path":"vpn","name":"ipsec","status":"success"}`
	in := &ipsec.TunnelIntent{ID: 9, Name: "fwm-t9"}
	in.Ends[0] = ipsec.EndpointSpec{Vendor: "fortigate", PeerIP: "76.66.145.98"}
	in.Ends[1] = ipsec.EndpointSpec{Vendor: "opnsense", PeerIP: "192.168.5.107"}
	st, err := d.ParseStatus(raw, ipsec.ViewFor(in, 0))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.IKE != ipsec.SAUp || st.Child != ipsec.SAUp {
		t.Fatalf("REAL t9 FortiGate doc parsed %+v, want ike/child up", st)
	}
	t.Logf("REAL t9 FortiGate → %+v", st)
}
