package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
)

// The list response must state the tunnel's REAL IKE version.
//
// The V2 console rendered a hardcoded "IKEv2" for every tunnel, because the
// list response carried no IKE version at all and the console invented one.
// That is a false statement about an IKEv1 tunnel — the validator accepts
// IKEv1 (it warns that it is deprecated, RFC 9395) and the deploy path honours
// the version that was stored.
//
// The version lives inside the serialized intent rather than in a promoted
// column, so the list decodes it. A tunnel whose intent cannot be decoded
// reports NO version rather than a wrong one.
func TestListIPSecTunnels_ReportsTheRealIKEVersion(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")

	// One tunnel per version. The row is written directly so the test is about
	// what the LIST reports, not about what the validator would accept.
	preset, _ := ipsec.PresetByName(ipsec.ProfileCompatible)
	seed := func(name string, version ipsec.IKEVersion) uint {
		t.Helper()
		in := &ipsec.TunnelIntent{
			Name: name, Enabled: true, IKEVersion: version, Mode: ipsec.ModePolicyBased,
			IKE: preset.IKE, ESP: preset.ESP, IKELifetimeSecs: preset.IKELifetimeSecs,
			DPD: ipsec.DPD{DelaySecs: 30},
			PSK: "abcDEF012345678901234567890XYZ",
			Ends: [2]ipsec.EndpointSpec{
				{DeviceID: fw.ID, Vendor: "fortigate", PeerIP: "203.0.113.1", EgressIface: "port1", LANIface: "port3",
					LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "a"}, ProtectedSubnets: []string{"10.0.0.0/24"}},
				{DeviceID: opn.ID, Vendor: "opnsense", PeerIP: "198.51.100.1", EgressIface: "wan", LANIface: "lan",
					LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "b"}, ProtectedSubnets: []string{"192.168.150.0/24"}},
			},
		}
		row, err := database.IPSecIntentToModel(in)
		if err != nil {
			t.Fatalf("to model: %v", err)
		}
		row.Name = name
		if err := db.CreateIPSecTunnel(row); err != nil {
			t.Fatalf("create tunnel: %v", err)
		}
		return row.ID
	}
	v2ID := seed("fwm-ike2", ipsec.IKEv2)
	v1ID := seed("fwm-ike1", ipsec.IKEv1)

	c, rec := jsonReq(http.MethodGet, "/x", "")
	h.ListIPSecTunnels(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			ID         uint   `json:"id"`
			Name       string `json:"name"`
			IKEVersion string `json:"ike_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}

	got := map[uint]string{}
	for _, row := range resp.Data {
		got[row.ID] = row.IKEVersion
	}
	if got[v2ID] != string(ipsec.IKEv2) {
		t.Errorf("tunnel %d (IKEv2): ike_version = %q, want %q", v2ID, got[v2ID], ipsec.IKEv2)
	}
	if got[v1ID] != string(ipsec.IKEv1) {
		t.Errorf("tunnel %d (IKEv1): ike_version = %q, want %q", v1ID, got[v1ID], ipsec.IKEv1)
	}
}
