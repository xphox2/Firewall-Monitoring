package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"

	"github.com/gin-gonic/gin"
)

func ipsecCreateBody() string {
	m, _ := ipsec.PresetByName(ipsec.ProfileModern)
	in := ipsec.TunnelIntent{
		Enabled: true, IKEVersion: m.IKEVersion, Mode: ipsec.ModeRouteBased,
		IKE: m.IKE, ESP: m.ESP, IKELifetimeSecs: m.IKELifetimeSecs,
		DPD: ipsec.DPD{DelaySecs: 30},
		Ends: [2]ipsec.EndpointSpec{
			{DeviceID: 1, Vendor: "fortigate", PeerIP: "203.0.113.1", EgressIface: "port1", LANIface: "port3",
				LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "a"}, ProtectedSubnets: []string{"10.10.10.0/24"}, MSSClamp: 1350},
			{DeviceID: 2, Vendor: "opnsense", PeerIP: "198.51.100.1", Dynamic: true, EgressIface: "wan", LANIface: "lan",
				LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "b"}, ProtectedSubnets: []string{"192.168.50.0/24"}, MSSClamp: 1350},
		},
	}
	b, _ := json.Marshal(&in)
	return string(b)
}

func decodeTunnel(t *testing.T, body []byte) tunnelResponse {
	t.Helper()
	var resp struct {
		Data tunnelResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return resp.Data
}

func TestIPSec_CreateGetPreview(t *testing.T) {
	h, db := setupTestHandler(t)

	// Create → PSK generated + masked, VTI + name hydrated, no blocks.
	c, rec := jsonReq(http.MethodPost, "/admin/api/ipsec/tunnels", ipsecCreateBody())
	h.CreateIPSecTunnel(c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d (%s)", rec.Code, rec.Body.String())
	}
	created := decodeTunnel(t, rec.Body.Bytes())
	if created.Intent.ID == 0 || created.Intent.Name != "fwm-t"+strconv.Itoa(int(created.Intent.ID)) {
		t.Fatalf("name not hydrated: %+v", created.Intent)
	}
	if created.Intent.PSK != ipsecPSKMask {
		t.Errorf("create response must mask the PSK, got %q", created.Intent.PSK)
	}
	if created.Intent.VTISubnet == "" || created.Intent.Ends[0].InnerIP == "" {
		t.Errorf("VTI not hydrated: %+v", created.Intent)
	}
	if ipsec.HasBlock(created.Validation) {
		t.Errorf("clean intent should have no validation blocks: %+v", created.Validation)
	}
	id := created.Intent.ID

	// The stored PSK is real (not the mask) — a generated 256-bit key.
	stored, err := db.GetIPSecTunnel(id)
	if err != nil || stored.PSK == "" || stored.PSK == ipsecPSKMask || len(stored.PSK) < 40 {
		t.Fatalf("stored PSK looks wrong: %q err=%v", stored.PSK, err)
	}

	// Get → masked.
	c2, rec2 := jsonReq(http.MethodGet, "/x", "")
	c2.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecTunnel(c2)
	if rec2.Code != http.StatusOK || decodeTunnel(t, rec2.Body.Bytes()).Intent.PSK != ipsecPSKMask {
		t.Fatalf("get should return masked PSK; status=%d", rec2.Code)
	}

	// Preview → both ends rendered, PSK never present.
	c3, rec3 := jsonReq(http.MethodGet, "/x", "")
	c3.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.PreviewIPSecTunnel(c3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("preview status = %d (%s)", rec3.Code, rec3.Body.String())
	}
	body := rec3.Body.String()
	if !strings.Contains(body, "fortigate") || !strings.Contains(body, "opnsense") {
		t.Errorf("preview should render both vendors")
	}
	if strings.Contains(body, stored.PSK) {
		t.Errorf("preview leaked the real PSK")
	}
	if !strings.Contains(body, "aes256gcm") {
		t.Errorf("preview should contain the modern proposal; got %s", body)
	}
}

func TestIPSec_Capabilities(t *testing.T) {
	h, _ := setupTestHandler(t)
	c, rec := jsonReq(http.MethodGet, "/admin/api/ipsec/capabilities?a=fortigate&b=opnsense", "")
	h.IPSecCapabilities(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "allowed") || !strings.Contains(rec.Body.String(), "aes256gcm16") {
		t.Errorf("capabilities should return the allowed intersection: %s", rec.Body.String())
	}

	// Unknown vendor → 400.
	c2, rec2 := jsonReq(http.MethodGet, "/x?a=fortigate&b=nope", "")
	h.IPSecCapabilities(c2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("unknown vendor should 400, got %d", rec2.Code)
	}
}

func TestIPSec_CreateRejectsUnknownVendor(t *testing.T) {
	h, _ := setupTestHandler(t)
	body := strings.Replace(ipsecCreateBody(), `"opnsense"`, `"nintendo"`, 1)
	c, rec := jsonReq(http.MethodPost, "/x", body)
	h.CreateIPSecTunnel(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown vendor should 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}
