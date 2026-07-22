package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors"

	"github.com/gin-gonic/gin"
)

// validPreviewIntent is a Modern FortiGate⇄OPNsense route-based intent the wizard
// would POST (no server-hydrated fields: name/vti/inner/reqid omitted).
func validPreviewIntent(psk string) ipsec.TunnelIntent {
	m, _ := ipsec.PresetByName(ipsec.ProfileModern)
	return ipsec.TunnelIntent{
		Enabled: true, IKEVersion: m.IKEVersion, Mode: ipsec.ModePolicyBased, // FG⇄OPNsense ⇒ policy-based
		IKE: m.IKE, ESP: m.ESP, IKELifetimeSecs: m.IKELifetimeSecs,
		DPD: ipsec.DPD{DelaySecs: 30}, PSK: psk,
		Ends: [2]ipsec.EndpointSpec{
			{DeviceID: 1, Vendor: "fortigate", PeerIP: "66.179.9.155", EgressIface: "port1", LANIface: "port3",
				LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "site-a"}, ProtectedSubnets: []string{"10.10.10.0/24"}, ChildLifetimeSecs: 7200},
			{DeviceID: 2, Vendor: "opnsense", PeerIP: "192.168.5.107", Dynamic: true, EgressIface: "wan", LANIface: "lan",
				LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "site-b"}, ProtectedSubnets: []string{"192.168.50.0/24"}, ChildLifetimeSecs: 3600},
		},
	}
}

func postPreview(t *testing.T, h *Handler, intent ipsec.TunnelIntent) (int, map[string]any, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/ipsec/preview", h.PreviewIPSecIntent)
	body, _ := json.Marshal(intent)
	req := httptest.NewRequest("POST", "/api/ipsec/preview", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp struct {
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp.Data, w.Body.String()
}

func TestPreviewIPSecIntent_PRB(t *testing.T) {
	h, _ := setupTestHandler(t)

	// Blank PSK → renders both ends, psk_autogen + provisional true, and the
	// placeholder PSK is NEVER in the response body.
	code, data, raw := postPreview(t, h, validPreviewIntent(""))
	if code != http.StatusOK {
		t.Fatalf("preview = %d: %s", code, raw)
	}
	ends, _ := data["ends"].([]any)
	if len(ends) != 2 {
		t.Fatalf("want 2 ends, got %d", len(ends))
	}
	if data["psk_autogen"] != true || data["provisional"] != true {
		t.Fatalf("blank PSK / id=0 should be psk_autogen+provisional; got %+v", data)
	}
	if strings.Contains(raw, "preview_placeholder") || strings.Contains(strings.ToLower(raw), "psk\":\"preview") {
		t.Fatal("the synthetic preview PSK must never be echoed")
	}

	// Masked PSK is treated like blank (edit-flow round-trips "********").
	_, dataM, _ := postPreview(t, h, validPreviewIntent("********"))
	if dataM["psk_autogen"] != true {
		t.Fatalf("masked PSK must be treated as auto-generate; got %+v", dataM)
	}

	// Unknown vendor → 400.
	bad := validPreviewIntent("")
	bad.Ends[0].Vendor = "nope"
	code2, _, _ := postPreview(t, h, bad)
	if code2 != http.StatusBadRequest {
		t.Fatalf("unknown vendor should 400, got %d", code2)
	}

	// EMPTY vendor must 400, not panic on a nil driver (the sentinel-collision
	// bug: "" was indistinguishable from resolveCaps' all-good return). gin.New()
	// has no Recovery, so a panic would fail the test outright.
	empty := validPreviewIntent("")
	empty.Ends[0].Vendor = ""
	code3, _, _ := postPreview(t, h, empty)
	if code3 != http.StatusBadRequest {
		t.Fatalf("empty vendor should 400 (no nil-driver panic), got %d", code3)
	}
	// A completely empty body likewise.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/ipsec/preview", h.PreviewIPSecIntent)
	req := httptest.NewRequest("POST", "/api/ipsec/preview", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty body should 400 (no panic), got %d", w.Code)
	}
}
