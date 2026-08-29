package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// doCreateConnectionRequest POSTs a JSON body to CreateDeviceConnection.
func doCreateConnectionRequest(t *testing.T, h *Handler, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/api/connections", h.CreateDeviceConnection)
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/connections", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func seedConnectionEndpoints(t *testing.T, h *Handler) (src, dst *models.Device) {
	t.Helper()
	src = &models.Device{Name: "fw-src", IPAddress: "192.168.7.1"}
	dst = &models.Device{Name: "fw-dst", IPAddress: "192.168.7.2"}
	for _, d := range []*models.Device{src, dst} {
		if err := h.db.Gorm().Create(d).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}
	return src, dst
}

// TestUpdateDeviceConnection_RejectsInvalidConnectionType is the AUDIT-184
// server-side regression: connection_type is rendered into innerHTML by the
// badge helpers, so the update handler must 400 anything off the allowlist —
// previously any operator-role PUT could store an HTML payload.
func TestUpdateDeviceConnection_RejectsInvalidConnectionType(t *testing.T) {
	h, _ := setupTestHandler(t)
	conn, _ := seedConnectionWithSecrets(t, h)

	w := doPartialUpdateRequest(t, h.UpdateDeviceConnection, "/api/connections/:id", conn.ID,
		map[string]interface{}{"connection_type": `<img onerror=x>`})
	if w.Code != 400 {
		t.Fatalf("XSS-payload connection_type: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}

	// Non-string values must be rejected too (the enum check type-asserts).
	w = doPartialUpdateRequest(t, h.UpdateDeviceConnection, "/api/connections/:id", conn.ID,
		map[string]interface{}{"connection_type": 42})
	if w.Code != 400 {
		t.Fatalf("numeric connection_type: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}

	// The payload must not have been stored.
	var stored models.DeviceConnection
	if err := h.db.Gorm().First(&stored, conn.ID).Error; err != nil {
		t.Fatalf("re-fetch: %v", err)
	}
	if stored.ConnectionType != "ethernet" {
		t.Errorf("stored connection_type = %q, want the seeded %q", stored.ConnectionType, "ethernet")
	}
}

// TestUpdateDeviceConnection_AllowlistIsSupersetOfUI pins that the server
// allowlist covers the poller-emitted types the admin UI's select omits
// (ethernet/bridge/offnet). If the list were narrowed to the UI's subset,
// editing an auto-detected ethernet link's type would 400.
func TestUpdateDeviceConnection_AllowlistIsSupersetOfUI(t *testing.T) {
	h, _ := setupTestHandler(t)
	conn, _ := seedConnectionWithSecrets(t, h)

	for _, typ := range []string{"ethernet", "bridge", "offnet"} {
		w := doPartialUpdateRequest(t, h.UpdateDeviceConnection, "/api/connections/:id", conn.ID,
			map[string]interface{}{"connection_type": typ})
		if w.Code != 200 {
			t.Errorf("connection_type %q: status = %d, want 200 (server allowlist must be a superset of the UI select); body: %s",
				typ, w.Code, w.Body.String())
		}
	}
}

// TestCreateDeviceConnection_ValidatesTypeAndResetsMatchMethod covers the
// create path of AUDIT-184: an off-allowlist connection_type must 400, and
// match_method — a server-owned field written only by the poller's
// auto-detection but bindable via ShouldBindJSON — must be reset so the GORM
// default applies instead of a client payload (the second stored-XSS vector).
func TestCreateDeviceConnection_ValidatesTypeAndResetsMatchMethod(t *testing.T) {
	h, _ := setupTestHandler(t)
	src, dst := seedConnectionEndpoints(t, h)

	// Off-allowlist type → 400.
	w := doCreateConnectionRequest(t, h, map[string]interface{}{
		"name": "bad", "source_device_id": src.ID, "dest_device_id": dst.ID,
		"connection_type": `<script>alert(1)</script>`,
	})
	if w.Code != 400 {
		t.Fatalf("XSS-payload connection_type on create: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}

	// Valid create with a client-supplied match_method payload.
	const payload = `<img src=x onerror=alert(1)>`
	w = doCreateConnectionRequest(t, h, map[string]interface{}{
		"name": "good", "source_device_id": src.ID, "dest_device_id": dst.ID,
		"connection_type": "ethernet", "match_method": payload,
	})
	if w.Code != 201 {
		t.Fatalf("valid create: status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var stored models.DeviceConnection
	if err := h.db.Gorm().Where("name = ?", "good").First(&stored).Error; err != nil {
		t.Fatalf("fetch created connection: %v", err)
	}
	if stored.MatchMethod == payload {
		t.Errorf("client-supplied match_method was stored (AUDIT-184 second vector)")
	}
	if stored.MatchMethod != "ip_match" {
		t.Errorf("stored match_method = %q, want the GORM default %q", stored.MatchMethod, "ip_match")
	}

	// Empty connection_type takes the documented default rather than 400ing.
	w = doCreateConnectionRequest(t, h, map[string]interface{}{
		"name": "defaulted", "source_device_id": src.ID, "dest_device_id": dst.ID,
	})
	if w.Code != 201 {
		t.Fatalf("create without connection_type: status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var defaulted models.DeviceConnection
	if err := h.db.Gorm().Where("name = ?", "defaulted").First(&defaulted).Error; err != nil {
		t.Fatalf("fetch defaulted connection: %v", err)
	}
	if defaulted.ConnectionType != "ipsec" {
		t.Errorf("defaulted connection_type = %q, want %q", defaulted.ConnectionType, "ipsec")
	}
}
