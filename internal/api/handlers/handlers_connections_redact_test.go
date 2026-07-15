package handlers

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// seedConnectionWithSecrets creates two devices with encrypted credentials and
// a connection between them, returning the connection and the RAW stored
// ciphertexts (which must never appear in any API response).
func seedConnectionWithSecrets(t *testing.T, h *Handler) (conn *models.DeviceConnection, ciphertexts []string) {
	t.Helper()
	db := h.db
	src := &models.Device{
		Name:          "fw-a",
		IPAddress:     "192.168.5.1",
		SNMPCommunity: db.EncryptField("snmp-secret-a"),
		SSHPassword:   db.EncryptField("ssh-secret-a"),
	}
	dst := &models.Device{
		Name:          "fw-b",
		IPAddress:     "192.168.5.2",
		SNMPCommunity: db.EncryptField("snmp-secret-b"),
		SSHPassword:   db.EncryptField("ssh-secret-b"),
	}
	for _, d := range []*models.Device{src, dst} {
		if err := db.Gorm().Create(d).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}
	conn = &models.DeviceConnection{
		Name:           "a-b",
		SourceDeviceID: src.ID,
		DestDeviceID:   dst.ID,
		ConnectionType: "ethernet",
		Status:         "up",
	}
	if err := db.Gorm().Create(conn).Error; err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	return conn, []string{src.SNMPCommunity, src.SSHPassword, dst.SNMPCommunity, dst.SSHPassword}
}

func doGetRequest(t *testing.T, h func(*gin.Context), path string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.GET("/x/*any", h)
	req := httptest.NewRequest("GET", "/x"+path, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// doGetByIDRequest routes a GET through a :id route pattern (ParseID handlers).
func doGetByIDRequest(t *testing.T, h func(*gin.Context), routePattern string, id uint) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.GET(routePattern, h)
	req := httptest.NewRequest("GET", replaceFirst(routePattern, ":id", fmt.Sprintf("%d", id)), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestGetDeviceConnections_RedactsDeviceSecrets is the regression for the
// connection-list leak: GetAllConnections preloads the FULL source/dest Device
// rows, and the handler returned them unredacted — every connection-map load
// shipped every endpoint device's stored (encrypted) SNMP community, SNMPv3
// passphrases, and SSH password to the browser.
func TestGetDeviceConnections_RedactsDeviceSecrets(t *testing.T) {
	h, _ := setupTestHandler(t)
	_, ciphertexts := seedConnectionWithSecrets(t, h)

	w := doGetRequest(t, h.GetDeviceConnections, "/connections")
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, ct := range ciphertexts {
		if ct != "" && strings.Contains(body, ct) {
			t.Errorf("response contains stored device secret ciphertext %q", ct)
		}
	}
	if !strings.Contains(body, httputil.RedactedMask) {
		t.Errorf("response does not contain the redaction mask — devices not preloaded or not redacted? body: %s", body)
	}
}

// TestGetConnectionDetail_RedactsDeviceSecrets: same leak on the
// connection-detail endpoint (detail.Connection embeds the preloaded devices).
func TestGetConnectionDetail_RedactsDeviceSecrets(t *testing.T) {
	h, _ := setupTestHandler(t)
	conn, ciphertexts := seedConnectionWithSecrets(t, h)

	w := doGetByIDRequest(t, h.GetConnectionDetail, "/api/connections/:id/detail", conn.ID)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, ct := range ciphertexts {
		if ct != "" && strings.Contains(body, ct) {
			t.Errorf("detail response contains stored device secret ciphertext %q", ct)
		}
	}
}

// TestGetDevices_RedactsPreloadedProbeSecrets: GetAllDevices preloads each
// device's assigned Probe, whose registration-key hash and TLS paths are
// secret material — RedactDevice must mask the embedded probe exactly like
// the probe endpoints do (the sibling of the connection-endpoint leak).
func TestGetDevices_RedactsPreloadedProbeSecrets(t *testing.T) {
	h, db := setupTestHandler(t)
	_, _ = setupProbeAndDevice(t, db) // seeds a probe with a HASHED registration key + an assigned device

	storedHash := database.HashProbeKey("test-key-abc123") // what setupProbeAndDevice stores at rest

	w := doGetRequest(t, h.GetDevices, "/devices")
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, storedHash) {
		t.Errorf("device list response contains the probe registration-key hash")
	}
}

// TestUpdateDeviceConnection_RedactsDeviceSecrets: the update handler re-fetches
// the connection with preloaded devices for its response — masked too.
func TestUpdateDeviceConnection_RedactsDeviceSecrets(t *testing.T) {
	h, _ := setupTestHandler(t)
	conn, ciphertexts := seedConnectionWithSecrets(t, h)

	w := doPartialUpdateRequest(t, h.UpdateDeviceConnection, "/api/connections/:id", conn.ID,
		map[string]interface{}{"notes": "edited"})
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, ct := range ciphertexts {
		if ct != "" && strings.Contains(body, ct) {
			t.Errorf("update response contains stored device secret ciphertext %q", ct)
		}
	}
}
