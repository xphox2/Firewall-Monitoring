package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/relay"

	"github.com/gin-gonic/gin"
)

// The probe↔server registration handshake negotiates a schema_version so
// the independently-deployed collector and server can detect a wire-format
// mismatch instead of silently mis-parsing each other. Three behaviors are
// pinned:
//
//  1. A pre-handshake collector that doesn't send `schema_version` must keep
//     working — the server defaults the absent value to v1 and the probe
//     registers successfully.
//  2. A collector that sends a `schema_version` BELOW the supported range
//     must be rejected with HTTP 426 (Upgrade Required) — the server is
//     newer than the probe and the probe needs to upgrade its relay code.
//  3. A collector that sends a `schema_version` ABOVE the supported range
//     must also be rejected with HTTP 426, and the response must carry the
//     `X-Probe-Schema-Version-Supported` header so the operator can see what
//     range the server accepts.
//
// (Re-implements the intent of the now-closed PR #8 on current master, with
// a server version that actually exists — the PR mislabeled itself AUDIT-065,
// which is an unrelated, already-resolved frontend finding.)

const testSchemaProbeKey = "schemaversion-test-key"

var testSchemaProbeSeq int

// doSchemaRegister seeds a probe + its registration SystemSetting, then POSTs
// to /api/probes/register with the given JSON body. Returns the recorder so
// the caller can inspect status / headers / body.
func doSchemaRegister(t *testing.T, h *Handler, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	if err := h.db.Gorm().AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate system_settings: %v", err)
	}
	testSchemaProbeSeq++
	probeName := fmt.Sprintf("schemaversion-probe-%d", testSchemaProbeSeq)
	probe := &models.Probe{
		Name:            probeName,
		RegistrationKey: database.HashProbeKey(testSchemaProbeKey),
		ApprovalStatus:  "pending",
		Status:          "offline",
	}
	if err := h.db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	if err := h.db.Gorm().Create(&models.SystemSetting{
		Key:      "probe_registration_" + probe.RegistrationKey,
		Value:    probe.Name,
		Type:     "string",
		Label:    "schemaversion probe registration",
		Category: "probes",
	}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	if body == nil {
		body = map[string]interface{}{}
	}
	body["registration_key"] = testSchemaProbeKey

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	router := gin.New()
	router.POST("/api/probes/register", h.RegisterProbe)

	req := httptest.NewRequest("POST", "/api/probes/register", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestSchemaVersion_DefaultsTo1_WhenAbsent pins the backward-compat contract:
// a pre-handshake collector sends the registration request without
// `schema_version`, and the server must treat that as v1 and accept the
// registration, echoing back `schema_version: 1`.
func TestSchemaVersion_DefaultsTo1_WhenAbsent(t *testing.T) {
	h, _ := setupTestHandler(t)

	w := doSchemaRegister(t, h, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200; a pre-handshake collector MUST keep working", w.Code, w.Body.String())
	}

	var resp struct {
		Success       bool `json:"success"`
		Approved      bool `json:"approved"`
		ProbeID       uint `json:"probe_id"`
		SchemaVersion int  `json:"schema_version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	if !resp.Approved {
		t.Errorf("approved=false; want true. body=%s", w.Body.String())
	}
	if resp.SchemaVersion != 1 {
		t.Errorf("response schema_version=%d, want 1 (the default for an absent field)", resp.SchemaVersion)
	}
}

// TestSchemaVersion_OldVersion_Returns426 pins that a probe that explicitly
// advertises a too-old schema_version (below SchemaVersionMin) is rejected
// with HTTP 426. A negative value is unambiguously "below the supported
// range" (schema_version: 0 is the int zero-value and is conflated with
// "field absent" → v1, pinned by TestSchemaVersion_DefaultsTo1_WhenAbsent).
func TestSchemaVersion_OldVersion_Returns426(t *testing.T) {
	h, _ := setupTestHandler(t)

	const tooOld = -1
	if tooOld >= relay.SchemaVersionMin {
		t.Fatalf("test fixture %d is not below SchemaVersionMin %d", tooOld, relay.SchemaVersionMin)
	}

	w := doSchemaRegister(t, h, map[string]interface{}{"schema_version": tooOld})
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("status=%d body=%s, want 426", w.Code, w.Body.String())
	}

	gotHeader := w.Header().Get("X-Probe-Schema-Version-Supported")
	wantHeader := fmt.Sprintf("%d-%d", relay.SchemaVersionMin, relay.SchemaVersionMax)
	if gotHeader != wantHeader {
		t.Errorf("X-Probe-Schema-Version-Supported=%q, want %q", gotHeader, wantHeader)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("MIGRATING.md")) {
		t.Errorf("response body should point at MIGRATING.md, got: %s", w.Body.String())
	}
}

// TestSchemaVersion_UnsupportedVersion_Returns426_WithRange pins the
// forward-compat contract: a probe running a future relay format (e.g. v99)
// registers against a server that only supports v1 and gets HTTP 426 + the
// supported range in a header. This is the case operators hit when a probe
// is upgraded ahead of the server.
func TestSchemaVersion_UnsupportedVersion_Returns426_WithRange(t *testing.T) {
	h, _ := setupTestHandler(t)

	const tooNew = 99
	if tooNew <= relay.SchemaVersionMax {
		t.Fatalf("test fixture %d is not above SchemaVersionMax %d", tooNew, relay.SchemaVersionMax)
	}

	w := doSchemaRegister(t, h, map[string]interface{}{"schema_version": tooNew})
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("status=%d body=%s, want 426", w.Code, w.Body.String())
	}

	gotHeader := w.Header().Get("X-Probe-Schema-Version-Supported")
	wantHeader := fmt.Sprintf("%d-%d", relay.SchemaVersionMin, relay.SchemaVersionMax)
	if gotHeader != wantHeader {
		t.Errorf("X-Probe-Schema-Version-Supported=%q, want %q", gotHeader, wantHeader)
	}

	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	if resp.Success {
		t.Errorf("success=true on 426; want false. body=%s", w.Body.String())
	}
	// The error must name the version the probe sent so the operator can
	// correlate "I configured v99" with "server rejected v99".
	if !bytes.Contains(w.Body.Bytes(), []byte(strconv.Itoa(tooNew))) {
		t.Errorf("error should name the rejected version %d, got: %s", tooNew, w.Body.String())
	}
}
