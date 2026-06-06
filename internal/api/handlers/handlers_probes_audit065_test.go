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

// AUDIT-065: the probe↔server registration handshake now negotiates a
// schema_version. Three behaviors must be pinned:
//
//  1. A pre-AUDIT-065 collector that doesn't send `schema_version` must
//     keep working — the server defaults the absent / zero value to v1
//     and the probe registers successfully.
//  2. A collector that sends a `schema_version` BELOW the supported
//     range must be rejected with HTTP 426 (Upgrade Required) — the
//     server is "newer than the probe" and the probe needs to upgrade
//     its relay code, not the server.
//  3. A collector that sends a `schema_version` ABOVE the supported
//     range must also be rejected with HTTP 426, and the response must
//     carry the `X-Probe-Schema-Version-Supported` header so the
//     operator can see what range the server is willing to accept.

const testProbeKey = "audit065-test-key"

// doRegister seeds a probe + its registration SystemSetting, then POSTs
// to /api/probes/register with the given JSON body. Returns the recorder
// so the caller can inspect status / headers / body.
func doRegister(t *testing.T, h *Handler, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	if err := h.db.Gorm().AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate system_settings: %v", err)
	}
	probeName := fmt.Sprintf("audit065-probe-%d", len(testSchemaVersionSeen))
	probe := &models.Probe{
		Name:            probeName,
		RegistrationKey: database.HashProbeKey(testProbeKey),
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
		Label:    "audit065 probe registration",
		Category: "probes",
	}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	if body == nil {
		body = map[string]interface{}{}
	}
	body["registration_key"] = testProbeKey

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}

	router := gin.New()
	router.POST("/api/probes/register", h.RegisterProbe)

	req := httptest.NewRequest("POST", "/api/probes/register", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestSchemaVersion_DefaultsTo1_WhenAbsent_AUDIT065 pins AUDIT-065's
// backward-compat contract: a pre-AUDIT-065 collector sends the
// registration request without `schema_version`, and the server must
// treat that as v1 (the pre-AUDIT-065 wire format) and accept the
// registration. The response must echo back `schema_version: 1` so the
// (new) probe learns what version the server is using.
func TestSchemaVersion_DefaultsTo1_WhenAbsent_AUDIT065(t *testing.T) {
	h, _ := setupTestHandler(t)

	// No `schema_version` field at all — the body has only the
	// registration_key (added by doRegister).
	w := doRegister(t, h, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200; a pre-AUDIT-065 collector MUST keep working", w.Code, w.Body.String())
	}

	var resp struct {
		Success       bool                   `json:"success"`
		Approved      bool                   `json:"approved"`
		ProbeID       uint                   `json:"probe_id"`
		SchemaVersion int                    `json:"schema_version"`
		Data          map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	if !resp.Approved {
		t.Errorf("approved=false; want true. body=%s", w.Body.String())
	}
	if resp.SchemaVersion != 1 {
		t.Errorf("response schema_version=%d, want 1 (the default for absent field)", resp.SchemaVersion)
	}
}

// TestRegister_OldSchemaVersion_Returns426_AUDIT065 pins that a probe
// that explicitly advertises a too-old `schema_version` (below
// SchemaVersionMin) is rejected with HTTP 426 (Upgrade Required). We
// use a negative value because the contract is "< Min" → 426, and
// `schema_version: 0` is the zero-value of int and is intentionally
// conflated with "field absent" → defaults to v1 (pinned by
// TestSchemaVersion_DefaultsTo1_WhenAbsent_AUDIT065). A negative value
// is unambiguously "explicitly below the supported range" and exercises
// the < Min branch of the validation.
func TestRegister_OldSchemaVersion_Returns426_AUDIT065(t *testing.T) {
	h, _ := setupTestHandler(t)

	const tooOld = -1
	if tooOld >= relay.SchemaVersionMin {
		t.Fatalf("test fixture %d is not below SchemaVersionMin %d", tooOld, relay.SchemaVersionMin)
	}

	w := doRegister(t, h, map[string]interface{}{"schema_version": tooOld})
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("status=%d body=%s, want 426", w.Code, w.Body.String())
	}

	// AUDIT-065: the response carries the supported range in a header
	// so a probe's relay loop can self-diagnose without parsing the body.
	gotHeader := w.Header().Get("X-Probe-Schema-Version-Supported")
	wantHeader := fmt.Sprintf("%d-%d", relay.SchemaVersionMin, relay.SchemaVersionMax)
	if gotHeader != wantHeader {
		t.Errorf("X-Probe-Schema-Version-Supported=%q, want %q", gotHeader, wantHeader)
	}

	// The body should also mention MIGRATING.md so a human operator
	// reading the probe's logs knows where to look.
	if !bytes.Contains(w.Body.Bytes(), []byte("MIGRATING.md")) {
		t.Errorf("response body should mention MIGRATING.md, got: %s", w.Body.String())
	}
}

// TestRegister_UnsupportedVersion_Returns426_WithSupportedRange_AUDIT065
// pins the forward-compat contract: a probe running a future relay
// format (e.g. v99) registers against a server that only supports v1
// and gets HTTP 426 + the supported range in a header. This is the
// case operators hit when a probe is upgraded ahead of the server.
func TestRegister_UnsupportedVersion_Returns426_WithSupportedRange_AUDIT065(t *testing.T) {
	h, _ := setupTestHandler(t)

	// Pick something far above the current max so the test stays
	// meaningful as the range grows.
	const tooNew = 99
	if tooNew <= relay.SchemaVersionMax {
		t.Fatalf("test fixture %d is not above SchemaVersionMax %d", tooNew, relay.SchemaVersionMax)
	}

	w := doRegister(t, h, map[string]interface{}{"schema_version": tooNew})
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
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	if resp.Success {
		t.Errorf("success=true on 426; want false. body=%s", w.Body.String())
	}
	// The error message should name the version the probe sent so the
	// operator can correlate "I configured v99" with "server rejected v99".
	if !bytes.Contains(w.Body.Bytes(), []byte(strconv.Itoa(tooNew))) {
		t.Errorf("error should name the rejected version %d, got: %s", tooNew, w.Body.String())
	}
}

// testSchemaVersionSeen is only used to give each test a unique probe
// name (RegisterProbe is keyed on probe name → we don't want two tests
// in the same t.Run colliding on the seeded probe).
var testSchemaVersionSeen []string
