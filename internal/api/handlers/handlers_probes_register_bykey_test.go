package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestRegisterProbe_ByRegistrationKey_SurvivesStaleSetting locks in the fix for
// the "registration 404 despite the probe still existing" bug: RegisterProbe now
// looks the probe up by its stored registration_key (like heartbeat auth), so a
// renamed probe — whose probe_registration_<hash> setting still holds the OLD
// name — registers successfully instead of 404ing on the stale name lookup.
func TestRegisterProbe_ByRegistrationKey_SurvivesStaleSetting(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.SystemSetting{}, &models.Probe{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	const key = "bykey-test-registration-key"
	// Probe exists, approved, with its registration_key stored (as CreateProbe does).
	probe := &models.Probe{
		Name:            "collector-renamed",
		RegistrationKey: database.HashProbeKey(key),
		ApprovalStatus:  "approved",
		Status:          "offline",
	}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	// The registration setting points at a STALE name (the pre-rename value) —
	// the exact divergence that made the old name-based lookup 404.
	if err := db.Gorm().Create(&models.SystemSetting{
		Key: "probe_registration_" + database.HashProbeKey(key), Value: "old-name-that-no-longer-exists",
		Type: "string", Category: "probes",
	}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	router := gin.New()
	router.POST("/api/probes/register", h.RegisterProbe)
	body, _ := json.Marshal(map[string]any{"registration_key": key})
	req := httptest.NewRequest("POST", "/api/probes/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("register status = %d, want 200 (found by registration_key despite stale setting); body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Success bool `json:"success"`
		ProbeID uint `json:"probe_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	if !resp.Success || resp.ProbeID != probe.ID {
		t.Errorf("resp = %+v, want success for probe id %d", resp, probe.ID)
	}

	// And an unknown key still fails (401), not a false success.
	body2, _ := json.Marshal(map[string]any{"registration_key": "totally-unknown-key"})
	req2 := httptest.NewRequest("POST", "/api/probes/register", bytes.NewBuffer(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code == http.StatusOK {
		t.Errorf("unknown key must not register; got 200: %s", w2.Body.String())
	}
}
