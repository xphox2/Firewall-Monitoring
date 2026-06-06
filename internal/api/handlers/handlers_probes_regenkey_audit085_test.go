package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestRegenerateProbeKey_Atomic_AUDIT085 verifies the probe key rotation is
// atomic. Pre-fix the handler deleted the old key's SystemSetting first and
// only logged a warning if the new setting failed to write, so a mid-sequence
// failure could leave the probe with a rotated key but no usable registration
// setting — locked out. The fix generates the key first and wraps update-probe
// → delete-old → create-new in one transaction.
//
// This pins the success contract: a regenerate produces a new key, updates the
// probe row, removes the old registration setting, and creates exactly one new
// one — all consistent with each other.
func TestRegenerateProbeKey_Atomic_AUDIT085(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate system_settings: %v", err)
	}

	probe := &models.Probe{Name: "edge-probe", RegistrationKey: "OLDKEY123", ApprovalStatus: "approved"}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	if err := db.Gorm().Create(&models.SystemSetting{
		Key: "probe_registration_OLDKEY123", Value: probe.Name, Type: "string", Category: "probes",
	}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	router := gin.New()
	router.POST("/api/probes/:id/regenerate-key", h.RegenerateProbeKey)
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/regenerate-key", probe.ID), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			RegistrationKey string `json:"registration_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	newKey := resp.Data.RegistrationKey
	if newKey == "" || newKey == "OLDKEY123" {
		t.Fatalf("new key not generated (got %q)", newKey)
	}

	// Probe row must carry the new key.
	var after models.Probe
	if err := db.Gorm().First(&after, probe.ID).Error; err != nil {
		t.Fatalf("reload probe: %v", err)
	}
	if after.RegistrationKey != newKey {
		t.Errorf("probe.RegistrationKey = %q, want %q (response and row must agree)", after.RegistrationKey, newKey)
	}

	// Old setting gone, new setting present — exactly once each.
	var oldCount, newCount int64
	db.Gorm().Model(&models.SystemSetting{}).Where("key = ?", "probe_registration_OLDKEY123").Count(&oldCount)
	db.Gorm().Model(&models.SystemSetting{}).Where("key = ?", "probe_registration_"+newKey).Count(&newCount)
	if oldCount != 0 {
		t.Errorf("old registration setting not deleted (count=%d)", oldCount)
	}
	if newCount != 1 {
		t.Errorf("new registration setting not created exactly once (count=%d)", newCount)
	}
}
