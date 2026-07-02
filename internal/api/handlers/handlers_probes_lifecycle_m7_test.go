package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// seedLifecycleProbe creates an approved probe and then applies the given
// column overrides directly (GORM's `default:true` tag would silently replace
// a zero-value Enabled=false on Create, so overrides go through Updates).
func seedLifecycleProbe(t *testing.T, db *database.Database, name, key string, overrides map[string]interface{}) *models.Probe {
	t.Helper()
	p := &models.Probe{
		Name:            name,
		RegistrationKey: database.HashProbeKey(key),
		ApprovalStatus:  "approved",
		Status:          "offline",
	}
	if err := db.Gorm().Create(p).Error; err != nil {
		t.Fatalf("seed probe %s: %v", name, err)
	}
	if len(overrides) > 0 {
		if err := db.Gorm().Model(p).Updates(overrides).Error; err != nil {
			t.Fatalf("override probe %s: %v", name, err)
		}
	}
	return p
}

// TestRegisterProbe_LifecycleGates_M7 pins the 2026-07-01 audit M7 fix on the
// unauthenticated key-based register endpoint: a probe the admin REJECTED must
// not re-approve itself by re-POSTing register (RejectProbe leaves the key
// valid), and a decommissioned/disabled probe must not resurrect. Pre-fix,
// any probe that wasn't already approved+online was unconditionally flipped
// back to approved+online.
func TestRegisterProbe_LifecycleGates_M7(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.SystemSetting{}, &models.Probe{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	router := gin.New()
	router.POST("/api/probes/register", h.RegisterProbe)

	register := func(key string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"registration_key": key})
		req := httptest.NewRequest("POST", "/api/probes/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// Rejected probe: register must 403 and the row must STAY rejected.
	rejKey := "m7-rejected-key"
	rej := seedLifecycleProbe(t, db, "rejected-probe", rejKey, map[string]interface{}{
		"approval_status": "rejected", "status": "rejected",
	})
	if w := register(rejKey); w.Code != http.StatusForbidden {
		t.Errorf("rejected probe register status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	var check models.Probe
	db.Gorm().First(&check, rej.ID)
	if check.ApprovalStatus != "rejected" || check.Status == "online" {
		t.Errorf("rejected probe mutated by register: approval=%q status=%q (must stay rejected)", check.ApprovalStatus, check.Status)
	}

	// Decommissioned probe: register must 410 and stay decommissioned.
	decKey := "m7-decommissioned-key"
	now := time.Now().UTC()
	dec := seedLifecycleProbe(t, db, "decommissioned-probe", decKey, map[string]interface{}{
		"decommissioned_at": now, "enabled": false, "status": "offline",
	})
	if w := register(decKey); w.Code != http.StatusGone {
		t.Errorf("decommissioned probe register status = %d, want 410; body: %s", w.Code, w.Body.String())
	}
	// Fresh destination struct — GORM treats a reused struct's populated
	// primary key as an extra query condition.
	var check2 models.Probe
	db.Gorm().First(&check2, dec.ID)
	if check2.DecommissionedAt == nil || check2.Enabled || check2.Status == "online" {
		t.Errorf("decommissioned probe mutated by register: decommissioned_at=%v enabled=%v status=%q", check2.DecommissionedAt, check2.Enabled, check2.Status)
	}

	// Control: a plain approved+offline probe still registers fine.
	okKey := "m7-active-key"
	seedLifecycleProbe(t, db, "active-probe", okKey, nil)
	if w := register(okKey); w.Code != http.StatusOK {
		t.Errorf("active probe register status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// TestProbeHeartbeat_DecommissionedRefused_M7 pins that a still-running
// collector cannot resurrect a decommissioned probe: pre-fix the heartbeat
// wrote status='online' + fresh last_seen unconditionally, undoing an admin
// decommission within 30 seconds and keeping the probe immune to the stale
// sweep forever.
func TestProbeHeartbeat_DecommissionedRefused_M7(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.Probe{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	router := gin.New()
	router.POST("/api/probes/heartbeat", h.ProbeHeartbeat)

	key := "m7-heartbeat-key"
	now := time.Now().UTC()
	p := seedLifecycleProbe(t, db, "hb-decommissioned", key, map[string]interface{}{
		"decommissioned_at": now, "enabled": false, "status": "offline",
	})

	body, _ := json.Marshal(map[string]any{"status": "online"})
	req := httptest.NewRequest("POST", "/api/probes/heartbeat", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusGone {
		t.Errorf("decommissioned heartbeat status = %d, want 410; body: %s", w.Code, w.Body.String())
	}
	var check models.Probe
	db.Gorm().First(&check, p.ID)
	if check.Status == "online" {
		t.Error("decommissioned probe flipped to 'online' by heartbeat — the admin decommission was undone from the network side")
	}
}

// TestValidateProbe_DecommissionedIngestRefused_M7 pins the data-plane gate:
// DecommissionProbe deliberately leaves approval_status='approved', so the
// pre-fix approval-only check let a decommissioned probe keep ingesting (and
// each POST refreshed last_seen/last_data_received, making it look live).
func TestValidateProbe_DecommissionedIngestRefused_M7(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.Probe{}, &models.SystemStatus{}, &models.ProcessedBatch{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	router := gin.New()
	router.POST("/api/probes/:id/system-status", h.ReceiveSystemStatuses)

	key := "m7-ingest-key"
	now := time.Now().UTC()
	p := seedLifecycleProbe(t, db, "ingest-decommissioned", key, map[string]interface{}{
		"decommissioned_at": now, "enabled": false, "status": "offline",
	})

	body, _ := json.Marshal([]models.SystemStatus{{DeviceID: 0, CPUUsage: 10}})
	req := httptest.NewRequest("POST", "/api/probes/"+strconv.FormatUint(uint64(p.ID), 10)+"/system-status", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("decommissioned ingest status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	var n int64
	db.Gorm().Model(&models.SystemStatus{}).Count(&n)
	if n != 0 {
		t.Errorf("system_status rows = %d, want 0 (decommissioned probe's data must be refused)", n)
	}
}
