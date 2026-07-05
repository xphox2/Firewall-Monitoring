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
//
// LC-01 (2026-07-04 audit): the refusal must be 410 Gone — the same code
// RegisterProbe and ProbeHeartbeat return for this lifecycle state — NOT 403.
// The collector's taxonomy reads 403 as "auth broken → re-register", so the
// pre-fix 403 here turned every admin decommission into a permanent
// re-register/requeue loop instead of the documented non-retryable quiesce.
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

	if w.Code != http.StatusGone {
		t.Errorf("decommissioned ingest status = %d, want 410 (LC-01: must match register/heartbeat, 403 = re-register loop); body: %s", w.Code, w.Body.String())
	}
	var n int64
	db.Gorm().Model(&models.SystemStatus{}).Count(&n)
	if n != 0 {
		t.Errorf("system_status rows = %d, want 0 (decommissioned probe's data must be refused)", n)
	}
}

// TestValidateProbe_StatusCodeContract_LC01 pins the full status-code contract
// of the data-plane gate (validateProbe) so the collector's retry taxonomy can
// rely on it: 404 unknown probe, 403 not-approved, 401 bad/missing key, 410
// decommissioned-or-disabled (and ONLY that state — 410 is the non-retryable
// "gone on purpose" signal). The 410 branch sits after bearer verification, so
// a decommissioned probe presented with a WRONG key is still 401, and
// lifecycle state is never disclosed to an unauthenticated caller.
func TestValidateProbe_StatusCodeContract_LC01(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.Probe{}, &models.SystemStatus{}, &models.ProcessedBatch{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	router := gin.New()
	router.POST("/api/probes/:id/system-status", h.ReceiveSystemStatuses)

	ingest := func(probeID uint, bearer string) *httptest.ResponseRecorder {
		body, _ := json.Marshal([]models.SystemStatus{{DeviceID: 0, CPUUsage: 10}})
		req := httptest.NewRequest("POST", "/api/probes/"+strconv.FormatUint(uint64(probeID), 10)+"/system-status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	now := time.Now().UTC()
	goodKey := "lc01-good-key"
	active := seedLifecycleProbe(t, db, "lc01-active", goodKey, nil)
	decKey := "lc01-dec-key"
	dec := seedLifecycleProbe(t, db, "lc01-decommissioned", decKey, map[string]interface{}{
		"decommissioned_at": now, "enabled": false, "status": "offline",
	})
	pendKey := "lc01-pending-key"
	pending := seedLifecycleProbe(t, db, "lc01-pending", pendKey, map[string]interface{}{
		"approval_status": "pending",
	})

	// Unknown probe ID → 404 (not 410: only a KNOWN retired probe is "gone").
	if w := ingest(99999, goodKey); w.Code != http.StatusNotFound {
		t.Errorf("unknown probe ingest status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	// Known but not approved → 403 (admin decision pending; re-register path).
	if w := ingest(pending.ID, pendKey); w.Code != http.StatusForbidden {
		t.Errorf("unapproved probe ingest status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	// Bad key on an ACTIVE probe → 401, never 410.
	if w := ingest(active.ID, "wrong-key"); w.Code != http.StatusUnauthorized {
		t.Errorf("bad-key ingest status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
	// Bad key on a DECOMMISSIONED probe → still 401: auth failure dominates,
	// lifecycle state must not leak to a caller who can't authenticate.
	if w := ingest(dec.ID, "wrong-key"); w.Code != http.StatusUnauthorized {
		t.Errorf("bad-key ingest on decommissioned probe status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
	// Missing bearer entirely → 401 as well.
	if w := ingest(dec.ID, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no-auth ingest on decommissioned probe status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
	// Valid key + decommissioned → 410 Gone (the LC-01 fix).
	if w := ingest(dec.ID, decKey); w.Code != http.StatusGone {
		t.Errorf("decommissioned ingest status = %d, want 410; body: %s", w.Code, w.Body.String())
	}
	// Control: valid key + active probe → 2xx and last_seen is refreshed.
	if w := ingest(active.ID, goodKey); w.Code != http.StatusOK {
		t.Errorf("active probe ingest status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}
