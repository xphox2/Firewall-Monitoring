package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestRegisterProbe_AutoApproveWindow_D26 pins D-26: the registration key
// alone auto-approves a probe only within probeAutoApproveWindow of its
// creation; later it registers as pending (and is audit-logged) until an
// admin approves it. A probe that was already approved re-links without a new
// approval and keeps its original approved_at.
func TestRegisterProbe_AutoApproveWindow_D26(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.SystemSetting{}, &models.Probe{}, &models.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	router := gin.New()
	router.POST("/api/probes/register", h.RegisterProbe)
	register := func(key string) (int, bool) {
		body, _ := json.Marshal(map[string]any{"registration_key": key})
		req := httptest.NewRequest("POST", "/api/probes/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		var resp struct {
			Approved bool `json:"approved"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp.Approved
	}
	auditCount := func(action string) int64 {
		var n int64
		db.Gorm().Model(&models.AuditLog{}).Where("action = ?", action).Count(&n)
		return n
	}

	// Fresh pending probe: auto-approved, audit-logged.
	fresh := seedLifecycleProbe(t, db, "fresh-probe", "d26-fresh-key", map[string]interface{}{
		"approval_status": "pending", "status": "pending",
	})
	if code, ok := register("d26-fresh-key"); code != http.StatusOK || !ok {
		t.Fatalf("fresh probe: status=%d approved=%v, want 200 true", code, ok)
	}
	var got models.Probe
	db.Gorm().First(&got, fresh.ID)
	if got.ApprovalStatus != "approved" || got.Status != "online" || got.ApprovedAt == nil {
		t.Errorf("fresh probe not auto-approved: approval=%q status=%q approved_at=%v", got.ApprovalStatus, got.Status, got.ApprovedAt)
	}
	if auditCount("probe_auto_approved") != 1 {
		t.Errorf("auto-approval was not audit-logged")
	}

	// Stale pending probe (created beyond the window): stays pending.
	stale := seedLifecycleProbe(t, db, "stale-probe", "d26-stale-key", map[string]interface{}{
		"approval_status": "pending", "status": "pending",
		"created_at": time.Now().Add(-probeAutoApproveWindow - time.Hour),
	})
	if code, ok := register("d26-stale-key"); code != http.StatusOK || ok {
		t.Fatalf("stale probe: status=%d approved=%v, want 200 false", code, ok)
	}
	got = models.Probe{} // a non-zero ID in the struct would join First's WHERE
	db.Gorm().First(&got, stale.ID)
	if got.ApprovalStatus != "pending" || got.Status == "online" || got.ApprovedAt != nil || !got.LastSeen.IsZero() {
		t.Errorf("stale probe approved itself or looks live: approval=%q status=%q approved_at=%v last_seen=%v", got.ApprovalStatus, got.Status, got.ApprovedAt, got.LastSeen)
	}
	if auditCount("probe_registration_pending") != 1 {
		t.Errorf("pending registration was not audit-logged")
	}

	// A legacy row left 'pending' (column default) by a probe that has been
	// live before the upgrade: re-approved, not locked out.
	legacy := seedLifecycleProbe(t, db, "legacy-probe", "d26-legacy-key", map[string]interface{}{
		"approval_status": "pending", "status": "offline",
		"created_at": time.Now().Add(-90 * 24 * time.Hour), "last_seen": time.Now().Add(-time.Hour),
	})
	if code, ok := register("d26-legacy-key"); code != http.StatusOK || !ok {
		t.Fatalf("previously-live legacy probe: status=%d approved=%v, want 200 true", code, ok)
	}
	got = models.Probe{}
	db.Gorm().First(&got, legacy.ID)
	if got.ApprovalStatus != "approved" || got.Status != "online" {
		t.Errorf("legacy probe not re-approved: approval=%q status=%q", got.ApprovalStatus, got.Status)
	}

	// Long-approved probe coming back from offline: re-links, approval kept.
	firstApproved := time.Now().Add(-30 * 24 * time.Hour).UTC().Truncate(time.Second)
	old := seedLifecycleProbe(t, db, "old-probe", "d26-old-key", map[string]interface{}{
		"approval_status": "approved", "status": "offline",
		"created_at": time.Now().Add(-60 * 24 * time.Hour), "approved_at": firstApproved,
	})
	if code, ok := register("d26-old-key"); code != http.StatusOK || !ok {
		t.Fatalf("approved probe: status=%d approved=%v, want 200 true", code, ok)
	}
	got = models.Probe{}
	db.Gorm().First(&got, old.ID)
	if got.Status != "online" || got.ApprovalStatus != "approved" {
		t.Errorf("approved probe not re-linked: approval=%q status=%q", got.ApprovalStatus, got.Status)
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.UTC().Truncate(time.Second).Equal(firstApproved) {
		t.Errorf("approved_at = %v, want the original %v", got.ApprovedAt, firstApproved)
	}
}

// TestProbeHeartbeat_PendingRefused_D26: a probe left pending by the D-26
// window cannot heartbeat itself online (or receive commands) with its key.
func TestProbeHeartbeat_PendingRefused_D26(t *testing.T) {
	h, db := setupTestHandler(t)
	gin.SetMode(gin.TestMode)
	if err := db.Gorm().AutoMigrate(&models.Probe{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	router := gin.New()
	router.POST("/api/probes/heartbeat", h.ProbeHeartbeat)

	key := "d26-heartbeat-key"
	p := seedLifecycleProbe(t, db, "hb-pending", key, map[string]interface{}{
		"approval_status": "pending", "status": "pending",
	})
	body, _ := json.Marshal(map[string]any{"status": "online"})
	req := httptest.NewRequest("POST", "/api/probes/heartbeat", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("pending heartbeat status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	var check models.Probe
	db.Gorm().First(&check, p.ID)
	if check.Status == "online" || !check.LastSeen.IsZero() {
		t.Errorf("pending probe looks live after heartbeat: status=%q last_seen=%v", check.Status, check.LastSeen)
	}
}
