package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// doPartialUpdateRequest invokes a handler registered at PUT /resource/:id with
// a given numeric ID. Returns the response recorder for status + body assertions.
func doPartialUpdateRequest(t *testing.T, h func(*gin.Context), routePattern string, id uint, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.Handle("PUT", routePattern, h)

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}

	// Build the concrete path by substituting :id with the actual ID.
	concretePath := routePattern
	for _, seg := range []string{":id"} {
		concretePath = replaceFirst(concretePath, seg, fmt.Sprintf("%d", id))
	}
	req := httptest.NewRequest("PUT", concretePath, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// replaceFirst is a tiny helper to avoid pulling in strings.Replace in tests.
func replaceFirst(s, old, new string) string {
	idx := -1
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			idx = i
			break
		}
	}
	if idx < 0 {
		return s
	}
	return s[:idx] + new + s[idx+len(old):]
}

// --- DeviceAlertConfig: partial update preserves untouched fields ---
//
// Reproduces the v0.10.233-deferred bug: previous handler bound the request
// into a fresh struct and Save'd, so PUT {"cpu_threshold": 90} zeroed memory,
// disk, session, cooldown, flipped alerts_enabled to false, and cleared
// policy_id. After v0.10.234's load-then-bind fix, the untouched columns
// stay at their previous values.

func TestUpsertDeviceAlertConfig_partial_update_preserves_other_fields(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)

	// Seed full config.
	policyID := uint(42)
	initial := &models.DeviceAlertConfig{
		DeviceID:         device.ID,
		PolicyID:         &policyID,
		CPUThreshold:     80,
		MemoryThreshold:  85,
		DiskThreshold:    90,
		SessionThreshold: 5000,
		CooldownMinutes:  15,
		AlertsEnabled:    true,
	}
	if err := db.Gorm().Create(initial).Error; err != nil {
		t.Fatalf("seed initial: %v", err)
	}

	// PUT a body that only changes CPU.
	w := doPartialUpdateRequest(t, h.UpsertDeviceAlertConfig, "/api/devices/:id/alert-config", device.ID,
		map[string]interface{}{"cpu_threshold": 95})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	// Read back. Without the fix, every field except CPU would be zeroed.
	var after models.DeviceAlertConfig
	if err := db.Gorm().Where("device_id = ?", device.ID).First(&after).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}

	if after.CPUThreshold != 95 {
		t.Errorf("cpu_threshold = %v, want 95", after.CPUThreshold)
	}
	if after.MemoryThreshold != 85 {
		t.Errorf("memory_threshold zeroed by partial PUT — got %v, want 85", after.MemoryThreshold)
	}
	if after.DiskThreshold != 90 {
		t.Errorf("disk_threshold zeroed by partial PUT — got %v, want 90", after.DiskThreshold)
	}
	if after.SessionThreshold != 5000 {
		t.Errorf("session_threshold zeroed by partial PUT — got %v, want 5000", after.SessionThreshold)
	}
	if after.CooldownMinutes != 15 {
		t.Errorf("cooldown_minutes zeroed by partial PUT — got %v, want 15", after.CooldownMinutes)
	}
	if !after.AlertsEnabled {
		t.Errorf("alerts_enabled silently flipped to false by partial PUT")
	}
	if after.PolicyID == nil || *after.PolicyID != 42 {
		t.Errorf("policy_id cleared by partial PUT — got %v, want &42", after.PolicyID)
	}
}

func TestUpsertDeviceAlertConfig_rejects_invalid_threshold(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)

	w := doPartialUpdateRequest(t, h.UpsertDeviceAlertConfig, "/api/devices/:id/alert-config", device.ID,
		map[string]interface{}{"cpu_threshold": 150})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 for out-of-range threshold", w.Code, w.Body.String())
	}
}

func TestUpsertDeviceAlertConfig_creates_when_absent(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)

	// No prior config — PUT should create one with the AlertsEnabled=true default.
	w := doPartialUpdateRequest(t, h.UpsertDeviceAlertConfig, "/api/devices/:id/alert-config", device.ID,
		map[string]interface{}{"cpu_threshold": 75})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	var after models.DeviceAlertConfig
	if err := db.Gorm().Where("device_id = ?", device.ID).First(&after).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.CPUThreshold != 75 {
		t.Errorf("cpu_threshold = %v, want 75", after.CPUThreshold)
	}
	if !after.AlertsEnabled {
		t.Errorf("AlertsEnabled defaulted to false instead of true on insert")
	}
}

// --- SiteAlertConfig: partial update preserves untouched fields ---

func TestUpsertSiteAlertConfig_partial_update_preserves_other_fields(t *testing.T) {
	h, db := setupTestHandler(t)

	// Site model doesn't need probe/device — just create one directly.
	site := &models.Site{Name: "test-site"}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}

	policyID := uint(7)
	initial := &models.SiteAlertConfig{
		SiteID:           site.ID,
		PolicyID:         &policyID,
		CPUThreshold:     70,
		MemoryThreshold:  75,
		DiskThreshold:    80,
		SessionThreshold: 10000,
		CooldownMinutes:  30,
	}
	if err := db.Gorm().Create(initial).Error; err != nil {
		t.Fatalf("seed initial: %v", err)
	}

	w := doPartialUpdateRequest(t, h.UpsertSiteAlertConfig, "/api/sites/:id/alert-config", site.ID,
		map[string]interface{}{"memory_threshold": 88})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var after models.SiteAlertConfig
	if err := db.Gorm().Where("site_id = ?", site.ID).First(&after).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.MemoryThreshold != 88 {
		t.Errorf("memory_threshold = %v, want 88", after.MemoryThreshold)
	}
	if after.CPUThreshold != 70 {
		t.Errorf("cpu_threshold zeroed — got %v, want 70", after.CPUThreshold)
	}
	if after.DiskThreshold != 80 {
		t.Errorf("disk_threshold zeroed — got %v, want 80", after.DiskThreshold)
	}
	if after.SessionThreshold != 10000 {
		t.Errorf("session_threshold zeroed — got %v, want 10000", after.SessionThreshold)
	}
	if after.CooldownMinutes != 30 {
		t.Errorf("cooldown_minutes zeroed — got %v, want 30", after.CooldownMinutes)
	}
	if after.PolicyID == nil || *after.PolicyID != 7 {
		t.Errorf("policy_id cleared — got %v, want &7", after.PolicyID)
	}
}

// --- MaintenanceWindow: partial update preserves untouched fields ---

func TestUpdateMaintenanceWindow_partial_update_preserves_other_fields(t *testing.T) {
	h, db := setupTestHandler(t)

	deviceID := uint(99)
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 1, 4, 0, 0, 0, time.UTC)
	initial := &models.MaintenanceWindow{
		DeviceID:    &deviceID,
		Name:        "weekly-update",
		StartTime:   start,
		EndTime:     end,
		Recurring:   true,
		RecurRule:   "WEEKLY",
		RecurDays:   "MO,TU",
		SuppressAll: true,
		AlertTypes:  "CPU_HIGH,MEMORY_HIGH",
		Notes:       "scheduled OS patches",
	}
	if err := db.Gorm().Create(initial).Error; err != nil {
		t.Fatalf("seed initial: %v", err)
	}

	// PUT only the end-time. Without the fix every other column wipes.
	newEnd := time.Date(2026, 6, 1, 6, 0, 0, 0, time.UTC)
	w := doPartialUpdateRequest(t, h.UpdateMaintenanceWindow, "/api/maintenance-windows/:id", initial.ID,
		map[string]interface{}{"end_time": newEnd.Format(time.RFC3339)})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	var after models.MaintenanceWindow
	if err := db.Gorm().First(&after, initial.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}

	if !after.EndTime.Equal(newEnd) {
		t.Errorf("end_time = %v, want %v", after.EndTime, newEnd)
	}
	if after.Name != "weekly-update" {
		t.Errorf("name zeroed by partial PUT — got %q, want weekly-update", after.Name)
	}
	if !after.StartTime.Equal(start) {
		t.Errorf("start_time changed — got %v, want %v", after.StartTime, start)
	}
	if !after.Recurring {
		t.Errorf("recurring silently flipped to false by partial PUT")
	}
	if after.RecurRule != "WEEKLY" {
		t.Errorf("recur_rule wiped — got %q, want WEEKLY", after.RecurRule)
	}
	if after.RecurDays != "MO,TU" {
		t.Errorf("recur_days wiped — got %q, want MO,TU", after.RecurDays)
	}
	if !after.SuppressAll {
		t.Errorf("suppress_all silently flipped to false")
	}
	if after.AlertTypes != "CPU_HIGH,MEMORY_HIGH" {
		t.Errorf("alert_types wiped — got %q, want CPU_HIGH,MEMORY_HIGH", after.AlertTypes)
	}
	if after.Notes != "scheduled OS patches" {
		t.Errorf("notes wiped — got %q, want scheduled OS patches", after.Notes)
	}
	if after.DeviceID == nil || *after.DeviceID != 99 {
		t.Errorf("device_id cleared — got %v, want &99", after.DeviceID)
	}
}

func TestUpdateMaintenanceWindow_rejects_end_before_start(t *testing.T) {
	h, db := setupTestHandler(t)

	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 1, 4, 0, 0, 0, time.UTC)
	initial := &models.MaintenanceWindow{
		Name:      "test",
		StartTime: start,
		EndTime:   end,
	}
	if err := db.Gorm().Create(initial).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Try to move end_time to BEFORE start_time. Should reject.
	badEnd := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	w := doPartialUpdateRequest(t, h.UpdateMaintenanceWindow, "/api/maintenance-windows/:id", initial.ID,
		map[string]interface{}{"end_time": badEnd.Format(time.RFC3339)})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 for end<start", w.Code, w.Body.String())
	}
}
