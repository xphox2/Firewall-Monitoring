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

// doAdminTestRequest invokes an admin handler that doesn't take a probe-ID
// path param. The bulk-ack endpoint is registered at POST /api/alerts/bulk-acknowledge.
func doAdminTestRequest(t *testing.T, h func(*gin.Context), method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.Handle(method, path, h)
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func seedAlerts(t *testing.T, h *Handler, deviceID uint, n int) []uint {
	t.Helper()
	ids := make([]uint, 0, n)
	for i := 0; i < n; i++ {
		a := &models.Alert{
			DeviceID:     deviceID,
			AlertType:    "TEST_ALERT",
			Severity:     "warning",
			Message:      "seeded alert",
			Timestamp:    time.Now(),
			Acknowledged: false,
		}
		if err := h.db.Gorm().Create(a).Error; err != nil {
			t.Fatalf("create alert %d: %v", i, err)
		}
		ids = append(ids, a.ID)
	}
	return ids
}

func TestBulkAcknowledgeAlerts_AllUnacked_AcksAll(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	ids := seedAlerts(t, h, device.ID, 5)

	w := doAdminTestRequest(t, h.BulkAcknowledgeAlerts, "POST", "/api/alerts/bulk-acknowledge", map[string]interface{}{
		"ids":   ids,
		"notes": "bulk test",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var count int64
	db.Gorm().Model(&models.Alert{}).Where("acknowledged = true").Count(&count)
	if count != 5 {
		t.Errorf("expected 5 acked, got %d", count)
	}

	// Notes should be applied to all five.
	var acked []models.Alert
	db.Gorm().Where("acknowledged = true").Find(&acked)
	for _, a := range acked {
		if a.Notes != "bulk test" {
			t.Errorf("alert %d notes = %q, want %q", a.ID, a.Notes, "bulk test")
		}
		if a.AcknowledgedAt == nil || a.AcknowledgedAt.IsZero() {
			t.Errorf("alert %d acknowledged_at not set", a.ID)
		}
	}
}

func TestBulkAcknowledgeAlerts_MixedUnackedAndAlreadyAcked(t *testing.T) {
	// Pre-acked rows in the IN list should still succeed (no error). Their
	// notes get rewritten — that's the documented behavior.
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	ids := seedAlerts(t, h, device.ID, 4)

	// Pre-ack the first two.
	now := time.Now()
	db.Gorm().Model(&models.Alert{}).Where("id IN ?", ids[:2]).Updates(map[string]interface{}{
		"acknowledged":    true,
		"acknowledged_at": now,
		"notes":           "earlier notes",
	})

	w := doAdminTestRequest(t, h.BulkAcknowledgeAlerts, "POST", "/api/alerts/bulk-acknowledge", map[string]interface{}{
		"ids":   ids, // includes the two already-acked
		"notes": "second-pass notes",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var count int64
	db.Gorm().Model(&models.Alert{}).Where("acknowledged = true").Count(&count)
	if count != 4 {
		t.Errorf("expected 4 acked, got %d", count)
	}

	// All four should now have the new notes (caller signaled they want this).
	var acked []models.Alert
	db.Gorm().Where("acknowledged = true").Find(&acked)
	for _, a := range acked {
		if a.Notes != "second-pass notes" {
			t.Errorf("alert %d notes = %q, want %q", a.ID, a.Notes, "second-pass notes")
		}
	}
}

func TestBulkAcknowledgeAlerts_EmptyIDsReturns400(t *testing.T) {
	h, _ := setupTestHandler(t)
	w := doAdminTestRequest(t, h.BulkAcknowledgeAlerts, "POST", "/api/alerts/bulk-acknowledge", map[string]interface{}{
		"ids": []uint{},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty ids", w.Code)
	}
}

func TestBulkAcknowledgeAlerts_TooManyIDsReturns400(t *testing.T) {
	h, _ := setupTestHandler(t)
	tooMany := make([]uint, maxBulkAckIDs+1)
	for i := range tooMany {
		tooMany[i] = uint(i + 1)
	}
	w := doAdminTestRequest(t, h.BulkAcknowledgeAlerts, "POST", "/api/alerts/bulk-acknowledge", map[string]interface{}{
		"ids": tooMany,
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for over-limit ids", w.Code)
	}
}

// doAdminQueryRequest is a variant of doAdminTestRequest that supports query
// strings — needed for BulkAcknowledgeAlertsByFilter which reads filters from
// c.Query.
func doAdminQueryRequest(t *testing.T, h func(*gin.Context), method, path, query string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.Handle(method, path, h)
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	url := path
	if query != "" {
		url = path + "?" + query
	}
	req := httptest.NewRequest(method, url, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func seedAlertsWithMix(t *testing.T, h *Handler, deviceID uint) {
	t.Helper()
	mix := []struct {
		alertType string
		severity  string
		acked     bool
	}{
		{"DEVICE_OFFLINE", "critical", false},
		{"DEVICE_OFFLINE", "critical", false},
		{"DEVICE_OFFLINE", "critical", true},
		{"CPU_HIGH", "warning", false},
		{"CPU_HIGH", "warning", false},
		{"CONFIG_CHANGE", "info", false},
	}
	for i, m := range mix {
		a := &models.Alert{
			DeviceID:     deviceID,
			AlertType:    models.AlertType(m.alertType),
			Severity:     models.Severity(m.severity),
			Message:      "seeded alert",
			Timestamp:    time.Now(),
			Acknowledged: m.acked,
		}
		if err := h.db.Gorm().Create(a).Error; err != nil {
			t.Fatalf("create alert %d: %v", i, err)
		}
	}
}

func TestBulkAcknowledgeByFilter_BySeverity(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	seedAlertsWithMix(t, h, device.ID)

	w := doAdminQueryRequest(t, h.BulkAcknowledgeAlertsByFilter,
		"POST", "/api/alerts/bulk-acknowledge-filter", "severity=warning",
		map[string]interface{}{"notes": "filter test"})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}

	var ackedWarn, ackedCrit int64
	db.Gorm().Model(&models.Alert{}).Where("severity = ? AND acknowledged = true", "warning").Count(&ackedWarn)
	db.Gorm().Model(&models.Alert{}).Where("severity = ? AND acknowledged = true", "critical").Count(&ackedCrit)
	if ackedWarn != 2 {
		t.Errorf("warning rows acked: got %d, want 2", ackedWarn)
	}
	if ackedCrit != 1 {
		t.Errorf("critical rows acked should be unchanged at 1 (was pre-acked); got %d", ackedCrit)
	}
}

func TestBulkAcknowledgeByFilter_AcknowledgedFalseFilter(t *testing.T) {
	// The most common UI scenario: user filters to "Unacknowledged" and clicks
	// "Select all matching" → "Acknowledge". Should ack only the unacked rows.
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	seedAlertsWithMix(t, h, device.ID)

	w := doAdminQueryRequest(t, h.BulkAcknowledgeAlertsByFilter,
		"POST", "/api/alerts/bulk-acknowledge-filter", "acknowledged=false",
		map[string]interface{}{"notes": "all unacked"})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}

	var unacked int64
	db.Gorm().Model(&models.Alert{}).Where("acknowledged = false").Count(&unacked)
	if unacked != 0 {
		t.Errorf("after ack-all-unacked, unacked count should be 0; got %d", unacked)
	}
}

func TestBulkAcknowledgeByFilter_NoFilterReturns400(t *testing.T) {
	// Without ANY filter the endpoint would silently ack every alert in the
	// database, which is too dangerous. Must require at least one filter.
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	seedAlertsWithMix(t, h, device.ID)

	w := doAdminQueryRequest(t, h.BulkAcknowledgeAlertsByFilter,
		"POST", "/api/alerts/bulk-acknowledge-filter", "", nil)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 with no filter", w.Code)
	}

	var unacked int64
	db.Gorm().Model(&models.Alert{}).Where("acknowledged = false").Count(&unacked)
	if unacked != 5 {
		t.Errorf("nothing should have been acked; unacked count = %d, want 5", unacked)
	}
}

func TestBulkAcknowledgeByFilter_CombinedFilters(t *testing.T) {
	// device_id + alert_type + acknowledged=false → very narrow match.
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	seedAlertsWithMix(t, h, device.ID)
	// Also seed an unrelated device with a matching alert type to confirm the
	// device_id filter excludes it.
	otherDev := &models.Device{Name: "other-fw", IPAddress: "10.10.10.10"}
	if err := db.Gorm().Create(otherDev).Error; err != nil {
		t.Fatalf("create otherDev: %v", err)
	}
	if err := db.Gorm().Create(&models.Alert{
		DeviceID: otherDev.ID, AlertType: "DEVICE_OFFLINE", Severity: "critical",
		Message: "x", Timestamp: time.Now(), Acknowledged: false,
	}).Error; err != nil {
		t.Fatalf("create other alert: %v", err)
	}

	q := fmt.Sprintf("device_id=%d&alert_type=DEVICE_OFFLINE&acknowledged=false", device.ID)
	w := doAdminQueryRequest(t, h.BulkAcknowledgeAlertsByFilter,
		"POST", "/api/alerts/bulk-acknowledge-filter", q,
		map[string]interface{}{"notes": ""})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}

	// The two unacked DEVICE_OFFLINE rows on `device` should be acked.
	// The pre-acked DEVICE_OFFLINE row on `device` is excluded by acknowledged=false.
	// The DEVICE_OFFLINE row on `otherDev` is excluded by device_id.
	var ackedOnDev, totalAckedDeviceOffline int64
	db.Gorm().Model(&models.Alert{}).Where("device_id = ? AND alert_type = ? AND acknowledged = true", device.ID, "DEVICE_OFFLINE").Count(&ackedOnDev)
	db.Gorm().Model(&models.Alert{}).Where("alert_type = ? AND acknowledged = true", "DEVICE_OFFLINE").Count(&totalAckedDeviceOffline)
	if ackedOnDev != 3 {
		t.Errorf("device DEVICE_OFFLINE acked = %d, want 3 (2 newly + 1 pre-acked)", ackedOnDev)
	}
	if totalAckedDeviceOffline != 3 {
		t.Errorf("DEVICE_OFFLINE acked across all devices = %d, want 3 (otherDev's row should remain unacked)", totalAckedDeviceOffline)
	}
}

func TestBulkAcknowledgeAlerts_OmitsRowsNotInList(t *testing.T) {
	// Other alerts should be untouched — only the listed IDs should be acked.
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	ids := seedAlerts(t, h, device.ID, 6)

	target := ids[:3] // ack only the first three

	w := doAdminTestRequest(t, h.BulkAcknowledgeAlerts, "POST", "/api/alerts/bulk-acknowledge", map[string]interface{}{
		"ids":   target,
		"notes": "",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var ackedCount, unackedCount int64
	db.Gorm().Model(&models.Alert{}).Where("acknowledged = true").Count(&ackedCount)
	db.Gorm().Model(&models.Alert{}).Where("acknowledged = false").Count(&unackedCount)
	if ackedCount != 3 {
		t.Errorf("acked count = %d, want 3", ackedCount)
	}
	if unackedCount != 3 {
		t.Errorf("unacked count = %d, want 3", unackedCount)
	}
}
