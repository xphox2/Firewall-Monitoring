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
