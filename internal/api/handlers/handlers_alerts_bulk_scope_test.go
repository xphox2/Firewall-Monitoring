package handlers

import (
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The by-filter bulk endpoints must reach EXACTLY the set the list shows.
//
// The list hides snoozed alerts unless include_snoozed=true
// (handlers_analytics.go: "snoozed_until IS NULL OR snoozed_until < now"),
// but the by-filter database functions had no snooze predicate at all. So the
// console's cross-page "Select all N matching" was shown N alerts and the
// action reached the snoozed ones as well: the operator was told "all 12
// matching" and 17 rows changed.
//
// The endpoint now honours include_snoozed, and the console sends it.

func seedSnoozedAlerts(t *testing.T, h *Handler, deviceID uint) (snoozed, plain uint) {
	t.Helper()
	future := time.Now().Add(4 * time.Hour)
	past := time.Now().Add(-4 * time.Hour)

	rows := []models.Alert{
		// Snoozed into the future: hidden by the list, and the default for
		// the bulk action too.
		{DeviceID: deviceID, AlertType: models.AlertType("CPU_HIGH"), Severity: models.Severity("warning"),
			Message: "snoozed ahead", Timestamp: time.Now(), SnoozedUntil: &future},
		// A snooze that has EXPIRED: the list shows it (snoozed_until < now),
		// so the bulk action must reach it.
		{DeviceID: deviceID, AlertType: models.AlertType("CPU_HIGH"), Severity: models.Severity("warning"),
			Message: "snooze expired", Timestamp: time.Now(), SnoozedUntil: &past},
		// Never snoozed.
		{DeviceID: deviceID, AlertType: models.AlertType("CPU_HIGH"), Severity: models.Severity("warning"),
			Message: "plain", Timestamp: time.Now()},
	}
	for i := range rows {
		if err := h.db.Gorm().Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed alert %d: %v", i, err)
		}
	}
	return 1, 2
}

func TestBulkAcknowledgeByFilter_ExcludesSnoozedByDefault(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	seedSnoozedAlerts(t, h, device.ID)

	w := doAdminQueryRequest(t, h.BulkAcknowledgeAlertsByFilter,
		"POST", "/api/alerts/bulk-acknowledge-filter", "acknowledged=false",
		map[string]interface{}{"notes": "scope test"})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}

	// The snoozed-ahead row must be untouched: the list hides it, so the
	// action must not reach it.
	var snoozedAcked int64
	db.Gorm().Model(&models.Alert{}).
		Where("message = ? AND acknowledged = true", "snoozed ahead").Count(&snoozedAcked)
	if snoozedAcked != 0 {
		t.Errorf("the snoozed alert was acknowledged; the list hides it, so the bulk action must not reach it")
	}

	// The expired snooze and the plain row are both visible in the list, so
	// both must be acknowledged.
	var visibleAcked int64
	db.Gorm().Model(&models.Alert{}).
		Where("message IN ? AND acknowledged = true", []string{"snooze expired", "plain"}).Count(&visibleAcked)
	if visibleAcked != 2 {
		t.Errorf("visible rows acked = %d, want 2 (the expired snooze and the plain row)", visibleAcked)
	}
}

func TestBulkAcknowledgeByFilter_IncludesSnoozedWhenAsked(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	seedSnoozedAlerts(t, h, device.ID)

	w := doAdminQueryRequest(t, h.BulkAcknowledgeAlertsByFilter,
		"POST", "/api/alerts/bulk-acknowledge-filter", "acknowledged=false&include_snoozed=true",
		map[string]interface{}{"notes": "scope test"})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}

	// With the list showing the snoozed rows, the action must reach them.
	var snoozedAcked int64
	db.Gorm().Model(&models.Alert{}).
		Where("message = ? AND acknowledged = true", "snoozed ahead").Count(&snoozedAcked)
	if snoozedAcked != 1 {
		t.Errorf("the snoozed alert was not acknowledged; include_snoozed=true was sent, so it must be in scope")
	}
}

func TestBulkSnoozeByFilter_ExcludesSnoozedByDefault(t *testing.T) {
	h, db := setupTestHandler(t)
	_, device := setupProbeAndDevice(t, db)
	seedSnoozedAlerts(t, h, device.ID)

	w := doAdminQueryRequest(t, h.BulkSnoozeAlertsByFilter,
		"POST", "/api/alerts/bulk-snooze-filter", "acknowledged=false",
		map[string]interface{}{"hours": 2, "reason": "scope test"})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}

	// The already-snoozed row must be untouched: the list hides it, so the
	// action must not reach it.
	//
	// The check is on the snooze TIME, not on snoozed_by: SnoozedBy is a
	// plain string, so an unset one is "" and not NULL — "IS NOT NULL" would
	// match the untouched row as well. A re-snooze would move the time to
	// the bulk action's own horizon, so comparing it is unambiguous.
	var before models.Alert
	if err := db.Gorm().Where("message = ?", "snoozed ahead").First(&before).Error; err != nil {
		t.Fatalf("read the snoozed row: %v", err)
	}
	if before.SnoozedUntil == nil {
		t.Fatal("the seeded snoozed row has no snooze time — the seed is broken, not the handler")
	}

	// The already-snoozed row must be untouched: the list hides it, so the
	// action must not reach it.
	var after models.Alert
	if err := db.Gorm().Where("message = ?", "snoozed ahead").First(&after).Error; err != nil {
		t.Fatalf("re-read the snoozed row: %v", err)
	}
	if after.SnoozedUntil == nil || !after.SnoozedUntil.Equal(*before.SnoozedUntil) {
		t.Errorf("the snoozed alert was re-snoozed (%v -> %v); the list hides it, so the bulk action must not reach it",
			before.SnoozedUntil, after.SnoozedUntil)
	}

	var plainSnoozed int64
	db.Gorm().Model(&models.Alert{}).
		Where("message = ? AND snoozed_until IS NOT NULL", "plain").Count(&plainSnoozed)
	if plainSnoozed != 1 {
		t.Errorf("the plain row was not snoozed; it is visible in the list, so the action must reach it")
	}
}
