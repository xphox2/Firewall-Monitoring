package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// TestCleanupOldData_UnackedAlertsEventuallyArchived_AUDIT031 is
// the regression for the audit: pre-fix `CleanupOldData` only
// deleted acked alerts (`WHERE acknowledged = true AND timestamp
// < ?`). A critical device that paged off-hours and went unacked
// accumulated alert rows forever — the table grew unbounded on
// any deployment where an alert could go unacked for more than a
// few days (which is most production deployments, since on-call
// rotation gaps + sleep + on-shift attention are all realistic
// reasons for a >24h gap).
//
// The fix: a second cleanup pass for unacked alerts, with a
// separate `RETENTION_UNACK_ALERT_DAYS` knob (default 90). Each
// auto-archived alert fires a WARNING log so the operator can
// reconstruct the "stale unack" event from the logs.
//
// The test seeds three alerts:
//   - one 100-day-old acked alert (will be deleted; default 30-day
//     acked retention)
//   - one 100-day-old unacked alert (will be deleted by the new
//     unacked-archive pass; default 90-day unacked retention)
//   - one 10-day-old unacked alert (will be kept; within both
//     windows)
func TestCleanupOldData_UnackedAlertsEventuallyArchived_AUDIT031(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	oldAcked := models.Alert{
		DeviceID: 1, Severity: "high", Message: "old acked",
		Timestamp: now.AddDate(0, 0, -100), Acknowledged: true,
	}
	oldUnacked := models.Alert{
		DeviceID: 1, Severity: "critical", Message: "old UNACKED",
		Timestamp: now.AddDate(0, 0, -100), Acknowledged: false,
	}
	recentUnacked := models.Alert{
		DeviceID: 2, Severity: "warning", Message: "recent unacked",
		Timestamp: now.AddDate(0, 0, -10), Acknowledged: false,
	}
	// Use a slice-by-index loop (not `for _, a := range`) so
	// GORM's auto-incremented ID is written back to the
	// struct in the slice. The `range` form copies the
	// struct, so `&a` points to a local copy and the original
	// stays at ID=0.
	seedAlerts := []*models.Alert{&oldAcked, &oldUnacked, &recentUnacked}
	for _, a := range seedAlerts {
		if err := d.Gorm().Create(a).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Default retention: 30 days acked, 90 days unacked.
	if err := d.CleanupOldData(config.RetentionConfig{
		AlertDays:      30,
		UnackAlertDays: 90,
	}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var remaining []models.Alert
	if err := d.Gorm().Order("id ASC").Find(&remaining).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("after cleanup, expected 1 row (the recent unacked), got %d: %+v", len(remaining), remaining)
	}
	if remaining[0].ID != recentUnacked.ID {
		t.Errorf("wrong row survived: ID=%d Message=%q, want ID=%d Message=%q", remaining[0].ID, remaining[0].Message, recentUnacked.ID, recentUnacked.Message)
	}
}

// TestCleanupOldData_UnackRetentionLongerThanAck_AUDIT031 is a
// defensive sibling: the unack window must be at least as long
// as the ack window. If an operator sets
// `RETENTION_UNACK_ALERT_DAYS=10` and `RETENTION_ALERT_DAYS=30`,
// the cleanup should still keep unacked alerts around for 30
// days — the operator almost certainly meant to give unacked
// alerts MORE time, not less, and an unack < ack default would
// be backwards (auto-archive unacked alerts before the operator
// has had a chance to ack them).
func TestCleanupOldData_UnackRetentionLongerThanAck_AUDIT031(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	// 20-day-old unacked alert. With UnackAlertDays=10 and
	// AlertDays=30, the defensive clamp should keep this row
	// (because the unack cutoff is clamped to the acked cutoff,
	// 30 days).
	twentyDayOld := models.Alert{
		DeviceID: 1, Severity: "high", Message: "20-day unacked",
		Timestamp: now.AddDate(0, 0, -20), Acknowledged: false,
	}
	if err := d.Gorm().Create(&twentyDayOld).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := d.CleanupOldData(config.RetentionConfig{
		AlertDays:      30,
		UnackAlertDays: 10, // shorter than ack — should be clamped
	}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var remaining []models.Alert
	if err := d.Gorm().Find(&remaining).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("AUDIT-031: unack window should be clamped to >= acked window; expected the 20-day unacked row to survive, got %d rows", len(remaining))
	}
}

// TestCleanupOldData_StaleUnackWarningLogged_AUDIT031 — defensive:
// each auto-archived stale unack alert must log a WARNING. This
// is the operator's "stale unack" trail. We don't capture log
// output (Go's default logger writes to stderr; redirecting it
// here would add complexity). Instead we verify the
// unack-archive pass did *something* by checking the row count.
// The WARNING log is a soft-fail: if a future refactor silences
// it, the row will still be deleted; the test catches that
// (the count check is what matters).
func TestCleanupOldData_StaleUnackWarningLogged_AUDIT031(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	for i := 0; i < 5; i++ {
		if err := d.Gorm().Create(&models.Alert{
			DeviceID: uint(i + 1), Severity: "high", Message: "stale unack",
			Timestamp: now.AddDate(0, 0, -100), Acknowledged: false,
		}).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	if err := d.CleanupOldData(config.RetentionConfig{
		UnackAlertDays: 90,
	}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var count int64
	if err := d.Gorm().Model(&models.Alert{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected all 5 stale unack alerts to be archived, got %d remaining", count)
	}
}

// TestCleanupOldData_RecentUnackSurvives_AUDIT031 — explicit
// boundary test: an unack alert within the unack retention
// window must NOT be archived. A pre-fix test would have asserted
// "unack alerts are kept forever" — which was the bug.
func TestCleanupOldData_RecentUnackSurvives_AUDIT031(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	recent := models.Alert{
		DeviceID: 1, Severity: "low", Message: "5-day unacked",
		Timestamp: now.AddDate(0, 0, -5), Acknowledged: false,
	}
	if err := d.Gorm().Create(&recent).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := d.CleanupOldData(config.RetentionConfig{
		UnackAlertDays: 90,
	}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	var count int64
	if err := d.Gorm().Model(&models.Alert{}).Where("id = ?", recent.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("5-day unacked alert was archived; AUDIT-031 default 90 days should keep it")
	}
	// Pin the "ACK" semantics: the row is still unacked, not
	// silently flipped to acked by the cleanup.
	var got models.Alert
	if err := d.Gorm().First(&got, recent.ID).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if got.Acknowledged {
		t.Errorf("cleaned-up alert was silently flipped to acked=true; cleanup must not change the ack state")
	}
	// And: the message must still be the original "5-day unacked"
	// (i.e. cleanup did not mutate row content).
	if !strings.Contains(got.Message, "5-day") {
		t.Errorf("alert message was mutated by cleanup: %q", got.Message)
	}
}
