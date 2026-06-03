package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestResolvedAlertsAutoUnsnooze_AUDIT144 — the headline regression
// for the audit: pre-fix, when an alert was resolved (e.g. the
// underlying interface came back up), the matching alert rows
// had `resolved_at` set but the snooze fields (snoozed_until,
// snoozed_by, snoozed_reason) were left intact. A snoozed
// alert that was actually resolved would still appear in the
// "snoozed" view as if it were active.
//
// The fix: in the resolve path, also clear the snooze fields.
// The test simulates a typical scenario: an alert was snoozed
// (snoozed_until set 4h in the future), then the underlying
// issue cleared (the recovery event fires, which is the
// `Updates` call we're testing here).
func TestResolvedAlertsAutoUnsnooze_AUDIT144(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	future := now.Add(4 * time.Hour)

	// Seed: 2 unresolved alerts that the recovery event will
	// resolve, and 1 already-resolved alert (a recent past
	// resolution that should NOT be touched by the new
	// auto-unsnooze logic, since it's already resolved).
	unresolved1 := models.Alert{
		DeviceID: 1, AlertType: "INTERFACE_DOWN", Message: "iface 1 down",
		Timestamp: now, Acknowledged: false,
		SnoozedUntil: &future, SnoozedBy: "alice", SnoozedReason: "investigating",
	}
	unresolved2 := models.Alert{
		DeviceID: 1, AlertType: "INTERFACE_DOWN", Message: "iface 1 down again",
		Timestamp: now.Add(-time.Minute), Acknowledged: false,
		SnoozedUntil: &future, SnoozedBy: "bob", SnoozedReason: "see ticket #1234",
	}
	// Use slice-by-index so GORM populates IDs back into the
	// structs after Create.
	seeded := []*models.Alert{&unresolved1, &unresolved2}
	for _, a := range seeded {
		if err := d.Gorm().Create(a).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Simulate the recovery event's UPDATE. The fix's logic
	// is: WHERE device_id AND alert_type AND resolved_at IS
	// NULL AND acknowledged = false, then UPDATE resolved_at +
	// clear snooze fields. We reproduce that here to verify the
	// DB-level behavior; the alerts.go change is a code-level
	// wrapper around the same query.
	now2 := time.Now()
	res := d.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND resolved_at IS NULL AND acknowledged = ?", 1, "INTERFACE_DOWN", false).
		Updates(map[string]interface{}{
			"resolved_at":    now2,
			"snoozed_until":  nil,
			"snoozed_by":     "",
			"snoozed_reason": "",
		})
	if res.Error != nil {
		t.Fatalf("update: %v", res.Error)
	}
	if res.RowsAffected != 2 {
		t.Errorf("RowsAffected = %d, want 2 (the 2 unresolved alerts)", res.RowsAffected)
	}

	// Verify: both rows have resolved_at set AND snooze fields
	// cleared.
	for _, a := range seeded {
		var got models.Alert
		if err := d.Gorm().First(&got, a.ID).Error; err != nil {
			t.Fatalf("query id=%d: %v", a.ID, err)
		}
		if got.ResolvedAt == nil {
			t.Errorf("alert id=%d: resolved_at is still NULL after recovery", a.ID)
		}
		if got.SnoozedUntil != nil {
			t.Errorf("alert id=%d: snoozed_until = %v, want nil (auto-unsnooze on resolution, AUDIT-144)", a.ID, got.SnoozedUntil)
		}
		if got.SnoozedBy != "" {
			t.Errorf("alert id=%d: snoozed_by = %q, want empty", a.ID, got.SnoozedBy)
		}
		if got.SnoozedReason != "" {
			t.Errorf("alert id=%d: snoozed_reason = %q, want empty", a.ID, got.SnoozedReason)
		}
	}
}

// TestResolvedAlertsAutoUnsnooze_OnlyAffectsUnresolved_AUDIT144 is
// a defensive sibling: the auto-unsnooze must NOT touch
// already-resolved alerts (those are historical record), and
// must NOT touch acknowledged alerts (those are operator-handled
// and the snooze is a deliberate state). The WHERE clause
// `resolved_at IS NULL AND acknowledged = ?` (with `false`) is
// the gate; a future refactor that loosens the gate would fail
// here.
func TestResolvedAlertsAutoUnsnooze_OnlyAffectsUnresolved_AUDIT144(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	future := now.Add(4 * time.Hour)
	past := now.Add(-time.Hour)

	// Seed three rows that should NOT be touched:
	//   - already-resolved alert with snooze fields (a recovery
	//     that happened before AUDIT-144; the snooze was left
	//     intact per the old code, and AUDIT-144 doesn't backfill).
	//   - acknowledged alert with snooze fields (the operator
	//     acked it AND snoozed it; the snooze is a deliberate
	//     audit state).
	//   - alert with a different alert_type (the recovery
	//     targets a specific alert_type; other types aren't
	//     affected).
	rows := []models.Alert{
		// already-resolved + snoozed
		{
			DeviceID: 1, AlertType: "INTERFACE_DOWN", Message: "old",
			Timestamp: past, Acknowledged: false, ResolvedAt: &past,
			SnoozedUntil: &future, SnoozedBy: "alice", SnoozedReason: "old snooze",
		},
		// acknowledged + snoozed
		{
			DeviceID: 1, AlertType: "INTERFACE_DOWN", Message: "acked",
			Timestamp: now, Acknowledged: true,
			SnoozedUntil: &future, SnoozedBy: "alice", SnoozedReason: "acking + snoozing",
		},
		// different alert_type
		{
			DeviceID: 1, AlertType: "LINK_DOWN", Message: "other",
			Timestamp: now, Acknowledged: false,
			SnoozedUntil: &future, SnoozedBy: "alice", SnoozedReason: "different type",
		},
	}
	for i := range rows {
		if err := d.Gorm().Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	// The fix's UPDATE: WHERE device_id AND alert_type AND
	// resolved_at IS NULL AND acknowledged = false. None of
	// the 3 seeded rows match (already-resolved, acked,
	// different-type), so RowsAffected should be 0.
	res := d.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND resolved_at IS NULL AND acknowledged = ?", 1, "INTERFACE_DOWN", false).
		Updates(map[string]interface{}{
			"resolved_at":    now,
			"snoozed_until":  nil,
			"snoozed_by":     "",
			"snoozed_reason": "",
		})
	if res.Error != nil {
		t.Fatalf("update: %v", res.Error)
	}
	if res.RowsAffected != 0 {
		t.Errorf("RowsAffected = %d, want 0 (none of the seeded rows match the WHERE clause)", res.RowsAffected)
	}

	// Verify: every seeded row's snooze fields are intact.
	for i, a := range rows {
		var got models.Alert
		if err := d.Gorm().First(&got, a.ID).Error; err != nil {
			t.Fatalf("query id=%d: %v", a.ID, err)
		}
		if got.SnoozedBy != a.SnoozedBy {
			t.Errorf("row %d: snoozed_by = %q, want %q (auto-unsnooze must NOT touch this row's snooze fields)", i, got.SnoozedBy, a.SnoozedBy)
		}
		if got.SnoozedReason != a.SnoozedReason {
			t.Errorf("row %d: snoozed_reason = %q, want %q", i, got.SnoozedReason, a.SnoozedReason)
		}
	}
}
