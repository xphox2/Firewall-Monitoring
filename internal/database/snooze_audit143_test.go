package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestSnoozeAlertsBulk_ByIDs_AUDIT143 — the headline regression
// for the audit: pre-fix, bulk-snooze didn't exist. Operators
// who wanted to snooze N alerts at once had to write a loop of
// `SnoozeAlert(id, ...)` calls (N round-trips to the DB, no
// atomicity). The fix: `SnoozeAlertsBulk` does it in a single
// UPDATE statement.
//
// The test seeds three un-snoozed alerts, calls
// `SnoozeAlertsBulk` with all three IDs, and asserts that every
// row was updated to the same `snoozed_until` value, with the
// audit fields (`snoozed_by`, `snoozed_reason`) populated.
func TestSnoozeAlertsBulk_ByIDs_AUDIT143(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	future := now.Add(4 * time.Hour)

	for i := uint(1); i <= 3; i++ {
		if err := d.Gorm().Create(&models.Alert{
			DeviceID: 1, Severity: "high", Message: "test",
			Timestamp: now,
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Use []*models.Alert slice-by-index to ensure GORM
	// populates the IDs back into the structs (so we can
	// collect them for the bulk call).
	seeded := []*models.Alert{
		{DeviceID: 1, Severity: "low", Message: "s1", Timestamp: now},
		{DeviceID: 1, Severity: "low", Message: "s2", Timestamp: now},
		{DeviceID: 1, Severity: "low", Message: "s3", Timestamp: now},
	}
	for _, a := range seeded {
		if err := d.Gorm().Create(a).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	ids := []uint{seeded[0].ID, seeded[1].ID, seeded[2].ID}

	affected, err := d.SnoozeAlertsBulk(ids, future, "tester", "audit-143")
	if err != nil {
		t.Fatalf("SnoozeAlertsBulk: %v", err)
	}
	if affected != 3 {
		t.Errorf("affected = %d, want 3 (one row per ID in the input slice)", affected)
	}

	for _, id := range ids {
		var got models.Alert
		if err := d.Gorm().First(&got, id).Error; err != nil {
			t.Fatalf("query id=%d: %v", id, err)
		}
		if got.SnoozedUntil == nil {
			t.Errorf("alert id=%d was not snoozed", id)
			continue
		}
		if !got.SnoozedUntil.Equal(future) {
			t.Errorf("alert id=%d snoozed_until = %v, want %v", id, got.SnoozedUntil, future)
		}
		if got.SnoozedBy != "tester" {
			t.Errorf("alert id=%d snoozed_by = %q, want \"tester\"", id, got.SnoozedBy)
		}
		if got.SnoozedReason != "audit-143" {
			t.Errorf("alert id=%d snoozed_reason = %q, want \"audit-143\"", id, got.SnoozedReason)
		}
	}
}

// TestSnoozeAlertsBulk_EmptyIDsIsNoOp_AUDIT143 — defensive
// sibling: an empty `ids` slice is a no-op (returns 0, no
// error), matching the AcknowledgeAlertsBulk behavior. A
// refactor that fails loudly on empty input would break the
// admin UI's "Select all N matching" flow when N is 0.
func TestSnoozeAlertsBulk_EmptyIDsIsNoOp_AUDIT143(t *testing.T) {
	d := NewDatabaseForTesting(t)
	affected, err := d.SnoozeAlertsBulk([]uint{}, time.Now().Add(time.Hour), "tester", "")
	if err != nil {
		t.Errorf("SnoozeAlertsBulk([]) returned err: %v", err)
	}
	if affected != 0 {
		t.Errorf("affected = %d, want 0 for empty input", affected)
	}
}

// TestSnoozeAlertsByFilter_AUDIT143 — the filter variant.
// Mirrors the AcknowledgeAlertsByFilter test shape: seed a
// mix of matching / non-matching alerts, call
// `SnoozeAlertsByFilter` with a filter, assert the right
// subset is snoozed.
func TestSnoozeAlertsByFilter_AUDIT143(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	future := now.Add(4 * time.Hour)

	// Seed: 3 high-severity on device 1, 2 low-severity on device 1.
	seeded := []models.Alert{
		{DeviceID: 1, Severity: "high", Message: "h1", Timestamp: now},
		{DeviceID: 1, Severity: "high", Message: "h2", Timestamp: now},
		{DeviceID: 1, Severity: "high", Message: "h3", Timestamp: now},
		{DeviceID: 1, Severity: "low", Message: "l1", Timestamp: now},
		{DeviceID: 1, Severity: "low", Message: "l2", Timestamp: now},
	}
	for i := range seeded {
		if err := d.Gorm().Create(&seeded[i]).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	filter := AlertFilter{DeviceID: 1, Severity: "high"}
	affected, err := d.SnoozeAlertsByFilter(filter, future, "tester", "audit-143")
	if err != nil {
		t.Fatalf("SnoozeAlertsByFilter: %v", err)
	}
	if affected != 3 {
		t.Errorf("affected = %d, want 3 (the 3 high-severity alerts on device 1)", affected)
	}

	// Verify: the 3 high-severity rows are snoozed, the 2 low
	// rows are not.
	for _, a := range seeded {
		var got models.Alert
		if err := d.Gorm().First(&got, a.ID).Error; err != nil {
			t.Fatalf("query id=%d: %v", a.ID, err)
		}
		wantSnoozed := a.Severity == "high"
		gotSnoozed := got.SnoozedUntil != nil
		if gotSnoozed != wantSnoozed {
			t.Errorf("alert id=%d (severity=%s): snoozed=%v, want %v", a.ID, a.Severity, gotSnoozed, wantSnoozed)
		}
	}
}
