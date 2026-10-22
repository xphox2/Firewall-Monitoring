package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// A recurring window's stored end_time is only the FIRST occurrence's end.
// After that date passes it must still be returned to the policy cache and
// reported as active during later occurrences.
func TestMaintenanceRecurrence_StaysVisibleAfterFirstOccurrence(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	// Daily 09:00-11:00 analogue: start 25h ago, so today's occurrence began
	// an hour ago and the stored end_time (23h ago) is long past.
	start := now.Add(-25 * time.Hour)
	recurring := models.MaintenanceWindow{
		Name:      "nightly window",
		StartTime: start,
		EndTime:   start.Add(2 * time.Hour),
		Recurring: true,
		RecurRule: models.MaintenanceDaily,
	}
	pastOneOff := models.MaintenanceWindow{
		Name:      "past one-off",
		StartTime: now.Add(-48 * time.Hour),
		EndTime:   now.Add(-47 * time.Hour),
	}
	rows := []models.MaintenanceWindow{recurring, pastOneOff}
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	recurringID, oneOffID := rows[0].ID, rows[1].ID

	unexpired, err := d.GetUnexpiredMaintenanceWindows()
	if err != nil {
		t.Fatalf("GetUnexpiredMaintenanceWindows: %v", err)
	}
	foundRecurring := false
	for _, w := range unexpired {
		if w.ID == recurringID {
			foundRecurring = true
		}
		if w.ID == oneOffID {
			t.Errorf("past one-off returned to the policy cache: %+v", w)
		}
	}
	if !foundRecurring {
		t.Error("recurring window dropped from the cache after its first occurrence")
	}

	active, err := d.GetActiveMaintenanceWindows()
	if err != nil {
		t.Fatalf("GetActiveMaintenanceWindows: %v", err)
	}
	if len(active) != 1 || active[0].ID != recurringID {
		t.Fatalf("active = %+v, want just the recurring window", active)
	}
}
