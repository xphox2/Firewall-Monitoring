package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetUnacknowledgedAlerts_ExcludesActivelySnoozed (LC-10): the escalation
// engine's feed must skip alerts inside an active snooze window (the operator
// silenced them) while still returning expired-snooze and never-snoozed rows.
func TestGetUnacknowledgedAlerts_ExcludesActivelySnoozed(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	future := now.Add(2 * time.Hour)
	past := now.Add(-2 * time.Hour)

	rows := []models.Alert{
		{Timestamp: now.Add(-time.Hour), DeviceID: 1, AlertType: "CPU_HIGH", MetricName: "cpu_usage"},
		{Timestamp: now.Add(-time.Hour), DeviceID: 2, AlertType: "CPU_HIGH", MetricName: "cpu_usage", SnoozedUntil: &future},
		{Timestamp: now.Add(-time.Hour), DeviceID: 3, AlertType: "CPU_HIGH", MetricName: "cpu_usage", SnoozedUntil: &past},
	}
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := d.GetUnacknowledgedAlerts(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("GetUnacknowledgedAlerts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2 (actively-snoozed excluded, expired snooze included)", len(got))
	}
	for _, a := range got {
		if a.DeviceID == 2 {
			t.Fatalf("actively-snoozed alert (device 2) returned: %+v", a)
		}
	}
}

// TestGetUnexpiredMaintenanceWindows (LC-9): the policy cache loads active AND
// future-scheduled windows (resolveAlertConfig re-checks start/end itself), so
// a window created before a process starts still suppresses when it begins;
// fully-past windows are excluded.
func TestGetUnexpiredMaintenanceWindows(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	rows := []models.MaintenanceWindow{
		{Name: "past", StartTime: now.Add(-3 * time.Hour), EndTime: now.Add(-2 * time.Hour)},
		{Name: "active", StartTime: now.Add(-time.Hour), EndTime: now.Add(time.Hour)},
		{Name: "future", StartTime: now.Add(2 * time.Hour), EndTime: now.Add(3 * time.Hour)},
	}
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := d.GetUnexpiredMaintenanceWindows()
	if err != nil {
		t.Fatalf("GetUnexpiredMaintenanceWindows: %v", err)
	}
	names := map[string]bool{}
	for _, w := range got {
		names[w.Name] = true
	}
	if len(got) != 2 || !names["active"] || !names["future"] {
		t.Fatalf("windows = %v, want exactly {active, future}", names)
	}

	// The UI's "active" endpoint keeps its stricter semantics.
	active, err := d.GetActiveMaintenanceWindows()
	if err != nil {
		t.Fatalf("GetActiveMaintenanceWindows: %v", err)
	}
	if len(active) != 1 || active[0].Name != "active" {
		t.Fatalf("active windows = %d, want just the currently-active one", len(active))
	}
}
