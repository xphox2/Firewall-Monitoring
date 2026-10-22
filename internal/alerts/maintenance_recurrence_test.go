package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The manual check — "does a recurring window suppress during an occurrence?"
// — as a DB → policy-cache → resolver test. It seeds the window through the
// real database method, refreshes the cache exactly like the poller does, and
// reads the value the simulator's endpoint returns.
func TestEffectiveAlertConfig_RecurringMaintenanceFromDB(t *testing.T) {
	am, db := newTestManager(t)
	now := time.Now()

	// Daily, 2h: started 25h ago, so today's occurrence began an hour ago and
	// the stored first end_time is 23h in the past.
	start := now.Add(-25 * time.Hour)
	active := &models.MaintenanceWindow{
		Name:        "daily window",
		StartTime:   start,
		EndTime:     start.Add(2 * time.Hour),
		Recurring:   true,
		RecurRule:   models.MaintenanceDaily,
		SuppressAll: true,
	}
	if err := db.CreateMaintenanceWindow(active); err != nil {
		t.Fatalf("seed recurring window: %v", err)
	}

	// A daily window whose occurrence ended two hours ago (next one tomorrow).
	ended := &models.MaintenanceWindow{
		Name:        "ended window",
		StartTime:   now.Add(-3 * time.Hour),
		EndTime:     now.Add(-2 * time.Hour),
		Recurring:   true,
		RecurRule:   models.MaintenanceDaily,
		SuppressAll: true,
	}
	if err := db.CreateMaintenanceWindow(ended); err != nil {
		t.Fatalf("seed ended window: %v", err)
	}

	am.RefreshPolicyCache(db)

	resolved, _ := am.EffectiveAlertConfig(0, nil, "CPU_HIGH", "cpu_usage")
	if !resolved.InMaintenance {
		t.Fatalf("recurring occurrence did not suppress; cached windows=%+v", am.policyCache.windows)
	}

	// Removing the active window must clear the suppression even though the
	// other recurring window is still cached (it is outside its occurrence).
	if err := db.DeleteMaintenanceWindow(active.ID); err != nil {
		t.Fatalf("delete active window: %v", err)
	}
	am.RefreshPolicyCache(db)
	resolved, _ = am.EffectiveAlertConfig(0, nil, "CPU_HIGH", "cpu_usage")
	if resolved.InMaintenance {
		t.Error("ended occurrence must not suppress")
	}
}
