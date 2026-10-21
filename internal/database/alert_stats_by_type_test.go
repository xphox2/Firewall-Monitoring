package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetAlertStatsByType_ScopesEverything pins the per-type trend contract:
// total, severity split, type split and the hourly series must all obey the
// alert_type predicate, while the unfiltered call still sees every type.
func TestGetAlertStatsByType_ScopesEverything(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	mk := func(alertType string, severity models.Severity, ts time.Time) {
		t.Helper()
		if err := db.Gorm().Create(&models.Alert{
			Timestamp: ts,
			AlertType: models.AlertType(alertType),
			Severity:  severity,
			Message:   alertType,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	mk("CPU_HIGH", models.Severity("warning"), now.Add(-2*time.Hour))
	mk("CPU_HIGH", models.Severity("critical"), now.Add(-90*time.Minute))
	mk("CPU_HIGH", models.Severity("warning"), now.Add(-30*time.Minute))
	mk("LINK_DOWN", models.Severity("critical"), now.Add(-time.Hour))
	mk("CPU_HIGH", models.Severity("warning"), now.Add(-48*time.Hour)) // outside 24h

	stats, err := db.GetAlertStatsByType(24, 0, "CPU_HIGH")
	if err != nil {
		t.Fatalf("GetAlertStatsByType: %v", err)
	}
	if stats.Total != 3 {
		t.Fatalf("total = %d, want 3", stats.Total)
	}
	sev := map[string]int64{}
	for _, row := range stats.BySeverity {
		sev[row.Key] = row.Count
	}
	if sev["warning"] != 2 || sev["critical"] != 1 {
		t.Fatalf("by_severity = %+v, want warning=2 critical=1", stats.BySeverity)
	}
	if len(stats.ByType) != 1 || stats.ByType[0].Key != "CPU_HIGH" || stats.ByType[0].Count != 3 {
		t.Fatalf("by_type = %+v, want only CPU_HIGH=3", stats.ByType)
	}
	var series int64
	for _, bucket := range stats.OverTime {
		series += bucket.Count
	}
	if series != 3 {
		t.Fatalf("over_time sums to %d, want 3 (%+v)", series, stats.OverTime)
	}

	all, err := db.GetAlertStats(24, 0)
	if err != nil {
		t.Fatalf("GetAlertStats: %v", err)
	}
	if all.Total != 4 {
		t.Fatalf("unfiltered total = %d, want 4 (three CPU + one LINK, old row excluded)", all.Total)
	}
}
