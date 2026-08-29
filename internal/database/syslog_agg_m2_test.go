package database

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestAggregateSyslogToSummary_NoGroupLoss_M2 is the regression for the
// 2026-06-23 audit M2 finding: aggregateSyslogToSummary deleted ALL matching raw
// rows inside each internal unit's transaction, so the moment the first unit
// committed it wiped every still-un-summarized group — any distinct groups
// beyond it were silently dropped without being counted. The internal unit was
// a LIMIT/OFFSET page then and is a time window now (AUDIT-204); the pinned
// outcome is the same either way: with the delete scoped to exactly what each
// unit summarised, every group is summarized regardless of how many units the
// pass spans.
func TestAggregateSyslogToSummary_NoGroupLoss_M2(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Force the multi-window path: 1h windows with the 5 groups seeded in 5
	// DIFFERENT hours, so the pass spans 5 windows. Pre-M2, the first unit
	// would summarize its groups then delete every group's raw rows.
	orig := syslogAggWindow
	syslogAggWindow = time.Hour
	defer func() { syslogAggWindow = orig }()

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	const groups = 5
	for i := 0; i < groups; i++ {
		// Distinct app_name → distinct group; severity 6 = informational;
		// each group in its own hour window.
		if err := d.db.Create(&models.SyslogMessage{
			DeviceID: 1, Severity: 6, AppName: fmt.Sprintf("app%d", i),
			Timestamp: cutoff.Add(-time.Duration(i+2) * time.Hour), Message: "info",
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	ok, err := d.aggregateSyslogToSummary(cutoff, 6, "1h")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !ok {
		t.Fatal("expected work to be done")
	}

	// Every group must be summarized (pre-fix: only the first unit's).
	var summaries []models.SyslogSummary
	d.db.Find(&summaries)
	if len(summaries) != groups {
		t.Errorf("summary rows = %d, want %d (groups beyond the first window were silently dropped)", len(summaries), groups)
	}
	var totalCounted int64
	for _, s := range summaries {
		totalCounted += s.Count
	}
	if totalCounted != groups {
		t.Errorf("summed message count = %d, want %d", totalCounted, groups)
	}

	// And the consumed raw informational rows are gone.
	var rawLeft int64
	d.db.Model(&models.SyslogMessage{}).Where("timestamp < ? AND severity >= 6", cutoff).Count(&rawLeft)
	if rawLeft != 0 {
		t.Errorf("raw informational rows left = %d, want 0", rawLeft)
	}
}
