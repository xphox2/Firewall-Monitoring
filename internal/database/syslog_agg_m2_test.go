package database

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestAggregateSyslogToSummary_NoGroupLoss_M2 is the regression for the
// 2026-06-23 audit M2 finding: aggregateSyslogToSummary deleted ALL matching raw
// rows inside each page's transaction, so the moment page 1 committed it wiped
// every still-un-summarized group — any distinct groups beyond the first page
// were silently dropped without being counted. With the delete moved to after
// the loop, every group is summarized regardless of how many pages it spans.
func TestAggregateSyslogToSummary_NoGroupLoss_M2(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Force the multi-page path: tiny page size with more distinct groups than
	// one page holds. Pre-fix, page 1 would summarize 2 groups then delete all 5
	// groups' raw rows, losing 3.
	orig := syslogAggPageSize
	syslogAggPageSize = 2
	defer func() { syslogAggPageSize = orig }()

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := cutoff.Add(-2 * time.Hour)
	const groups = 5
	for i := 0; i < groups; i++ {
		// Distinct app_name → distinct group; severity 6 = informational.
		if err := d.db.Create(&models.SyslogMessage{
			DeviceID: 1, Severity: 6, AppName: fmt.Sprintf("app%d", i),
			Timestamp: old, Message: "info",
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

	// Every group must be summarized (pre-fix: only the first page = 2).
	var summaries []models.SyslogSummary
	d.db.Find(&summaries)
	if len(summaries) != groups {
		t.Errorf("summary rows = %d, want %d (groups beyond page 1 were silently dropped)", len(summaries), groups)
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
