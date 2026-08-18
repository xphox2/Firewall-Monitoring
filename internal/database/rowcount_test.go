package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestEstimateRowCount_FallsBackWithoutStatistics pins the contract that makes
// the estimate safe to display.
//
// estimateRowCount trades exactness for speed, which is only acceptable because
// it reports when it has nothing to offer. On SQLite there is no pg_class at
// all; on Postgres reltuples is -1 until the table is first analyzed (true of
// every table for a while after a dump/restore). Both must return ok=false so
// the caller counts exactly, because the alternative — the -1 clamped to 0 —
// renders as a confident "0 rows ingested" on the dashboard.
func TestEstimateRowCount_FallsBackWithoutStatistics(t *testing.T) {
	db := NewDatabaseForTesting(t)

	if _, ok := db.estimateRowCount("syslog_messages"); ok {
		t.Error("estimateRowCount reported ok on SQLite, which keeps no reltuples catalog — the caller would render a fabricated total instead of counting.")
	}
	// An unknown relation must not be reported as a real zero either.
	if _, ok := db.estimateRowCount("no_such_table"); ok {
		t.Error("estimateRowCount reported ok for a table that does not exist.")
	}
}

// TestGetTelemetryTotals_ExactWhenNotApproximated verifies the fallback is
// actually wired: with no statistics available the totals must be real counts
// and Approx must say so, otherwise the UI's "~" marker lies in the other
// direction.
func TestGetTelemetryTotals_ExactWhenNotApproximated(t *testing.T) {
	db := NewDatabaseForTesting(t)

	for i := 0; i < 3; i++ {
		if err := db.db.Create(&models.SyslogMessage{Message: "x"}).Error; err != nil {
			t.Fatalf("seed syslog: %v", err)
		}
	}

	totals, err := db.GetTelemetryTotals()
	if err != nil {
		t.Fatalf("GetTelemetryTotals: %v", err)
	}
	if totals.Approx {
		t.Error("Approx is true on SQLite, where every total was counted exactly — the UI would prefix exact figures with '~'.")
	}
	if totals.Syslog != 3 {
		t.Errorf("Syslog total = %d, want the exact 3 seeded rows", totals.Syslog)
	}
}
