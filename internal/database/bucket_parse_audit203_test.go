package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// AUDIT-203 (2026-08-27 audit): batchInsertRollups and
// batchInsertSyslogSummaries discarded time.Parse's error on the bucket string
// (`ts, _ := time.Parse(...)`). A bucket/layout mismatch — a future TimeBucket
// format change, or a dialect branch drift — would silently commit year-0001
// rows in the SAME transaction that deletes the raw rows, and retention would
// then reap the mis-dated aggregates: aggregated history vanishing with no
// log. AUDIT-145 fixed the identical silent-zero on the READ path
// (charts.go); these pin the WRITE path. The inserters must now return a
// wrapped error, which rolls back the enclosing transaction and preserves the
// raw rows for the next cycle.

// garbageBucketDialect makes every bucket expression yield a constant that no
// time layout parses, simulating a bucket/layout drift at the aggregation
// level.
type garbageBucketDialect struct{ Dialect }

func (garbageBucketDialect) TimeBucket(unit, column string) string { return "'garbage'" }

func TestBatchInsertSyslogSummaries_BucketParseError_AUDIT203(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	err := batchInsertSyslogSummaries(d.db, []syslogSummaryRow{
		{Bucket: "not-a-time", DeviceID: 1, Severity: 6, Count: 1, SampleMessage: "m"},
	}, "1h", "2006-01-02 15:04")
	if err == nil {
		t.Fatal("batchInsertSyslogSummaries swallowed the bucket parse failure — a year-0001 summary would commit and retention would reap it")
	}
	if !strings.Contains(err.Error(), "parse bucket") {
		t.Errorf("error %q does not identify the bucket parse failure", err)
	}
	var n int64
	d.db.Model(&models.SyslogSummary{}).Count(&n)
	if n != 0 {
		t.Errorf("summary rows = %d, want 0 — nothing may commit on a parse failure", n)
	}
}

func TestBatchInsertRollups_BucketParseError_AUDIT203(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	err := batchInsertRollups(d.db, []rollupRow{
		{Bucket: "not-a-time", DeviceID: 1, SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", BytesSum: 1, FlowCount: 1},
	}, "5m", "2006-01-02 15:04")
	if err == nil {
		t.Fatal("batchInsertRollups swallowed the bucket parse failure — a year-0001 rollup would commit and retention would reap it")
	}
	if !strings.Contains(err.Error(), "parse bucket") {
		t.Errorf("error %q does not identify the bucket parse failure", err)
	}
	var n int64
	d.db.Model(&models.FlowRollup{}).Count(&n)
	if n != 0 {
		t.Errorf("rollup rows = %d, want 0 — nothing may commit on a parse failure", n)
	}
}

// TestSyslogAggregation_BucketParseFailurePreservesRaw_AUDIT203 pins the
// failure at the aggregation level: with a drifted bucket expression the cycle
// must return an error, and the raw rows must SURVIVE (the pre-fix code
// committed mis-dated summaries and deleted the raw rows in the same
// transaction).
func TestSyslogAggregation_BucketParseFailurePreservesRaw_AUDIT203(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.SyslogMessage{}, &models.SyslogSummary{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	d.dialect = garbageBucketDialect{d.dialect}

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	seed(t, d, 1, 6, cutoff.Add(-2*time.Hour), "eligible")

	_, err := d.aggregateSyslogToSummary(cutoff, 6, "1h")
	if err == nil {
		t.Fatal("aggregateSyslogToSummary succeeded with an unparseable bucket — history would be silently mis-dated")
	}

	var raw, summaries int64
	d.db.Model(&models.SyslogMessage{}).Count(&raw)
	d.db.Model(&models.SyslogSummary{}).Count(&summaries)
	if raw != 1 {
		t.Errorf("raw rows = %d, want 1 — the failed cycle must preserve the raw rows", raw)
	}
	if summaries != 0 {
		t.Errorf("summary rows = %d, want 0 — the failed window must roll back its inserts", summaries)
	}
}

// TestFlowRollup_BucketParseFailurePreservesRaw_AUDIT203 is the flow-side
// twin of the test above.
func TestFlowRollup_BucketParseFailurePreservesRaw_AUDIT203(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	d.dialect = garbageBucketDialect{d.dialect}

	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	seedFlow(t, d, cutoff.Add(-2*time.Hour), 1001, 500)

	if d.aggregateFlowsToRollup(cutoff, "5m") {
		t.Error("aggregateFlowsToRollup reported committed work with an unparseable bucket")
	}

	var raw, rollups int64
	d.db.Model(&models.FlowSample{}).Count(&raw)
	d.db.Model(&models.FlowRollup{}).Count(&rollups)
	if raw != 1 {
		t.Errorf("raw samples = %d, want 1 — the failed cycle must preserve the raw rows", raw)
	}
	if rollups != 0 {
		t.Errorf("rollup rows = %d, want 0 — the failed window must roll back its inserts", rollups)
	}
}
