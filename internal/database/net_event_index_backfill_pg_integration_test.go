//go:build integration

// The v0.11.321 boot-path fix on a real PostgreSQL: EnsurePartitions must not
// spend minutes backfilling missing indexes on PRE-EXISTING leaves before the
// HTTP server listens — that synchronous backfill is what blocked startup for
// ~11 minutes on the v0.11.320 deploy (106 net_events indexes v82 left behind).
// It still builds indexes promptly for leaves it creates, and the daily cron
// pass backfills the rest, bounded per run and resumed across passes.
package database

import (
	"fmt"
	"testing"
	"time"
)

// TestEnsurePartitionsBootSkipsPreExistingLeafBackfill_PG: a pre-existing leaf
// missing its v82 indexes is left alone by the boot-time EnsurePartitions (no
// synchronous backfill), while a NEW leaf still gets its indexes immediately and
// the cron pass backfills the pre-existing leaf.
func TestEnsurePartitionsBootSkipsPreExistingLeafBackfill_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	d.netEventRetentionDays = 30
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions (fresh): %v", err)
	}
	today := utcDay(time.Now())
	leaf := "net_events_" + today.Format("20060102")

	// Simulate the incident: a pre-existing leaf missing its v82 indexes (what
	// the 90s migration deadline left for the partition pass).
	for _, ix := range netEventsReaddedLeafIndexes {
		if err := d.db.Exec(fmt.Sprintf(`DROP INDEX IF EXISTS idx_%s_%s`, leaf, ix.suffix)).Error; err != nil {
			t.Fatalf("drop %s: %v", ix.suffix, err)
		}
	}

	// Boot path: must NOT rebuild them synchronously on the pre-existing leaf.
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions (boot, pre-existing leaf): %v", err)
	}
	if idx := childNonUniqueIndexCols(t, d, leaf); hasReaddedLeafIndex(idx, leaf) {
		t.Errorf("boot EnsurePartitions rebuilt the v82 indexes on a pre-existing leaf (the ~11-minute startup block); indexes present: %v", idx)
	}

	// A NEW leaf still gets its indexes promptly at boot (requirement (a)).
	lost := "net_events_" + today.AddDate(0, 0, 2).Format("20060102")
	if err := d.db.Exec(`DROP TABLE ` + lost).Error; err != nil {
		t.Fatalf("drop %s: %v", lost, err)
	}
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions (boot, recreate %s): %v", lost, err)
	}
	if !contains(pgLeaves(t, d, "net_events"), lost) {
		t.Fatalf("%s was not recreated", lost)
	}
	assertReaddedLeafIndexes(t, d, lost)

	// The cron pass backfills the pre-existing leaf (idempotent).
	if err := d.EnsurePartitionsForCron(); err != nil {
		t.Fatalf("EnsurePartitionsForCron: %v", err)
	}
	assertReaddedLeafIndexes(t, d, leaf)
}

// TestEnsurePartitionsCronBackfillIsBounded_PG: the cron pass's index backfill
// is bounded by cronIndexBackfillDeadline and resumes on the next pass — a
// deadline already elapsed when the pass starts builds nothing, and the next
// pass (deadline restored) finishes the backlog.
func TestEnsurePartitionsCronBackfillIsBounded_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	d.netEventRetentionDays = 30
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions (fresh): %v", err)
	}
	today := utcDay(time.Now())
	leaf := "net_events_" + today.Format("20060102")
	for _, ix := range netEventsReaddedLeafIndexes {
		if err := d.db.Exec(fmt.Sprintf(`DROP INDEX IF EXISTS idx_%s_%s`, leaf, ix.suffix)).Error; err != nil {
			t.Fatalf("drop %s: %v", ix.suffix, err)
		}
	}

	// A deadline already past: the pass must build nothing, not one index.
	orig := cronIndexBackfillDeadline
	cronIndexBackfillDeadline = time.Nanosecond
	defer func() { cronIndexBackfillDeadline = orig }()
	if err := d.EnsurePartitionsForCron(); err != nil {
		t.Fatalf("EnsurePartitionsForCron (deadline already passed): %v", err)
	}
	if idx := childNonUniqueIndexCols(t, d, leaf); hasReaddedLeafIndex(idx, leaf) {
		t.Errorf("cron pass with an elapsed deadline still backfilled %s: %v", leaf, idx)
	}

	// Deadline restored: the next pass resumes and finishes the backlog.
	cronIndexBackfillDeadline = orig
	if err := d.EnsurePartitionsForCron(); err != nil {
		t.Fatalf("EnsurePartitionsForCron (resume): %v", err)
	}
	assertReaddedLeafIndexes(t, d, leaf)
}

// hasReaddedLeafIndex reports whether leaf carries any of the three v82 indexes.
func hasReaddedLeafIndex(idx map[string][]string, leaf string) bool {
	for _, ix := range netEventsReaddedLeafIndexes {
		if _, ok := idx["idx_"+leaf+"_"+ix.suffix]; ok {
			return true
		}
	}
	return false
}
