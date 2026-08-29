package database

import (
	"reflect"
	"testing"
)

// AUDIT-174 (2026-08-27 audit): EnsurePartitions must not create a per-leaf
// index that a parent-level PARTITIONED index already provides. v54 creates
// idx_syslog_sev_ts on the syslog_messages PARENT and v57 creates
// idx_trap_events_timestamp on the trap_events PARENT; PostgreSQL cascades a
// parent index to every new leaf, so the plan's identically-columned entry
// (matched by name only via IF NOT EXISTS) built a second physically identical
// btree on every fresh-install monthly partition — double index write
// amplification and disk on the volume-dominant table, forever, invisible to
// the name-keyed integration check. These tests pin the pure filtering rule;
// the catalog plumbing is exercised by the PG integration suite
// (NoDuplicateChildIndexes_AUDIT174).

func TestPlanEntriesNotCoveredByParent_AUDIT174(t *testing.T) {
	plan := []partitionIndex{
		{suffix: "device_ts", cols: []string{"device_id", "timestamp"}},
		{suffix: "timestamp", cols: []string{"timestamp"}},
		{suffix: "probe_id", cols: []string{"probe_id"}},
		{suffix: "severity_timestamp", cols: []string{"severity", "timestamp"}},
	}

	t.Run("EqualColumnsAreSkipped", func(t *testing.T) {
		// The v54 shape: the parent carries (severity, timestamp).
		kept, skipped := planEntriesNotCoveredByParent(plan, [][]string{{"severity", "timestamp"}})
		if !reflect.DeepEqual(skipped, []string{"severity_timestamp"}) {
			t.Errorf("skipped = %v, want [severity_timestamp]", skipped)
		}
		for _, k := range kept {
			if k.suffix == "severity_timestamp" {
				t.Error("severity_timestamp survived the filter — every fresh-install leaf gets a duplicate (severity, timestamp) btree")
			}
		}
		// (timestamp) is NOT a leading prefix of (severity, timestamp): a btree
		// leading on severity cannot serve a bare timestamp range scan. It must
		// survive.
		if len(kept) != 3 {
			t.Errorf("kept %d entries, want 3 (device_ts, timestamp, probe_id): %+v", len(kept), kept)
		}
	})

	t.Run("PrefixIsCovered", func(t *testing.T) {
		// A hypothetical standalone (severity) entry is a leading prefix of the
		// parent's (severity, timestamp) — covered, skip it.
		p := []partitionIndex{{suffix: "severity", cols: []string{"severity"}}}
		kept, skipped := planEntriesNotCoveredByParent(p, [][]string{{"severity", "timestamp"}})
		if len(kept) != 0 || !reflect.DeepEqual(skipped, []string{"severity"}) {
			t.Errorf("kept=%+v skipped=%v, want the prefix-covered entry skipped", kept, skipped)
		}
	})

	t.Run("SuffixIsNotCovered", func(t *testing.T) {
		// (timestamp) against a parent (severity, timestamp): trailing columns
		// don't cover — the v57 trap_events shape in reverse.
		p := []partitionIndex{{suffix: "timestamp", cols: []string{"timestamp"}}}
		kept, skipped := planEntriesNotCoveredByParent(p, [][]string{{"severity", "timestamp"}})
		if len(kept) != 1 || len(skipped) != 0 {
			t.Errorf("kept=%+v skipped=%v, want the non-prefix entry kept", kept, skipped)
		}
	})

	t.Run("NoParentIndexesKeepsFullPlan", func(t *testing.T) {
		// Production today: plain heaps carry no partitioned parent indexes, and
		// denied_events (the one partitioned prod table) has none either — the
		// filter must be a no-op there.
		kept, skipped := planEntriesNotCoveredByParent(plan, nil)
		if !reflect.DeepEqual(kept, plan) || len(skipped) != 0 {
			t.Errorf("kept=%+v skipped=%v, want the plan unchanged with no parent indexes", kept, skipped)
		}
	})
}
