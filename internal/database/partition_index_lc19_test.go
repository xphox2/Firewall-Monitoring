package database

import (
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

// LC-19 (2026-07-04 audit) drift guard: the per-partition index list used by
// EnsurePartitions must be DERIVED from the models' gorm index tags, and the
// derivation must cover every tag index. Pre-fix, EnsurePartitions carried a
// second hard-coded copy of the index list that had drifted — the AUDIT-034
// flow_samples src/dst indexes (and the probe_id / syslog_summaries indexes)
// were silently dropped on every fresh Postgres install, because the v2
// partition conversion recreates the parent with `INCLUDING DEFAULTS` only and
// the hard-coded list never re-created them.

// planCovers reports whether some planned index serves cols: either an exact
// match or a planned index that has cols as its leading prefix (a btree on
// (a, b) serves lookups on (a)).
func planCovers(plan []partitionIndex, cols []string) bool {
	for _, p := range plan {
		if isColPrefix(cols, p.cols) {
			return true
		}
	}
	return false
}

// TestPartitionIndexPlan_CoversAllModelTagIndexes_LC19 cross-checks the
// derived plan against an INDEPENDENT parse of each partitioned model's index
// tags: every non-unique, non-expression tag index must be covered by the
// plan. If someone adds a new `gorm:"index:..."` tag to a partitioned model,
// or reverts partitionIndexPlan to a hard-coded list that misses one, this
// fails.
func TestPartitionIndexPlan_CoversAllModelTagIndexes_LC19(t *testing.T) {
	var cache sync.Map
	for _, def := range partitionTables {
		model, ok := partitionModels[def.tableName]
		if !ok {
			t.Errorf("%s: partitioned table has no entry in partitionModels — its partitions would get no model-tag indexes", def.tableName)
			continue
		}
		plan, err := partitionIndexPlan(def)
		if err != nil {
			t.Fatalf("%s: partitionIndexPlan: %v", def.tableName, err)
		}

		// Baseline: every partitioned table's plan serves (device_id, ts) + (ts).
		for _, base := range [][]string{{"device_id", def.column}, {def.column}} {
			if !planCovers(plan, base) {
				t.Errorf("%s: plan lost the baseline index on (%s)", def.tableName, strings.Join(base, ", "))
			}
		}

		// Independent enumeration of the model's tag indexes.
		sch, err := schema.Parse(model, &cache, schema.NamingStrategy{IdentifierMaxLength: 64})
		if err != nil {
			t.Fatalf("%s: schema.Parse: %v", def.tableName, err)
		}
		for _, idx := range sch.ParseIndexes() {
			if idx.Class == "UNIQUE" {
				continue
			}
			var cols []string
			expr := false
			for _, f := range idx.Fields {
				if f.Expression != "" {
					expr = true
					break
				}
				cols = append(cols, f.DBName)
			}
			if expr || len(cols) == 0 {
				continue
			}
			if !planCovers(plan, cols) {
				t.Errorf("%s: model index %s (%s) is NOT covered by the per-partition plan — it would be silently dropped on every fresh PG install (the LC-19 drift)",
					def.tableName, idx.Name, strings.Join(cols, ", "))
			}
		}
	}

	// The reverse direction: partitionModels must not carry stale tables.
	for table := range partitionModels {
		found := false
		for _, def := range partitionTables {
			if def.tableName == table {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("partitionModels has %q but partitionTables does not — stale entry", table)
		}
	}
}

// TestPartitionIndexPlan_FlowSamplesAUDIT034_LC19 pins the concrete regression
// that motivated LC-19: the flow_samples plan must include the AUDIT-034
// src_addr / dst_addr indexes (which back the connection flow-stats
// `src_addr LIKE ?` queries) and the probe_id index. The sibling
// TestFlowSampleIndexes_AUDIT034 only checks the SQLite AutoMigrate path and
// can never catch the partition-recreation gap.
func TestPartitionIndexPlan_FlowSamplesAUDIT034_LC19(t *testing.T) {
	plan, err := partitionIndexPlan(partitionDef{"flow_samples", "timestamp"})
	if err != nil {
		t.Fatalf("partitionIndexPlan: %v", err)
	}
	for _, want := range []string{"src_addr", "dst_addr", "probe_id"} {
		if !planCovers(plan, []string{want}) {
			t.Errorf("flow_samples partition plan is missing the %s index (AUDIT-034 regression)", want)
		}
	}
}

// TestPartitionIndexSuffix_PinsLegacyNames_LC19 pins the per-partition index
// name suffixes for the indexes the pre-LC-19 code already created. If these
// change, `CREATE INDEX IF NOT EXISTS` would stop matching the indexes already
// present on existing deployments' partitions and build duplicates.
func TestPartitionIndexSuffix_PinsLegacyNames_LC19(t *testing.T) {
	cases := []struct {
		cols []string
		want string
	}{
		{[]string{"device_id", "timestamp"}, "device_ts"},
		{[]string{"timestamp"}, "timestamp"},
		{[]string{"device_id", "index", "timestamp"}, "device_idx_ts"},
		{[]string{"severity"}, "severity"},
		{[]string{"src_addr"}, "src_addr"},
	}
	for _, c := range cases {
		if got := partitionIndexSuffix(c.cols); got != c.want {
			t.Errorf("partitionIndexSuffix(%v) = %q, want %q", c.cols, got, c.want)
		}
	}
}
