//go:build integration

// Migration v82 on a real PostgreSQL: the three net_events leaf indexes the
// Events page reads come back on every existing leaf, the DEFAULT child and a
// leaf left standalone mid-move; a NEW leaf created by EnsurePartitions gets
// them from the tags; a re-run is idempotent; and a src_ip/rule_key filter
// plans on the new indexes.
package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

// assertReaddedLeafIndexes fails unless leaf carries each of the three v82
// indexes (as a column list — (rule_key, ts), (src_ip, ts), (dst_ip, ts)).
func assertReaddedLeafIndexes(t *testing.T, d *Database, leaf string) {
	t.Helper()
	idx := childNonUniqueIndexCols(t, d, leaf)
	for _, ix := range netEventsReaddedLeafIndexes {
		want := strings.Join(ix.cols, ",")
		found := false
		for _, cols := range idx {
			if joinCols(cols) == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s lacks the (%s) index; has %v", leaf, want, idx)
		}
	}
}

// TestReaddNetEventIndexes_PG: a post-v80 install — the three indexes dropped
// from every leaf, the DEFAULT child and a standalone leaf left mid-move. v82
// rebuilds them all, a re-run finds nothing missing, and a NEW leaf created by
// EnsurePartitions carries them from the model tags.
func TestReaddNetEventIndexes_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	d.netEventRetentionDays = 30
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := d.db.Exec(q, args...).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	today := utcDay(time.Now())
	stray := "net_events_" + today.AddDate(0, 0, -60).Format("20060102") // standalone, mid-move
	exec(fmt.Sprintf(`CREATE TABLE %s (LIKE net_events INCLUDING DEFAULTS)`, stray))
	children := append(pgLeaves(t, d, "net_events"), stray)

	// The pre-v82 shape: v80 dropped the three indexes from every leaf.
	for _, leaf := range children {
		for _, ix := range netEventsReaddedLeafIndexes {
			exec(fmt.Sprintf(`DROP INDEX IF EXISTS idx_%s_%s`, leaf, ix.suffix))
		}
	}

	// A few rows so the builds index real data.
	exec(`INSERT INTO net_events (ts, device_id, probe_id, activity, action, raw_id, raw_ts, rule_key, src_ip, dst_ip)
		SELECT ?::timestamptz + g * interval '1 second', 1, 1, 1, 1, g, ?::timestamptz + g * interval '1 second',
		       'i:' || (g % 10), ('198.51.100.' || (g % 250))::inet, ('203.0.113.' || (g % 200))::inet
		FROM generate_series(1, 5000) g`, today.Add(6*time.Hour), today.Add(6*time.Hour))
	exec(`ANALYZE net_events`)

	if err := d.migrateReaddNetEventIndexes(); err != nil {
		t.Fatalf("v82: %v", err)
	}
	for _, leaf := range children {
		assertReaddedLeafIndexes(t, d, leaf)
	}

	// Idempotent: a re-run finds nothing missing and builds nothing.
	if err := d.migrateReaddNetEventIndexes(); err != nil {
		t.Fatalf("v82 re-run: %v", err)
	}
	for _, leaf := range children {
		assertReaddedLeafIndexes(t, d, leaf)
	}

	// A NEW leaf created by EnsurePartitions gets them from the tags: drop a
	// leaf, let the pass recreate it, and the three indexes are back.
	lost := "net_events_" + today.AddDate(0, 0, 2).Format("20060102")
	exec(`DROP TABLE ` + lost)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions (recreate %s): %v", lost, err)
	}
	if !contains(pgLeaves(t, d, "net_events"), lost) {
		t.Fatalf("%s was not recreated", lost)
	}
	assertReaddedLeafIndexes(t, d, lost)
}

// explainNoSeqScan EXPLAINs sql on a throwaway pooled connection with
// enable_seqscan off, so a selective equality cannot fall back to a seq scan —
// proving the (src_ip, ts) / (rule_key, ts) btree indexes exist and are usable.
// Returns the plan nodes (type, relation, index), one per line.
func explainNoSeqScan(t *testing.T, d *Database, label, sql string, args ...any) string {
	t.Helper()
	ctx := context.Background()
	conn, err := d.pgxPool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire conn: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SET enable_seqscan = off"); err != nil {
		t.Fatalf("set enable_seqscan: %v", err)
	}
	var raw string
	if err := conn.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+sql, args...).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN %s: %v\n%s", label, err, sql)
	}
	var top []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(raw), &top); err != nil || len(top) != 1 {
		t.Fatalf("EXPLAIN %s JSON: %v", label, err)
	}
	var b strings.Builder
	var walk func(n planNode, depth int)
	walk = func(n planNode, depth int) {
		fmt.Fprintf(&b, "%s%s %s %s\n", strings.Repeat("  ", depth), n.Type, n.Relation, n.Index)
		for _, c := range n.Plans {
			walk(c, depth+1)
		}
	}
	walk(top[0].Plan, 0)
	return b.String()
}

// TestReaddNetEventIndexes_PlanUsesIndexes_PG: with seq scans disabled, a
// src_ip = … / rule_key = … filter on a seeded leaf plans on the new indexes
// rather than a whole-table scan.
func TestReaddNetEventIndexes_PlanUsesIndexes_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	d.netEventRetentionDays = 30
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	today := utcDay(time.Now())
	if err := d.db.Exec(`INSERT INTO net_events (ts, device_id, probe_id, activity, action, raw_id, raw_ts, rule_key, src_ip, dst_ip)
		SELECT ?::timestamptz + g * interval '1 second', 1, 1, 1, 1, g, ?::timestamptz + g * interval '1 second',
		       'i:' || (g % 200), ('198.51.100.' || (g % 250))::inet, ('203.0.113.' || (g % 200))::inet
		FROM generate_series(1, 100000) g`, today.Add(6*time.Hour), today.Add(6*time.Hour)).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := d.db.Exec(`ANALYZE net_events`).Error; err != nil {
		t.Fatalf("analyze: %v", err)
	}

	cutoff := today.Add(5 * time.Hour)
	src := d.db.Session(&gorm.Session{DryRun: true}).Table("net_events").
		Where("ts >= ?", cutoff).Where("src_ip = ?::inet", "198.51.100.5").
		Order("ts DESC").Limit(100).Find(&[]NetEventRow{}).Statement
	plan := explainNoSeqScan(t, d, "src_ip =", src.SQL.String(), src.Vars...)
	if !strings.Contains(plan, "src_ip_ts") {
		t.Errorf("src_ip = filter did not use the (src_ip, ts) index:\n%s", plan)
	}

	rule := d.db.Session(&gorm.Session{DryRun: true}).Table("net_events").
		Where("ts >= ?", cutoff).Where("rule_key = ?", "i:1").
		Order("ts DESC").Limit(100).Find(&[]NetEventRow{}).Statement
	plan = explainNoSeqScan(t, d, "rule_key =", rule.SQL.String(), rule.Vars...)
	if !strings.Contains(plan, "rule_key_ts") {
		t.Errorf("rule_key = filter did not use the (rule_key, ts) index:\n%s", plan)
	}
}
