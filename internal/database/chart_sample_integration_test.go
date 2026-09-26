//go:build integration

// Only PostgreSQL runs the LATERAL form of the public-chart sampler, so this
// lane is its only proof: it must pick exactly the rows the portable form
// (which the SQLite tests pin) picks, and plan as one index probe per bucket.
// Both tables are monthly-partitioned parents on this fresh schema.
package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestChartSampleIntegration_LateralMatchesPortable(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	to := time.Now().Truncate(time.Second)
	from := to.Add(-10 * time.Hour)
	at := func(h, m int) time.Time { return from.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }

	var iface []models.InterfaceStats
	var status []models.SystemStatus
	add := func(ts time.Time) {
		iface = append(iface, models.InterfaceStats{DeviceID: 1, Index: 1, Name: "wan1", Timestamp: ts, InBytes: uint64(ts.Unix())})
		status = append(status, models.SystemStatus{DeviceID: 1, Timestamp: ts, CPUUsage: 1})
	}
	add(from.Add(-30 * time.Minute)) // outside
	add(at(0, 10))
	add(at(0, 40))
	add(at(2, 0)) // exactly on the edge after the empty bucket 1: belongs to bucket 2 only (PostgreSQL compares instants, so no DST hazard here)
	add(at(2, 30))
	add(at(2, 30)) // same-instant duplicate
	for h := 3; h <= 9; h++ {
		add(at(h, 30))
	}
	add(at(9, 30)) // duplicate at the newest instant
	if err := d.db.Create(&iface).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.db.Create(&status).Error; err != nil {
		t.Fatal(err)
	}
	// A production-density series (one row per 2.5 s, ~1,440 per bucket) on
	// interface 2 for the plan check below. On a sparse series a sort of the
	// bucket is genuinely cheaper and the planner picks it, so the check would
	// test the fixture, not the design.
	if err := d.db.Exec(`INSERT INTO interface_stats (device_id, "index", name, timestamp, in_bytes, out_bytes)
		SELECT 1, 2, 'lan1', ?::timestamptz + g * interval '2.5 seconds', g, g
		FROM generate_series(1, 14350) g`, from).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.db.Exec("ANALYZE interface_stats; ANALYZE system_status").Error; err != nil {
		t.Fatal(err)
	}

	step := to.Sub(from) / 10
	for _, spec := range []sampleSpec{
		{"interface_stats", `device_id = ? AND "index" = ?`, []interface{}{1, 1}},
		{"system_status", `device_id = ?`, []interface{}{1}},
	} {
		ids := func(sql string, args []interface{}) []uint {
			var rows []struct{ ID uint }
			if err := d.db.Raw(sql, args...).Scan(&rows).Error; err != nil {
				t.Fatalf("%s: %v", spec.table, err)
			}
			out := make([]uint, len(rows))
			for i, r := range rows {
				out[i] = r.ID
			}
			return out
		}
		lat := ids(lateralSampleSQL(spec, from, to, step, 10))
		port := ids(portableSampleSQL(spec, from, to, step, 10))
		if len(lat) != len(port) {
			t.Fatalf("%s: lateral %v vs portable %v", spec.table, lat, port)
		}
		for i := range lat {
			if lat[i] != port[i] {
				t.Fatalf("%s: lateral %v vs portable %v", spec.table, lat, port)
			}
		}
		if len(lat) != 10 { // 9 buckets with rows + the newest row, before the Go dedup
			t.Fatalf("%s: %d rows before dedup, want 10", spec.table, len(lat))
		}
	}

	got, err := d.SampleInterfaceStats(1, 1, from, to, 10)
	if err != nil || len(got) != 9 {
		t.Fatalf("SampleInterfaceStats: %d rows, err %v; want 9 after the same-instant dedup", len(got), err)
	}
	for i := 1; i < len(got); i++ {
		if !got[i].Timestamp.After(got[i-1].Timestamp) {
			t.Fatalf("points %d and %d are not strictly increasing in time", i-1, i)
		}
	}

	// One index probe per bucket at production density: the index supplies the
	// timestamp order, so under each probe's Limit there may be at most an
	// Incremental Sort for the id tiebreak (presorted on timestamp, reading only
	// the tied rows) — never a plain Sort of the whole bucket.
	sql, args := lateralSampleSQL(sampleSpec{"interface_stats", `device_id = ? AND "index" = ?`, []interface{}{1, 2}}, from, to, step, 10)
	rows, err := d.db.Raw("EXPLAIN (ANALYZE, BUFFERS, COSTS OFF) "+sql, args...).Rows()
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("explain rows: %v", err)
	}
	text := strings.Join(plan, "\n")
	// Which index wins (composite vs timestamp) is a production-scale choice —
	// on one small leaf the two tie — and is verified by the production EXPLAIN
	// (1,585 buffers at 1 year). What this lane can prove: every scan that runs
	// is an index scan, and each probe yields one row.
	if !strings.Contains(text, "rows=1 loops=10") {
		t.Fatalf("probes do not return one row each:\n%s", text)
	}
	for _, line := range plan {
		if strings.Contains(line, " on interface_stats_") && !strings.Contains(line, "(never executed)") {
			node := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "->"))
			if !strings.HasPrefix(node, "Index Scan") && !strings.HasPrefix(node, "Index Only Scan") {
				t.Fatalf("an executed scan is not an index scan: %q\n%s", node, text)
			}
		}
	}
	// Total reads stay a handful per probe; reading whole buckets of a dense
	// series would be hundreds of buffers.
	var hit int
	for _, line := range plan {
		if n, err := fmt.Sscanf(strings.TrimSpace(line), "Buffers: shared hit=%d", &hit); err == nil && n == 1 {
			break
		}
	}
	if hit == 0 || hit > 8*10 {
		t.Fatalf("top-level shared buffers = %d, want 1..80 for 10 probes:\n%s", hit, text)
	}
	// The root may be the outer ORDER BY's Sort over at most buckets+1 rows;
	// any other plain Sort would sit under a probe and sort its whole bucket.
	for i, line := range plan {
		if i > 0 && strings.Contains(line, "Sort (") && !strings.Contains(line, "Incremental Sort") {
			t.Fatalf("a plain Sort below the root — each bucket would be sorted in full:\n%s", text)
		}
	}
}
