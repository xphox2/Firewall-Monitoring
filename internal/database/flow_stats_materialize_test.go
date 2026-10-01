package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// The materialized run (flow_stats_run.go) must produce exactly what the
// direct run produces, for every filter that triggers it. Fixture rows sit at
// mid-day offsets, never near a day chunk's edge or the window's start.

func seedFlowWeek(t *testing.T, d *Database) {
	t.Helper()
	now := time.Now()
	var rows []models.FlowRollup
	for day := 0; day < 7; day++ {
		tier := "1h"
		if day < 2 {
			tier = "5m"
		}
		ts := now.Add(-time.Duration(day*24+12) * time.Hour) // mid-day of chunk 6-day
		for i, c := range []struct {
			src, dst string
			port     uint16
			asn      uint32
			bytes    uint64
		}{
			{"10.0.0.1", "8.8.8.8", 443, 15169, 1000},
			{"10.0.0.1", "1.1.1.1", 53, 13335, 700},
			{"10.0.0.2", "8.8.8.8", 443, 15169, 400},
			{"10.0.1.9", "9.9.9.9", 853, 19281, 250},
			{"192.168.105.5", "10.0.0.1", 22, 0, 90},
		} {
			rows = append(rows, models.FlowRollup{
				Timestamp: ts.Add(time.Duration(i) * time.Minute), DeviceID: 1, IntervalType: tier,
				SrcAddr: c.src, DstAddr: c.dst, DstPort: c.port, Protocol: 6, DstASN: c.asn,
				BytesSum: c.bytes * uint64(day+1), PacketsSum: uint64(day + 1), FlowCount: int64(i + 1 + day),
				SamplingRateAvg: 1, DstCountry: "US", ScopeLocal: c.src == "192.168.105.5",
			})
		}
	}
	if err := d.db.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	raw := []models.FlowSample{{Timestamp: now.Add(-5 * time.Minute), DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Bytes: 111, Packets: 1}}
	if err := d.db.Create(&raw).Error; err != nil {
		t.Fatal(err)
	}
}

func flowStatsJSON(t *testing.T, d *Database, hours int, f FlowStatsFilter) string {
	t.Helper()
	res, err := d.GetFlowStats(hours, f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFlowStatsMaterialized_EqualsDirect(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFlowWeek(t, d)
	port := uint16(443)
	asn := uint32(15169)
	for _, tc := range []struct {
		name string
		f    FlowStatsFilter
	}{
		{"src", FlowStatsFilter{SrcAddr: "10.0.0.1"}},
		{"dst", FlowStatsFilter{DstAddr: "8.8.8.8"}},
		{"src cidr", FlowStatsFilter{SrcAddr: "10.0.0.0/24"}},
		{"port", FlowStatsFilter{DstPort: &port}},
		{"asn", FlowStatsFilter{DstASN: &asn}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !FlowStatsMaterializes(168, tc.f) {
				t.Fatal("this filter must take the materialized run")
			}
			flowStatsMaterialize = false
			direct := flowStatsJSON(t, d, 168, tc.f)
			flowStatsMaterialize = true
			mat := flowStatsJSON(t, d, 168, tc.f)
			if direct != mat {
				t.Fatalf("materialized differs from direct:\ndirect: %s\nmater.: %s", direct, mat)
			}
			if strings.Contains(mat, `"degraded":true`) {
				t.Fatalf("degraded result: %s", mat)
			}
			if !strings.Contains(mat, `"total_flows":`) || strings.Contains(mat, `"total_flows":0,`) {
				t.Fatalf("no rolled-up totals: %s", mat)
			}
		})
	}
	flowStatsMaterialize = true
}

func flowScopeTablesLeft(t *testing.T, d *Database) int64 {
	t.Helper()
	var n int64
	if err := d.db.Raw(`SELECT count(*) FROM sqlite_temp_master WHERE type='table' AND name LIKE 'flow_scope_%'`).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFlowStatsMaterialized_ProgressAndCleanup(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFlowWeek(t, d)
	var steps []FlowStatsProgress
	// A query that escaped the pinned connection would wait forever for the
	// harness's single connection; bound it so that fails here, fast.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := d.WithContext(ctx).GetFlowStatsOpts(168, FlowStatsFilter{SrcAddr: "10.0.0.1"}, FlowStatsOptions{
		Progress: func(p FlowStatsProgress) { steps = append(steps, p) },
	})
	if err != nil || res.Degraded {
		t.Fatalf("err %v degraded %v %v", err, res != nil && res.Degraded, res)
	}
	var labels []string
	for i, p := range steps {
		labels = append(labels, p.Label)
		if p.Done != i || p.Done >= p.Total {
			t.Fatalf("step %d = %+v: done must count up by one and stay below total", i, p)
		}
	}
	joined := strings.Join(labels, " | ")
	for i := 1; i <= 7; i++ {
		if !strings.Contains(joined, fmt.Sprintf("Reading day %d of 7", i)) {
			t.Fatalf("missing day %d: %s", i, joined)
		}
	}
	for _, want := range []string{"Reading recent samples", "Aggregating panels", "Top destinations", "Traffic over time"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q: %s", want, joined)
		}
	}
	last := steps[len(steps)-1]
	if last.Done != last.Total-1 {
		t.Fatalf("last step %+v: the total must be exact by the end", last)
	}
	if n := flowScopeTablesLeft(t, d); n != 0 {
		t.Fatalf("%d scope tables left behind", n)
	}
}

// Cancelled part-way through the scan: the run must stop, leave no scope table,
// and report every rolled-up panel as partial rather than feed them a
// partly-filled window.
func TestFlowStatsMaterialized_CancelMidScanNeverReportsPartialWindow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFlowWeek(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := d.WithContext(ctx).GetFlowStatsOpts(168, FlowStatsFilter{SrcAddr: "10.0.0.1"}, FlowStatsOptions{
		Progress: func(p FlowStatsProgress) {
			if p.Label == "Reading day 4 of 7" {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if !res.Degraded {
		t.Fatal("a cancelled scan must report degraded")
	}
	blocks := strings.Join(res.DegradedBlocks, ",")
	for _, b := range []string{"totals", "top_destinations", "bytes_over_time", "unique_src_addr"} {
		if !strings.Contains(blocks, b) {
			t.Fatalf("degraded blocks %q missing %s", blocks, b)
		}
	}
	if res.TotalFlows != 1 {
		t.Fatalf("total flows %d, want only the raw sample (1) — no partial rolled-up days", res.TotalFlows)
	}
	// The drop must succeed on its own (uncancelled) context. If it failed, the
	// connection would be discarded — and on the unit lane's in-memory SQLite
	// that throws the whole database away, which would make "no scope table"
	// true for the wrong reason. The seeded rows still being there proves the
	// connection was kept.
	var kept int64
	if err := d.db.Model(&models.FlowRollup{}).Count(&kept).Error; err != nil || kept == 0 {
		t.Fatalf("seeded rollups gone after cancel (%d, %v): the scope drop failed and the connection was discarded", kept, err)
	}
	if n := flowScopeTablesLeft(t, d); n != 0 {
		t.Fatalf("%d scope tables left behind after cancel", n)
	}
}

func TestFlowScopeName(t *testing.T) {
	a, err := newFlowScopeName()
	if err != nil || !flowScopeNameRE.MatchString(a) {
		t.Fatalf("%q %v", a, err)
	}
	if b, _ := newFlowScopeName(); a == b {
		t.Fatal("scope names must be unique per run")
	}
}

// With equal results either way, only the statements show whether the panels
// really read the scope table: in the materialized run flow_rollups may appear
// only in the scope table's creation and the day-chunk inserts.
func TestFlowStatsMaterialized_PanelsReadTheScopeTable(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFlowWeek(t, d)
	var rollupStmts []string
	capture := func(tx *gorm.DB) {
		// gorm renders a subquery argument by running it through the query
		// callbacks in dry-run mode; that is SQL text, not a read.
		if tx.DryRun || tx.Statement.DB.DryRun {
			return
		}
		if sql := tx.Statement.SQL.String(); strings.Contains(sql, "flow_rollups") {
			rollupStmts = append(rollupStmts, sql)
		}
	}
	for _, reg := range []func() error{
		func() error { return d.db.Callback().Query().After("gorm:query").Register("test:mat_q", capture) },
		func() error { return d.db.Callback().Row().After("gorm:row").Register("test:mat_r", capture) },
		func() error { return d.db.Callback().Raw().After("gorm:raw").Register("test:mat_x", capture) },
	} {
		if err := reg(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.GetFlowStats(168, FlowStatsFilter{SrcAddr: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	creates, inserts := 0, 0
	for _, s := range rollupStmts {
		switch {
		case strings.HasPrefix(s, "CREATE TEMP TABLE flow_scope_"):
			creates++
		case strings.HasPrefix(s, "INSERT INTO flow_scope_"):
			inserts++
		default:
			t.Fatalf("a panel read flow_rollups directly in the materialized run: %s", s)
		}
	}
	if creates != 1 || inserts != 7 {
		t.Fatalf("%d creates, %d inserts; want 1 and 7 (one per day)", creates, inserts)
	}
}

// A day whose INSERT hits the statement timeout is split in half and retried,
// so a slower system still finishes — with the same result as the direct run.
func TestFlowStatsMaterialized_SplitsAChunkThatTimesOut(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFlowWeek(t, d)
	var tried []time.Duration
	flowScopeChunkHook = func(a, b time.Time) error {
		tried = append(tried, b.Sub(a))
		if b.Sub(a) > 6*time.Hour {
			return &pgconn.PgError{Code: "57014", Message: "canceling statement due to statement timeout"}
		}
		return nil
	}
	defer func() { flowScopeChunkHook = nil }()

	flowStatsMaterialize = false
	direct := flowStatsJSON(t, d, 168, FlowStatsFilter{SrcAddr: "10.0.0.1"})
	flowStatsMaterialize = true
	mat := flowStatsJSON(t, d, 168, FlowStatsFilter{SrcAddr: "10.0.0.1"})
	if mat != direct {
		t.Fatalf("split run differs from direct:\ndirect: %s\nsplit:  %s", direct, mat)
	}
	var small int
	for _, d := range tried {
		if d <= 6*time.Hour {
			small++
		}
	}
	if small < 7*4 {
		t.Fatalf("each timed-out day must be split down to pieces under 6 h; got %d such pieces from %v", small, tried)
	}
}

// With LongRunning there is no overall deadline: the budget never skips a panel.
func TestFlowStatsBudget_ZeroAllowanceHasNoDeadline(t *testing.T) {
	if got := materializedAllowance(FlowStatsOptions{LongRunning: true}); got != 0 {
		t.Fatalf("the stream's allowance = %v, want none", got)
	}
	if got := materializedAllowance(FlowStatsOptions{}); got != flowStatsRollupBudget {
		t.Fatalf("the synchronous allowance = %v, want %v", got, flowStatsRollupBudget)
	}
	b := newFlowStatsBudget(context.Background(), 0)
	ctx, cancel, ok := b.context()
	defer cancel()
	if !ok {
		t.Fatal("a zero allowance must never be spent")
	}
	if _, has := ctx.Deadline(); has {
		t.Fatal("a zero allowance must carry no deadline")
	}
	parent, stop := context.WithCancel(context.Background())
	stop()
	if _, _, ok := newFlowStatsBudget(parent, 0).context(); ok {
		t.Fatal("a cancelled request must still stop the run")
	}
}

// A raw-only window (1 h) has no rolled-up panels; its progress must still end
// at an exact total, not two-thirds of the way along.
func TestFlowStats_RawOnlyProgressEndsExact(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFlowWeek(t, d)
	var last FlowStatsProgress
	if _, err := d.GetFlowStatsOpts(1, FlowStatsFilter{}, FlowStatsOptions{
		Progress: func(p FlowStatsProgress) { last = p },
	}); err != nil {
		t.Fatal(err)
	}
	if last.Done != last.Total-1 {
		t.Fatalf("last step %+v: the bar would stop short of the end", last)
	}
}
