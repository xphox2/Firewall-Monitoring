package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// The archive's verified-id retention gate (archive plan PR 5) on the SQLite
// lane: V's derivation, and that retention, the severity 6/7 aggregation and
// the flow rollup leave every raw row above V in place. The PostgreSQL lane
// (archive_gate_pg_integration_test.go) adds the partition drop, both table
// shapes and the plans. Synthetic fixtures only.

// gateChunk is one archive_chunks row of a test: (lo, hi] and a status.
type gateChunk struct {
	seq    int64
	lo, hi int64
	status string
}

// seedGateChunks writes chunks of table (one UTC day apart, all in the past).
func seedGateChunks(t *testing.T, d *Database, table string, cs ...gateChunk) {
	t.Helper()
	day := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range cs {
		start := day.AddDate(0, 0, int(c.seq))
		row := models.ArchiveChunk{SourceTable: table, Seq: c.seq, IDLo: c.lo, IDHi: c.hi, PeriodStart: start,
			PeriodEnd: start.Add(24 * time.Hour), Month: export.MonthOf(start), Status: c.status}
		if err := d.db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func gateVerifyAll(t *testing.T, d *Database, table string) {
	t.Helper()
	if err := d.db.Model(&models.ArchiveChunk{}).Where("table_name = ?", table).Update("status", models.ArchiveChunkVerified).Error; err != nil {
		t.Fatal(err)
	}
}

// TestArchiveTableProgress_RunStopsAtFirstBreak: V is the id_hi of the last
// chunk of the verified run from seq 1 / id 0. Any status other than verified,
// a missing seq, an id gap or a first chunk not starting at id 0 ends it.
func TestArchiveTableProgress_RunStopsAtFirstBreak(t *testing.T) {
	v := models.ArchiveChunkVerified
	for _, tc := range []struct {
		name   string
		chunks []gateChunk
		want   int64
	}{
		{"none", nil, 0},
		{"all verified", []gateChunk{{1, 0, 10, v}, {2, 10, 20, v}, {3, 20, 20, v}}, 20},
		{"needs_attention holds", []gateChunk{{1, 0, 10, v}, {2, 10, 20, models.ArchiveChunkNeedsAttention}, {3, 20, 30, v}}, 10},
		{"verifying holds", []gateChunk{{1, 0, 10, v}, {2, 10, 20, models.ArchiveChunkVerifying}, {3, 20, 30, v}}, 10},
		{"failed first", []gateChunk{{1, 0, 10, models.ArchiveChunkFailed}, {2, 10, 20, v}}, 0},
		{"seq gap", []gateChunk{{1, 0, 10, v}, {2, 10, 20, v}, {4, 20, 30, v}}, 20},
		{"id gap", []gateChunk{{1, 0, 10, v}, {2, 10, 20, v}, {3, 25, 30, v}}, 20},
		{"id overlap", []gateChunk{{1, 0, 10, v}, {2, 8, 20, v}}, 10},
		{"first not at id 0", []gateChunk{{1, 5, 10, v}, {2, 10, 20, v}}, 0},
		{"first not seq 1", []gateChunk{{2, 0, 10, v}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			seedGateChunks(t, d, export.TableSyslog, tc.chunks...)
			p, err := d.ArchiveTableProgress(context.Background(), export.TableSyslog)
			if err != nil {
				t.Fatal(err)
			}
			if p.VerifiedThroughID != tc.want || p.Chunks != (len(tc.chunks) > 0) {
				t.Fatalf("V = %d (chunks %v), want %d", p.VerifiedThroughID, p.Chunks, tc.want)
			}
		})
	}
}

// gateFixture seeds every gated table with 20 rows (ids 1..20): syslog
// alternating severity 3 / 6 (odd / even ids), 40 days old; flow_samples 3 h
// old (past the rollup's 1 h); flow_if_counters 40 days old.
func gateFixture(t *testing.T, d *Database) config.RetentionConfig {
	t.Helper()
	old := time.Now().Add(-40 * 24 * time.Hour)
	for i := 1; i <= 20; i++ {
		sev := 3
		if i%2 == 0 {
			sev = 6
		}
		if err := d.db.Create(&models.SyslogMessage{Timestamp: old.Add(time.Duration(i) * time.Second), DeviceID: 1, ProbeID: 1,
			Hostname: "fw-example-01", AppName: "traffic", Message: "srcip=192.0.2.10 dstip=198.51.100.7", Severity: sev}).Error; err != nil {
			t.Fatal(err)
		}
		if err := d.db.Create(&models.FlowSample{Timestamp: time.Now().Add(-3*time.Hour + time.Duration(i)*time.Second), DeviceID: 1, ProbeID: 1,
			SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7", DstPort: 443, Protocol: 6, Bytes: 1500, Packets: 1, SamplingRate: 1}).Error; err != nil {
			t.Fatal(err)
		}
		if err := d.db.Create(&models.FlowInterfaceCounter{Timestamp: old.Add(time.Duration(i) * time.Second), DeviceID: 1, ProbeID: 1,
			SamplerAddress: "192.0.2.1", IfIndex: uint32(i)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	return config.RetentionConfig{DefaultDays: 30, SyslogCriticalDays: 30, SyslogInfoDays: 7, FlowDays: 30}
}

func gateIDs(t *testing.T, d *Database, table string) []int64 {
	t.Helper()
	var ids []int64
	if err := d.db.Table(table).Order("id").Pluck("id", &ids).Error; err != nil {
		t.Fatal(err)
	}
	return ids
}

func idRange(lo, hi int64) []int64 {
	var out []int64
	for i := lo; i <= hi; i++ {
		out = append(out, i)
	}
	return out
}

func sameIDs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// runDeletePaths runs every gated path once: the 5-minute rollup tick (flow
// rollup, then the syslog aggregation) and the daily retention pass.
func runDeletePaths(t *testing.T, d *Database, ret config.RetentionConfig) {
	t.Helper()
	d.RunFlowRollupCycle()
	if err := d.RunSyslogAggregationCycle(ret); err != nil {
		t.Fatalf("aggregation: %v", err)
	}
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestArchiveGate_HoldsRowsAboveV: with both streams enabled, retention
// (syslog and flow_if_counters), the severity 6 aggregation and the flow
// rollup delete exactly the rows at or below each table's V, summarise /
// roll up only those, and leave the rest raw. Once the chunks verify, the
// next run takes the rest.
func TestArchiveGate_HoldsRowsAboveV(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true, Flows: true}
	ret := gateFixture(t, d)
	v := models.ArchiveChunkVerified
	// syslog V = 10 (chunk 3 verifying); flow_samples V = 8 (chunk 2
	// needs_attention); flow_if_counters V = 4 (seq 2 missing).
	seedGateChunks(t, d, export.TableSyslog, gateChunk{1, 0, 6, v}, gateChunk{2, 6, 10, v}, gateChunk{3, 10, 20, models.ArchiveChunkVerifying})
	seedGateChunks(t, d, export.TableFlows, gateChunk{1, 0, 8, v}, gateChunk{2, 8, 20, models.ArchiveChunkNeedsAttention})
	seedGateChunks(t, d, export.TableCounters, gateChunk{1, 0, 4, v}, gateChunk{3, 4, 20, v})

	runDeletePaths(t, d, ret)

	if got := gateIDs(t, d, "syslog_messages"); !sameIDs(got, idRange(11, 20)) {
		t.Errorf("syslog_messages ids %v, want 11..20 (V = 10: rows above it are neither deleted nor aggregated)", got)
	}
	var summarised int64
	d.db.Model(&models.SyslogSummary{}).Select("COALESCE(SUM(count), 0)").Scan(&summarised)
	if summarised != 5 {
		t.Errorf("summarised %d severity-6 rows, want 5 (ids 2, 4, 6, 8, 10)", summarised)
	}
	if got := gateIDs(t, d, "flow_samples"); !sameIDs(got, idRange(9, 20)) {
		t.Errorf("flow_samples ids %v, want 9..20 (V = 8)", got)
	}
	var rolled int64
	d.db.Model(&models.FlowRollup{}).Select("COALESCE(SUM(flow_count), 0)").Scan(&rolled)
	if rolled != 8 {
		t.Errorf("rolled up %d flow samples, want 8", rolled)
	}
	if got := gateIDs(t, d, "flow_if_counters"); !sameIDs(got, idRange(5, 20)) {
		t.Errorf("flow_if_counters ids %v, want 5..20 (V = 4: seq 2 is missing)", got)
	}

	// The archive catches up: every chunk verifies and the gap closes.
	for _, tb := range []string{export.TableSyslog, export.TableFlows, export.TableCounters} {
		gateVerifyAll(t, d, tb)
	}
	seedGateChunks(t, d, export.TableCounters, gateChunk{2, 4, 4, v})
	if err := d.db.Model(&models.ArchiveChunk{}).Where("table_name = ? AND seq = 3", export.TableCounters).Update("id_lo", 4).Error; err != nil {
		t.Fatal(err)
	}
	runDeletePaths(t, d, ret)
	for _, tb := range []string{"syslog_messages", "flow_samples", "flow_if_counters"} {
		if got := gateIDs(t, d, tb); len(got) != 0 {
			t.Errorf("%s after the archive caught up: ids %v left, want none", tb, got)
		}
	}
	d.db.Model(&models.SyslogSummary{}).Select("COALESCE(SUM(count), 0)").Scan(&summarised)
	d.db.Model(&models.FlowRollup{}).Select("COALESCE(SUM(flow_count), 0)").Scan(&rolled)
	if summarised != 10 || rolled != 20 {
		t.Errorf("after catching up: %d summarised, %d rolled up; want 10 and 20 (each row consumed exactly once)", summarised, rolled)
	}
}

// TestArchiveGate_OnlyEnabledStreamIsGated: syslog enabled, flows disabled —
// the flow tables are consumed as without the archive although their chunks
// would hold them, and syslog with no chunk at all keeps everything.
func TestArchiveGate_OnlyEnabledStreamIsGated(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true}
	ret := gateFixture(t, d)
	seedGateChunks(t, d, export.TableFlows, gateChunk{1, 0, 2, models.ArchiveChunkNeedsAttention})
	runDeletePaths(t, d, ret)
	if got := gateIDs(t, d, "syslog_messages"); len(got) != 20 {
		t.Errorf("syslog with no verified chunk: %d rows left, want all 20", len(got))
	}
	for _, tb := range []string{"flow_samples", "flow_if_counters"} {
		if got := gateIDs(t, d, tb); len(got) != 0 {
			t.Errorf("%s (flows disabled): ids %v left, want none", tb, got)
		}
	}
}

// TestArchiveGate_Override: an active override releases only its stream;
// an expired one, one ending more than 24 h ahead (not written by the
// route) and an unparseable one leave the gate on.
func TestArchiveGate_Override(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	for _, tc := range []struct {
		name  string
		value string
		open  bool
	}{
		{"active", now.Add(time.Hour).UTC().Format(time.RFC3339), true},
		{"24h exactly", now.Add(24 * time.Hour).UTC().Format(time.RFC3339), true},
		{"expired", now.Add(-time.Minute).UTC().Format(time.RFC3339), false},
		{"beyond 24h", now.Add(48 * time.Hour).UTC().Format(time.RFC3339), false},
		{"garbage", "tomorrow", false},
		{"cleared", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			d.archiveGateCfg = ArchiveGateConfig{Syslog: true, Flows: true}
			if err := d.UpsertSetting(&models.SystemSetting{Key: ArchiveGateOverrideKey(ArchiveGateSyslog), Value: tc.value}); err != nil {
				t.Fatal(err)
			}
			if g := d.archiveGate(ctx, export.TableSyslog); g.on == tc.open {
				t.Fatalf("syslog gate on = %v with override %q, want %v", g.on, tc.value, !tc.open)
			}
			if g := d.archiveGate(ctx, export.TableFlows); !g.on || g.v != 0 {
				t.Fatalf("flows gate %+v: a syslog override must not release it", g)
			}
		})
	}

	// Through the setter, end to end: released rows are deleted, the other
	// stream's are not, and re-engaging holds again.
	d := NewDatabaseForTesting(t)
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true, Flows: true}
	ret := gateFixture(t, d)
	if err := d.SetArchiveGateOverride(ArchiveGateSyslog, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if until, active := d.ArchiveGateOverride(ArchiveGateSyslog, now); !active || until.Before(now.Add(time.Hour)) {
		t.Fatalf("override read back: %s active %v", until, active)
	}
	runDeletePaths(t, d, ret)
	if got := gateIDs(t, d, "syslog_messages"); len(got) != 0 {
		t.Errorf("syslog under an override: %d rows left, want none", len(got))
	}
	if got := gateIDs(t, d, "flow_samples"); len(got) != 20 {
		t.Errorf("flow_samples: %d rows left, want all 20 (no flows override)", len(got))
	}
	if err := d.SetArchiveGateOverride(ArchiveGateSyslog, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, active := d.ArchiveGateOverride(ArchiveGateSyslog, now); active {
		t.Fatal("override still active after clearing")
	}
	if err := d.SetArchiveGateOverride("bogus", now.Add(time.Hour)); err == nil {
		t.Fatal("an unknown stream was accepted")
	}
}

// TestResetArchiveChunk: only a needs_attention chunk is reset (to pending,
// counters cleared, attempts kept); anything else is refused unchanged.
func TestResetArchiveChunk(t *testing.T) {
	d := NewDatabaseForTesting(t)
	ctx := context.Background()
	seedGateChunks(t, d, export.TableSyslog, gateChunk{1, 0, 10, models.ArchiveChunkVerified}, gateChunk{2, 10, 20, models.ArchiveChunkNeedsAttention})
	var parked models.ArchiveChunk
	d.db.Where("seq = 2").First(&parked)
	d.db.Model(&parked).Updates(map[string]interface{}{"mismatches": 3, "verify_failures": 2, "attempts": 4, "runner_id": "w1", "error": "sha mismatch"})

	list, err := d.ListArchiveChunksNeedingAttention(10)
	if err != nil || len(list) != 1 || list[0].ID != parked.ID {
		t.Fatalf("needs attention: %v %v", list, err)
	}
	if p, _ := d.ArchiveTableProgress(ctx, export.TableSyslog); p.VerifiedThroughID != 10 {
		t.Fatalf("V = %d before the reset, want 10", p.VerifiedThroughID)
	}
	got, err := d.ResetArchiveChunk(ctx, parked.ID, "reset by alice: bucket fixed", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.ArchiveChunkPending || got.Mismatches != 0 || got.VerifyFailures != 0 || got.Attempts != 4 ||
		got.RunnerID != "" || got.Error != "reset by alice: bucket fixed" {
		t.Fatalf("after reset: %+v", got)
	}
	if next, err := d.NextArchiveChunk(ctx, export.TableSyslog, time.Now()); err != nil || next == nil || next.ID != parked.ID {
		t.Fatalf("the worker's next chunk is %+v (%v), want the reset one", next, err)
	}
	if _, err := d.ResetArchiveChunk(ctx, parked.ID, "again", time.Now()); !errors.Is(err, ErrArchiveChunkNotParked) {
		t.Fatalf("second reset: %v, want ErrArchiveChunkNotParked", err)
	}
	var verified models.ArchiveChunk
	d.db.Where("seq = 1").First(&verified)
	if c, err := d.ResetArchiveChunk(ctx, verified.ID, "x", time.Now()); !errors.Is(err, ErrArchiveChunkNotParked) || c.Status != models.ArchiveChunkVerified {
		t.Fatalf("reset of a verified chunk: %v (%+v)", err, c)
	}
	if _, err := d.ResetArchiveChunk(ctx, 99999, "x", time.Now()); err == nil {
		t.Fatal("reset of an unknown chunk succeeded")
	}
}

func TestParseArchiveGateStreams(t *testing.T) {
	for in, want := range map[string]int{"syslog": 1, "flows": 1, "ALL": 2, " all ": 2} {
		if got, err := ParseArchiveGateStreams(in); err != nil || len(got) != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "sflow", "netflow", "syslog,flows"} {
		if _, err := ParseArchiveGateStreams(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// TestArchiveGate_ReReadPerBatch: an override that ends in the middle of a
// retention pass stops the ungated deletes at the next batch — the gate is
// read before every batch, not once per pass.
func TestArchiveGate_ReReadPerBatch(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true}
	gateFixture(t, d)
	start := time.Now()
	if err := d.SetArchiveGateOverride(ArchiveGateSyslog, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	origBatch, origSleep, origClock := cleanupDeleteBatchSize, batchDeleteInterSleep, archiveGateClock
	cleanupDeleteBatchSize, batchDeleteInterSleep = 4, 0
	clock := start
	archiveGateClock = func() time.Time { return clock }
	calls := 0
	cleanupBatchHook = func(int) error {
		calls++
		if calls == 1 {
			clock = start.Add(2 * time.Hour) // the override ends during batch 1
		}
		return nil
	}
	t.Cleanup(func() {
		cleanupDeleteBatchSize, batchDeleteInterSleep, archiveGateClock, cleanupBatchHook = origBatch, origSleep, origClock, nil
	})
	if err := d.batchedDeleteOlderThanGated(&models.SyslogMessage{}, "syslog_messages", time.Now(), d.archiveGateFn("syslog_messages"), ""); err != nil {
		t.Fatal(err)
	}
	if got := gateIDs(t, d, "syslog_messages"); !sameIDs(got, idRange(5, 20)) {
		t.Fatalf("syslog ids %v after the override ended mid-pass, want 5..20 (one released batch of 4, then gated with V = 0)", got)
	}
}
