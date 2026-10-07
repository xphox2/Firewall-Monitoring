package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// Settle latency, the live status of a settling chunk, and the current
// chunk's progress in the worker's snapshot. The settle check always passes
// on SQLite, so these tests stand in for it (Worker.settled); the PostgreSQL
// lane runs the real one (worker_pg_integration_test.go).

// settleUntil makes the settle check report "settling" until the worker's
// clock reaches at, then pass; calls counts the checks.
func settleUntil(h *harness, at time.Time, calls *int) {
	h.w.settled = func(_ context.Context, _ *models.ArchiveChunk) error {
		*calls++
		if left := at.Sub(h.clk.now()); left > 0 {
			return &database.ArchiveUnsettledError{SettleLeft: left}
		}
		return nil
	}
}

func runtimeOf(t *testing.T, h *harness) *status.Runtime {
	t.Helper()
	raw, ok, err := h.db.ArchiveWorkerState(ctx)
	if err != nil || !ok {
		t.Fatalf("no worker state: %v %v", ok, err)
	}
	rt, err := status.ParseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// TestWorker_SettlingChunkRetriedWhenWindowEnds: a chunk cut on a pass waits
// out its one-minute settle window and is exported on the first tick after
// it — not on the next pass, ten minutes later. While it waits the snapshot
// records the window's end (the status counts down from it) instead of a
// "time left" fixed when it was written, and no tick before the window's end
// runs the settle check again.
func TestWorker_SettlingChunkRetriedWhenWindowEnds(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0))
	start := h.clk.now()
	var checks int
	settleUntil(h, start.Add(time.Minute), &checks)

	h.w.Tick(ctx) // the first pass: plans 4 Oct; its cut settles for a minute
	if cs := h.chunks(export.TableSyslog); len(cs) != 1 || cs[0].Status != models.ArchiveChunkPending {
		t.Fatalf("after the first pass: %+v", cs)
	}
	rt := runtimeOf(t, h)
	tr := rt.Tables[export.TableSyslog]
	if tr.Reason != "settling" || tr.Until == nil || !tr.Until.Equal(start.Add(time.Minute).UTC()) || strings.Contains(tr.Detail, "left") {
		t.Fatalf("settling recorded as %+v, want the window's end and no time left in the detail", tr)
	}
	if rt.NextPassAt == nil || !rt.NextPassAt.Equal(start.Add(time.Minute).UTC()) {
		t.Fatalf("next pass %v, want the end of the settle window %v", rt.NextPassAt, start.Add(time.Minute))
	}

	h.clk.add(30 * time.Second)
	before := checks
	h.w.Tick(ctx) // still settling: not checked again
	if checks != before {
		t.Fatalf("a tick inside the settle window ran %d settle checks", checks-before)
	}
	h.clk.add(30 * time.Second)
	h.w.Tick(ctx) // the window has ended: exported now
	if cs := h.chunks(export.TableSyslog); cs[0].Status != models.ArchiveChunkVerified {
		t.Fatalf("one tick after the settle window the chunk is %s, want verified (not at the next pass)", cs[0].Status)
	}
	if rt := runtimeOf(t, h); rt.Tables[export.TableSyslog].Reason != "" || rt.Activity != nil {
		t.Fatalf("after the export: waits %+v, activity %+v", rt.Tables, rt.Activity)
	}
}

// TestWorker_OpenWriterRetriedEveryTick: a chunk held by an open writing
// transaction is checked on every tick (the writer may finish at any time)
// and exported on the first tick it is clear.
func TestWorker_OpenWriterRetriedEveryTick(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0))
	held := true
	var checks int
	h.w.settled = func(context.Context, *models.ArchiveChunk) error {
		checks++
		if held {
			return &database.ArchiveUnsettledError{GuardXmax: 900, Xmin: 800}
		}
		return nil
	}
	h.w.Tick(ctx)
	if rt := runtimeOf(t, h); rt.Tables[export.TableSyslog].Reason != "open_writer" {
		t.Fatalf("waits %+v, want open_writer", rt.Tables)
	}
	h.clk.add(TickInterval)
	before := checks
	h.w.Tick(ctx)
	if checks != before+1 {
		t.Fatalf("a tick ran %d settle checks of the held chunk, want 1", checks-before)
	}
	held = false
	h.clk.add(TickInterval)
	h.w.Tick(ctx)
	if cs := h.chunks(export.TableSyslog); cs[0].Status != models.ArchiveChunkVerified {
		t.Fatalf("the tick after the writer finished left the chunk %s", cs[0].Status)
	}
}

// TestWorker_ActivityProgress: the snapshot names the chunk being worked and
// how far it got — rows read during the export, objects and bytes during the
// upload and the read-back — and none once it is done.
func TestWorker_ActivityProgress(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	ids := seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0), day(10, 4, 3, 0))
	seen := map[string]status.Activity{}
	capture := func(name string) func(context.Context, *models.ArchiveChunk) error {
		return func(context.Context, *models.ArchiveChunk) error {
			if a := h.w.rt.Snapshot(h.clk.now()).Activity; a != nil {
				seen[name] = *a
			}
			return nil
		}
	}
	h.w.afterExport, h.w.beforeVerify, h.w.beforeCount = capture("export"), capture("uploaded"), capture("read back")
	h.tick(ctx)

	c := h.chunks(export.TableSyslog)[0]
	ex, up, vf := seen["export"], seen["uploaded"], seen["read back"]
	if ex.Stage != "export" || ex.ChunkID != c.ID || ex.Table != export.TableSyslog || ex.RowsDone != 3 ||
		ex.IDSpan != ids[2] || ex.IDsDone != ex.IDSpan || !ex.PeriodStart.Equal(day(10, 4, 0, 0)) {
		t.Fatalf("after the export: %+v", ex)
	}
	if up.Stage != "upload" || up.ObjectsTotal != 2 || up.ObjectsDone != 2 || up.BytesTotal == 0 || up.BytesDone != up.BytesTotal || up.Rows != 3 {
		t.Fatalf("after the upload: %+v", up)
	}
	if vf.Stage != "verify" || vf.ObjectsDone != 2 || vf.BytesDone != vf.BytesTotal {
		t.Fatalf("after the read-back: %+v", vf)
	}
	if rt := runtimeOf(t, h); rt.Activity != nil || rt.LastPassAt == nil {
		t.Fatalf("after the pass: activity %+v, last pass %v", rt.Activity, rt.LastPassAt)
	}
}

// TestWorker_ProgressWriteThrottled: progress is reported as often as rows
// are read, but the snapshot is written at most every status.ProgressEvery.
func TestWorker_ProgressWriteThrottled(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), nil)
	h.w.rt.StartActivity(&status.Activity{Table: export.TableSyslog, ChunkID: 7, Stage: "export", IDSpan: 1000})
	seenAt := func() time.Time {
		raw, ok, err := h.db.ArchiveWorkerState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return time.Time{}
		}
		rt, err := status.ParseRuntime(raw)
		if err != nil {
			t.Fatal(err)
		}
		return rt.SeenAt
	}
	report := func(rows int64) {
		h.w.rt.UpdateActivity(func(a *status.Activity) { a.RowsDone = rows })
		h.w.progress(ctx)
	}
	report(1)
	first := seenAt()
	if first.IsZero() {
		t.Fatal("the first progress report wrote nothing")
	}
	for i := int64(2); i < 200; i++ {
		h.clk.add(50 * time.Millisecond) // 10 s in all
		report(i)
	}
	if got := seenAt(); !got.Equal(first) {
		t.Fatalf("198 reports within 10 s rewrote the snapshot (seen %v, first %v)", got, first)
	}
	h.clk.add(status.ProgressEvery)
	report(500)
	rt := runtimeOf(t, h)
	if !rt.SeenAt.After(first) || rt.Activity == nil || rt.Activity.RowsDone != 500 {
		t.Fatalf("after %v: seen %v, activity %+v", status.ProgressEvery, rt.SeenAt, rt.Activity)
	}

	// A stage change writes sooner (stageEvery), but not twice within it.
	written := rt.SeenAt
	h.clk.add(time.Second)
	h.w.stage(ctx, "upload", nil)
	if got := seenAt(); !got.Equal(written) {
		t.Fatalf("a stage change 1 s after a write rewrote the snapshot")
	}
	h.clk.add(stageEvery)
	h.w.stage(ctx, "verify", nil)
	if rt := runtimeOf(t, h); !rt.SeenAt.After(written) || rt.Activity.Stage != "verify" {
		t.Fatalf("a stage change %v after a write: seen %v, activity %+v", stageEvery, rt.SeenAt, rt.Activity)
	}
}

// TestWorker_SettleFailureIsNotRechecked: a settle check that fails (not a
// wait) is retried by the next pass, not on every tick — also when the chunk
// was waiting (and so being rechecked every tick) before the failure.
func TestWorker_SettleFailureIsNotRechecked(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0))
	var checks int
	h.w.settled = func(context.Context, *models.ArchiveChunk) error { checks++; return errors.New("connection reset") }
	h.w.Tick(ctx)
	h.clk.add(TickInterval)
	before := checks
	h.w.Tick(ctx)
	if checks != before {
		t.Fatalf("a failed settle check was retried on the next tick (%d checks), want at the next pass", checks-before)
	}

	// Waiting on an open writer (checked every tick), then the check fails.
	h2 := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h2.db, day(10, 4, 1, 0))
	fail := false
	checks = 0
	h2.w.settled = func(context.Context, *models.ArchiveChunk) error {
		checks++
		if fail {
			return errors.New("connection reset")
		}
		return &database.ArchiveUnsettledError{GuardXmax: 900, Xmin: 800}
	}
	h2.w.Tick(ctx) // the pass: open_writer, rechecked every tick
	fail = true
	h2.clk.add(TickInterval)
	h2.w.Tick(ctx) // the recheck fails
	h2.clk.add(TickInterval)
	before = checks
	h2.w.Tick(ctx)
	if checks != before {
		t.Fatalf("after a failed recheck the next tick checked again (%d checks), want the next pass", checks-before)
	}
}
