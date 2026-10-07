package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// A pass that works a long syslog backlog keeps planning the flow tables: the
// rollup deletes raw flows after about an hour and the retention gate holds
// them until their chunk is verified, so the hourly flow chunks may not wait
// for the backlog to end. The worker's clock is fake; a syslog chunk's export
// advances it (a slow export), and the hook takes the marks the pass's
// one-minute mark ticker would take in real time.

func addFlowSample(t *testing.T, h *harness, at time.Time) {
	t.Helper()
	f := models.FlowSample{Timestamp: at, DeviceID: 7, SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7"}
	if err := h.db.Gorm().Create(&f).Error; err != nil {
		t.Fatal(err)
	}
}

func addCounter(t *testing.T, h *harness, at time.Time) {
	t.Helper()
	c := models.FlowInterfaceCounter{Timestamp: at, DeviceID: 7, SamplerAddress: "192.0.2.1", IfIndex: 3}
	if err := h.db.Gorm().Create(&c).Error; err != nil {
		t.Fatal(err)
	}
}

// verifiedThrough is the end of the newest verified chunk of table (zero:
// none) and how many of its chunks are verified.
func verifiedThrough(h *harness, table string) (time.Time, int) {
	var end time.Time
	n := 0
	for _, c := range h.chunks(table) {
		if c.Status == models.ArchiveChunkVerified {
			n++
			if c.PeriodEnd.After(end) {
				end = c.PeriodEnd.UTC()
			}
		}
	}
	return end, n
}

// TestWorker_FlowsNotStarvedBySyslogBacklog: one pass exports sixteen days of
// syslog, each taking 20 minutes (five hours and twenty minutes in all). While
// it does, every flow hour is verified within one syslog chunk of becoming
// due — the flow lag never exceeds 1 h 20 min — and the daily counter chunk
// that comes due at 02:00 is verified by the next syslog chunk; the snapshot
// says a pass is running and names no next pass. Before 0.11.313 the pass
// planned the flow tables once, at its start: flows stayed verified through
// 22:00 for the whole backlog.
func TestWorker_FlowsNotStarvedBySyslogBacklog(t *testing.T) {
	start := day(10, 10, 22, 20)
	h := newHarness(t, start, nil)
	var days []time.Time
	for d := 0; d < 15; d++ {
		days = append(days, day(9, 25+d, 12, 0)) // 25 Sep .. 9 Oct
	}
	seedSyslog(t, h.db, days...)
	seedSyslog(t, h.db, day(10, 10, 12, 0)) // 10 Oct: due at 02:00 on the 11th, during the pass
	addFlowSample(t, h, day(10, 10, 21, 30))
	addCounter(t, h, day(10, 9, 12, 0))
	addCounter(t, h, day(10, 10, 12, 0))

	const exportTakes = 20 * time.Minute
	const maxLag = time.Hour + exportTakes // a closed hour waits at most its 5 min plus one syslog chunk
	var hooks int
	h.w.afterExport = func(ctx context.Context, c *models.ArchiveChunk) error {
		if c.SourceTable != export.TableSyslog {
			return nil
		}
		hooks++
		h.clk.add(exportTakes)
		now := h.clk.now()
		addFlowSample(t, h, now.Add(-time.Minute))
		addCounter(t, h, now.Add(-time.Minute))
		h.w.takeMarks(ctx) // the pass's mark ticker, in fake time

		if end, _ := verifiedThrough(h, export.TableFlows); now.Sub(end) > maxLag {
			t.Errorf("at %s (syslog chunk %d) flows are verified through %s: lag %s, want at most %s",
				now.Format("01-02 15:04"), c.Seq, end.Format("01-02 15:04"), now.Sub(end), maxLag)
		}
		// The 10 Oct counter chunk is due at 02:00 on the 11th.
		if due := day(10, 11, 2, 0); now.Sub(due) > exportTakes {
			if end, _ := verifiedThrough(h, export.TableCounters); end.Before(day(10, 11, 0, 0)) {
				t.Errorf("at %s counters are verified through %s, want 11 Oct 00:00", now.Format("01-02 15:04"), end.Format("01-02 15:04"))
			}
		}
		rt := h.w.rt.Snapshot(now)
		if !rt.PassRunning || rt.NextPassAt != nil || rt.LastPassAt == nil || !rt.LastPassAt.Equal(start.UTC()) {
			t.Errorf("during the pass: running %v, last %v, next %v; want running since %s and no next pass", rt.PassRunning, rt.LastPassAt, rt.NextPassAt, start)
		}
		return nil
	}

	h.w.Tick(ctx) // one pass works the whole backlog
	end := h.clk.now()

	if _, n := verifiedThrough(h, export.TableSyslog); n != 16 || hooks != 16 {
		t.Fatalf("%d syslog chunks verified (%d exports), want 16", n, hooks)
	}
	flowsEnd, nf := verifiedThrough(h, export.TableFlows)
	if end.Sub(flowsEnd) > maxLag || nf < 6 {
		t.Fatalf("after the pass (%s): %d flow chunks verified through %s", end.Format("01-02 15:04"), nf, flowsEnd.Format("01-02 15:04"))
	}
	for _, c := range h.chunks(export.TableFlows) {
		if c.Status != models.ArchiveChunkVerified {
			t.Fatalf("flow chunk %d (%s) is %s", c.Seq, c.PeriodStart.UTC().Format("01-02 15:04"), c.Status)
		}
	}
	rt := runtimeOf(t, h)
	if rt.PassRunning || rt.LastPassAt == nil || !rt.LastPassAt.Equal(start.UTC()) || rt.NextPassAt == nil || !rt.NextPassAt.Equal(end.UTC()) {
		t.Fatalf("after the pass: running %v, last %v, next %v; want last %s and next now (%s), not ten minutes after the start",
			rt.PassRunning, rt.LastPassAt, rt.NextPassAt, start, end)
	}
}

// TestWorker_PassRechecksWaitsAtMostEveryMinute: during a pass of quick
// syslog chunks (15 s each) a flow chunk whose cut settles for three minutes
// is checked when planned and once more when the window has ended, then
// verified in the same pass; a counter chunk held by an open writer for five
// minutes is checked at most once a minute (not between every two syslog
// chunks) and verified in the same pass once the writer is gone.
func TestWorker_PassRechecksWaitsAtMostEveryMinute(t *testing.T) {
	start := day(10, 10, 10, 20)
	h := newHarness(t, start, nil)
	var days []time.Time
	for d := 0; d < 30; d++ {
		days = append(days, day(9, 1+d, 12, 0)) // 1 .. 30 Sep; with the empty days to 9 Oct 39 chunks, 9.75 min
	}
	seedSyslog(t, h.db, days...)
	addFlowSample(t, h, day(10, 10, 9, 30))
	addCounter(t, h, day(10, 9, 12, 0))

	settleEnd, writerGone := start.Add(3*time.Minute), start.Add(5*time.Minute)
	var flowChecks, ctrChecks []time.Time
	h.w.settled = func(_ context.Context, c *models.ArchiveChunk) error {
		now := h.clk.now()
		switch c.SourceTable {
		case export.TableFlows:
			flowChecks = append(flowChecks, now)
			if left := settleEnd.Sub(now); left > 0 {
				return &database.ArchiveUnsettledError{SettleLeft: left}
			}
		case export.TableCounters:
			ctrChecks = append(ctrChecks, now)
			if now.Before(writerGone) {
				return &database.ArchiveUnsettledError{GuardXmax: 900, Xmin: 800}
			}
		}
		return nil
	}
	h.w.afterExport = func(_ context.Context, c *models.ArchiveChunk) error {
		if c.SourceTable == export.TableSyslog {
			h.clk.add(15 * time.Second)
		}
		return nil
	}

	h.w.Tick(ctx)

	if _, n := verifiedThrough(h, export.TableSyslog); n != 39 {
		t.Fatalf("%d syslog chunks verified, want 39", n)
	}
	if fc := h.chunks(export.TableFlows); len(fc) != 1 || fc[0].Status != models.ArchiveChunkVerified {
		t.Fatalf("flow chunks %+v, want the settling chunk verified in the pass", fc)
	}
	if len(flowChecks) != 2 || flowChecks[1].Before(settleEnd) || flowChecks[1].Sub(settleEnd) > 15*time.Second {
		t.Fatalf("flow settle checks at %v, want two: when planned and the first chunk boundary after %s", flowChecks, settleEnd)
	}
	if cc := h.chunks(export.TableCounters); len(cc) != 1 || cc[0].Status != models.ArchiveChunkVerified {
		t.Fatalf("counter chunks %+v, want the held chunk verified in the pass", cc)
	}
	for i := 1; i < len(ctrChecks); i++ {
		if d := ctrChecks[i].Sub(ctrChecks[i-1]); d < replanEvery {
			t.Fatalf("counter checks %v: two %s apart, want at least %s", ctrChecks, d, replanEvery)
		}
	}
	if n := len(ctrChecks); n < 5 || n > 7 || ctrChecks[n-1].Before(writerGone) {
		t.Fatalf("counter checks %v: want one a minute until the writer is gone at %s", ctrChecks, writerGone)
	}
}

// TestWorker_FailedFlowChunkRetriedInPass: a flow chunk whose export fails
// during a syslog backlog does not stop the flow table for the rest of the
// pass: it is retried once its backoff has passed and verified, and the
// later flow hours are verified too — all in the one pass.
func TestWorker_FailedFlowChunkRetriedInPass(t *testing.T) {
	start := day(10, 10, 22, 20)
	h := newHarness(t, start, nil)
	var days []time.Time
	for d := 0; d < 9; d++ {
		days = append(days, day(10, 1+d, 12, 0)) // 1 .. 9 Oct: 9 chunks, 3 h
	}
	seedSyslog(t, h.db, days...)
	addFlowSample(t, h, day(10, 10, 21, 30))
	addCounter(t, h, day(10, 9, 12, 0))

	failed := 0
	h.w.afterExport = func(ctx context.Context, c *models.ArchiveChunk) error {
		switch c.SourceTable {
		case export.TableFlows:
			if c.Seq == 2 && failed == 0 {
				failed++
				return errors.New("synthetic export failure")
			}
		case export.TableSyslog:
			h.clk.add(20 * time.Minute)
			addFlowSample(t, h, h.clk.now().Add(-time.Minute))
			h.w.takeMarks(ctx)
		}
		return nil
	}

	h.w.Tick(ctx)

	if failed != 1 {
		t.Fatalf("the flow chunk failed %d times, want once", failed)
	}
	fc := h.chunks(export.TableFlows)
	if len(fc) < 4 {
		t.Fatalf("%d flow chunks planned, want every closed hour to 01:00", len(fc))
	}
	for _, c := range fc {
		if c.Status != models.ArchiveChunkVerified {
			t.Fatalf("flow chunk %d (%s) is %s after %d attempts, want verified in the pass", c.Seq, c.PeriodStart.UTC().Format("01-02 15:04"), c.Status, c.Attempts)
		}
	}
	if fc[1].Attempts != 2 {
		t.Fatalf("flow chunk 2: %d attempts, want 2 (failed, then retried after its backoff)", fc[1].Attempts)
	}
}
