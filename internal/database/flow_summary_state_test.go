package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The flow summary's health record, its verdict, and the strict progress
// reads that came with it. Fixtures hold 5m rows only (see
// flow_summary_dirty_scan_test.go), so the daily tier owns nothing.

// useSummaryClock gives the health record a clock the test moves, and puts
// every hook this file touches back afterwards.
func useSummaryClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	origNow, origWrite, origBound := flowSummaryNow, flowSummaryStateWrite, flowSummaryMaxCycleDuration
	flowSummaryNow = func() time.Time { return now }
	t.Cleanup(func() {
		flowSummaryNow, flowSummaryStateWrite, flowSummaryMaxCycleDuration = origNow, origWrite, origBound
		flowSummarySettingsHook = nil
		flowSummaryDirtyHook = nil
		flowSummaryBucketHook = nil
	})
	return &now
}

func summaryState(t *testing.T, d *Database) *FlowSummaryState {
	t.Helper()
	st, present, err := d.flowSummaryState(context.Background())
	if err != nil || !present {
		t.Fatalf("health record: present=%v err=%v", present, err)
	}
	return st
}

func settingKeyIn(keys []string, want string) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

// TestFlowSummary_ProgressReadFailureDoesNothing: a pass that cannot READ its
// watermark must leave it alone. Reading the failure as 0 took the first-pass
// arm — no dirty walk, watermark moved to the newest id — so the changed
// bucket here would never be rebuilt.
func TestFlowSummary_ProgressReadFailureDoesNothing(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useSummaryClock(t)
	base, watermark := builtSummary(t, d, 4)
	seedSummaryHour(t, d, base, 2, 900, "10.0.0.9") // changes bucket 2

	flowSummarySettingsHook = func(keys []string) error {
		if settingKeyIn(keys, flowSummaryWatermarkKeyPrefix+"1h") {
			return errors.New("connection reset")
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	if got := d.summaryWatermark("1h"); got != watermark {
		t.Fatalf("watermark moved from %d to %d on a pass that could not read it", watermark, got)
	}
	if want, got := summaryBucketBytes(d, base.Add(2*time.Hour)); got == want {
		t.Fatal("precondition: the changed bucket was rebuilt by a pass that should have done nothing")
	}
	if st := summaryState(t, d).Tiers["1h"]; st == nil || st.LastErrorClass != flowSummaryErrSettings || st.FailingSince.IsZero() {
		t.Fatalf("the failed read was not recorded as a settings failure: %+v", st)
	}

	flowSummarySettingsHook = nil
	d.RunFlowSummaryCycle()
	assertBucketsAgree(t, d, base, 4, "after the read recovered")
	if got := d.summaryWatermark("1h"); got <= watermark {
		t.Fatalf("watermark still %d after a clean pass", got)
	}
}

// TestFlowSummary_UnparseableWatermarkIsAnError: garbage in the watermark is
// not zero. A blank fill marker IS zero — the summariser stores "" itself when
// it restarts a backfill — and so is an unparseable one: both only make the
// tier rebuild, where failing would stall it until someone edited the setting.
func TestFlowSummary_UnparseableWatermarkIsAnError(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useSummaryClock(t)
	base, _ := builtSummary(t, d, 4)

	d.clearSummaryFillMarker("1h")
	if _, filled, err := d.summaryProgress("1h"); err != nil || !filled.IsZero() {
		t.Fatalf("blank fill marker: filled=%v err=%v, want zero and no error", filled, err)
	}
	d.RunFlowSummaryCycle()
	if st := summaryState(t, d).Tiers["1h"]; st.LastErrorClass != "" || !st.CaughtUp {
		t.Fatalf("a blank marker failed or stalled the pass: %+v", st)
	}
	assertBucketsAgree(t, d, base, 4, "after a marker reset")

	if err := d.UpsertSetting(&models.SystemSetting{Key: flowSummaryWatermarkKeyPrefix + "1h", Value: "12x", Category: "system", Type: "number"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.summaryProgress("1h"); !errors.Is(err, errSummarySettings) {
		t.Fatalf("watermark \"12x\": err = %v, want a settings error", err)
	}
	if err := d.UpsertSetting(&models.SystemSetting{Key: flowSummaryFillKeyPrefix + "1h", Value: "yesterday", Category: "system", Type: "string"}); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertSetting(&models.SystemSetting{Key: flowSummaryWatermarkKeyPrefix + "1h", Value: "12", Category: "system", Type: "number"}); err != nil {
		t.Fatal(err)
	}
	if _, filled, err := d.summaryProgress("1h"); err != nil || !filled.IsZero() {
		t.Fatalf("fill marker \"yesterday\": filled=%v err=%v, want never-filled and no error", filled, err)
	}
	d.RunFlowSummaryCycle()
	if st := summaryState(t, d).Tiers["1h"]; st.LastErrorClass != "" || !st.CaughtUp {
		t.Fatalf("an unparseable fill marker stalled the tier instead of rebuilding it: %+v", st)
	}
	assertBucketsAgree(t, d, base, 4, "after an unparseable fill marker")
}

// TestFlowSummary_UnreadableStampFailsTheScan: a source row whose timestamp
// cannot be read must fail the dirty scan. Skipping it lets the watermark pass
// a row whose bucket was never marked.
func TestFlowSummary_UnreadableStampFailsTheScan(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Hour)
	seedSummaryHour(t, d, base, 0, 100, "10.0.0.1")
	seedSummaryHour(t, d, base, 1, 100, "10.0.0.1")
	top := maxRollupID(t, d)
	if err := d.Gorm().Exec("UPDATE flow_rollups SET timestamp = 'not a time' WHERE id = ?", top).Error; err != nil {
		t.Fatal(err)
	}
	stamps, err := dirtyChunkStamps(d.db.Session(&gorm.Session{}), []string{"5m"}, 0, top)
	if err == nil {
		t.Fatalf("scan returned %d stamp(s) and no error for an unreadable timestamp", len(stamps))
	}
}

// TestFlowSummaryState_RecordsOutcomes: failing_since marks the START of a run
// of failures, the class is recorded and the error text is not, and a success
// clears it.
func TestFlowSummaryState_RecordsOutcomes(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	builtSummary(t, d, 3)

	flowSummaryDirtyHook = func(interval string) error {
		if interval == "1h" {
			return errors.New("SELECT secret_column FROM somewhere")
		}
		return nil
	}
	*now = now.Add(5 * time.Minute) // the last good pass is behind us
	first := *now
	for i := 0; i < 3; i++ {
		d.RunFlowSummaryCycle()
		*now = now.Add(5 * time.Minute)
	}
	st := summaryState(t, d).Tiers["1h"]
	if !st.FailingSince.Equal(first) {
		t.Fatalf("failing_since = %v, want the first failure %v", st.FailingSince, first)
	}
	if st.ConsecutiveFailures != 3 || st.LastErrorClass != flowSummaryErrQuery {
		t.Fatalf("failures = %d class = %q, want 3 and %q", st.ConsecutiveFailures, st.LastErrorClass, flowSummaryErrQuery)
	}
	if !st.LastOKAt.Before(first) {
		t.Fatalf("last_ok_at %v moved during the failures (first at %v)", st.LastOKAt, first)
	}
	if raw, _ := d.GetSettingValue(FlowSummaryStateKey); strings.Contains(raw, "secret_column") {
		t.Fatalf("the record repeats the error text: %s", raw)
	}

	flowSummaryDirtyHook = nil
	d.RunFlowSummaryCycle()
	st = summaryState(t, d).Tiers["1h"]
	if !st.FailingSince.IsZero() || st.ConsecutiveFailures != 0 || !st.LastOKAt.Equal(*now) {
		t.Fatalf("a success did not clear the failure: %+v (now %v)", st, *now)
	}
}

// TestFlowSummaryState_WriteFailureDoesNotStopThePass: the record describes
// the summariser; it must never be why the summariser did less.
func TestFlowSummaryState_WriteFailureDoesNotStopThePass(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useSummaryClock(t)
	base, watermark := builtSummary(t, d, 4)
	seedSummaryHour(t, d, base, 1, 700, "10.0.0.7")

	writes := 0
	flowSummaryStateWrite = func(*Database, string) error {
		writes++
		return errors.New("disk full")
	}
	d.RunFlowSummaryCycle()
	if writes == 0 {
		t.Fatal("precondition: the record was never written")
	}
	assertBucketsAgree(t, d, base, 4, "with the health record unwritable")
	if got := d.summaryWatermark("1h"); got <= watermark {
		t.Fatalf("watermark stayed at %d", got)
	}
}

// TestFlowSummaryState_PanicIsAFailedPass: a tier that panics is recorded as
// failing AND the tier after it still runs. The daily tier runs first, so it
// is the one made to panic; the hourly tier must then complete a pass of its
// own in the same cycle. Without the per-tier recover the cycle ended at the
// panic, nothing was recorded, and both tiers kept their last good record.
func TestFlowSummaryState_PanicIsAFailedPass(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	base, _ := builtSummary(t, d, 3)
	seedSummaryHour(t, d, base, 1, 300, "10.0.0.3")
	*now = now.Add(5 * time.Minute) // tell this cycle's records from the build's

	flowSummarySettingsHook = func(keys []string) error {
		if settingKeyIn(keys, flowSummaryWatermarkKeyPrefix+"1d") {
			panic("nil map")
		}
		return nil
	}
	d.RunFlowSummaryCycle() // must not panic out of the cycle
	st := summaryState(t, d)
	if day := st.Tiers["1d"]; day == nil || day.LastErrorClass != flowSummaryErrPanic || !day.FailingSince.Equal(*now) {
		t.Fatalf("daily tier after a panic: %+v", day)
	}
	if h := st.Tiers["1h"]; h == nil || !h.LastPassAt.Equal(*now) || !h.LastOKAt.Equal(*now) {
		t.Fatalf("the hourly tier did not run after the daily tier panicked: %+v (now %v)", h, *now)
	}
	assertBucketsAgree(t, d, base, 3, "after the other tier panicked")
}

// TestFlowSummaryState_OwnsNothingIsCaughtUp: a tier with nothing to build is
// not "rebuilding". Both shapes: no rollups at all, and (the daily tier here)
// rollups it does not own.
func TestFlowSummaryState_OwnsNothingIsCaughtUp(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	start := now.Add(-time.Minute)

	d.RunFlowSummaryCycle()
	for _, iv := range []string{"1h", "1d"} {
		if ts := summaryState(t, d).Tiers[iv]; ts == nil || !ts.CaughtUp {
			t.Fatalf("no rollups: %s tier caught_up = %+v", iv, ts)
		}
	}
	h := d.EvaluateFlowSummaryHealth(context.Background(), *now, 60, start)
	for iv, th := range h.Tiers {
		if th.Verdict != FlowSummaryOK {
			t.Fatalf("no rollups: %s verdict = %q, want ok", iv, th.Verdict)
		}
	}

	builtSummary(t, d, 3)
	if ts := summaryState(t, d).Tiers["1d"]; !ts.CaughtUp {
		t.Fatalf("5m rows only: the daily tier reads as not caught up: %+v", ts)
	}
	h = d.EvaluateFlowSummaryHealth(context.Background(), *now, 60, start)
	if v := h.Tiers["1d"].Verdict; v != FlowSummaryOK {
		t.Fatalf("5m rows only: daily verdict = %q, want ok", v)
	}
}

// TestFlowSummaryState_LongBackfillIsNotAStall: passes that end on the time
// bound before the history is built are SUCCESSES. Hours of that must read as
// rebuilding and never as stalled.
func TestFlowSummaryState_LongBackfillIsNotAStall(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	start := *now
	base := time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 6; h++ {
		seedSummaryHour(t, d, base, h, 100, "10.0.0.1")
	}

	flowSummaryMaxCycleDuration = -time.Hour // every pass stops on the bound at once
	for i := 0; i < 30; i++ {                // 2.5 hours of cycles
		d.RunFlowSummaryCycle()
		*now = now.Add(5 * time.Minute)
	}
	st := summaryState(t, d).Tiers["1h"]
	if st.CaughtUp || !st.FailingSince.IsZero() {
		t.Fatalf("precondition: want a successful, unfinished backfill, got %+v", st)
	}
	h := d.EvaluateFlowSummaryHealth(context.Background(), *now, 60, start)
	if v := h.Tiers["1h"].Verdict; v != FlowSummaryCatchingUp {
		t.Fatalf("after 2.5 h of bounded passes the verdict is %q, want catching_up", v)
	}

	flowSummaryMaxCycleDuration = time.Minute
	d.RunFlowSummaryCycle()
	h = d.EvaluateFlowSummaryHealth(context.Background(), *now, 60, start)
	if v := h.Tiers["1h"].Verdict; v != FlowSummaryOK {
		t.Fatalf("after the backfill finished the verdict is %q, want ok", v)
	}
}

// TestFlowSummaryVerdict walks the ordered rules. Times are minutes relative
// to `now`; the threshold is 60.
func TestFlowSummaryVerdict(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	ago := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	var never time.Time
	tier := func(lastPass, lastOK, failingSince time.Time, caughtUp bool) *FlowSummaryTierState {
		ts := &FlowSummaryTierState{LastPassAt: lastPass, LastOKAt: lastOK, FailingSince: failingSince, CaughtUp: caughtUp}
		if !failingSince.IsZero() {
			ts.ConsecutiveFailures = 2 // a run of failures unless a case says otherwise
			if failingSince.Equal(lastPass) {
				ts.ConsecutiveFailures = 1
			}
		}
		return ts
	}
	state := func(cycleAt time.Time, hourly *FlowSummaryTierState) *FlowSummaryState {
		st := &FlowSummaryState{CycleProgressAt: cycleAt, Tiers: map[string]*FlowSummaryTierState{}}
		if hourly != nil {
			st.Tiers["1h"] = hourly
		}
		return st
	}
	longUp := ago(600) // the poller has been running for ten hours

	cases := []struct {
		name    string
		st      *FlowSummaryState
		start   time.Time
		rollups bool
		want    string
	}{
		{"healthy between cycles", state(ago(4), tier(ago(4), ago(4), never, true)), longUp, true, FlowSummaryOK},
		// The pass has been running 20 minutes; the tier's own record is 20
		// minutes old and says caught up. A routine pass is not a rebuild.
		{"pass in flight on a caught-up tier", state(ago(1), tier(ago(20), ago(20), never, true)), longUp, true, FlowSummaryOK},
		{"single failure", state(ago(2), tier(ago(2), ago(7), ago(2), true)), longUp, true, FlowSummaryFailing},
		// Idle for three hours behind the other tier's walk, then ONE failed
		// pass: its last success is old, but that is one failure, not a stall.
		{"single failure after a long idle", state(ago(2), tier(ago(2), ago(185), ago(2), true)), longUp, true, FlowSummaryFailing},
		{"failing for exactly the threshold", state(ago(1), tier(ago(1), ago(60), ago(55), true)), longUp, true, FlowSummaryStalled},
		{"failing for just under the threshold", state(ago(1), tier(ago(1), ago(59), ago(55), true)), longUp, true, FlowSummaryFailing},
		// One poison bucket: every pass fails, and every pass is busy.
		{"failing every pass with fresh progress", state(ago(1), tier(ago(1), ago(90), ago(85), true)), longUp, true, FlowSummaryStalled},
		{"hung pass", state(ago(75), tier(ago(80), ago(80), never, true)), longUp, true, FlowSummaryStalled},
		// The hourly tier has been walking a backlog for 90 minutes; the daily
		// tier (judged here as "1h" for brevity) finished at the cycle's start
		// and has done nothing since. The cycle is alive, so it is not stalled
		// — and its 90-minute-old "ok" is not evidence that it is fine either.
		{"idle tier while the other walks", state(ago(1), tier(ago(90), ago(90), never, true)), longUp, true, FlowSummaryUnknown},
		{"idle tier, the walk still short", state(ago(1), tier(ago(40), ago(40), never, true)), longUp, true, FlowSummaryOK},
		// A cycle hung for 95 minutes (rule 3 alerted) and has just come back
		// to life. This tier has not passed since: its old "ok" must not
		// clear the alert.
		{"cycle revived, tier not passed since the hang", state(ago(0), tier(ago(95), ago(95), never, true)), longUp, true, FlowSummaryUnknown},
		// Failing before the restart and not reached since, an hour on: the
		// failure is not this process's evidence, so it is not yet a stall.
		{"failing before a restart, not reached for an hour", state(ago(1), tier(ago(300), ago(400), ago(390), true)), ago(61), true, FlowSummaryFailing},
		{"never ran, rollups, before the threshold", nil, ago(30), true, FlowSummaryUnknown},
		{"never ran, rollups, after the threshold", nil, ago(61), true, FlowSummaryStalled},
		{"never ran, no rollups", nil, longUp, false, FlowSummaryUnknown},
		// The record says ok, but it was written before this process started.
		{"record older than the process", state(ago(300), tier(ago(300), ago(300), never, true)), ago(1), true, FlowSummaryUnknown},
		// Down for five hours with a failing tier: no page at boot.
		{"failing before a restart", state(ago(300), tier(ago(300), ago(400), ago(390), true)), ago(1), true, FlowSummaryUnknown},
		{"failing through a restart, an hour on", state(ago(2), tier(ago(2), ago(400), ago(390), true)), ago(61), true, FlowSummaryStalled},
		{"rebuilding", state(ago(2), tier(ago(2), ago(2), never, false)), longUp, true, FlowSummaryCatchingUp},
		// Restarted five minutes ago; a cycle has STARTED (and may be hung),
		// but this tier's "ok" is still the one from before the restart.
		{"cycle started, no pass yet in this process", state(ago(1), tier(ago(300), ago(300), never, true)), ago(5), true, FlowSummaryUnknown},
		{"same, an hour on with the cycle still alive", state(ago(1), tier(ago(300), ago(300), never, true)), ago(70), true, FlowSummaryUnknown},
		{"no pass recorded for the tier", state(ago(2), nil), longUp, true, FlowSummaryUnknown},
	}
	for _, c := range cases {
		if got := flowSummaryVerdict(c.st, "1h", now, time.Hour, c.start, c.rollups); got != c.want {
			t.Errorf("%s: verdict = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestFlowSummaryHealth_Evaluation: an unreadable record is "unknown" for
// every tier; a threshold of 0 (alerting off) still judges, against the
// default; and what the poller stores is what a reader gets back, marked stale
// once it is old.
func TestFlowSummaryHealth_Evaluation(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	ctx := context.Background()
	start := now.Add(-10 * time.Hour)
	builtSummary(t, d, 3)

	for _, minutes := range []int{60, 0} {
		h := d.EvaluateFlowSummaryHealth(ctx, *now, minutes, start)
		if v := h.Tiers["1h"].Verdict; v != FlowSummaryOK {
			t.Fatalf("threshold %d, healthy: verdict = %q, want ok", minutes, v)
		}
		if h.LongWindowsLive == nil || *h.LongWindowsLive {
			t.Fatalf("a built summary is reported as read live or undetermined: %v", h.LongWindowsLive)
		}
	}

	// Fail the hourly tier for two hours.
	flowSummaryDirtyHook = func(interval string) error {
		if interval == "1h" {
			return errors.New("boom")
		}
		return nil
	}
	for i := 0; i < 25; i++ {
		*now = now.Add(5 * time.Minute)
		d.RunFlowSummaryCycle()
	}
	for _, minutes := range []int{60, 0} {
		h := d.EvaluateFlowSummaryHealth(ctx, *now, minutes, start)
		if v := h.Tiers["1h"].Verdict; v != FlowSummaryStalled {
			t.Fatalf("threshold %d, failing two hours: verdict = %q, want stalled", minutes, v)
		}
		if th := h.Tiers["1h"]; th.LastErrorClass != flowSummaryErrQuery || th.LastOKAt.IsZero() {
			t.Fatalf("the evaluation lacks what the banner needs: %+v", th)
		}
	}

	flowSummarySettingsHook = func(keys []string) error {
		if settingKeyIn(keys, FlowSummaryStateKey) {
			return errors.New("connection reset")
		}
		return nil
	}
	h := d.EvaluateFlowSummaryHealth(ctx, *now, 60, start)
	for iv, th := range h.Tiers {
		if th.Verdict != FlowSummaryUnknown {
			t.Fatalf("unreadable record: %s verdict = %q, want unknown", iv, th.Verdict)
		}
	}
	flowSummarySettingsHook = nil

	stalled := d.EvaluateFlowSummaryHealth(ctx, *now, 60, start)
	// In this fixture nothing newer has been rolled up, so the fill marker is
	// still at the newest bucket and the summary is still what long windows
	// are served from. (On a live system a failing dirty scan also stops the
	// backfill, so the marker falls behind within the hour.)
	if stalled.LongWindowsLive == nil || *stalled.LongWindowsLive {
		t.Fatalf("a stalled but built summary is reported as read live or undetermined: %v", stalled.LongWindowsLive)
	}
	// Once ANY tier's fill marker is behind, nothing is served from the
	// summary: the read path is all-or-nothing, whichever tier the alert is
	// about.
	d.clearSummaryFillMarker("1h")
	if live := d.EvaluateFlowSummaryHealth(ctx, *now, 60, start).LongWindowsLive; live == nil || !*live {
		t.Fatalf("with a tier's history incomplete, long windows are not reported as read live: %v", live)
	}
	if err := d.SaveFlowSummaryHealth(ctx, stalled); err != nil {
		t.Fatal(err)
	}
	// The reader repeats the stored verdict even when a fresh evaluation
	// would differ: repair the tier, do not re-store.
	flowSummaryDirtyHook = nil
	d.RunFlowSummaryCycle()
	got, err := d.GetFlowSummaryHealth(ctx)
	if err != nil || got.Stale || got.Tiers["1h"].Verdict != FlowSummaryStalled {
		t.Fatalf("stored evaluation: stale=%v verdict=%q err=%v, want the stored stalled verdict", got.Stale, got.Tiers["1h"].Verdict, err)
	}
	*now = now.Add(16 * time.Minute)
	if got, _ = d.GetFlowSummaryHealth(ctx); !got.Stale {
		t.Fatal("an evaluation 16 minutes old is not marked stale")
	}
}

// TestFlowSummaryHealth_NothingStored: before the poller's first evaluation a
// reader gets "unknown" for every tier, not an error and not stale.
func TestFlowSummaryHealth_NothingStored(t *testing.T) {
	d := NewDatabaseForTesting(t)
	h, err := d.GetFlowSummaryHealth(context.Background())
	if err != nil || h.Stale || len(h.Tiers) != len(flowSummaryTiers) {
		t.Fatalf("nothing stored: %+v err=%v", h, err)
	}
	for iv, th := range h.Tiers {
		if th.Verdict != FlowSummaryUnknown {
			t.Fatalf("%s verdict = %q, want unknown", iv, th.Verdict)
		}
	}
}

// TestGetFlowStats_SaysWhichReadServedIt covers every value of ServedFrom and
// the bypass reason.
func TestGetFlowStats_SaysWhichReadServedIt(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useSummaryClock(t)
	builtSummary(t, d, 4)
	origMin := flowSummaryMinHours
	t.Cleanup(func() { flowSummaryMinHours = origMin })

	served := func(hours int, f FlowStatsFilter) (string, string) {
		t.Helper()
		res, err := d.GetFlowStats(hours, f)
		if err != nil {
			t.Fatalf("GetFlowStats(%d): %v", hours, err)
		}
		return res.ServedFrom, res.SummaryBypassReason
	}
	if from, why := served(1, FlowStatsFilter{}); from != FlowServedRaw || why != "" {
		t.Fatalf("1 h: served_from=%q reason=%q, want raw", from, why)
	}
	// Below the summary's minimum: live, and the summary was never a candidate.
	if from, why := served(24, FlowStatsFilter{}); from != FlowServedLive || why != "" {
		t.Fatalf("24 h: served_from=%q reason=%q, want live with no reason", from, why)
	}
	flowSummaryMinHours = 1
	if from, why := served(24, FlowStatsFilter{}); from != FlowServedSummary || why != "" {
		t.Fatalf("summary window: served_from=%q reason=%q, want summary", from, why)
	}
	d.clearSummaryFillMarker("1h")
	if from, why := served(24, FlowStatsFilter{}); from != FlowServedLive || why != FlowLiveReasonSummaryBehind {
		t.Fatalf("summary behind: served_from=%q reason=%q, want live + %q", from, why, FlowLiveReasonSummaryBehind)
	}
	if from, why := served(24, FlowStatsFilter{SrcAddr: "10.0.0.1"}); from != FlowServedMaterialized || why != "" {
		t.Fatalf("address filter: served_from=%q reason=%q, want materialized", from, why)
	}
}

// TestFlowSummaryState_CorruptRecordIsReplaced: a record that does not parse
// never will. The next cycle starts a new one; left in place it would make
// every verdict "unknown" for good — no banner and no alert, silently.
func TestFlowSummaryState_CorruptRecordIsReplaced(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	builtSummary(t, d, 3)
	if err := flowSummaryStateWrite(d, "{not json"); err != nil {
		t.Fatal(err)
	}
	start := now.Add(-10 * time.Hour)
	if v := d.EvaluateFlowSummaryHealth(context.Background(), *now, 60, start).Tiers["1h"].Verdict; v != FlowSummaryUnknown {
		t.Fatalf("corrupt record: verdict = %q, want unknown", v)
	}
	*now = now.Add(5 * time.Minute)
	d.RunFlowSummaryCycle()
	if v := d.EvaluateFlowSummaryHealth(context.Background(), *now, 60, start).Tiers["1h"].Verdict; v != FlowSummaryOK {
		t.Fatalf("after the next cycle the verdict is %q, want ok (the record was not replaced)", v)
	}

	// An UNREADABLE record is not replaced: that would erase last_ok_at.
	before, _ := d.GetSettingValue(FlowSummaryStateKey)
	flowSummarySettingsHook = func(keys []string) error {
		if settingKeyIn(keys, FlowSummaryStateKey) {
			return errors.New("connection reset")
		}
		return nil
	}
	*now = now.Add(5 * time.Minute)
	d.RunFlowSummaryCycle()
	if after, _ := d.GetSettingValue(FlowSummaryStateKey); after != before {
		t.Fatal("a cycle that could not read the record overwrote it")
	}
}

// TestFlowSummaryState_RecordReadIsRetriedWithinTheCycle: one failed read of
// the previous record at the START of a cycle must not silence the whole
// cycle — a long pass would then show no sign of life and read as stalled
// while it is working. Nothing is written until the read succeeds (a fresh
// record would erase last_ok_at); after that the cycle records as usual.
func TestFlowSummaryState_RecordReadIsRetriedWithinTheCycle(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	base, _ := builtSummary(t, d, 3)
	okBefore := summaryState(t, d).Tiers["1h"].LastOKAt
	seedSummaryHour(t, d, base, 1, 400, "10.0.0.4")
	*now = now.Add(5 * time.Minute)

	failed := 0
	flowSummarySettingsHook = func(keys []string) error {
		if settingKeyIn(keys, FlowSummaryStateKey) && failed == 0 {
			failed++
			return errors.New("connection reset")
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	if failed != 1 {
		t.Fatalf("precondition: the record read failed %d time(s), want 1", failed)
	}
	st := summaryState(t, d)
	if h := st.Tiers["1h"]; !h.LastOKAt.Equal(*now) || !h.LastOKAt.After(okBefore) {
		t.Fatalf("the cycle recorded nothing after one failed read: last_ok_at %v (before %v, now %v)", h.LastOKAt, okBefore, *now)
	}
	if !st.CycleProgressAt.Equal(*now) {
		t.Fatalf("cycle_progress_at = %v, want %v", st.CycleProgressAt, *now)
	}
}

// TestFlowSummaryHealth_ReadPathProbeFailureIsNotReadLive: when the probe
// behind long_windows_live fails, the evaluation says nothing. Recording
// "read live" would put one failed query into an alert's text.
func TestFlowSummaryHealth_ReadPathProbeFailureIsNotReadLive(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	builtSummary(t, d, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.WithContext(ctx).summaryBackfillState(); err == nil {
		t.Fatal("precondition: the probe did not fail on a cancelled context")
	}
	if h := d.EvaluateFlowSummaryHealth(ctx, *now, 60, now.Add(-time.Hour)); h.LongWindowsLive != nil {
		t.Fatalf("a failed probe was recorded as long_windows_live=%v", *h.LongWindowsLive)
	}
}

// TestFlowSummaryHealth_MarkerReadFailureIsNotReadLive: the same, for the
// second read the probe makes — a fill marker that could not be READ is not a
// fill marker that is behind.
func TestFlowSummaryHealth_MarkerReadFailureIsNotReadLive(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	builtSummary(t, d, 3)
	flowSummarySettingsHook = func(keys []string) error {
		if settingKeyIn(keys, flowSummaryFillKeyPrefix+"1h") {
			return errors.New("connection reset")
		}
		return nil
	}
	if h := d.EvaluateFlowSummaryHealth(context.Background(), *now, 60, now.Add(-time.Hour)); h.LongWindowsLive != nil {
		t.Fatalf("a failed marker read was recorded as long_windows_live=%v", *h.LongWindowsLive)
	}
	// The read path itself still refuses the summary for that request.
	if d.summaryBackfillComplete() {
		t.Fatal("the read path used the summary without being able to read its marker")
	}
}
