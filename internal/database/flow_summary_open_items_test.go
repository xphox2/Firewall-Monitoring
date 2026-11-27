package database

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Tests for v0.11.464: a rebuild that does not move, panics outside a tier,
// and the recompute step's reads of its own state.

// useHourlyCap caps the hourly tier's backfill at n buckets a pass, so a
// backfill takes many cycles, and restores it.
func useHourlyCap(t *testing.T, n int) {
	t.Helper()
	for i := range flowSummaryTiers {
		if flowSummaryTiers[i].interval == "1h" {
			i, orig := i, flowSummaryTiers[i].maxPerPass
			flowSummaryTiers[i].maxPerPass = n
			t.Cleanup(func() { flowSummaryTiers[i].maxPerPass = orig })
			return
		}
	}
	t.Fatal("no hourly tier")
}

// starve makes every backfill find its time bound already spent: the pass
// succeeds and builds no history. (The dirty walk is not bounded by it.)
func starve() { flowSummaryMaxCycleDuration = -time.Hour }
func feed()   { flowSummaryMaxCycleDuration = time.Minute }

func hourlyVerdict(d *Database, now, start time.Time) (string, string) {
	th := d.EvaluateFlowSummaryHealth(context.Background(), now, 60, start).Tiers["1h"]
	return th.Verdict, th.StallClass
}

// newerHours adds rows in hours after the built range, so the tier is behind
// again: its fill marker stops short of the newest bucket it owns.
func newerHours(t *testing.T, d *Database, base time.Time, from, n int) {
	t.Helper()
	for h := from; h < from+n; h++ {
		seedSummaryHour(t, d, base, h, 100, "10.0.0.1")
	}
}

// TestFlowSummaryState_RebuildWithoutProgressIsAStall: passes that succeed and
// never move the fill marker are a stall once they have gone on for the
// threshold — the case that used to read "rebuilding" for ever. One pass that
// does move the marker makes it a rebuild again.
func TestFlowSummaryState_RebuildWithoutProgressIsAStall(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	start := *now
	base := time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Hour)
	newerHours(t, d, base, 0, 6)

	starve()
	for i := 0; i < 14; i++ { // 70 minutes of passes that build nothing
		*now = now.Add(5 * time.Minute)
		d.RunFlowSummaryCycle()
	}
	st := summaryState(t, d).Tiers["1h"]
	if st.CaughtUp || !st.FailingSince.IsZero() || st.StuckPasses < 2 {
		t.Fatalf("precondition: want successful passes that build nothing, got %+v", st)
	}
	if v, class := hourlyVerdict(d, *now, start); v != FlowSummaryStalled || class != FlowSummaryStallNoProgress {
		t.Fatalf("after 70 minutes without progress the verdict is %q (%q), want stalled (no_progress)", v, class)
	}

	feed()
	useHourlyCap(t, 1)
	*now = now.Add(5 * time.Minute)
	d.RunFlowSummaryCycle()
	if st := summaryState(t, d).Tiers["1h"]; st.StuckPasses != 0 || !st.ProgressAt.Equal(*now) || st.CaughtUp {
		t.Fatalf("a pass that moved the marker did not restart the clock: %+v", st)
	}
	if v, _ := hourlyVerdict(d, *now, start); v != FlowSummaryCatchingUp {
		t.Fatalf("after the marker moved the verdict is %q, want catching_up", v)
	}
}

// TestFlowSummaryState_CaughtUpPassesKeepTheClockFresh: a caught-up tier's
// marker stands still for hours with nothing wrong. If only a MOVING marker
// stamped progress, the first two starved passes after 20 quiet hours would
// read as 20 hours without progress.
func TestFlowSummaryState_CaughtUpPassesKeepTheClockFresh(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	start := *now
	base, _ := builtSummary(t, d, 3)
	marker := summaryState(t, d).Tiers["1h"].FilledTo

	for i := 0; i < 4; i++ { // 20 hours of caught-up passes
		*now = now.Add(5 * time.Hour)
		d.RunFlowSummaryCycle()
	}
	if st := summaryState(t, d).Tiers["1h"]; !st.CaughtUp || !st.FilledTo.Equal(marker) {
		t.Fatalf("precondition: want a caught-up tier whose marker has not moved, got %+v", st)
	}

	newerHours(t, d, base, 3, 2) // the tier is behind now
	starve()
	for i := 0; i < 2; i++ {
		*now = now.Add(5 * time.Minute)
		d.RunFlowSummaryCycle()
	}
	st := summaryState(t, d).Tiers["1h"]
	if st.CaughtUp || st.StuckPasses != 2 {
		t.Fatalf("precondition: want two starved passes on a tier that is behind, got %+v", st)
	}
	if v, class := hourlyVerdict(d, *now, start); v != FlowSummaryCatchingUp {
		t.Fatalf("ten minutes behind after 20 quiet hours reads %q (%q), want catching_up", v, class)
	}
}

// TestFlowSummaryState_OneStarvedPassIsNotAStall: the tier was last seen
// caught up three hours ago and has not run since (the other tier's long
// walk). Its first pass finds no time left. That is one pass, not three hours
// of them.
func TestFlowSummaryState_OneStarvedPassIsNotAStall(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	start := *now
	base, _ := builtSummary(t, d, 3)

	*now = now.Add(3 * time.Hour) // no cycle in between
	newerHours(t, d, base, 3, 2)
	starve()
	d.RunFlowSummaryCycle()
	st := summaryState(t, d).Tiers["1h"]
	if st.CaughtUp || st.StuckPasses != 1 || now.Sub(st.ProgressAt) < 3*time.Hour {
		t.Fatalf("precondition: want one starved pass with progress three hours old, got %+v", st)
	}
	if v, class := hourlyVerdict(d, *now, start); v != FlowSummaryCatchingUp {
		t.Fatalf("one starved pass reads %q (%q), want catching_up", v, class)
	}
}

// TestFlowSummaryState_FailedPassesDoNotTouchTheStuckCount: a failed pass is
// rule 1's business. It must not add to the count of stuck passes, and it must
// not clear it either — or a tier alternating between failing and stuck would
// be neither. A pass that fails before it knows its range says nothing at all.
func TestFlowSummaryState_FailedPassesDoNotTouchTheStuckCount(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	base, _ := builtSummary(t, d, 3)
	newerHours(t, d, base, 3, 2)
	starve()
	tick := func() *FlowSummaryTierState {
		*now = now.Add(5 * time.Minute)
		d.RunFlowSummaryCycle()
		return summaryState(t, d).Tiers["1h"]
	}
	st := tick()
	progress := st.ProgressAt
	if st.StuckPasses != 1 {
		t.Fatalf("precondition: stuck passes = %d, want 1", st.StuckPasses)
	}

	// A failed pass WITH bounds: a changed bucket whose rebuild fails.
	seedSummaryHour(t, d, base, 1, 50, "10.0.0.5")
	flowSummaryBucketHook = func(interval string, b time.Time) error {
		if interval == "1h" && b.Equal(base.Add(time.Hour)) {
			return errors.New("poison bucket")
		}
		return nil
	}
	if st = tick(); st.FailingSince.IsZero() || st.StuckPasses != 1 || !st.ProgressAt.Equal(progress) {
		t.Fatalf("a failed pass with bounds changed the stuck count or the clock: %+v", st)
	}
	flowSummaryBucketHook = nil

	// A failed pass WITHOUT bounds: the changed-rows scan fails.
	flowSummaryDirtyHook = func(interval string) error {
		if interval == "1h" {
			return errors.New("scan failed")
		}
		return nil
	}
	if st = tick(); st.StuckPasses != 1 || !st.ProgressAt.Equal(progress) {
		t.Fatalf("a pass that failed before knowing its range changed the stuck count or the clock: %+v", st)
	}
	flowSummaryDirtyHook = nil

	if st = tick(); st.StuckPasses != 2 || !st.ProgressAt.Equal(progress) {
		t.Fatalf("the next stuck pass did not continue the count: %+v", st)
	}
}

// TestFlowSummaryState_LongBackfillAtOneBucketAPassIsNotAStall replaces the
// "every pass stops at once" version of this test, which the stuck-rebuild
// rule now (rightly) calls a stall: here the marker advances on every pass,
// for hours, and that is a rebuild.
func TestFlowSummaryState_LongBackfillAtOneBucketAPassIsNotAStall(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	start := *now
	base := time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Hour)
	newerHours(t, d, base, 0, 6)
	useHourlyCap(t, 1)

	for i := 0; i < 5; i++ { // five passes, 40 minutes apart: 3 h 20 min
		*now = now.Add(40 * time.Minute)
		d.RunFlowSummaryCycle()
		if v, class := hourlyVerdict(d, *now, start); v != FlowSummaryCatchingUp {
			t.Fatalf("pass %d of a moving backfill reads %q (%q), want catching_up", i+1, v, class)
		}
	}
	*now = now.Add(40 * time.Minute)
	d.RunFlowSummaryCycle()
	if v, _ := hourlyVerdict(d, *now, start); v != FlowSummaryOK {
		t.Fatalf("after the last bucket the verdict is %q, want ok", v)
	}
}

// TestFlowSummaryCycle_PanicOutsideATierIsContained: the two steps that run
// outside any tier. A panic in the first used to end the cycle before any tier
// ran; in the second, after — either way under the poller's recover, with the
// cycle's own start stamp still saying the summariser was alive.
func TestFlowSummaryCycle_PanicOutsideATierIsContained(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := useSummaryClock(t)
	base, _ := builtSummary(t, d, 3)
	t.Cleanup(func() { flowSummaryConsumeHook, flowSummaryRecomputeHook = nil, nil })

	*now = now.Add(5 * time.Minute)
	flowSummaryConsumeHook = func() { panic("nil map in the request step") }
	d.RunFlowSummaryCycle() // must not panic
	flowSummaryConsumeHook = nil
	st := summaryState(t, d)
	for _, iv := range []string{"1d", "1h"} {
		if ts := st.Tiers[iv]; ts == nil || !ts.LastPassAt.Equal(*now) || !ts.LastOKAt.Equal(*now) {
			t.Fatalf("after a panic in the request step the %s tier did not run: %+v (now %v)", iv, ts, *now)
		}
	}

	// The recompute step: give it a walk to do (no reclassification due, a
	// cursor to walk from), and make the walk panic.
	for k, v := range map[string]string{FlowReclassDoneRevKey: "1", FlowReclassTargetRevKey: "1"} {
		if err := d.setReclassSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	mark := recomputeMark{rev: 1, bucket: base}.String()
	if err := d.setReclassSetting(recomputeCursorKey("1h"), mark); err != nil {
		t.Fatal(err)
	}
	walked := false
	flowSummaryRecomputeHook = func(string, time.Time) error { walked = true; panic("nil map in the recompute step") }
	*now = now.Add(5 * time.Minute)
	d.RunFlowSummaryCycle() // must not panic
	if !walked {
		t.Fatal("precondition: the recompute step did not reach its walk")
	}
	if ts := summaryState(t, d).Tiers["1h"]; !ts.LastOKAt.Equal(*now) {
		t.Fatalf("the hourly tier's pass was not recorded before the recompute step panicked: %+v", ts)
	}
}

// TestFlowSummaryRecompute_NullStatusEntriesDoNotPanic: a stored status with a
// null tier (and a stray key) used to be dereferenced on every cycle.
func TestFlowSummaryRecompute_NullStatusEntriesDoNotPanic(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useSummaryClock(t)
	base, _ := builtSummary(t, d, 3)
	if err := d.setReclassSetting(flowSummaryRecomputeStatusKey, `{"rev":1,"tiers":{"1h":null,"x":null}}`); err != nil {
		t.Fatal(err)
	}
	// A cursor, so the step has work and writes the status back.
	if err := d.setReclassSetting(recomputeCursorKey("1h"), recomputeMark{rev: 1, bucket: base}.String()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the recompute step panicked on a null status entry: %v", r)
		}
	}()
	d.runSummaryRecompute(flowSummaryTiers, map[string]tierBounds{}, time.Now().Add(time.Minute), nil)
	if st := d.GetFlowSummaryRecomputeStatus(); st.Tiers["1h"] == nil || st.Tiers["x"] != nil {
		t.Fatalf("the status was not rewritten without its null entries: %+v", st.Tiers)
	}
}

// reclassDoneFixture is a built summary with a reclassification at revision 3
// complete, so the recompute step is free to run.
func reclassDoneFixture(t *testing.T) (*Database, time.Time) {
	t.Helper()
	d := NewDatabaseForTesting(t)
	useSummaryClock(t)
	base, _ := builtSummary(t, d, 4)
	for k, v := range map[string]string{FlowReclassDoneRevKey: "3", FlowReclassTargetRevKey: "3"} {
		if err := d.setReclassSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	return d, base
}

func settingRaw(t *testing.T, d *Database, key string) (string, bool) {
	t.Helper()
	vals, err := d.SettingValues(context.Background(), []string{key})
	if err != nil {
		t.Fatal(err)
	}
	v, ok := vals[key]
	return v, ok
}

// failReadsOf fails every strict settings read that includes key.
func failReadsOf(key string) {
	flowSummarySettingsHook = func(keys []string) error {
		if settingKeyIn(keys, key) {
			return errors.New("connection reset")
		}
		return nil
	}
}

// TestFlowSummaryRecompute_RequestSurvivesAFailedCursorRead: the request is
// merged with the tier's cursor — the EARLIER bucket wins. Read the cursor as
// absent and the request's later bucket replaces it, the request is deleted,
// and the buckets in between are never recomputed.
func TestFlowSummaryRecompute_RequestSurvivesAFailedCursorRead(t *testing.T) {
	d, base := reclassDoneFixture(t)
	early := recomputeMark{rev: 3, bucket: base}.String()
	late := recomputeMark{rev: 3, bucket: base.Add(3 * time.Hour)}.String()
	if err := d.setReclassSetting(recomputeCursorKey("1h"), early); err != nil {
		t.Fatal(err)
	}
	if err := d.setReclassSetting(flowSummaryRecomputeRequestKey, late); err != nil {
		t.Fatal(err)
	}

	failReadsOf(recomputeCursorKey("1h"))
	d.consumeRecomputeRequest()
	if got, _ := settingRaw(t, d, recomputeCursorKey("1h")); got != early {
		t.Fatalf("after a failed read the cursor is %q, want it untouched at %q", got, early)
	}
	if got, ok := settingRaw(t, d, flowSummaryRecomputeRequestKey); !ok || got != late {
		t.Fatalf("after a failed read the request is %q (present %v), want it kept", got, ok)
	}

	flowSummarySettingsHook = nil
	d.consumeRecomputeRequest()
	if got, _ := settingRaw(t, d, recomputeCursorKey("1h")); got != early {
		t.Fatalf("after the merge the cursor is %q, want the earlier bucket %q", got, early)
	}
	if _, ok := settingRaw(t, d, flowSummaryRecomputeRequestKey); ok {
		t.Fatal("the request was not consumed once the read succeeded")
	}
}

// TestFlowSummaryRecompute_GarbledCursorIsAbsentNotAnError: strict means the
// READ. A cursor that was read and does not parse is replaced by the request,
// as it always was; treating it as an error would abort every cycle for good.
func TestFlowSummaryRecompute_GarbledCursorIsAbsentNotAnError(t *testing.T) {
	d, base := reclassDoneFixture(t)
	req := recomputeMark{rev: 3, bucket: base.Add(time.Hour)}.String()
	if err := d.setReclassSetting(recomputeCursorKey("1h"), "not a cursor"); err != nil {
		t.Fatal(err)
	}
	if err := d.setReclassSetting(flowSummaryRecomputeRequestKey, req); err != nil {
		t.Fatal(err)
	}
	d.consumeRecomputeRequest()
	if got, _ := settingRaw(t, d, recomputeCursorKey("1h")); got != req {
		t.Fatalf("a garbled cursor was left at %q, want the request %q", got, req)
	}
	if _, ok := settingRaw(t, d, flowSummaryRecomputeRequestKey); ok {
		t.Fatal("the request was not consumed")
	}
}

// TestFlowSummaryRecompute_RetryListSurvivesAFailedRead: the retry list holds
// buckets whose recompute failed. Read it as empty and it is SAVED as empty —
// which deletes it — and the tier then finishes "done" with those buckets
// still holding pre-reclassification rows.
func TestFlowSummaryRecompute_RetryListSurvivesAFailedRead(t *testing.T) {
	d, base := reclassDoneFixture(t)
	t.Cleanup(func() { flowSummaryRecomputeHook = nil })
	list := fmt.Sprintf(`["%s"]`, base.Add(time.Hour).Format(time.RFC3339))
	// A cursor as well, at the last bucket: with the walk still in progress
	// the step SAVES the retry list when it is done with it — which is where
	// a list read as empty was written back as "nothing to retry".
	cursor := recomputeMark{rev: 3, bucket: base.Add(3 * time.Hour)}.String()
	set := func() {
		t.Helper()
		if err := d.setReclassSetting(recomputeRetryKey("1h"), list); err != nil {
			t.Fatal(err)
		}
		if err := d.setReclassSetting(recomputeCursorKey("1h"), cursor); err != nil {
			t.Fatal(err)
		}
		d.deleteSetting(recomputeDoneKey("1h"))
	}

	// Control: with the read working, the bucket is retried and the list goes.
	set()
	d.RunFlowSummaryCycle()
	if _, ok := settingRaw(t, d, recomputeRetryKey("1h")); ok {
		t.Fatal("precondition: this fixture does not clear the retry list when the read works")
	}

	set()
	failReadsOf(recomputeRetryKey("1h"))
	d.RunFlowSummaryCycle()
	if got, ok := settingRaw(t, d, recomputeRetryKey("1h")); !ok || got != list {
		t.Fatalf("after a failed read the retry list is %q (present %v), want it kept as %q", got, ok, list)
	}
	if _, done := settingRaw(t, d, recomputeDoneKey("1h")); done {
		t.Fatal("the tier was marked done on a retry list it could not read")
	}
	if got, _ := settingRaw(t, d, recomputeCursorKey("1h")); got != cursor {
		t.Fatalf("the cursor moved to %q on a cycle that could not read the tier's state", got)
	}
}

// TestFlowSummaryRecompute_ServiceBoundaryNeedsEveryReadToSucceed: removing
// flow_summary_service_since cannot be undone. Each fact it rests on — is a
// request pending, is a reclassification due or running, is anything left to
// retry — used to read as "no" when the read failed.
func TestFlowSummaryRecompute_ServiceBoundaryNeedsEveryReadToSucceed(t *testing.T) {
	arm := func(t *testing.T) *Database {
		t.Helper()
		d, _ := reclassDoneFixture(t)
		for k, v := range map[string]string{
			flowSummaryServiceSinceKey: time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339),
			recomputeDoneKey("1h"):     "3", recomputeDoneKey("1d"): "3",
		} {
			if err := d.setReclassSetting(k, v); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}

	// Control: everything rebuilt for the current revision — the boundary goes.
	d := arm(t)
	d.maybeClearServiceSince()
	if _, ok := settingRaw(t, d, flowSummaryServiceSinceKey); ok {
		t.Fatal("precondition: this fixture does not clear the boundary when every read works")
	}

	d = arm(t)
	failReadsOf(FlowReclassTargetRevKey)
	d.maybeClearServiceSince()
	if _, ok := settingRaw(t, d, flowSummaryServiceSinceKey); !ok {
		t.Fatal("the boundary was removed although the reclassification target could not be read")
	}
	flowSummarySettingsHook = nil

	// And each fact still holds it when it IS readable.
	for name, hold := range map[string]func(d *Database) error{
		"a request pending": func(d *Database) error {
			return d.setReclassSetting(flowSummaryRecomputeRequestKey, "3|2026-01-01T00:00:00Z")
		},
		"a reclassification due":            func(d *Database) error { return d.setReclassSetting(FlowReclassTargetRevKey, "4") },
		"a reclassification running":        func(d *Database) error { return d.setReclassSetting(flowReclassStateKey, `{"rev":4}`) },
		"a tier done for an older revision": func(d *Database) error { return d.setReclassSetting(recomputeDoneKey("1d"), "2") },
		"a cursor": func(d *Database) error {
			return d.setReclassSetting(recomputeCursorKey("1h"), "3|2026-01-01T00:00:00Z")
		},
		"buckets to retry": func(d *Database) error {
			return d.setReclassSetting(recomputeRetryKey("1d"), `["2026-01-01T00:00:00Z"]`)
		},
	} {
		d := arm(t)
		if err := hold(d); err != nil {
			t.Fatal(err)
		}
		d.maybeClearServiceSince()
		if _, ok := settingRaw(t, d, flowSummaryServiceSinceKey); !ok {
			t.Errorf("the boundary was removed with %s", name)
		}
	}
}

// TestFlowSummaryRecompute_StatusIsNotOverwrittenWhenItCannotBeRead: the
// status is history. A cycle that cannot read it must not replace it with
// this cycle's zeroes.
func TestFlowSummaryRecompute_StatusIsNotOverwrittenWhenItCannotBeRead(t *testing.T) {
	d, base := reclassDoneFixture(t)
	t.Cleanup(func() { flowSummaryRecomputeHook = nil })
	stored := `{"rev":3,"tiers":{"1h":{"state":"rebuilding","remaining_buckets":7,"done_buckets":41,"buckets_per_cycle":9.5}},"updated_at":"2026-01-01T00:00:00Z"}`
	arm := func() {
		t.Helper()
		if err := d.setReclassSetting(flowSummaryRecomputeStatusKey, stored); err != nil {
			t.Fatal(err)
		}
		if err := d.setReclassSetting(recomputeCursorKey("1h"), recomputeMark{rev: 3, bucket: base}.String()); err != nil {
			t.Fatal(err)
		}
	}

	// Control: with the read working, an active rebuild rewrites the status.
	arm()
	d.RunFlowSummaryCycle()
	if got, _ := settingRaw(t, d, flowSummaryRecomputeStatusKey); got == stored {
		t.Fatal("precondition: this fixture does not rewrite the status when the read works")
	}

	arm()
	failReadsOf(flowSummaryRecomputeStatusKey)
	d.RunFlowSummaryCycle()
	if got, _ := settingRaw(t, d, flowSummaryRecomputeStatusKey); got != stored {
		t.Fatalf("the status was overwritten on a failed read:\nwas: %s\nnow: %s", stored, got)
	}
}

// TestFlowSummaryVerdict_NoProgress pins the rule itself, apart from how the
// summariser fills the fields.
func TestFlowSummaryVerdict_NoProgress(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	ago := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	start := ago(600)
	tier := func(stuck int, progress time.Time) *FlowSummaryState {
		return &FlowSummaryState{CycleProgressAt: ago(1), Tiers: map[string]*FlowSummaryTierState{"1h": {
			LastPassAt: ago(1), LastOKAt: ago(1), CaughtUp: false, StuckPasses: stuck, ProgressAt: progress}}}
	}
	for _, c := range []struct {
		name      string
		st        *FlowSummaryState
		start     time.Time
		want, cls string
	}{
		{"stuck for the threshold", tier(12, ago(60)), start, FlowSummaryStalled, FlowSummaryStallNoProgress},
		{"stuck, just under the threshold", tier(11, ago(59)), start, FlowSummaryCatchingUp, ""},
		{"one stuck pass, however old the progress", tier(1, ago(600)), start, FlowSummaryCatchingUp, ""},
		{"moving", tier(0, ago(1)), start, FlowSummaryCatchingUp, ""},
		// Progress recorded before this process started is not this process's
		// evidence: the clock starts at the restart.
		{"stuck since before a restart 20 minutes ago", tier(5, ago(300)), ago(20), FlowSummaryCatchingUp, ""},
		// The fields are absent after an upgrade: zero progress time, measured
		// from the start.
		{"no progress time recorded, started 30 minutes ago", tier(3, time.Time{}), ago(30), FlowSummaryCatchingUp, ""},
	} {
		v, cls := flowSummaryJudge(c.st, "1h", now, time.Hour, c.start, true)
		if v != c.want || cls != c.cls {
			t.Errorf("%s: verdict %q (%q), want %q (%q)", c.name, v, cls, c.want, c.cls)
		}
	}
	// The other two causes name themselves too.
	failing := &FlowSummaryState{CycleProgressAt: ago(1), Tiers: map[string]*FlowSummaryTierState{"1h": {
		LastPassAt: ago(1), LastOKAt: ago(90), FailingSince: ago(85), ConsecutiveFailures: 9, CaughtUp: true}}}
	if v, cls := flowSummaryJudge(failing, "1h", now, time.Hour, start, true); v != FlowSummaryStalled || cls != FlowSummaryStallFailing {
		t.Errorf("failing for the threshold: %q (%q)", v, cls)
	}
	hung := &FlowSummaryState{CycleProgressAt: ago(75), Tiers: map[string]*FlowSummaryTierState{"1h": {
		LastPassAt: ago(80), LastOKAt: ago(80), CaughtUp: true}}}
	if v, cls := flowSummaryJudge(hung, "1h", now, time.Hour, start, true); v != FlowSummaryStalled || cls != FlowSummaryStallNoCycle {
		t.Errorf("no cycle alive: %q (%q)", v, cls)
	}
}
