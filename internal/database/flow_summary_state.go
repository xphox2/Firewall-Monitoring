package database

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The flow summary's health record.
//
// WHY this exists: on 2026-10-25 the hourly tier began failing every pass and
// kept failing for a month. The only sign was one log line every five minutes;
// the Flows page showed long windows as "partial" with nothing to say why, and
// nobody was told. The summariser's progress markers could not answer "is it
// working?" either — the watermark is written by a pass that owns nothing and
// by the first-pass arm of a pass that failed. So each pass now records what
// it did, a verdict is derived from that record, and the verdict feeds a
// banner on the Flows page and an alert (cmd/poller/flowsummaryalerts.go).
//
// Two settings, two writers:
//
//	flow_summary_state   written by the summariser, under its advisory lock
//	flow_summary_health  written by the poller's server-health tick: the
//	                     verdicts, as evaluated there
//
// The API serves the second and never evaluates. A verdict needs the poller's
// start time (a record from before a restart says nothing about this process),
// and the API is a different binary that does not know it.
const (
	FlowSummaryStateKey  = "flow_summary_state"
	FlowSummaryHealthKey = "flow_summary_health"
)

// Verdicts, in the order flowSummaryVerdict decides them.
const (
	FlowSummaryUnknown    = "unknown"     // cannot be judged: neither alert nor all-clear
	FlowSummaryStalled    = "stalled"     // failing for the threshold, or no cycle alive for it
	FlowSummaryFailing    = "failing"     // the latest pass failed, more recently than that
	FlowSummaryCatchingUp = "catching_up" // passes succeed; history is still being built
	FlowSummaryOK         = "ok"
)

// Error classes recorded for a failed pass. A class, never the error text: the
// record is served to browsers, and a database error quotes SQL.
const (
	flowSummaryErrSettings = "settings"
	flowSummaryErrTimeout  = "timeout"
	flowSummaryErrBucket   = "bucket"
	flowSummaryErrPanic    = "panic"
	flowSummaryErrQuery    = "query"
)

var errSummaryPanic = errors.New("flow summary panic")

// FlowSummaryDefaultStallMinutes is the stall threshold when the operator has
// not set one, and the threshold the VERDICT uses when alerting is switched
// off (0): the banner still has to tell a stalled tier from a healthy one.
const FlowSummaryDefaultStallMinutes = 60

// flowSummaryHealthMaxAge is how old stored verdicts may be before a reader
// stops repeating them. The poller evaluates every five minutes; three missed
// evaluations means it is stopped or wedged.
const flowSummaryHealthMaxAge = 15 * time.Minute

// flowSummaryProgressEvery throttles the liveness write inside a pass.
const flowSummaryProgressEvery = 30 * time.Second

// flowSummaryNow is the health record's clock, a variable so tests can move it.
var flowSummaryNow = time.Now

// flowSummaryStateWrite persists the health record; a variable so a test can
// make it fail. It is the ONLY write the record makes.
var flowSummaryStateWrite = func(d *Database, value string) error {
	return d.UpsertSetting(&models.SystemSetting{
		Key: FlowSummaryStateKey, Value: value, Category: "system", Type: "json",
		Label: "Flow summary health record",
	})
}

// FlowSummaryState is what the summariser records about its own passes.
type FlowSummaryState struct {
	// CycleProgressAt is the last moment a cycle was seen doing work: at its
	// start, at each tier's end and, throttled, from inside the long loops.
	//
	// Cycle-wide on purpose. The dirty walk is unbounded by design, so one
	// tier can legitimately work for an hour while the other sits idle and the
	// poller skips every tick in between; a per-tier liveness stamp would call
	// the idle tier dead.
	CycleProgressAt time.Time                        `json:"cycle_progress_at"`
	Tiers           map[string]*FlowSummaryTierState `json:"tiers"`
}

// FlowSummaryTierState is one tier's record, written when its pass ends.
type FlowSummaryTierState struct {
	LastPassAt time.Time `json:"last_pass_at"`
	// LastOKAt is the end of the last pass that returned no error. A pass that
	// owned nothing, or stopped on the time bound mid-backfill, succeeded.
	LastOKAt time.Time `json:"last_ok_at"`
	// FailingSince is set by the first failed pass after a success and cleared
	// by the next success, so it marks the start of the current run of failures.
	FailingSince        time.Time `json:"failing_since"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastErrorClass      string    `json:"last_error_class,omitempty"`
	// CaughtUp: the contiguous backfill has reached the tier's last owned
	// bucket — or the tier owns nothing, which is also nothing left to build.
	CaughtUp bool      `json:"caught_up"`
	OwnedTo  time.Time `json:"owned_to"`
	FilledTo time.Time `json:"filled_to"`
	// ProgressAt and StuckPasses answer "is a tier that is behind getting
	// anywhere?". A tier whose dirty walk uses the whole cycle deadline every
	// time never errors and never builds a bucket of history; without these it
	// read as "rebuilding" for ever.
	//
	// ProgressAt is stamped when the fill marker MOVED (a reset counts: the
	// tier is working again from the start), when a pass ended caught up or
	// owning nothing, and when the tier is first recorded. It is NOT "when the
	// marker last moved": a caught-up tier's marker stands still for an hour
	// (hourly) or a day (daily) with nothing wrong, so the clock has to restart
	// on every caught-up pass or one starved pass afterwards would look like a
	// day without progress.
	//
	// StuckPasses counts consecutive SUCCESSFUL passes that ended behind with
	// the marker where it was. A failed pass neither adds to it nor clears it:
	// failures are rule 1's, and letting one clear the count would let a tier
	// alternating between failing and stuck escape both rules.
	ProgressAt  time.Time `json:"progress_at"`
	StuckPasses int       `json:"stuck_passes"`
}

// summaryReporter keeps the health record for one cycle. progress, tierDone
// and flush are safe on a nil receiver, and none of them can fail a pass: the record describes
// the summariser, it must never be a reason the summariser did less.
type summaryReporter struct {
	d         *Database
	state     FlowSummaryState
	lastWrite time.Time
	// loaded is false until the previous record has been read. Nothing is
	// written before that (see load).
	loaded bool
}

// newSummaryReporter starts the cycle's record: load the previous one and
// stamp the cycle's start.
func (d *Database) newSummaryReporter() *summaryReporter {
	r := &summaryReporter{d: d}
	if r.load() {
		r.write(flowSummaryNow())
	}
	return r
}

// load reads the previous record, once. While it cannot be READ, nothing is
// written: a fresh record would erase last_ok_at, and with it the evidence of
// how long a tier has been failing. It is tried again on every later call, so
// one failed read at the start of an hour-long pass does not leave the whole
// pass looking dead. A record that was read but does not PARSE is different —
// it never will, so it is replaced; left alone it would make every verdict
// "unknown" for good.
func (r *summaryReporter) load() bool {
	if r.loaded {
		return true
	}
	st, present, err := r.d.flowSummaryState(context.Background())
	if err != nil && !present {
		log.Printf("Flow summary: health record unreadable, not updated yet: %v", err)
		return false
	}
	if err != nil {
		log.Printf("Flow summary: health record corrupt, starting a new one: %v", err)
		st = nil
	}
	if st != nil {
		r.state = *st
	}
	if r.state.Tiers == nil {
		r.state.Tiers = map[string]*FlowSummaryTierState{}
	}
	r.loaded = true
	return true
}

// progress records that the cycle is alive, at most once per
// flowSummaryProgressEvery.
func (r *summaryReporter) progress() {
	if r == nil {
		return
	}
	if now := flowSummaryNow(); now.Sub(r.lastWrite) >= flowSummaryProgressEvery {
		// lastWrite moves even when the load fails, so an unreadable record
		// is retried at the throttle's pace and not once per bucket.
		r.lastWrite = now
		if r.load() {
			r.write(now)
		}
	}
}

// tierDone records the outcome of one tier's pass.
func (r *summaryReporter) tierDone(interval string, b tierBounds, err error) {
	if r == nil || !r.load() {
		return
	}
	now := flowSummaryNow().UTC()
	ts := r.state.Tiers[interval]
	first := ts == nil
	if first {
		ts = &FlowSummaryTierState{ProgressAt: now}
		r.state.Tiers[interval] = ts
	}
	ts.LastPassAt = now
	if err == nil {
		ts.LastOKAt = now
		ts.FailingSince = time.Time{}
		ts.ConsecutiveFailures = 0
		ts.LastErrorClass = ""
	} else {
		if ts.FailingSince.IsZero() {
			ts.FailingSince = now
		}
		ts.ConsecutiveFailures++
		ts.LastErrorClass = summaryErrorClass(err)
	}
	// A pass that failed before it knew its range returns zero bounds, which
	// say nothing: keep what the last pass that did know recorded.
	if err == nil || b.ownsNothing || !b.ownedTo.IsZero() {
		caughtUp := b.caughtUp || b.ownsNothing
		// Compared BEFORE FilledTo is overwritten, and only here: outside this
		// guard a zero-bounds pass would compare a zero marker with the stored
		// one and count as movement.
		moved := !b.filled.UTC().Equal(ts.FilledTo)
		switch {
		case moved || caughtUp || first:
			ts.ProgressAt, ts.StuckPasses = now, 0
		case err == nil:
			ts.StuckPasses++
		}
		ts.CaughtUp = caughtUp
		ts.OwnedTo = b.ownedTo.UTC()
		ts.FilledTo = b.filled.UTC()
	}
	r.write(now)
}

func (r *summaryReporter) flush() {
	if r != nil && r.load() {
		r.write(flowSummaryNow())
	}
}

func (r *summaryReporter) write(now time.Time) {
	r.state.CycleProgressAt = now.UTC()
	r.lastWrite = now
	js, err := json.Marshal(r.state)
	if err == nil {
		err = flowSummaryStateWrite(r.d, string(js))
	}
	if err != nil {
		log.Printf("Flow summary: health record not saved: %v", err)
	}
}

// summaryErrorClass names why a pass failed without repeating the error.
func summaryErrorClass(err error) string {
	msg := err.Error()
	switch {
	case errors.Is(err, errSummaryPanic):
		return flowSummaryErrPanic
	case errors.Is(err, errSummarySettings):
		return flowSummaryErrSettings
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		strings.Contains(msg, "57014"), strings.Contains(msg, "statement timeout"):
		return flowSummaryErrTimeout
	case strings.HasPrefix(msg, "bucket "):
		return flowSummaryErrBucket
	default:
		return flowSummaryErrQuery
	}
}

// flowSummaryState reads the record. present is false when it was never
// written; err is a failed read or a record that does not parse.
func (d *Database) flowSummaryState(ctx context.Context) (st *FlowSummaryState, present bool, err error) {
	vals, err := d.summarySettings(ctx, FlowSummaryStateKey)
	if err != nil {
		return nil, false, err
	}
	raw, ok := vals[FlowSummaryStateKey]
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, false, nil
	}
	st = &FlowSummaryState{}
	if err := json.Unmarshal([]byte(raw), st); err != nil {
		return nil, true, err
	}
	return st, true, nil
}

// flowSummaryVerdict judges one tier. It is an ORDERED decision: each rule
// assumes the ones above it did not apply.
//
// st is nil when the record was never written. processStart is when the
// evaluating poller started; `since` — what "how long without a success" is
// measured from — is never earlier than that, so downtime or a restored backup
// cannot page at boot for time the summariser was not running.
func flowSummaryVerdict(st *FlowSummaryState, interval string, now time.Time, threshold time.Duration, processStart time.Time, rollupsExist bool) string {
	verdict, _ := flowSummaryJudge(st, interval, now, threshold, processStart, rollupsExist)
	return verdict
}

// Why a tier is stalled (FlowSummaryTierHealth.StallClass). The three causes
// read differently to an operator and are handled differently by the poller.
const (
	FlowSummaryStallFailing    = "failing"     // passes keep failing
	FlowSummaryStallNoCycle    = "no_cycle"    // no summary cycle shows signs of life
	FlowSummaryStallNoProgress = "no_progress" // passes succeed; the rebuild does not move
)

// flowSummaryJudge is flowSummaryVerdict with the cause of a stall.
func flowSummaryJudge(st *FlowSummaryState, interval string, now time.Time, threshold time.Duration, processStart time.Time, rollupsExist bool) (verdict, stallClass string) {
	var tier *FlowSummaryTierState
	var cycleAt time.Time
	if st != nil {
		tier, cycleAt = st.Tiers[interval], st.CycleProgressAt
	}
	laterOf := func(a, b time.Time) time.Time {
		if a.After(b) {
			return a
		}
		return b
	}
	failing := tier != nil && !tier.FailingSince.IsZero()

	// 1. The latest pass — one made by THIS process — failed, and there has
	// been no success for the threshold. Progress does NOT excuse this: a pass
	// that fails still walks its other buckets, so a tier with one poison
	// bucket is busy every cycle and broken every cycle. A failure recorded
	// before a restart is not evidence about this process (rule 4 still shows
	// it as failing). And it takes TWO failures in a row: a tier that sat idle
	// for hours behind the other tier's walk has an old last_ok_at through no
	// fault of its own, and one failed pass after that is a single failure,
	// not hours of them — paging on it would also start the alert's cooldown
	// and mute a real stall that began soon after.
	if failing && tier.ConsecutiveFailures >= 2 && tier.LastPassAt.After(processStart) &&
		now.Sub(laterOf(tier.LastOKAt, processStart)) >= threshold {
		return FlowSummaryStalled, FlowSummaryStallFailing
	}
	// 2. No cycle has run in this process yet. The record is from before the
	// restart: it can neither confirm a stall nor clear one, and above all it
	// must not resolve an open alert on the strength of an old "ok".
	if !cycleAt.After(processStart) && now.Sub(processStart) < threshold {
		return FlowSummaryUnknown, ""
	}
	// 3. There is work to summarise and no cycle has shown signs of life for
	// the threshold: a pass that hung, or a summariser that never runs (an old
	// poller holding the lock, a panic before the first write). Both tiers.
	if rollupsExist && now.Sub(laterOf(cycleAt, processStart)) >= threshold {
		return FlowSummaryStalled, FlowSummaryStallNoCycle
	}
	// 4. Failed, but not for long enough to call it stalled.
	if failing {
		return FlowSummaryFailing, ""
	}
	// 5. The tier's last good pass is not RECENT evidence: it predates this
	// process, or it is older than the threshold. A cycle that has merely
	// started stamps cycle_progress_at, so rules 2 and 3 pass while this
	// tier's record is still an old "ok" — from before a restart, or from
	// before a hang that rule 3 alerted on. Calling that ok would resolve the
	// open alert with no pass since; if the pass now under way then failed,
	// the alert's cooldown would keep it from being raised again for hours.
	// Unknown neither raises nor resolves. (A tier idle behind the other
	// tier's hours-long walk lands here too, which is right: nothing has been
	// learned about it.)
	if tier == nil || !tier.LastPassAt.After(processStart) || now.Sub(tier.LastPassAt) >= threshold {
		return FlowSummaryUnknown, ""
	}
	// 6. Passes succeed but history is still being built; long windows are
	// served by the live read meanwhile. A pass IN FLIGHT does not put a
	// caught-up tier here — that would show "rebuilding" during every routine
	// pass.
	if !tier.CaughtUp {
		// ...unless it is behind and not moving: at least two successful
		// passes in a row left the fill marker where it was, and it has been
		// the threshold since the tier last got anywhere (see ProgressAt).
		// Two passes, because one pass that found no time left (the other
		// tier's long walk, a busy cycle at an hour boundary) is routine.
		if tier.StuckPasses >= 2 && now.Sub(laterOf(tier.ProgressAt, processStart)) >= threshold {
			return FlowSummaryStalled, FlowSummaryStallNoProgress
		}
		return FlowSummaryCatchingUp, ""
	}
	return FlowSummaryOK, ""
}

// FlowSummaryHealth is the poller's evaluation, as stored for the API.
type FlowSummaryHealth struct {
	EvaluatedAt time.Time `json:"evaluated_at"`
	// Stale is set by the reader, not stored: the evaluation is older than
	// flowSummaryHealthMaxAge, so the poller is stopped or wedged and the
	// verdicts below describe the past.
	Stale bool `json:"stale"`
	// ThresholdMinutes is the stall threshold this evaluation used, so the
	// next one can use the same yardstick if it cannot read the setting.
	ThresholdMinutes int `json:"threshold_minutes,omitempty"`
	// LongWindowsLive: at the evaluation, windows the summary would serve were
	// being read live instead (summaryBackfillComplete was false).
	//
	// One flag for the whole summary, NOT derived from a tier's CaughtUp: the
	// read path is all-or-nothing across tiers. A caught-up hourly tier that
	// fails on one bucket is still served — unless the daily tier is behind,
	// in which case nothing is. Judging "is it read live?" per tier told the
	// operator the opposite of what the page was doing in exactly that case.
	//
	// A pointer: nil when the probe behind it failed, so that one failed
	// query is not written into an alert as "read live".
	LongWindowsLive *bool                            `json:"long_windows_live,omitempty"`
	Tiers           map[string]FlowSummaryTierHealth `json:"tiers"`
}

// FlowSummaryTierHealth is one tier's verdict and what the banner needs to
// phrase it.
type FlowSummaryTierHealth struct {
	Verdict string `json:"verdict"`
	// StallClass says why a stalled tier is stalled (FlowSummaryStall*).
	StallClass string `json:"stall_class,omitempty"`
	// ProgressAt is when a tier that is behind last got anywhere.
	ProgressAt     time.Time `json:"progress_at"`
	LastOKAt       time.Time `json:"last_ok_at"`
	FailingSince   time.Time `json:"failing_since"`
	CaughtUp       bool      `json:"caught_up"`
	FilledTo       time.Time `json:"filled_to"`
	OwnedTo        time.Time `json:"owned_to"`
	LastErrorClass string    `json:"last_error_class,omitempty"`
}

// EvaluateFlowSummaryHealth judges every tier from the summariser's record.
// thresholdMinutes <= 0 means alerting is off; the verdict is still computed,
// against the default (see FlowSummaryDefaultStallMinutes).
//
// It does not fail: a record or a probe that cannot be read yields "unknown"
// for the tiers it would have judged, which is the honest answer.
func (d *Database) EvaluateFlowSummaryHealth(ctx context.Context, now time.Time, thresholdMinutes int, processStart time.Time) FlowSummaryHealth {
	if thresholdMinutes <= 0 {
		thresholdMinutes = FlowSummaryDefaultStallMinutes
	}
	threshold := time.Duration(thresholdMinutes) * time.Minute
	h := FlowSummaryHealth{EvaluatedAt: now.UTC(), ThresholdMinutes: thresholdMinutes, Tiers: map[string]FlowSummaryTierHealth{}}
	if complete, err := d.WithContext(ctx).summaryBackfillState(); err == nil {
		live := !complete
		h.LongWindowsLive = &live
	} else {
		log.Printf("Flow summary: read-path probe failed: %v", err)
	}

	st, _, stErr := d.flowSummaryState(ctx)
	rollupsExist, probeErr := d.flowRollupsExist(ctx)
	if stErr != nil {
		log.Printf("Flow summary: health record unreadable: %v", stErr)
	}
	if probeErr != nil {
		log.Printf("Flow summary: rollup probe failed: %v", probeErr)
	}
	for _, tier := range flowSummaryTiers {
		th := FlowSummaryTierHealth{Verdict: FlowSummaryUnknown}
		if stErr == nil && probeErr == nil {
			th.Verdict, th.StallClass = flowSummaryJudge(st, tier.interval, now, threshold, processStart, rollupsExist)
		}
		if st != nil {
			if ts := st.Tiers[tier.interval]; ts != nil {
				th.LastOKAt, th.FailingSince, th.CaughtUp = ts.LastOKAt, ts.FailingSince, ts.CaughtUp
				th.FilledTo, th.OwnedTo, th.LastErrorClass = ts.FilledTo, ts.OwnedTo, ts.LastErrorClass
				th.ProgressAt = ts.ProgressAt
			}
		}
		h.Tiers[tier.interval] = th
	}
	return h
}

// flowRollupsExist is an existence probe (one id, not a count).
func (d *Database) flowRollupsExist(ctx context.Context) (bool, error) {
	var probe []uint
	err := d.db.WithContext(ctx).Session(&gorm.Session{}).Model(&models.FlowRollup{}).
		Select("id").Limit(1).Find(&probe).Error
	return len(probe) > 0, err
}

// SaveFlowSummaryHealth stores the poller's evaluation for the API.
func (d *Database) SaveFlowSummaryHealth(ctx context.Context, h FlowSummaryHealth) error {
	h.Stale = false
	js, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return d.WithContext(ctx).UpsertSetting(&models.SystemSetting{
		Key: FlowSummaryHealthKey, Value: string(js), Category: "system", Type: "json",
		Label: "Flow summary health (poller evaluation)",
	})
}

// GetFlowSummaryHealth returns the stored evaluation. It never re-evaluates
// (see the file comment). With no stored evaluation every tier is "unknown";
// with one older than flowSummaryHealthMaxAge the result is marked Stale.
func (d *Database) GetFlowSummaryHealth(ctx context.Context) (FlowSummaryHealth, error) {
	h := FlowSummaryHealth{Tiers: map[string]FlowSummaryTierHealth{}}
	vals, err := d.SettingValues(ctx, []string{FlowSummaryHealthKey})
	if err != nil {
		return h, err
	}
	if raw := strings.TrimSpace(vals[FlowSummaryHealthKey]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &h); err != nil {
			return FlowSummaryHealth{Tiers: map[string]FlowSummaryTierHealth{}}, err
		}
	}
	if h.Tiers == nil {
		h.Tiers = map[string]FlowSummaryTierHealth{}
	}
	for _, tier := range flowSummaryTiers {
		if _, ok := h.Tiers[tier.interval]; !ok {
			h.Tiers[tier.interval] = FlowSummaryTierHealth{Verdict: FlowSummaryUnknown}
		}
	}
	h.Stale = !h.EvaluatedAt.IsZero() && flowSummaryNow().Sub(h.EvaluatedAt) > flowSummaryHealthMaxAge
	return h, nil
}

// FlowSummaryTierIntervals lists the summary's tiers ("1h", "1d"), so a caller
// that alerts or reports per tier cannot fall out of step with the tiers that
// are actually summarised.
func FlowSummaryTierIntervals() []string {
	out := make([]string, 0, len(flowSummaryTiers))
	for _, t := range flowSummaryTiers {
		out = append(out, t.interval)
	}
	return out
}
