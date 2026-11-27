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
	FlowSummaryStalled    = "stalled"     // no successful pass for the threshold
	FlowSummaryFailing    = "failing"     // the latest pass failed, more recently than that
	FlowSummaryCatchingUp = "catching_up" // passes succeed; history is still being built
	FlowSummaryOK         = "ok"
	// FlowSummaryStale is not a verdict: it is what a reader reports when the
	// stored verdicts are too old to trust (see GetFlowSummaryHealth).
	FlowSummaryStale = "stale"
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
}

// summaryReporter keeps the health record for one cycle. progress, tierDone
// and flush are safe on a nil receiver, and none of them can fail a pass: the record describes
// the summariser, it must never be a reason the summariser did less.
type summaryReporter struct {
	d         *Database
	state     FlowSummaryState
	lastWrite time.Time
}

// newSummaryReporter loads the previous record and stamps the cycle's start.
// If the previous record cannot be READ the cycle records nothing: writing a
// fresh one would erase last_ok_at, and with it the evidence of how long a
// tier has been failing. A record that was read but does not PARSE is
// different — it will never parse, so it is replaced; left alone it would make
// every verdict "unknown" for good.
func (d *Database) newSummaryReporter() *summaryReporter {
	st, present, err := d.flowSummaryState(context.Background())
	if err != nil && !present {
		log.Printf("Flow summary: health record unreadable, not updated this cycle: %v", err)
		return nil
	}
	if err != nil {
		log.Printf("Flow summary: health record corrupt, starting a new one: %v", err)
		st = nil
	}
	r := &summaryReporter{d: d}
	if st != nil {
		r.state = *st
	}
	if r.state.Tiers == nil {
		r.state.Tiers = map[string]*FlowSummaryTierState{}
	}
	r.write(flowSummaryNow())
	return r
}

// progress records that the cycle is alive, at most once per
// flowSummaryProgressEvery.
func (r *summaryReporter) progress() {
	if r == nil {
		return
	}
	if now := flowSummaryNow(); now.Sub(r.lastWrite) >= flowSummaryProgressEvery {
		r.write(now)
	}
}

// tierDone records the outcome of one tier's pass.
func (r *summaryReporter) tierDone(interval string, b tierBounds, err error) {
	if r == nil {
		return
	}
	now := flowSummaryNow().UTC()
	ts := r.state.Tiers[interval]
	if ts == nil {
		ts = &FlowSummaryTierState{}
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
		ts.CaughtUp = b.caughtUp || b.ownsNothing
		ts.OwnedTo = b.ownedTo.UTC()
		ts.FilledTo = b.filled.UTC()
	}
	r.write(now)
}

func (r *summaryReporter) flush() {
	if r != nil {
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

	// 1. The latest pass failed and there has been no success for the
	// threshold. Progress does NOT excuse this: a pass that fails still walks
	// its other buckets, so a tier with one poison bucket is busy every cycle
	// and broken every cycle.
	if failing && now.Sub(laterOf(tier.LastOKAt, processStart)) >= threshold {
		return FlowSummaryStalled
	}
	// 2. No cycle has run in this process yet. The record is from before the
	// restart: it can neither confirm a stall nor clear one, and above all it
	// must not resolve an open alert on the strength of an old "ok".
	if !cycleAt.After(processStart) && now.Sub(processStart) < threshold {
		return FlowSummaryUnknown
	}
	// 3. There is work to summarise and no cycle has shown signs of life for
	// the threshold: a pass that hung, or a summariser that never runs (an old
	// poller holding the lock, a panic before the first write). Both tiers.
	if rollupsExist && now.Sub(laterOf(cycleAt, processStart)) >= threshold {
		return FlowSummaryStalled
	}
	// 4. Failed, but not for long enough to call it stalled.
	if failing {
		return FlowSummaryFailing
	}
	// 5. No pass has completed for this tier IN THIS PROCESS. Rule 2 is not
	// enough on its own: a cycle that has merely started stamps
	// cycle_progress_at, and if it then hangs the tier's record is still the
	// "ok" from before the restart — which would resolve an open alert that
	// rule 3 is about to raise again.
	if tier == nil || !tier.LastPassAt.After(processStart) {
		return FlowSummaryUnknown
	}
	// 6. Passes succeed but history is still being built; long windows are
	// served by the live read meanwhile. A pass IN FLIGHT does not put a
	// caught-up tier here — that would show "rebuilding" during every routine
	// pass.
	if !tier.CaughtUp {
		return FlowSummaryCatchingUp
	}
	return FlowSummaryOK
}

// FlowSummaryHealth is the poller's evaluation, as stored for the API.
type FlowSummaryHealth struct {
	EvaluatedAt time.Time `json:"evaluated_at"`
	// Stale is set by the reader, not stored: the evaluation is older than
	// flowSummaryHealthMaxAge, so the poller is stopped or wedged and the
	// verdicts below describe the past.
	Stale bool                             `json:"stale"`
	Tiers map[string]FlowSummaryTierHealth `json:"tiers"`
}

// FlowSummaryTierHealth is one tier's verdict and what the banner needs to
// phrase it.
type FlowSummaryTierHealth struct {
	Verdict        string    `json:"verdict"`
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
	h := FlowSummaryHealth{EvaluatedAt: now.UTC(), Tiers: map[string]FlowSummaryTierHealth{}}

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
			th.Verdict = flowSummaryVerdict(st, tier.interval, now, threshold, processStart, rollupsExist)
		}
		if st != nil {
			if ts := st.Tiers[tier.interval]; ts != nil {
				th.LastOKAt, th.FailingSince, th.CaughtUp = ts.LastOKAt, ts.FailingSince, ts.CaughtUp
				th.FilledTo, th.OwnedTo, th.LastErrorClass = ts.FilledTo, ts.OwnedTo, ts.LastErrorClass
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
