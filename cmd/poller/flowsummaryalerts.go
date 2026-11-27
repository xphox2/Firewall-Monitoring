package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The flow summary's health: evaluated here, on the server-health tick, stored
// for the API (the Flows page banner) and turned into FLOW_SUMMARY_STALLED.
//
// WHY the poller evaluates and the API only repeats it: a verdict depends on
// when THIS process started. A record written before a restart says nothing
// about whether the summariser works now — treating it as current would
// resolve an open alert at boot on the strength of an old "ok", or page at
// boot for the hours the poller was down. The API is another binary and has
// no idea when the poller started. (database/flow_summary_state.go has the
// rules.)

// FlowSummaryStallMinutesKey is the alert threshold: minutes a tier may go
// without a successful pass. 0 turns the alert off — the banner still works.
const FlowSummaryStallMinutesKey = "flow_summary_stall_alert_minutes"

// flowSummaryProcessStart is when this poller started; flowSummaryAlertClock
// is the tick's clock. Variables so tests can set both.
var (
	flowSummaryProcessStart = time.Now()
	flowSummaryAlertClock   = time.Now
)

// flowSummaryTierName is how an alert names a tier. The tiers themselves come
// from the database package, so a tier added there is alerted on here.
func flowSummaryTierName(interval string) string {
	switch interval {
	case "1h":
		return "hourly"
	case "1d":
		return "daily"
	}
	return interval
}

// checkFlowSummaryHealth evaluates, stores and alerts.
func (p *Poller) checkFlowSummaryHealth() {
	if p.db == nil || p.alertManager == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	now := flowSummaryAlertClock()

	// Read strictly: a failed read must not be taken for "0, alerting off",
	// which would resolve an open alert.
	minutes, readErr := flowSummaryStallMinutes(ctx, p.db)
	if readErr != nil {
		log.Printf("flow summary health: read the threshold: %v (alerts left as they are)", readErr)
		// The verdict still has to be computed, for the Flows page — against
		// the threshold the operator last had, not the default: on a 180-minute
		// threshold the default would show "stalled" two hours early.
		minutes = flowSummaryThresholdFallback(ctx, p.db)
	} else {
		flowSummaryLastThreshold.minutes, flowSummaryLastThreshold.known = minutes, true
	}

	// The verdict is computed whatever the threshold says (0 uses the default).
	h := p.db.EvaluateFlowSummaryHealth(ctx, now, minutes, flowSummaryProcessStart)
	flowSummaryDebounceNoCycle(&h, now)
	if err := p.db.SaveFlowSummaryHealth(ctx, h); err != nil {
		log.Printf("flow summary health: store the evaluation: %v", err)
	}
	if readErr != nil {
		return
	}
	p.alertManager.CheckServerConditions(flowSummaryConditions(h, minutes, flowSummaryProcessStart))
}

// flowSummaryLastThreshold is the last threshold this process read
// successfully.
var flowSummaryLastThreshold struct {
	minutes int
	known   bool
}

// flowSummaryThresholdFallback is the threshold to judge with when the setting
// cannot be read: the last one this process read; after a restart, the one the
// previous evaluation recorded; the default only when there is neither.
func flowSummaryThresholdFallback(ctx context.Context, db *database.Database) int {
	if flowSummaryLastThreshold.known {
		return flowSummaryLastThreshold.minutes
	}
	if prev, err := db.GetFlowSummaryHealth(ctx); err == nil && prev.ThresholdMinutes > 0 {
		return prev.ThresholdMinutes
	}
	return database.FlowSummaryDefaultStallMinutes
}

// flowSummaryNoCycleSeen records, per tier, that the PREVIOUS evaluation in
// this process found no summary cycle alive.
var flowSummaryNoCycleSeen = map[string]bool{}

// flowSummaryLaunchedAt is when this process last launched a summary cycle
// (unix nanoseconds; set by startFlowSummaryAsync once it holds the lock).
var flowSummaryLaunchedAt atomic.Int64

// flowSummaryLaunchGrace is how long after a launch "no cycle alive" is not
// judged at all. The cycle's first write follows its launch by one settings
// read; a minute is orders of magnitude more than that and far below the
// smallest threshold (30 minutes), so a pass that is really hung is not hidden.
const flowSummaryLaunchGrace = time.Minute

// flowSummaryDebounceNoCycle makes "no summary cycle shows signs of life"
// count only on its second evaluation in a row; the first is reported as
// unknown, which neither raises nor resolves an alert.
//
// WHY: the summariser is started from the same loop that runs this check.
// After that loop has been blocked for the threshold — a long rollup cycle, a
// database outage — this check can run just BEFORE the summariser's first
// write of the new cycle, see a liveness stamp older than the threshold, and
// call both tiers stalled; five minutes later it would see the fresh stamp.
// One false alert, and its six-hour cooldown then mutes a real stall. Which of
// the two runs first is not something to reason about (two attempts to do so
// each left a race): a state that lasts one evaluation is simply not acted on.
//
// Counting evaluations is not quite enough on its own: after a gap, the first
// check can see the stale stamp, a long rollup can then hold the loop past the
// next tick, and the second check can again run in the instant before the new
// cycle's first write — two sightings, no cycle in between. So a check that
// runs within flowSummaryLaunchGrace of a launch does not judge this cause at
// all, and does not count as a sighting.
//
// The price is that a summariser that really is hung, or never runs, is
// reported one evaluation (five minutes) later. The other two causes of a
// stall are not delayed: each already takes two passes to establish.
func flowSummaryDebounceNoCycle(h *database.FlowSummaryHealth, now time.Time) {
	launched := flowSummaryLaunchedAt.Load()
	justLaunched := launched != 0 && now.Sub(time.Unix(0, launched)) < flowSummaryLaunchGrace && !now.Before(time.Unix(0, launched))
	for interval, th := range h.Tiers {
		noCycle := th.Verdict == database.FlowSummaryStalled && th.StallClass == database.FlowSummaryStallNoCycle
		if noCycle && (justLaunched || !flowSummaryNoCycleSeen[interval]) {
			th.Verdict, th.StallClass = database.FlowSummaryUnknown, ""
			h.Tiers[interval] = th
		}
		if !(noCycle && justLaunched) {
			flowSummaryNoCycleSeen[interval] = noCycle
		}
	}
}

// flowSummaryStallMinutes reads the threshold; absent means the default.
func flowSummaryStallMinutes(ctx context.Context, db *database.Database) (int, error) {
	vals, err := db.SettingValues(ctx, []string{FlowSummaryStallMinutesKey})
	if err != nil {
		return 0, err
	}
	raw := strings.TrimSpace(vals[FlowSummaryStallMinutesKey])
	if raw == "" {
		return database.FlowSummaryDefaultStallMinutes, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s = %q is not a number of minutes", FlowSummaryStallMinutesKey, raw)
	}
	return n, nil
}

// flowSummaryConditions turns verdicts into conditions, one per tier.
//
// A verdict that cannot say either way produces NO condition, so the alert is
// neither fired nor resolved: "unknown" (the record is unreadable, or no cycle
// has run since this process started) and "failing" (the last pass failed, but
// not for long enough yet) both leave an open alert open.
func flowSummaryConditions(h database.FlowSummaryHealth, minutes int, processStart time.Time) []alerts.ServerCondition {
	var out []alerts.ServerCondition
	for _, interval := range database.FlowSummaryTierIntervals() {
		th, ok := h.Tiers[interval]
		if !ok {
			continue
		}
		name := flowSummaryTierName(interval)
		c := alerts.ServerCondition{
			Type:     models.AlertTypeFlowSummaryStalled,
			Key:      "flow_summary_stalled_" + interval,
			Metric:   "flow_summary_" + interval,
			Fields:   map[string]string{"tier": interval},
			Recovery: fmt.Sprintf("The %s flow summary is updating again.", name),
		}
		switch {
		case minutes <= 0:
			// Alerting is off: resolve whatever is open, without claiming
			// the tier recovered.
			c.Recovery = fmt.Sprintf("Alerting on the %s flow summary is switched off (threshold 0).", name)
		case th.Verdict == database.FlowSummaryStalled:
			c.Breached = true
			at := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }
			// What a reader of the Flows page gets is a property of the whole
			// summary, not of this tier (see FlowSummaryHealth.LongWindowsLive).
			// Unknown (the probe failed) says nothing rather than guess.
			effect := ""
			if h.LongWindowsLive != nil && *h.LongWindowsLive {
				effect = "Long windows on the Flows page are read live meanwhile: slow, and possibly partial. "
			} else if h.LongWindowsLive != nil {
				effect = "Long windows on the Flows page still use the summary, with figures that may be out of date. "
			}
			// Every clock here starts at this poller's start at the earliest
			// (the verdict's rule), so no message quotes an older time as if
			// the alert had been waiting since then.
			var what string
			switch th.StallClass {
			case database.FlowSummaryStallNoProgress:
				// Passes SUCCEED here; saying "no successful update" would
				// send the operator looking for an error that does not exist.
				since := "since the poller started at " + at(processStart)
				if th.ProgressAt.After(processStart) {
					since = "since " + at(th.ProgressAt)
				}
				what = fmt.Sprintf("The %s flow summary is rebuilding its history but has made no progress %s: "+
					"its passes complete without building anything, usually because other summary work uses the whole cycle", name, since)
			case database.FlowSummaryStallNoCycle:
				what = fmt.Sprintf("No flow summary cycle has shown any sign of life for the threshold (%s tier): "+
					"a pass is hung, or the summariser is not being run at all", name)
			default:
				since := "since the poller started at " + at(processStart)
				if th.LastOKAt.After(processStart) {
					since = "since " + at(th.LastOKAt)
				} else if !th.LastOKAt.IsZero() {
					since += " (last success " + at(th.LastOKAt) + ")"
				}
				what = fmt.Sprintf("The %s flow summary has had no successful update %s", name, since)
			}
			c.Message = fmt.Sprintf("%s (threshold %d minutes). %sSee the poller log for \"Flow summary:\" lines.", what, minutes, effect)
			if th.StallClass != "" {
				c.Fields["stall_class"] = th.StallClass
			}
			// The field is attached whenever the tier has a last failure, as
			// before, so a rule scoped on it keeps matching; the sentence is
			// only true of a tier that is stalled BECAUSE it fails.
			if th.LastErrorClass != "" {
				c.Fields["error_class"] = th.LastErrorClass
				if th.StallClass == database.FlowSummaryStallFailing {
					c.Message += " Last failure: " + th.LastErrorClass + "."
				}
			}
		case th.Verdict == database.FlowSummaryOK, th.Verdict == database.FlowSummaryCatchingUp:
			// Healthy, or rebuilding with passes succeeding: resolve.
		default:
			continue
		}
		out = append(out, c)
	}
	return out
}
