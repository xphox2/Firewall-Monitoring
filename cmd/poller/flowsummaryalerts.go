package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
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
	}

	// The verdict is computed whatever the threshold says (0 uses the default).
	h := p.db.EvaluateFlowSummaryHealth(ctx, now, minutes, flowSummaryProcessStart)
	if err := p.db.SaveFlowSummaryHealth(ctx, h); err != nil {
		log.Printf("flow summary health: store the evaluation: %v", err)
	}
	if readErr != nil {
		return
	}
	p.alertManager.CheckServerConditions(flowSummaryConditions(h, minutes, flowSummaryProcessStart))
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
			// "No success since" is counted from this poller's start at the
			// earliest (the verdict's rule), so the message must not quote an
			// older time as if the alert had been waiting since then.
			since := "since the poller started at " + processStart.UTC().Format("2006-01-02 15:04 UTC")
			if th.LastOKAt.After(processStart) {
				since = "since " + th.LastOKAt.UTC().Format("2006-01-02 15:04 UTC")
			} else if !th.LastOKAt.IsZero() {
				since += " (last success " + th.LastOKAt.UTC().Format("2006-01-02 15:04 UTC") + ")"
			}
			// What a reader of the Flows page gets is a property of the whole
			// summary, not of this tier (see FlowSummaryHealth.LongWindowsLive).
			// Unknown (the probe failed) says nothing rather than guess.
			effect := ""
			if h.LongWindowsLive != nil && *h.LongWindowsLive {
				effect = "Long windows on the Flows page are read live meanwhile: slow, and possibly partial. "
			} else if h.LongWindowsLive != nil {
				effect = "Long windows on the Flows page still use the summary, with figures that may be out of date. "
			}
			c.Message = fmt.Sprintf("The %s flow summary has had no successful update %s (threshold %d minutes). %s"+
				"See the poller log for \"Flow summary:\" lines.", name, since, minutes, effect)
			if th.LastErrorClass != "" {
				c.Message += " Last failure: " + th.LastErrorClass + "."
				c.Fields["error_class"] = th.LastErrorClass
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
