package main

import (
	"encoding/json"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// FLOW_SUMMARY_STALLED on the server-health tick. The summariser's record is
// written directly here: these tests are about what the tick makes of it.

type summaryTierRecord struct {
	lastPass, lastOK, failingSince time.Time
	caughtUp                       bool
}

// summaryAlertPoller is a poller whose flow-summary tick runs at `now`, in a
// process that started at `start`, with one rollup row to summarise.
func summaryAlertPoller(t *testing.T, now, start time.Time) (*Poller, *database.Database) {
	t.Helper()
	p, db := newTestPoller(t)
	p.alertManager = alerts.NewAlertManager(p.cfg, notifier.NewNotifier(p.cfg), db)
	origClock, origStart := flowSummaryAlertClock, flowSummaryProcessStart
	flowSummaryAlertClock = func() time.Time { return now }
	flowSummaryProcessStart = start
	t.Cleanup(func() { flowSummaryAlertClock, flowSummaryProcessStart = origClock, origStart })
	if err := db.Gorm().Create(&models.FlowRollup{Timestamp: now.Add(-2 * time.Hour), DeviceID: 1, IntervalType: "5m",
		SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6, BytesSum: 1, PacketsSum: 1, FlowCount: 1}).Error; err != nil {
		t.Fatal(err)
	}
	return p, db
}

func writeSummaryRecord(t *testing.T, db *database.Database, cycleAt time.Time, tiers map[string]summaryTierRecord) {
	t.Helper()
	st := database.FlowSummaryState{CycleProgressAt: cycleAt, Tiers: map[string]*database.FlowSummaryTierState{}}
	for iv, r := range tiers {
		st.Tiers[iv] = &database.FlowSummaryTierState{LastPassAt: r.lastPass, LastOKAt: r.lastOK, FailingSince: r.failingSince, CaughtUp: r.caughtUp}
	}
	js, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertSetting(&models.SystemSetting{Key: database.FlowSummaryStateKey, Value: string(js), Category: "system", Type: "json"}); err != nil {
		t.Fatal(err)
	}
}

func openSummaryAlerts(t *testing.T, db *database.Database, interval string) int64 {
	t.Helper()
	var n int64
	if err := db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND metric_name = ? AND resolved_at IS NULL", models.AlertTypeFlowSummaryStalled, "flow_summary_"+interval).
		Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func setStallMinutes(t *testing.T, db *database.Database, v string) {
	t.Helper()
	if err := db.UpsertSetting(&models.SystemSetting{Key: FlowSummaryStallMinutesKey, Value: v, Category: "alerts", Type: "string"}); err != nil {
		t.Fatal(err)
	}
}

// TestFlowSummaryAlert_FiresPerTierAndResolves: a tier failing for longer than
// the threshold raises ONE alert, for that tier only; it does not fire again
// on the next tick; it resolves when the tier succeeds; and the evaluation is
// stored for the API.
func TestFlowSummaryAlert_FiresPerTierAndResolves(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, db := summaryAlertPoller(t, now, now.Add(-10*time.Hour))
	ago := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	healthy := summaryTierRecord{lastPass: ago(1), lastOK: ago(1), caughtUp: true}
	failing := summaryTierRecord{lastPass: ago(1), lastOK: ago(90), failingSince: ago(85), caughtUp: true}

	writeSummaryRecord(t, db, ago(1), map[string]summaryTierRecord{"1h": failing, "1d": healthy})
	p.checkFlowSummaryHealth()
	p.checkFlowSummaryHealth() // a second tick inside the cooldown
	if got := openSummaryAlerts(t, db, "1h"); got != 1 {
		t.Fatalf("hourly alerts = %d, want exactly 1", got)
	}
	if got := openSummaryAlerts(t, db, "1d"); got != 0 {
		t.Fatalf("the healthy daily tier has %d alert(s)", got)
	}
	h, err := db.GetFlowSummaryHealth(t.Context())
	if err != nil || h.Tiers["1h"].Verdict != database.FlowSummaryStalled || h.Tiers["1d"].Verdict != database.FlowSummaryOK {
		t.Fatalf("stored evaluation: %+v err=%v", h.Tiers, err)
	}

	// Rebuilding counts as recovered: passes succeed again.
	writeSummaryRecord(t, db, ago(0), map[string]summaryTierRecord{
		"1h": {lastPass: ago(0), lastOK: ago(0), caughtUp: false}, "1d": healthy})
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 0 {
		t.Fatalf("hourly alert still open after a successful pass: %d", got)
	}
}

// TestFlowSummaryAlert_LeavesAnOpenAlertWhenItCannotJudge: three states say
// neither "stalled" nor "fine", and none of them may close an open alert — a
// record from before a restart, a single recent failure, and an unreadable
// threshold. The first is the one that matters most: the tick runs at startup,
// before any cycle, and the record still holds the last pass's "ok".
func TestFlowSummaryAlert_LeavesAnOpenAlertWhenItCannotJudge(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, db := summaryAlertPoller(t, now, now.Add(-10*time.Hour))
	ago := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	healthy := summaryTierRecord{lastPass: ago(1), lastOK: ago(1), caughtUp: true}

	// A hung cycle: both tiers stall and alert.
	stale := summaryTierRecord{lastPass: ago(120), lastOK: ago(120), caughtUp: true}
	writeSummaryRecord(t, db, ago(120), map[string]summaryTierRecord{"1h": stale, "1d": stale})
	p.checkFlowSummaryHealth()
	if openSummaryAlerts(t, db, "1h") != 1 || openSummaryAlerts(t, db, "1d") != 1 {
		t.Fatal("precondition: a hung cycle did not alert on both tiers")
	}

	// The operator restarts the poller. The record is unchanged and says ok.
	flowSummaryProcessStart = now
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 1 {
		t.Fatalf("a record from before the restart resolved the alert (%d open)", got)
	}
	flowSummaryProcessStart = now.Add(-10 * time.Hour)

	// One failure, two minutes ago, after a good pass seven minutes ago.
	writeSummaryRecord(t, db, ago(2), map[string]summaryTierRecord{
		"1h": {lastPass: ago(2), lastOK: ago(7), failingSince: ago(2), caughtUp: true}, "1d": healthy})
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 1 {
		t.Fatalf("a single failure resolved the alert (%d open)", got)
	}
	if got := openSummaryAlerts(t, db, "1d"); got != 0 {
		t.Fatalf("the daily tier recovered but its alert is still open (%d)", got)
	}

	// A threshold that cannot be read is not "0, alerting off".
	writeSummaryRecord(t, db, ago(1), map[string]summaryTierRecord{"1h": healthy, "1d": healthy})
	setStallMinutes(t, db, "soon")
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 1 {
		t.Fatalf("an unreadable threshold resolved the alert (%d open)", got)
	}
	// The evaluation is still stored — the banner does not depend on it.
	if h, _ := db.GetFlowSummaryHealth(t.Context()); h.Tiers["1h"].Verdict != database.FlowSummaryOK {
		t.Fatalf("with an unreadable threshold the stored verdict is %q, want ok", h.Tiers["1h"].Verdict)
	}
}

// TestFlowSummaryAlert_ZeroTurnsTheAlertOffNotTheVerdict: 0 resolves and
// silences the alert, and the tier is still judged (against the default) so
// the Flows page can say it is stalled.
func TestFlowSummaryAlert_ZeroTurnsTheAlertOffNotTheVerdict(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, db := summaryAlertPoller(t, now, now.Add(-10*time.Hour))
	ago := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	healthy := summaryTierRecord{lastPass: ago(1), lastOK: ago(1), caughtUp: true}
	failing := summaryTierRecord{lastPass: ago(1), lastOK: ago(120), failingSince: ago(115), caughtUp: true}

	writeSummaryRecord(t, db, ago(1), map[string]summaryTierRecord{"1h": failing, "1d": healthy})
	p.checkFlowSummaryHealth()
	if openSummaryAlerts(t, db, "1h") != 1 {
		t.Fatal("precondition: no alert at the default threshold")
	}
	setStallMinutes(t, db, "0")
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 0 {
		t.Fatalf("threshold 0 left %d alert(s) open", got)
	}
	h, _ := db.GetFlowSummaryHealth(t.Context())
	if h.Tiers["1h"].Verdict != database.FlowSummaryStalled || h.Tiers["1d"].Verdict != database.FlowSummaryOK {
		t.Fatalf("threshold 0: verdicts %q / %q, want stalled / ok", h.Tiers["1h"].Verdict, h.Tiers["1d"].Verdict)
	}

	// A longer threshold than the failure: not stalled yet, so no alert.
	setStallMinutes(t, db, "180")
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 0 {
		t.Fatalf("a 180-minute threshold fired after 120 minutes (%d open)", got)
	}
}

// TestCheckServerHealth_RunsTheFlowSummaryCheck: the check rides the
// server-health tick and is not skipped by that tick's early returns.
func TestCheckServerHealth_RunsTheFlowSummaryCheck(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, db := summaryAlertPoller(t, now, now.Add(-10*time.Hour))
	p.checkServerHealth()
	h, err := db.GetFlowSummaryHealth(t.Context())
	if err != nil || h.EvaluatedAt.IsZero() {
		t.Fatalf("the server-health tick stored no flow summary evaluation: %+v err=%v", h, err)
	}
}
