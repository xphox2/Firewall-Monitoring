package main

import (
	"encoding/json"
	"strings"
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
	// What the tick remembers between evaluations belongs to one process.
	resetTickMemory := func() {
		flowSummaryNoCycleSeen = map[string]bool{}
		flowSummaryLastThreshold.minutes, flowSummaryLastThreshold.known = 0, false
	}
	resetTickMemory()
	t.Cleanup(func() {
		flowSummaryAlertClock, flowSummaryProcessStart = origClock, origStart
		resetTickMemory()
	})
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
		ts := &database.FlowSummaryTierState{LastPassAt: r.lastPass, LastOKAt: r.lastOK, FailingSince: r.failingSince, CaughtUp: r.caughtUp}
		if !r.failingSince.IsZero() {
			ts.ConsecutiveFailures = 2 // a run of failures...
			if r.failingSince.Equal(r.lastPass) {
				ts.ConsecutiveFailures = 1 // ...unless the record is of a single one
			}
		}
		st.Tiers[iv] = ts
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

	// A hung cycle: both tiers stall and alert (on the second evaluation that
	// finds no cycle alive; see TestFlowSummaryAlert_NoCycleNeedsTwoEvaluations).
	stale := summaryTierRecord{lastPass: ago(120), lastOK: ago(120), caughtUp: true}
	writeSummaryRecord(t, db, ago(120), map[string]summaryTierRecord{"1h": stale, "1d": stale})
	p.checkFlowSummaryHealth()
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
	// Asserted on the VERDICT: the alert's own cooldown would hide a fire here
	// whatever the threshold did.
	if h, _ = db.GetFlowSummaryHealth(t.Context()); h.Tiers["1h"].Verdict != database.FlowSummaryFailing {
		t.Fatalf("120 minutes into a 180-minute threshold the verdict is %q, want failing", h.Tiers["1h"].Verdict)
	}
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

// TestFlowSummaryConditions_MessageSaysWhatTheReaderGets: whether long windows
// are read live is a property of the whole summary, not of the stalled tier —
// a caught-up hourly tier is NOT served while the daily tier is behind. The
// message also names the kind of failure, does not quote a "since" older than
// this process as if the alert had waited that long, and switching alerting
// off resolves without claiming a recovery.
func TestFlowSummaryConditions_MessageSaysWhatTheReaderGets(t *testing.T) {
	start := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	lastOK := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	yes, no := true, false
	tiers := func(live *bool, hourlyOK time.Time) database.FlowSummaryHealth {
		return database.FlowSummaryHealth{LongWindowsLive: live, Tiers: map[string]database.FlowSummaryTierHealth{
			"1h": {Verdict: database.FlowSummaryStalled, StallClass: database.FlowSummaryStallFailing, LastOKAt: hourlyOK, CaughtUp: true, LastErrorClass: "timeout"},
			"1d": {Verdict: database.FlowSummaryCatchingUp, CaughtUp: false},
		}}
	}
	hourlyOf := func(h database.FlowSummaryHealth, minutes int) alerts.ServerCondition {
		t.Helper()
		conds := flowSummaryConditions(h, minutes, start)
		if len(conds) != len(database.FlowSummaryTierIntervals()) {
			t.Fatalf("%d condition(s) for %d tiers", len(conds), len(database.FlowSummaryTierIntervals()))
		}
		for _, c := range conds {
			if c.Fields["tier"] == "1h" {
				return c
			}
		}
		t.Fatal("no hourly condition")
		return alerts.ServerCondition{}
	}

	served := hourlyOf(tiers(&no, lastOK), 60)
	if !served.Breached || served.Fields["error_class"] != "timeout" {
		t.Fatalf("stalled hourly tier: %+v", served)
	}
	for _, want := range []string{"hourly", "since 2026-11-27 09:00 UTC", "still use the summary", "Last failure: timeout."} {
		if !strings.Contains(served.Message, want) {
			t.Errorf("message lacks %q: %s", want, served.Message)
		}
	}
	if strings.Contains(served.Message, "read live") {
		t.Errorf("a served summary is said to be read live: %s", served.Message)
	}

	// The same caught-up hourly tier, with the daily tier behind.
	live := hourlyOf(tiers(&yes, lastOK), 60)
	if !strings.Contains(live.Message, "read live") || strings.Contains(live.Message, "still use the summary") {
		t.Errorf("with the summary bypassed the message says: %s", live.Message)
	}

	// Last success before this process started.
	old := hourlyOf(tiers(&no, start.Add(-5*time.Hour)), 60)
	for _, want := range []string{"since the poller started at 2026-11-27 08:00 UTC", "(last success 2026-11-27 03:00 UTC)"} {
		if !strings.Contains(old.Message, want) {
			t.Errorf("message lacks %q: %s", want, old.Message)
		}
	}

	// The read-path probe failed: the message does not guess.
	unsure := hourlyOf(tiers(nil, lastOK), 60)
	if strings.Contains(unsure.Message, "read live") || strings.Contains(unsure.Message, "still use the summary") ||
		!strings.Contains(unsure.Message, "(threshold 60 minutes). See the poller log") {
		t.Errorf("with the read path undetermined the message says: %s", unsure.Message)
	}

	off := hourlyOf(tiers(&no, lastOK), 0)
	if off.Breached || !strings.Contains(off.Recovery, "switched off") {
		t.Errorf("threshold 0: breached=%v recovery=%q", off.Breached, off.Recovery)
	}
}

// TestFlowSummaryAlert_NoCycleNeedsTwoEvaluations: "no summary cycle shows any
// sign of life" is acted on only when two evaluations in a row find it. After
// the poller's loop has been blocked for the threshold, the check can run just
// before the summariser's first write of the new cycle; that state lasts one
// evaluation, and it must not raise an alert (whose cooldown would then mute a
// real stall). A tier that is FAILING is not delayed: it already took two
// passes to get there.
func TestFlowSummaryAlert_NoCycleNeedsTwoEvaluations(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, db := summaryAlertPoller(t, now, now.Add(-10*time.Hour))
	ago := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	quiet := summaryTierRecord{lastPass: ago(70), lastOK: ago(70), caughtUp: true}
	fresh := summaryTierRecord{lastPass: ago(0), lastOK: ago(0), caughtUp: true}
	verdict := func() string {
		t.Helper()
		h, err := db.GetFlowSummaryHealth(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return h.Tiers["1h"].Verdict
	}

	// First sighting: nothing fires, and the page is told nothing either.
	writeSummaryRecord(t, db, ago(70), map[string]summaryTierRecord{"1h": quiet, "1d": quiet})
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h") + openSummaryAlerts(t, db, "1d"); got != 0 {
		t.Fatalf("the first evaluation that found no cycle alive raised %d alert(s)", got)
	}
	if v := verdict(); v != database.FlowSummaryUnknown {
		t.Fatalf("first sighting stored as %q, want unknown", v)
	}

	// The new cycle's stamp lands before the next evaluation: it was the race.
	writeSummaryRecord(t, db, ago(0), map[string]summaryTierRecord{"1h": fresh, "1d": fresh})
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 0 || verdict() != database.FlowSummaryOK {
		t.Fatalf("after the cycle came back: %d alert(s), verdict %q", got, verdict())
	}

	// A real hang: found twice in a row. The sighting before the recovery
	// above does not count towards it.
	writeSummaryRecord(t, db, ago(70), map[string]summaryTierRecord{"1h": quiet, "1d": quiet})
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 0 {
		t.Fatalf("a sighting from before a recovery was counted: %d alert(s) on the first new sighting", got)
	}
	p.checkFlowSummaryHealth()
	if openSummaryAlerts(t, db, "1h") != 1 || openSummaryAlerts(t, db, "1d") != 1 || verdict() != database.FlowSummaryStalled {
		t.Fatalf("a hang seen twice did not alert on both tiers (verdict %q)", verdict())
	}
}

// TestFlowSummaryAlert_FailingTierIsNotDelayed is the other half: the delay
// applies to one cause only.
func TestFlowSummaryAlert_FailingTierIsNotDelayed(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, db := summaryAlertPoller(t, now, now.Add(-10*time.Hour))
	ago := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	writeSummaryRecord(t, db, ago(1), map[string]summaryTierRecord{
		"1h": {lastPass: ago(1), lastOK: ago(90), failingSince: ago(85), caughtUp: true},
		"1d": {lastPass: ago(1), lastOK: ago(1), caughtUp: true}})
	p.checkFlowSummaryHealth()
	if got := openSummaryAlerts(t, db, "1h"); got != 1 {
		t.Fatalf("a tier failing for the threshold did not alert on the first evaluation (%d open)", got)
	}
}

// TestFlowSummaryAlert_UnreadableThresholdKeepsTheYardstick: when the
// threshold cannot be read the verdict (for the Flows page) is still computed
// — against the threshold the operator last had, not the default. On 180
// minutes the default would show "stalled" two hours early. The value is
// carried from tick to tick, and across a restart through the stored record.
func TestFlowSummaryAlert_UnreadableThresholdKeepsTheYardstick(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, db := summaryAlertPoller(t, now, now.Add(-10*time.Hour))
	ago := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	// Failing for two hours: stalled against 60, merely failing against 180.
	writeSummaryRecord(t, db, ago(1), map[string]summaryTierRecord{
		"1h": {lastPass: ago(1), lastOK: ago(120), failingSince: ago(115), caughtUp: true},
		"1d": {lastPass: ago(1), lastOK: ago(1), caughtUp: true}})
	stored := func() database.FlowSummaryHealth {
		t.Helper()
		h, err := db.GetFlowSummaryHealth(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	setStallMinutes(t, db, "180")
	p.checkFlowSummaryHealth()
	if h := stored(); h.Tiers["1h"].Verdict != database.FlowSummaryFailing || h.ThresholdMinutes != 180 {
		t.Fatalf("precondition: verdict %q at threshold %d, want failing at 180", h.Tiers["1h"].Verdict, h.ThresholdMinutes)
	}

	setStallMinutes(t, db, "soon")
	for tick := 1; tick <= 2; tick++ {
		p.checkFlowSummaryHealth()
		if h := stored(); h.Tiers["1h"].Verdict != database.FlowSummaryFailing || h.ThresholdMinutes != 180 {
			t.Fatalf("tick %d with an unreadable threshold: verdict %q at %d, want failing at 180", tick, h.Tiers["1h"].Verdict, h.ThresholdMinutes)
		}
	}
	if got := openSummaryAlerts(t, db, "1h"); got != 0 {
		t.Fatalf("an unreadable threshold raised %d alert(s)", got)
	}

	// A restart forgets the in-memory value; the stored record still has it.
	flowSummaryLastThreshold.minutes, flowSummaryLastThreshold.known = 0, false
	p.checkFlowSummaryHealth()
	if h := stored(); h.Tiers["1h"].Verdict != database.FlowSummaryFailing || h.ThresholdMinutes != 180 {
		t.Fatalf("after a restart: verdict %q at %d, want failing at 180", h.Tiers["1h"].Verdict, h.ThresholdMinutes)
	}
}

// TestFlowSummaryConditions_MessageNamesTheCause: three causes, three
// messages. A rebuild that makes no progress has passes that SUCCEED, so "no
// successful update" would be false; and "no cycle alive" has no failure to
// name.
func TestFlowSummaryConditions_MessageNamesTheCause(t *testing.T) {
	start := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	progress := time.Date(2026, 11, 27, 10, 30, 0, 0, time.UTC)
	message := func(class string, th database.FlowSummaryTierHealth) alerts.ServerCondition {
		t.Helper()
		th.Verdict, th.StallClass = database.FlowSummaryStalled, class
		h := database.FlowSummaryHealth{Tiers: map[string]database.FlowSummaryTierHealth{"1h": th, "1d": {Verdict: database.FlowSummaryOK}}}
		for _, c := range flowSummaryConditions(h, 60, start) {
			if c.Fields["tier"] == "1h" {
				return c
			}
		}
		t.Fatal("no hourly condition")
		return alerts.ServerCondition{}
	}

	stuck := message(database.FlowSummaryStallNoProgress, database.FlowSummaryTierHealth{
		LastOKAt: progress.Add(55 * time.Minute), ProgressAt: progress, LastErrorClass: "timeout"})
	for _, want := range []string{"rebuilding its history but has made no progress since 2026-11-27 10:30 UTC", "(threshold 60 minutes)"} {
		if !strings.Contains(stuck.Message, want) {
			t.Errorf("no-progress message lacks %q: %s", want, stuck.Message)
		}
	}
	for _, not := range []string{"no successful update", "Last failure"} {
		if strings.Contains(stuck.Message, not) {
			t.Errorf("no-progress message says %q: %s", not, stuck.Message)
		}
	}
	if !stuck.Breached || stuck.Fields["stall_class"] != database.FlowSummaryStallNoProgress || stuck.Fields["error_class"] != "" {
		t.Errorf("no-progress condition: breached=%v fields=%v", stuck.Breached, stuck.Fields)
	}
	// Progress from before this poller started is not quoted as the wait.
	old := message(database.FlowSummaryStallNoProgress, database.FlowSummaryTierHealth{ProgressAt: start.Add(-3 * time.Hour)})
	if !strings.Contains(old.Message, "since the poller started at 2026-11-27 08:00 UTC") {
		t.Errorf("no-progress message with older progress: %s", old.Message)
	}

	hung := message(database.FlowSummaryStallNoCycle, database.FlowSummaryTierHealth{LastOKAt: progress, LastErrorClass: "timeout"})
	if !strings.Contains(hung.Message, "No flow summary cycle has shown any sign of life") || strings.Contains(hung.Message, "Last failure") {
		t.Errorf("no-cycle message: %s", hung.Message)
	}

	failing := message(database.FlowSummaryStallFailing, database.FlowSummaryTierHealth{LastOKAt: progress, LastErrorClass: "timeout"})
	if !strings.Contains(failing.Message, "no successful update since 2026-11-27 10:30 UTC") || !strings.Contains(failing.Message, "Last failure: timeout.") {
		t.Errorf("failing message: %s", failing.Message)
	}
}
