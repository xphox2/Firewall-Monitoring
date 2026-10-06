package status

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The archive status and its alerts (archive plan PR 8) on SQLite. Synthetic
// configuration only: example.com, obviously fake credentials.

const (
	testKeyID  = "keyid-test-abcd"
	testSecret = "secret-test-value-do-not-print"
)

// at is the evaluation instant of every test: 6 October 2026, 12:00 UTC.
var at = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func testConfig(syslog, flows bool) *config.Config {
	cfg := &config.Config{}
	cfg.Archive = config.ArchiveConfig{SyslogEnabled: syslog, FlowsEnabled: flows,
		Endpoint: "https://s3.example.com", Region: "us-test-1", Bucket: "example-bucket", Prefix: "fwmon-test",
		AccessKeyID: testKeyID, SecretAccessKey: config.Secret(testSecret), MinAgeHours: 2, SealGraceHours: 48,
		SealReverify: "head", StagingDir: "/tmp/fwmon-archive-test"}
	cfg.Retention.SyslogMonths = 1
	cfg.Retention.FlowDays = 365
	return cfg
}

func chunk(t *testing.T, db *database.Database, table string, seq, lo, hi int64, start time.Time, period time.Duration, status string) models.ArchiveChunk {
	t.Helper()
	c := models.ArchiveChunk{SourceTable: table, Seq: seq, IDLo: lo, IDHi: hi, PeriodStart: start, PeriodEnd: start.Add(period),
		Month: export.MonthOf(start), Status: status, CutAt: start.Add(period), Error: "", Mismatches: 0}
	if status == models.ArchiveChunkVerified {
		v := start.Add(period + 3*time.Hour)
		c.VerifiedAt = &v
	}
	if status == models.ArchiveChunkNeedsAttention {
		c.Mismatches, c.Error = 3, "read-back sha256 differs"
	}
	if err := db.Gorm().Create(&c).Error; err != nil {
		t.Fatal(err)
	}
	return c
}

// seed builds the archive this file's tests read:
//   - syslog_messages: verified through id 300 (period end 5 October), one
//     chunk parked after it (it holds the gate); months 2026-08 sealed,
//     2026-09 seal_failed, 2026-10 open;
//   - flow_samples: verified through 6 October 08:00 (lag 4 h);
//   - flow_if_counters: verified through 6 October 00:00 (lag 12 h).
func seed(t *testing.T, db *database.Database) {
	t.Helper()
	day := 24 * time.Hour
	chunk(t, db, export.TableSyslog, 1, 0, 100, time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC), day, models.ArchiveChunkVerified)
	chunk(t, db, export.TableSyslog, 2, 100, 200, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), day, models.ArchiveChunkVerified)
	chunk(t, db, export.TableSyslog, 3, 200, 300, time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), day, models.ArchiveChunkVerified)
	chunk(t, db, export.TableSyslog, 4, 300, 400, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), day, models.ArchiveChunkNeedsAttention)
	chunk(t, db, export.TableFlows, 1, 0, 50, time.Date(2026, 10, 6, 7, 0, 0, 0, time.UTC), time.Hour, models.ArchiveChunkVerified)
	chunk(t, db, export.TableFlows, 2, 50, 60, time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC), time.Hour, models.ArchiveChunkPending)
	chunk(t, db, export.TableCounters, 1, 0, 10, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), day, models.ArchiveChunkVerified)
	sealed := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	for _, m := range []models.ArchiveMonth{
		{Stream: export.StreamSyslog, Month: "2026-08", Status: models.ArchiveMonthSealed, Partial: true, PartialNote: "first archived month", SealedAt: &sealed, ChunkCount: 1, RowCount: 100},
		{Stream: export.StreamSyslog, Month: "2026-09", Status: models.ArchiveMonthSealFailed, Error: "incomplete: chunk 2 is not the last of the month"},
	} {
		if err := db.Gorm().Create(&m).Error; err != nil {
			t.Fatal(err)
		}
	}
	ev := models.ArchiveGateEvent{Stream: database.ArchiveGateSyslog, Kind: models.ArchiveGateEventOverride,
		From: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)}
	to := ev.From.Add(6 * time.Hour)
	ev.To = &to
	if err := db.Gorm().Create(&ev).Error; err != nil {
		t.Fatal(err)
	}
}

// saveRuntime stores a worker snapshot seen at seen, with syslog_messages
// waiting on an open writer since since.
func saveRuntime(t *testing.T, db *database.Database, seen, since time.Time) {
	t.Helper()
	r := NewRecorder("fw-example-01-123", "/tmp/fwmon-archive-test", 2<<30, testSecret, testKeyID)
	r.SetUnsettled(export.TableSyslog, "open_writer", "held by pid 4242 (client backend, application \"psql\")", since)
	r.Failed("upload", &testErr{"PUT https://s3.example.com/example-bucket: 403 for key " + testKeyID + " secret " + testSecret}, since)
	r.SetPreflight(true)
	r.SetStagingFree(5<<30, nil)
	js, err := r.JSON(seen)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}
}

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }

func build(t *testing.T, db *database.Database, cfg *config.Config, now time.Time) *Status {
	t.Helper()
	st, err := Build(context.Background(), db, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Problems) > 0 {
		t.Fatalf("problems: %v", st.Problems)
	}
	return st
}

func tableOf(t *testing.T, st *Status, name string) TableView {
	t.Helper()
	for _, tv := range st.Tables {
		if tv.Table == name {
			return tv
		}
	}
	t.Fatalf("no table %s", name)
	return TableView{}
}

func streamOf(t *testing.T, st *Status, name string) StreamView {
	t.Helper()
	for _, sv := range st.Streams {
		if sv.Stream == name {
			return sv
		}
	}
	t.Fatalf("no stream %s", name)
	return StreamView{}
}

// TestBuild: V, lag, chunk counts, the parked chunk holding the gate, the
// month table (sealed / seal_failed / open, partial, the override event), the
// seal overdue days, the worker snapshot, retention held — and no secret.
func TestBuild(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	seed(t, db)
	saveRuntime(t, db, at.Add(-time.Minute), at.Add(-7*time.Hour))
	st := build(t, db, testConfig(true, true), at)

	sys := tableOf(t, st, export.TableSyslog)
	if sys.VerifiedThroughID != 300 || sys.LagSeconds == nil || *sys.LagSeconds != (36*time.Hour).Seconds() {
		t.Fatalf("syslog V / lag: %+v", sys)
	}
	if sys.Chunks[models.ArchiveChunkVerified] != 3 || sys.Chunks[models.ArchiveChunkNeedsAttention] != 1 {
		t.Fatalf("syslog chunks: %v", sys.Chunks)
	}
	if sys.Unsettled == nil || sys.Unsettled.Reason != "open_writer" || sys.Unsettled.ForSeconds != (7*time.Hour).Seconds() {
		t.Fatalf("syslog unsettled: %+v", sys.Unsettled)
	}
	if sys.Retention == nil || sys.Retention.Window != "1mo" || sys.Retention.HeldSeconds != 0 {
		t.Fatalf("syslog retention: %+v", sys.Retention)
	}
	flows := tableOf(t, st, export.TableFlows)
	if flows.LagSeconds == nil || *flows.LagSeconds != (4*time.Hour).Seconds() || flows.Retention == nil ||
		flows.Retention.HeldSeconds != (3*time.Hour).Seconds() {
		t.Fatalf("flows lag / held: %+v %+v", flows, flows.Retention)
	}
	if len(st.NeedsAttention) != 1 || st.NeedsAttention[0].Seq != 4 || !st.NeedsAttention[0].HoldsGate {
		t.Fatalf("needs attention: %+v", st.NeedsAttention)
	}
	ss := streamOf(t, st, export.StreamSyslog)
	if ss.OldestUnsealed != "2026-09" || ss.UnsealedDays != 3.5 {
		t.Fatalf("syslog unsealed: %q %v", ss.OldestUnsealed, ss.UnsealedDays)
	}
	if len(ss.Months) != 3 || ss.Months[0].Month != "2026-10" || ss.Months[0].Status != models.ArchiveMonthOpen || ss.Months[0].Due ||
		ss.Months[1].Status != models.ArchiveMonthSealFailed || !ss.Months[1].Due || len(ss.Months[1].Degraded) != 1 ||
		ss.Months[2].Status != models.ArchiveMonthSealed || !ss.Months[2].Partial || len(ss.Months[2].Degraded) != 0 {
		t.Fatalf("syslog months: %+v", ss.Months)
	}
	if st.Worker == nil || st.Worker.Stale || !st.Worker.PreflightOK || len(st.Worker.Stages) != 1 || st.Worker.Staging.FreeBytes == nil {
		t.Fatalf("worker: %+v", st.Worker)
	}
	if st.Config.AccessKeyID != "…abcd" || st.Config.Endpoint != "https://s3.example.com" {
		t.Fatalf("config view: %+v", st.Config)
	}
	js, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testSecret, testKeyID} {
		if strings.Contains(string(js), secret) {
			t.Fatalf("the status carries %q: %s", secret, js)
		}
	}

	// Once the snapshot is old, the worker is stale.
	if st := build(t, db, testConfig(true, true), at.Add(StaleAfter+2*time.Minute)); st.Worker == nil || !st.Worker.Stale {
		t.Fatalf("worker not stale: %+v", st.Worker)
	}

	// A corrupt worker state is reported apart: the manifest still reads.
	if err := db.SaveArchiveWorkerState(context.Background(), "{"); err != nil {
		t.Fatal(err)
	}
	if st := build(t, db, testConfig(true, true), at); st.Worker != nil || st.WorkerError == "" {
		t.Fatalf("corrupt worker state: %+v %q", st.Worker, st.WorkerError)
	}

	// Released: the parked chunk no longer holds deletes, nothing is held.
	if err := db.SetArchiveGateOverride(database.ArchiveGateFlows, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.SetArchiveGateOverride(database.ArchiveGateSyslog, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	st = build(t, db, testConfig(true, true), at)
	if st.NeedsAttention[0].HoldsGate || tableOf(t, st, export.TableFlows).Retention.HeldSeconds != 0 {
		t.Fatalf("an override still holds: %+v %+v", st.NeedsAttention, tableOf(t, st, export.TableFlows).Retention)
	}
}

func conditionOf(t *testing.T, cs []Condition, typ models.AlertType, label string) Condition {
	t.Helper()
	for _, c := range cs {
		if c.Type == typ && c.Label == label {
			return c
		}
	}
	t.Fatalf("no %s %s condition", typ, label)
	return Condition{}
}

// TestConditions: each alert fires on its threshold and clears below it.
func TestConditions(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	seed(t, db)
	saveRuntime(t, db, at.Add(-time.Minute), at.Add(-7*time.Hour))
	cfg := testConfig(true, true)
	th := ReadThresholds(nil)
	growing := DiskTrend{Known: true, Growing: true}
	e := NewEvaluator()

	cs := e.Conditions(build(t, db, cfg, at), th, growing)
	// Syslog lag 36 h > 26 h, but a daily stream must stay over it an hour.
	if c := conditionOf(t, cs, models.AlertTypeArchiveLag, export.TableSyslog); c.Breached || !c.Known {
		t.Fatalf("syslog lag fired at once: %+v", c)
	}
	// Flows 4 h > 3 h: an hourly stream fires at once.
	if c := conditionOf(t, cs, models.AlertTypeArchiveLag, export.TableFlows); !c.Breached || !strings.Contains(c.Message, "4.0 h behind") ||
		!strings.Contains(c.Message, "sflow and netflow") {
		t.Fatalf("sflow lag: %+v", c)
	}
	lags := 0
	for _, c := range cs {
		if c.Type == models.AlertTypeArchiveLag {
			lags++
		}
	}
	if lags != 3 {
		t.Fatalf("%d ARCHIVE_LAG conditions, want one per table (sflow and netflow share flow_samples)", lags)
	}
	// Counters: 12 h < 26 h.
	if c := conditionOf(t, cs, models.AlertTypeArchiveLag, export.TableCounters); c.Breached {
		t.Fatalf("counters lag fired: %+v", c)
	}
	if c := conditionOf(t, cs, models.AlertTypeArchiveNeedsAttention, export.TableSyslog); !c.Breached || !strings.Contains(c.Message, "1 hold its raw deletes") {
		t.Fatalf("needs attention syslog: %+v", c)
	}
	if c := conditionOf(t, cs, models.AlertTypeArchiveNeedsAttention, export.TableFlows); c.Breached {
		t.Fatalf("needs attention flows: %+v", c)
	}
	if c := conditionOf(t, cs, models.AlertTypeArchiveSealOverdue, export.StreamSyslog); !c.Breached || !strings.Contains(c.Message, "incomplete") {
		t.Fatalf("seal overdue syslog: %+v", c)
	}
	if c := conditionOf(t, cs, models.AlertTypeArchiveUnsettledLong, export.TableSyslog); !c.Known || !c.Breached || c.Fields["reason"] != "open_writer" {
		t.Fatalf("unsettled syslog: %+v", c)
	}
	// Flows held 3 h past the rollup age, below the 6 h default.
	if c := conditionOf(t, cs, models.AlertTypeRetentionHeld, export.TableFlows); c.Breached {
		t.Fatalf("held fired below its threshold: %+v", c)
	}

	// An hour later the syslog lag (now 37 h) has stayed over 26 h: it fires.
	cs = e.Conditions(build(t, db, cfg, at.Add(time.Hour)), th, growing)
	if c := conditionOf(t, cs, models.AlertTypeArchiveLag, export.TableSyslog); !c.Breached {
		t.Fatalf("syslog lag did not fire after the sustain: %+v", c)
	}

	// RETENTION_HELD at 2 h: fires while the disk grows (or is not
	// measured), not while it shrinks.
	th2 := th
	th2.Held = 2 * time.Hour
	for _, tc := range []struct {
		disk DiskTrend
		want bool
	}{{growing, true}, {DiskTrend{}, true}, {DiskTrend{Known: true}, false}} {
		cs = NewEvaluator().Conditions(build(t, db, cfg, at), th2, tc.disk)
		if c := conditionOf(t, cs, models.AlertTypeRetentionHeld, export.TableFlows); c.Breached != tc.want {
			t.Fatalf("held with disk %+v: breached %v, want %v", tc.disk, c.Breached, tc.want)
		}
	}

	// A stale snapshot: the wait alert holds its state (unknown).
	cs = NewEvaluator().Conditions(build(t, db, cfg, at.Add(StaleAfter+time.Minute)), th, growing)
	if c := conditionOf(t, cs, models.AlertTypeArchiveUnsettledLong, export.TableSyslog); c.Known {
		t.Fatalf("unsettled judged from a stale snapshot: %+v", c)
	}

	// Thresholds of 0 turn the alerts off.
	off := Thresholds{}
	for _, c := range NewEvaluator().Conditions(build(t, db, cfg, at.Add(2*time.Hour)), off, growing) {
		if c.Breached && c.Type != models.AlertTypeArchiveNeedsAttention {
			t.Fatalf("%s %s fired with its threshold 0", c.Type, c.Label)
		}
	}

	// Recovered: the chunk verified, the archive caught up, the month sealed,
	// the writer gone — every condition clears.
	if err := db.Gorm().Model(&models.ArchiveChunk{}).Where("1 = 1").Updates(map[string]interface{}{"status": models.ArchiveChunkVerified}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Model(&models.ArchiveMonth{}).Where("1 = 1").Updates(map[string]interface{}{"status": models.ArchiveMonthSealed}).Error; err != nil {
		t.Fatal(err)
	}
	r := NewRecorder("fw-example-01-123", "/tmp/x", 0)
	js, _ := r.JSON(at.Add(time.Hour))
	if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}
	late := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC) // 1 h after the last chunk's period end (6 Oct 00:00)
	for _, c := range e.Conditions(build(t, db, cfg, late.Add(time.Hour)), th, growing) {
		if !c.Known || c.Breached {
			t.Fatalf("%s %s still breached or unknown after recovery: %+v", c.Type, c.Label, c)
		}
	}

	// Archiving disabled: nothing fires, everything resolves.
	for _, c := range NewEvaluator().Conditions(build(t, db, testConfig(false, false), at.Add(2*time.Hour)), th, growing) {
		if c.Breached && c.Type != models.AlertTypeArchiveNeedsAttention {
			t.Fatalf("%s %s fired with archiving disabled", c.Type, c.Label)
		}
	}
}

// TestRecorderRedacts: neither credential reaches a recorded message, and a
// wait's start survives a repeat of the same reason but not a change.
func TestRecorderRedacts(t *testing.T) {
	r := NewRecorder("fw-example-01-1", "/tmp/x", 1, testSecret, testKeyID)
	r.Failed("upload", &testErr{"signature for " + testKeyID + " with " + testSecret + " rejected"}, at)
	r.SetUnsettled("t", "open_writer", "a", at)
	r.SetUnsettled("t", "open_writer", "b", at.Add(time.Hour))
	snap := r.Snapshot(at.Add(time.Hour))
	if msg := snap.Stages["upload"].Error; strings.Contains(msg, testSecret) || strings.Contains(msg, testKeyID) || !strings.Contains(msg, "[redacted]") {
		t.Fatalf("recorded %q", msg)
	}
	if u := snap.Tables["t"]; !u.Since.Equal(at) || u.Detail != "b" {
		t.Fatalf("repeat moved the start: %+v", u)
	}
	r.SetUnsettled("t", "unattached_leaf", "c", at.Add(2*time.Hour))
	if u := r.Snapshot(at).Tables["t"]; !u.Since.Equal(at.Add(2 * time.Hour)) {
		t.Fatalf("a new reason kept the old start: %+v", u)
	}
	r.SetUnsettled("t", "", "", at)
	if _, ok := r.Snapshot(at).Tables["t"]; ok {
		t.Fatal("cleared wait still recorded")
	}
}

// TestUnsealedDays pins the formula the gauge and the alert share.
func TestUnsealedDays(t *testing.T) {
	for _, tc := range []struct {
		month string
		now   time.Time
		want  float64
	}{
		{"", at, 0},
		{"bogus", at, 0},
		{"2026-09", time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), 0},
		{"2026-09", time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), 1},
		{"2026-12", time.Date(2027, 1, 6, 0, 0, 0, 0, time.UTC), 3},
	} {
		if got := UnsealedDays(tc.month, 48*time.Hour, tc.now); got != tc.want {
			t.Errorf("UnsealedDays(%q, %s) = %v, want %v", tc.month, tc.now, got, tc.want)
		}
	}
}

// stored reads the threshold settings as the poller does.
func stored(t *testing.T, db *database.Database) map[string]string {
	t.Helper()
	m, err := db.SettingValues(context.Background(), ThresholdKeys())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestReadThresholds: stored values replace the defaults; a blank, malformed
// or out-of-range value keeps the default; 0 turns an alert off.
func TestReadThresholds(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	for k, v := range map[string]string{LagHoursSyslogKey: "30", LagHoursFlowsKey: "0", HeldHoursKey: "721", UnsettledHoursKey: "x", SealOverdueDaysKey: ""} {
		if err := db.UpsertSetting(&models.SystemSetting{Key: k, Value: v}); err != nil {
			t.Fatal(err)
		}
	}
	th := ReadThresholds(stored(t, db))
	want := Thresholds{LagSyslog: 30 * time.Hour, LagFlows: 0, LagCounters: 26 * time.Hour, SealOverdueDays: 3,
		Held: 6 * time.Hour, Unsettled: 6 * time.Hour}
	if th != want {
		t.Fatalf("thresholds %+v, want %+v", th, want)
	}
}

// TestConditions_NoChunkYet: an enabled stream that has cut no chunk (a
// bucket that never passes its preflight) gets no lag to measure, yet the
// gate holds its every raw row: ARCHIVE_LAG fires once that has lasted
// longer than the threshold, naming the preflight failure, and clears with
// the first chunk.
func TestConditions_NoChunkYet(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	r := NewRecorder("fw-example-01-1", "/tmp/x", 1, testSecret)
	r.Failed("preflight", &testErr{"403 Forbidden"}, at)
	js, _ := r.JSON(at.Add(27*time.Hour - time.Minute))
	if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(true, false)
	th := ReadThresholds(nil)
	e := NewEvaluator()
	if c := conditionOf(t, e.Conditions(build(t, db, cfg, at), th, DiskTrend{}), models.AlertTypeArchiveLag, export.TableSyslog); c.Breached || !c.Known {
		t.Fatalf("fired at first sight: %+v", c)
	}
	c := conditionOf(t, e.Conditions(build(t, db, cfg, at.Add(27*time.Hour)), th, DiskTrend{}), models.AlertTypeArchiveLag, export.TableSyslog)
	if !c.Breached || !strings.Contains(c.Message, "cut no chunk") || !strings.Contains(c.Message, "403 Forbidden") {
		t.Fatalf("no chunk for 27 h: %+v", c)
	}
	// Flows are disabled: never.
	if c := conditionOf(t, e.Conditions(build(t, db, cfg, at.Add(28*time.Hour)), th, DiskTrend{}), models.AlertTypeArchiveLag, export.TableFlows); c.Breached {
		t.Fatalf("disabled stream fired: %+v", c)
	}
	chunk(t, db, export.TableSyslog, 1, 0, 10, at.Add(26*time.Hour), 24*time.Hour, models.ArchiveChunkVerified)
	if c := conditionOf(t, e.Conditions(build(t, db, cfg, at.Add(28*time.Hour)), th, DiskTrend{}), models.AlertTypeArchiveLag, export.TableSyslog); c.Breached {
		t.Fatalf("still firing after the first chunk: %+v", c)
	}
}

// TestConditions_RetentionHeldStaysWhileHeld: the disk trend only fires
// RETENTION_HELD; once active it stays through a moment of free space rising
// (a partition drop, WAL recycling) and resolves only when the hold clears.
func TestConditions_RetentionHeldStaysWhileHeld(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	seed(t, db)
	cfg := testConfig(true, true)
	th := ReadThresholds(nil)
	th.Held = 2 * time.Hour // flows are held 3 h past the rollup age
	e := NewEvaluator()
	held := func(disk DiskTrend) bool {
		return conditionOf(t, e.Conditions(build(t, db, cfg, at), th, disk), models.AlertTypeRetentionHeld, export.TableFlows).Breached
	}
	growing, shrinking := DiskTrend{Known: true, Growing: true}, DiskTrend{Known: true}
	if held(shrinking) {
		t.Fatal("fired while the disk shrinks")
	}
	if !held(growing) {
		t.Fatal("did not fire while the disk grows")
	}
	if !held(shrinking) {
		t.Fatal("a free-space rise resolved an active hold")
	}
	if !held(growing) {
		t.Fatal("not breached after growing again")
	}
	// The archive catches up: resolved, and a shrinking disk does not re-fire.
	if err := db.Gorm().Model(&models.ArchiveChunk{}).Where("table_name = ?", export.TableFlows).Update("status", models.ArchiveChunkVerified).Error; err != nil {
		t.Fatal(err)
	}
	if held(growing) {
		t.Fatal("still breached once the hold cleared")
	}
	if err := db.Gorm().Model(&models.ArchiveChunk{}).Where("table_name = ? AND seq = 2", export.TableFlows).Update("status", models.ArchiveChunkPending).Error; err != nil {
		t.Fatal(err)
	}
	if held(shrinking) {
		t.Fatal("re-fired on a shrinking disk after it resolved")
	}
}

// TestBuild_OverrideReadFailure: a gate override that cannot be read is a
// problem (the alerts are then not evaluated), not "not overridden".
func TestBuild_OverrideReadFailure(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	seed(t, db)
	if err := db.Gorm().Exec("ALTER TABLE system_settings RENAME TO system_settings_away").Error; err != nil {
		t.Fatal(err)
	}
	st, err := Build(context.Background(), db, testConfig(true, true), at)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range st.Problems {
		if strings.HasPrefix(p, "gate override of syslog") {
			found = true
		}
	}
	if !found {
		t.Fatalf("override read failure not reported: %v", st.Problems)
	}
}
