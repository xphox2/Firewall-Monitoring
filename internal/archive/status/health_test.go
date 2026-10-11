package status

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The health verdict (Assess) on synthetic statuses: every issue at and
// around its threshold, the neutral idle stream, HEALTHY only when caught up,
// and the alerts naming the same issues.

func fptr(v float64) *float64 { return &v }

func tp(t time.Time) *time.Time { return &t }

func u64(v uint64) *uint64 { return &v }

// healthyStatus is an install like the operator's: flows archived to an S3
// bucket with Object Lock, syslog off, NetFlow arriving, sFlow switched off
// (its sflow stream and the sflow-counters table receive nothing).
func healthyStatus() *Status {
	now := at
	fresh := now.Add(-30 * time.Second)
	flowsEnd := now.Add(-55 * time.Minute)
	countersEnd := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) // the daily chunk of 5 October, verified
	lastOK := now.Add(-40 * time.Minute)
	return &Status{
		GeneratedAt: now, Enabled: true,
		Config: ConfigView{FlowsEnabled: true, Target: "s3", Bucket: "example-bucket", Prefix: "fwmon-test",
			ObjectLockDays: 30, ObjectLockMode: "GOVERNANCE", SealGraceHours: 48},
		Worker: &WorkerView{SeenAt: fresh, AgeSeconds: 30, Runner: "fw-example-01-1", PreflightOK: true,
			Staging: Staging{Dir: "/archive/staging", FreeBytes: u64(50 << 30), MinFreeBytes: 2 << 30}, Stages: []StageView{}},
		Gates: []GateView{{Stream: database.ArchiveGateSyslog}, {Stream: database.ArchiveGateFlows, Enabled: true, Gated: true}},
		Tables: []TableView{
			{Table: export.TableSyslog, GateStream: database.ArchiveGateSyslog, Streams: []string{export.StreamSyslog}},
			{Table: export.TableFlows, GateStream: database.ArchiveGateFlows, Streams: []string{export.StreamSFlow, export.StreamNetFlow},
				Enabled: true, HasChunks: true, VerifiedThroughEnd: &flowsEnd, LagSeconds: fptr(55 * 60), LastVerifiedAt: &lastOK,
				Backlog:   &BacklogView{Chunks: 500, Verified: 499, Remaining: 1, RemainingRows: 20000, State: "current"},
				Retention: &RetentionView{Window: "rollup after 1 h", Cutoff: now.Add(-time.Hour)}},
			{Table: export.TableCounters, GateStream: database.ArchiveGateFlows, Streams: []string{export.StreamSFlowCounters},
				Enabled: true, HasChunks: true, VerifiedThroughEnd: &countersEnd, LagSeconds: fptr(now.Sub(countersEnd).Seconds()),
				LastVerifiedAt: tp(now.Add(-8 * time.Hour)),
				Backlog:        &BacklogView{Chunks: 20, Verified: 19, Remaining: 1, State: "current"},
				Retention:      &RetentionView{Window: "365d", Cutoff: now.AddDate(0, 0, -365)}},
		},
		Streams: []StreamView{
			{Stream: export.StreamSyslog, Table: export.TableSyslog, Months: []MonthView{}},
			{Stream: export.StreamSFlow, Table: export.TableFlows, Enabled: true, Months: []MonthView{}, RecentChunks: 10},
			{Stream: export.StreamNetFlow, Table: export.TableFlows, Enabled: true, Months: []MonthView{{Month: "2026-10", Status: "open"}},
				RecentChunks: 10, RecentRows: 900000, RecentRawBytes: 400 << 20, RecentObjectBytes: 50 << 20, ArchivedRows: 9e7, ArchivedObjectBytes: 5 << 30},
			{Stream: export.StreamSFlowCounters, Table: export.TableCounters, Enabled: true, Months: []MonthView{}, RecentChunks: 10},
		},
		NeedsAttention: []ParkedChunk{}, Recent: []ChunkView{}, Retrying: []ChunkView{},
	}
}

func defaultTh() Thresholds { return ReadThresholds(nil) }

// sched fills each table's schedule (the operator's: ARCHIVE_MIN_AGE_HOURS
// 2) and its lateness from its raw lag, as Build does — the tests set the
// lag; the verdict and the alerts judge the lateness.
func sched(st *Status) *Status {
	cfg := config.ArchiveConfig{MinAgeHours: 2}
	for i := range st.Tables {
		t := &st.Tables[i]
		t.Schedule = scheduleOf(cfg, t.Table)
		t.DueAt, t.OverdueSeconds = nil, nil
		if t.LagSeconds != nil {
			end := st.GeneratedAt.Add(-secs(*t.LagSeconds))
			due := t.Schedule.DueAfter(end)
			o := t.Schedule.Overdue(end, st.GeneratedAt).Seconds()
			t.DueAt, t.OverdueSeconds = &due, &o
		} else if t.Schedule.PeriodSeconds == 0 {
			t.Schedule = scheduleOf(cfg, t.Table)
		}
	}
	return st
}

var growing = DiskTrend{Known: true, Growing: true, Detail: "10.0 GiB free, 11.0 GiB an hour or more ago"}

func issueOf(h *Health, code string) *Issue {
	for i := range h.Issues {
		if h.Issues[i].Code == code {
			return &h.Issues[i]
		}
	}
	return nil
}

func streamHealth(t *testing.T, h *Health, stream string) StreamHealth {
	t.Helper()
	for _, s := range h.Streams {
		if s.Stream == stream {
			return s
		}
	}
	t.Fatalf("no stream %s", stream)
	return StreamHealth{}
}

func table(st *Status, name string) *TableView {
	for i := range st.Tables {
		if st.Tables[i].Table == name {
			return &st.Tables[i]
		}
	}
	return nil
}

func stream(st *Status, name string) *StreamView {
	for i := range st.Streams {
		if st.Streams[i].Stream == name {
			return &st.Streams[i]
		}
	}
	return nil
}

// TestAssess_HealthyWithIdleSFlow: the operator's steady state is HEALTHY;
// the switched-off sFlow streams are neutral ("no data received", info),
// NetFlow is up to date with its compression ratio.
func TestAssess_HealthyWithIdleSFlow(t *testing.T) {
	h := Assess(healthyStatus(), defaultTh(), growing)
	if h.Verdict != VerdictHealthy || h.Errors != 0 || h.Warnings != 0 {
		t.Fatalf("verdict %s errors %d warnings %d: %+v", h.Verdict, h.Errors, h.Warnings, h.Issues)
	}
	for _, s := range []string{export.StreamSFlow, export.StreamSFlowCounters} {
		sh := streamHealth(t, h, s)
		if sh.State != "idle" || sh.Label != "No data received" {
			t.Errorf("%s: state %s %q, want idle", s, sh.State, sh.Label)
		}
	}
	nf := streamHealth(t, h, export.StreamNetFlow)
	if nf.State != "ok" || nf.CompressionRatio == nil || *nf.CompressionRatio != 8 {
		t.Errorf("netflow: %+v", nf)
	}
	if sh := streamHealth(t, h, export.StreamSyslog); sh.State != "off" {
		t.Errorf("syslog: %s, want off", sh.State)
	}
	idle := 0
	for _, is := range h.Issues {
		if is.Code == IssueStreamIdle {
			idle++
			if is.Severity != SeverityInfo {
				t.Errorf("stream_idle severity %s", is.Severity)
			}
		}
	}
	if idle != 2 {
		t.Errorf("%d stream_idle issues, want 2: %+v", idle, h.Issues)
	}
	if h.LastSuccessAt == nil || !h.LastSuccessAt.Equal(at.Add(-40*time.Minute)) {
		t.Errorf("last success %v", h.LastSuccessAt)
	}
	// The idle counters table (verified through yesterday) does not set
	// "verified through": flows does.
	if h.VerifiedThrough == nil || !h.VerifiedThrough.Equal(at.Add(-55*time.Minute)) {
		t.Errorf("verified through %v", h.VerifiedThrough)
	}
}

// TestAssess_IdleIsPresentationOnly: an idle sflow-counters table whose
// (empty) chunks stop being verified lags, and its overdue month is overdue —
// errors like any other table's; its state shows the error, not "No data
// received". Idle only names a stream that is otherwise fine.
func TestAssess_IdleIsPresentationOnly(t *testing.T) {
	st := healthyStatus()
	c := table(st, export.TableCounters)
	c.LagSeconds = fptr(200 * 3600)
	c.Backlog = &BacklogView{Chunks: 20, Verified: 15, Remaining: 5, RemainingRows: 0, State: "catching_up"}
	s := stream(st, export.StreamSFlowCounters)
	s.OldestUnsealed, s.UnsealedDays = "2026-08", 30
	h := Assess(sched(st), defaultTh(), growing)
	if lag, seal := issueOf(h, IssueArchiveLag), issueOf(h, IssueSealOverdue); lag == nil || seal == nil || lag.Severity != SeverityError ||
		seal.Severity != SeverityError || h.Verdict != VerdictError {
		t.Fatalf("verdict %s: %+v", h.Verdict, h.Issues)
	}
	if sh := streamHealth(t, h, export.StreamSFlowCounters); sh.State != "error" {
		t.Errorf("counters state %s, want error", sh.State)
	}
	if issueOf(h, IssueStreamIdle) == nil {
		t.Error("the idle note is gone")
	}
}

// TestAssess_DataResumesWhileTargetFails: NetFlow was silent, so flow_samples
// is idle (its last verified chunks are empty); it resumes while the target
// fails, so nothing with rows verifies and the table stays "idle" — the lag
// must still be an error, and ARCHIVE_LAG must still fire.
func TestAssess_DataResumesWhileTargetFails(t *testing.T) {
	st := healthyStatus()
	stream(st, export.StreamNetFlow).RecentRows = 0
	f := table(st, export.TableFlows)
	f.LagSeconds = fptr(5 * 3600)
	f.Backlog = &BacklogView{Chunks: 500, Verified: 495, Remaining: 5, RemainingRows: 90000, State: "catching_up"}
	st.Retrying = []ChunkView{{ID: 501, Table: export.TableFlows, Attempts: 4, Error: "upload: 503"}}
	if idle, _ := Idle(st); !idle[export.StreamNetFlow] {
		t.Fatal("fixture: netflow is not idle")
	}
	h := Assess(sched(st), defaultTh(), growing)
	if is := issueOf(h, IssueArchiveLag); is == nil || is.Severity != SeverityError || h.Verdict != VerdictError {
		t.Fatalf("verdict %s: %+v", h.Verdict, h.Issues)
	}
	if sh := streamHealth(t, h, export.StreamNetFlow); sh.State != "error" {
		t.Errorf("netflow %s, want error", sh.State)
	}
	if c := conditionOf(t, NewEvaluator().Conditions(sched(st), defaultTh(), growing), models.AlertTypeArchiveLag, export.TableFlows); !c.Breached {
		t.Errorf("ARCHIVE_LAG not breached: %+v", c)
	}
}

// TestAssess_HealthyOnlyWhenCaughtUp: one chunk left (the current period)
// is caught up; two or more is a backlog warning.
func TestAssess_HealthyOnlyWhenCaughtUp(t *testing.T) {
	for _, tc := range []struct {
		remaining int64
		state     string
		want      string
	}{{0, "caught_up", VerdictHealthy}, {1, "current", VerdictHealthy}, {2, "catching_up", VerdictWarning}, {40, "catching_up", VerdictWarning}} {
		st := healthyStatus()
		f := table(st, export.TableFlows)
		f.Backlog = &BacklogView{Chunks: 500, Verified: 500 - tc.remaining, Remaining: tc.remaining, RemainingRows: tc.remaining * 1000,
			State: tc.state, ETASeconds: fptr(1800)}
		h := Assess(sched(st), defaultTh(), growing)
		if h.Verdict != tc.want {
			t.Errorf("remaining %d: verdict %s, want %s (%+v)", tc.remaining, h.Verdict, tc.want, h.Issues)
		}
		if tc.want == VerdictWarning {
			if is := issueOf(h, IssueBacklog); is == nil || is.Table != export.TableFlows {
				t.Errorf("remaining %d: no backlog issue", tc.remaining)
			}
			if sh := streamHealth(t, h, export.StreamNetFlow); sh.State != "catching_up" {
				t.Errorf("remaining %d: netflow %s", tc.remaining, sh.State)
			}
			if h.BacklogChunks != tc.remaining-1 || h.ETASeconds == nil {
				t.Errorf("remaining %d: backlog %d eta %v", tc.remaining, h.BacklogChunks, h.ETASeconds)
			}
		}
	}
	// No chunk yet is not HEALTHY either.
	st := healthyStatus()
	f := table(st, export.TableFlows)
	f.HasChunks, f.Backlog, f.LagSeconds, f.VerifiedThroughEnd = false, nil, nil, nil
	stream(st, export.StreamNetFlow).RecentChunks = 0
	h := Assess(sched(st), defaultTh(), growing)
	if is := issueOf(h, IssueNoChunkYet); is == nil || h.Verdict != VerdictWarning {
		t.Errorf("no chunk: %s %+v", h.Verdict, h.Issues)
	}
}

// TestAssess_Issues: each condition, just under and just over its
// threshold.
func TestAssess_Issues(t *testing.T) {
	now := at
	stage := func(name string, since, last time.Time, msg string) StageView {
		return StageView{Stage: name, At: last, Since: &since, Error: msg, Count: 3}
	}
	cases := []struct {
		name    string
		mut     func(st *Status)
		disk    *DiskTrend
		code    string // "" = no issue but the steady state's
		sev     string
		verdict string
	}{
		{"worker never reported", func(st *Status) { st.Worker = nil }, nil, IssueWorkerNotRunning, SeverityError, VerdictError},
		{"worker stale", func(st *Status) { st.Worker.Stale, st.Worker.SeenAt = true, now.Add(-20*time.Minute) }, nil, IssueWorkerNotRunning, SeverityError, VerdictError},
		{"config refused", func(st *Status) {
			st.Worker.Runner, st.Worker.PreflightOK = ConfigProblemRunner, false
			st.Worker.Stages = []StageView{stage("config", now.Add(-time.Minute), now, "ARCHIVE_S3_BUCKET is required")}
		}, nil, IssueConfigInvalid, SeverityError, VerdictError},
		{"preflight failing 5 min", func(st *Status) {
			st.Worker.PreflightOK = false
			st.Worker.Stages = []StageView{stage("preflight", now.Add(-5*time.Minute), now, "dial tcp: i/o timeout")}
		}, nil, IssuePreflightFailing, SeverityWarning, VerdictWarning},
		{"preflight failing 16 min", func(st *Status) {
			st.Worker.PreflightOK = false
			st.Worker.Stages = []StageView{stage("preflight", now.Add(-16*time.Minute), now, "dial tcp: i/o timeout")}
		}, nil, IssuePreflightFailing, SeverityError, VerdictError},
		{"marker missing", func(st *Status) {
			st.Worker.PreflightOK, st.Worker.PreflightIssue = false, PreflightMarkerMissing
			st.Worker.Stages = []StageView{stage("preflight", now.Add(-time.Minute), now, "archive target not initialised")}
		}, nil, IssueMarkerMissing, SeverityError, VerdictError},
		{"marker foreign", func(st *Status) {
			st.Worker.PreflightOK, st.Worker.PreflightIssue = false, PreflightMarkerForeign
		}, nil, IssueMarkerForeign, SeverityError, VerdictError},
		{"retrying, target failing 30 min", func(st *Status) {
			table(st, export.TableFlows).LastVerifiedAt = tp(now.Add(-2 * time.Hour))
			st.Retrying = []ChunkView{{ID: 7, Table: export.TableFlows, Attempts: 3, Error: "upload: 503"}}
			st.Worker.Stages = []StageView{stage("upload", now.Add(-30*time.Minute), now.Add(-time.Minute), "503 Service Unavailable")}
		}, nil, IssueChunksRetrying, SeverityWarning, VerdictWarning},
		{"retrying, target failing 61 min", func(st *Status) {
			table(st, export.TableFlows).LastVerifiedAt = tp(now.Add(-2 * time.Hour))
			table(st, export.TableCounters).LastVerifiedAt = tp(now.Add(-3 * time.Hour))
			st.Retrying = []ChunkView{{ID: 7, Table: export.TableFlows, Attempts: 3, Error: "upload: 503"}}
			st.Worker.Stages = []StageView{stage("upload", now.Add(-61*time.Minute), now.Add(-time.Minute), "503 Service Unavailable")}
		}, nil, IssueTargetFailing, SeverityError, VerdictError},
		{"retrying, a success since the first failure", func(st *Status) {
			table(st, export.TableFlows).LastVerifiedAt = tp(now.Add(-10 * time.Minute))
			st.Retrying = []ChunkView{{ID: 7, Table: export.TableFlows, Attempts: 1, Error: "upload: 503"}}
			st.Worker.Stages = []StageView{stage("upload", now.Add(-5*time.Hour), now.Add(-time.Minute), "503 Service Unavailable")}
		}, nil, IssueChunksRetrying, SeverityWarning, VerdictWarning},
		{"needs attention", func(st *Status) {
			st.NeedsAttention = []ParkedChunk{{ID: 9, Table: export.TableFlows, Seq: 9, Error: "count differs", HoldsGate: true, UpdatedAt: now.Add(-time.Hour)}}
		}, nil, IssueNeedsAttention, SeverityError, VerdictError},
		{"seal 2.9 days late", func(st *Status) {
			s := stream(st, export.StreamNetFlow)
			s.OldestUnsealed, s.UnsealedDays = "2026-09", 2.9
		}, nil, "", "", VerdictHealthy},
		{"seal 3.1 days late", func(st *Status) {
			s := stream(st, export.StreamNetFlow)
			s.OldestUnsealed, s.UnsealedDays = "2026-09", 3.1
		}, nil, IssueSealOverdue, SeverityError, VerdictError},
		{"held 5 h", func(st *Status) { table(st, export.TableFlows).Retention.HeldSeconds = 5 * 3600 }, nil, "", "", VerdictHealthy},
		{"held 7 h, disk growing", func(st *Status) { table(st, export.TableFlows).Retention.HeldSeconds = 7 * 3600 }, nil,
			IssueRetentionHeld, SeverityError, VerdictError},
		{"held 7 h, disk unknown", func(st *Status) { table(st, export.TableFlows).Retention.HeldSeconds = 7 * 3600 }, &DiskTrend{Detail: "not measured"},
			IssueRetentionHeld, SeverityError, VerdictError},
		{"held 7 h, disk not growing", func(st *Status) { table(st, export.TableFlows).Retention.HeldSeconds = 7 * 3600 },
			&DiskTrend{Known: true, Detail: "steady"}, IssueRetentionHeld, SeverityWarning, VerdictWarning},
		{"held 7 h, gate released", func(st *Status) {
			table(st, export.TableFlows).Retention.HeldSeconds = 7 * 3600
			st.Gates[1].Gated, st.Gates[1].OverrideActive = false, true
		}, nil, IssueOverrideActive, SeverityWarning, VerdictWarning},
		// Lateness: an hour's chunk is due 1 h 15 min after the verified
		// data's end, so a 3 h threshold is passed at a lag of 4.25 h.
		{"flows lag 4.2 h (2.95 h late)", func(st *Status) { table(st, export.TableFlows).LagSeconds = fptr(4.2 * 3600) }, nil, "", "", VerdictHealthy},
		{"flows lag 4.3 h (3.05 h late)", func(st *Status) { table(st, export.TableFlows).LagSeconds = fptr(4.3 * 3600) }, nil, IssueArchiveLag, SeverityError, VerdictError},
		{"staging under 2x floor", func(st *Status) { st.Worker.Staging.FreeBytes = u64(3 << 30) }, nil, IssueStagingLow, SeverityWarning, VerdictWarning},
		{"staging under floor", func(st *Status) { st.Worker.Staging.FreeBytes = u64(1 << 30) }, nil, IssueStagingFull, SeverityError, VerdictError},
		{"staging unknown", func(st *Status) {
			st.Worker.Staging.FreeBytes, st.Worker.Staging.Error = nil, "statfs: permission denied"
		}, nil,
			IssueStagingLow, SeverityWarning, VerdictWarning},
		{"override on a disabled gate", func(st *Status) { st.Gates[0].OverrideActive = true }, nil, "", "", VerdictHealthy},
		{"gate unreadable 5 min", func(st *Status) {
			st.GateRead = &GateReadView{FailingSince: now.Add(-5 * time.Minute), ForSeconds: 300, Error: "timeout"}
		}, nil, IssueGateUnreadable, SeverityWarning, VerdictWarning},
		{"gate unreadable 16 min", func(st *Status) {
			st.GateRead = &GateReadView{FailingSince: now.Add(-16 * time.Minute), ForSeconds: 960, Error: "timeout", HoldingAll: true}
		}, nil, IssueGateUnreadable, SeverityError, VerdictError},
		{"open writer 5 h", func(st *Status) {
			table(st, export.TableFlows).Unsettled = &UnsettledView{Reason: "open_writer", ForSeconds: 5 * 3600}
		}, nil, "", "", VerdictHealthy},
		{"open writer 7 h", func(st *Status) {
			table(st, export.TableFlows).Unsettled = &UnsettledView{Reason: "open_writer", ForSeconds: 7 * 3600, Detail: "pid 4242"}
		}, nil, IssueUnsettledLong, SeverityWarning, VerdictWarning},
		{"settling 7 h is not a wait", func(st *Status) {
			table(st, export.TableFlows).Unsettled = &UnsettledView{Reason: "settling", ForSeconds: 7 * 3600}
		}, nil, "", "", VerdictHealthy},
		{"object lock off", func(st *Status) { st.Config.ObjectLockDays = 0 }, nil, IssueObjectLockOff, SeverityWarning, VerdictWarning},
		{"local target without object lock", func(st *Status) {
			st.Config.ObjectLockDays, st.Config.Target, st.Config.LocalDir, st.Config.Bucket = 0, config.ArchiveTargetLocal, "/archive/fwmon", ""
		}, nil, "", "", VerdictHealthy},
		{"settings pending", func(st *Status) { st.ConfigPending = true }, nil, IssueConfigPending, SeverityWarning, VerdictWarning},
		{"status incomplete", func(st *Status) { st.Problems = []string{"chunk counts: timeout"} }, nil, IssueStatusIncomplete, SeverityWarning, VerdictWarning},
		{"partial month is information", func(st *Status) {
			stream(st, export.StreamNetFlow).Months = []MonthView{{Month: "2026-09", Status: models.ArchiveMonthSealed, Partial: true, PartialNote: "override"}}
		}, nil, IssueMonthPartial, SeverityInfo, VerdictHealthy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := healthyStatus()
			tc.mut(st)
			disk := growing
			if tc.disk != nil {
				disk = *tc.disk
			}
			h := Assess(sched(st), defaultTh(), disk)
			if h.Verdict != tc.verdict {
				t.Errorf("verdict %s, want %s: %+v", h.Verdict, tc.verdict, h.Issues)
			}
			if tc.code == "" {
				for _, is := range h.Issues {
					if is.Code != IssueStreamIdle {
						t.Errorf("unexpected issue %s (%s)", is.Code, is.Severity)
					}
				}
				return
			}
			is := issueOf(h, tc.code)
			if is == nil {
				t.Fatalf("no %s issue: %+v", tc.code, h.Issues)
			}
			if is.Severity != tc.sev {
				t.Errorf("%s severity %s, want %s", tc.code, is.Severity, tc.sev)
			}
			if is.Title == "" || is.Meaning == "" || is.Action == "" || is.Action != strings.ReplaceAll(IssueActions[tc.code], "<stream>", "flows") {
				t.Errorf("%s incomplete: %+v", tc.code, is)
			}
			if tc.verdict != VerdictHealthy && h.Summary == "" {
				t.Error("no summary")
			}
		})
	}
}

// TestAssess_SinceAndOrder: the "since" of a failing target runs from its
// first failure (or the last success after it); a blocking error marks every
// enabled stream stalled, and the lag it causes is part of it — one cause,
// one error — not a second error.
func TestAssess_SinceAndOrder(t *testing.T) {
	st := healthyStatus()
	first := at.Add(-20 * time.Minute)
	st.Worker.PreflightOK = false
	st.Worker.Stages = []StageView{{Stage: "preflight", At: at, Since: &first, Error: "403 Forbidden"}}
	table(st, export.TableFlows).LagSeconds = fptr(5 * 3600)
	h := Assess(sched(st), defaultTh(), growing)
	if len(h.Issues) < 1 || h.Issues[0].Code != IssuePreflightFailing || issueOf(h, IssueArchiveLag) != nil || h.Errors != 1 ||
		!strings.Contains(h.Issues[0].Risk, "The flow archive is 5.0 h behind.") {
		t.Fatalf("issues: %+v", h.Issues)
	}
	if h.Issues[0].Since == nil || !h.Issues[0].Since.Equal(first) || h.Issues[0].Detail != "403 Forbidden" || h.Issues[0].Fix == nil || h.Issues[0].Fix.Kind != "test" {
		t.Errorf("preflight issue: %+v", h.Issues[0])
	}
	if h.Summary != "The archive target cannot be reached" {
		t.Errorf("summary %q", h.Summary)
	}
	if sh := streamHealth(t, h, export.StreamNetFlow); sh.State != "stalled" {
		t.Errorf("netflow %s, want stalled", sh.State)
	}
	if sh := streamHealth(t, h, export.StreamSFlow); sh.State != "stalled" {
		t.Errorf("sflow %s, want stalled", sh.State)
	}
}

// TestAssess_LagMergedIntoStageCause: a planner failing for a table is the
// cause of its lag: one error (stage_failing, saying how far behind), not
// two; a step failing for another table leaves the lag its own error.
func TestAssess_LagMergedIntoStageCause(t *testing.T) {
	for _, subject := range []string{export.TableFlows, export.TableCounters} {
		st := healthyStatus()
		f := table(st, export.TableFlows)
		f.LagSeconds = fptr(5 * 3600)
		f.Backlog = &BacklogView{Chunks: 500, Verified: 500, State: "caught_up"}
		st.Worker.Failing = []Streak{{Stage: "plan", Subject: subject, Since: at.Add(-3 * time.Hour), At: at.Add(-time.Minute), Error: "refused", Count: 18}}
		h := Assess(sched(st), defaultTh(), growing)
		sf, lag := issueOf(h, IssueStageFailing), issueOf(h, IssueArchiveLag)
		if subject == export.TableFlows {
			if sf == nil || lag != nil || h.Errors != 1 || !strings.Contains(sf.Risk, "The flow archive is 5.0 h behind.") {
				t.Fatalf("same table: %+v", h.Issues)
			}
		} else if sf == nil || lag == nil || h.Errors != 2 {
			t.Fatalf("other table: %+v", h.Issues)
		}
	}
}

// TestAssess_DisabledAndNotConfigured: archiving off is neutral, named by
// whether a target is set.
func TestAssess_DisabledAndNotConfigured(t *testing.T) {
	st := healthyStatus()
	st.Enabled = false
	st.Worker = nil
	for i := range st.Tables {
		st.Tables[i].Enabled = false
	}
	for i := range st.Streams {
		st.Streams[i].Enabled = false
	}
	h := Assess(sched(st), defaultTh(), growing)
	if h.Verdict != VerdictDisabled || len(h.Issues) != 0 {
		t.Errorf("disabled: %s %+v", h.Verdict, h.Issues)
	}
	st.Config.Bucket = ""
	if h := Assess(sched(st), defaultTh(), growing); h.Verdict != VerdictNotConfigured {
		t.Errorf("not configured: %s", h.Verdict)
	}
	st.Config.Target, st.Config.LocalDir = config.ArchiveTargetLocal, "/archive/fwmon"
	if h := Assess(sched(st), defaultTh(), growing); h.Verdict != VerdictDisabled {
		t.Errorf("local disabled: %s", h.Verdict)
	}
}

// TestConditions_NameIssueAndAction: the alerts carry the verdict's issue
// codes and actions; an alert that is the effect of a blocking error names
// that cause.
func TestConditions_NameIssueAndAction(t *testing.T) {
	st := healthyStatus()
	first := at.Add(-time.Hour)
	st.Worker.PreflightOK = false
	st.Worker.Stages = []StageView{{Stage: "preflight", At: at, Since: &first, Error: "403 Forbidden"}}
	table(st, export.TableFlows).LagSeconds = fptr(5 * 3600)
	st.NeedsAttention = []ParkedChunk{{ID: 9, Table: export.TableFlows, Seq: 9, UpdatedAt: at}}
	cs := NewEvaluator().Conditions(sched(st), defaultTh(), growing)
	lag := conditionOf(t, cs, models.AlertTypeArchiveLag, export.TableFlows)
	if !lag.Breached || lag.Fields["issue"] != IssueArchiveLag || lag.Fields["cause"] != IssuePreflightFailing || lag.Fields["verdict"] != VerdictError {
		t.Fatalf("lag: %+v", lag)
	}
	if !strings.Contains(lag.Message, "Cause: The archive target cannot be reached") || !strings.Contains(lag.Message, IssueActions[IssuePreflightFailing]) {
		t.Errorf("lag message %q", lag.Message)
	}
	na := conditionOf(t, cs, models.AlertTypeArchiveNeedsAttention, export.TableFlows)
	if na.Fields["issue"] != IssueNeedsAttention || !strings.HasSuffix(na.Message, "Action: "+IssueActions[IssueNeedsAttention]) {
		t.Errorf("needs attention: %+v", na)
	}
	// A condition that is not breached carries the code, not the action.
	seal := conditionOf(t, cs, models.AlertTypeArchiveSealOverdue, export.StreamNetFlow)
	if seal.Breached || seal.Fields["issue"] != IssueSealOverdue || strings.Contains(seal.Message, "Action:") {
		t.Errorf("seal: %+v", seal)
	}
	since := at.Add(-20 * time.Minute)
	gc := GateReadCondition(database.ArchiveGateHealth{FailingSince: &since, Error: "timeout", SeenAt: at}, at)
	if !gc.Breached || gc.Fields["issue"] != IssueGateUnreadable || !strings.Contains(gc.Message, "Action: "+IssueActions[IssueGateUnreadable]) {
		t.Errorf("gate: %+v", gc)
	}
}

// TestRecorderStageSince: a stage's first failure is kept as Since while
// its last moves on; the preflight issue clears when the preflight passes.
func TestRecorderStageSince(t *testing.T) {
	r := NewRecorder("fw-example-01-1", "/tmp/x", 1)
	t0 := at.Add(-time.Hour)
	r.Failed("preflight", errors.New("a"), t0)
	r.Failed("preflight", errors.New("b"), at)
	r.SetPreflightIssue(PreflightMarkerMissing)
	snap := r.Snapshot(at)
	e := snap.Stages["preflight"]
	if e.Since == nil || !e.Since.Equal(t0) || !e.At.Equal(at) || e.Count != 2 || snap.PreflightIssue != PreflightMarkerMissing {
		t.Fatalf("stage %+v issue %q", e, snap.PreflightIssue)
	}
	r.SetPreflight(true)
	if r.Snapshot(at).PreflightIssue != "" {
		t.Error("preflight issue kept after the preflight passed")
	}
}

// TestBuild_HealthInputs: Build reports the per-stream recent rows and bytes
// from the verified objects (a stream without objects is idle), the
// preflight issue and stage since from the snapshot, and ConfigPending
// when the fresh worker runs other settings than those in effect.
func TestBuild_HealthInputs(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	c := chunk(t, db, export.TableFlows, 1, 0, 50, time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC), time.Hour, models.ArchiveChunkVerified)
	object(t, db, c, export.StreamNetFlow, 40, 1000)
	chunk(t, db, export.TableCounters, 1, 0, 0, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), 24*time.Hour, models.ArchiveChunkVerified)
	cfg := testConfig(false, true)

	r := NewRecorder("fw-example-01-1", "/tmp/x", 1)
	r.SetConfigFingerprint(cfg.Archive.Fingerprint())
	r.Failed("preflight", errors.New("archive target not initialised"), at.Add(-time.Hour))
	r.SetPreflightIssue(PreflightMarkerMissing)
	save := func() {
		js, err := r.JSON(at.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
			t.Fatal(err)
		}
	}
	save()
	st := build(t, db, cfg, at)
	nf, sf, ct := streamOf(t, st, export.StreamNetFlow), streamOf(t, st, export.StreamSFlow), streamOf(t, st, export.StreamSFlowCounters)
	if nf.RecentChunks != 1 || nf.RecentRows != 40 || nf.RecentObjectBytes != 1000 || nf.RecentRawBytes != 4000 {
		t.Errorf("netflow recent: %+v", nf)
	}
	if sf.RecentChunks != 1 || sf.RecentRows != 0 || ct.RecentChunks != 1 || ct.RecentRows != 0 {
		t.Errorf("idle streams: sflow %+v counters %+v", sf, ct)
	}
	if st.Worker.PreflightIssue != PreflightMarkerMissing || st.ConfigPending {
		t.Errorf("worker %+v pending %v", st.Worker, st.ConfigPending)
	}
	if len(st.Worker.Stages) != 1 || st.Worker.Stages[0].Since == nil || !st.Worker.Stages[0].Since.Equal(at.Add(-time.Hour)) {
		t.Errorf("stages %+v", st.Worker.Stages)
	}
	h := Assess(sched(st), defaultTh(), growing)
	if is := issueOf(h, IssueMarkerMissing); is == nil || h.Verdict != VerdictError {
		t.Errorf("verdict %s %+v", h.Verdict, h.Issues)
	}
	if idle, _ := Idle(st); !idle[export.StreamSFlow] || idle[export.StreamNetFlow] {
		t.Errorf("idle %v", idle)
	}
	// A blocking error stalls every stream, the idle ones too.
	if sh := streamHealth(t, h, export.StreamSFlow); sh.State != "stalled" {
		t.Errorf("sflow %s", sh.State)
	}

	// The settings change; the worker still runs the old ones.
	cfg.Archive.MinAgeHours = 3
	if st := build(t, db, cfg, at); !st.ConfigPending {
		t.Error("settings changed: not pending")
	}
	// A stale snapshot says nothing about the settings.
	if st := build(t, db, cfg, at.Add(StaleAfter+time.Hour)); st.ConfigPending {
		t.Error("stale snapshot: pending")
	}
}

// TestFingerprint: every field but the secret changes it.
func TestFingerprint(t *testing.T) {
	a := testConfig(false, true).Archive
	fp := a.Fingerprint()
	if len(fp) != 16 || fp != a.Fingerprint() {
		t.Fatalf("fingerprint %q", fp)
	}
	b := a
	b.SecretAccessKey = "another-test-secret"
	if b.Fingerprint() != fp {
		t.Error("the secret changes the fingerprint")
	}
	b = a
	b.Bucket = "example-bucket-2"
	if b.Fingerprint() == fp {
		t.Error("the bucket does not change the fingerprint")
	}
}

// TestAssess_LagWithoutBacklog: a table lags with no chunk left to export
// (its planner fails, so nothing new is cut): still an archive_lag error, not
// HEALTHY — idle or not.
func TestAssess_LagWithoutBacklog(t *testing.T) {
	st := healthyStatus()
	f := table(st, export.TableFlows)
	f.LagSeconds = fptr(5 * 3600)
	f.Backlog = &BacklogView{Chunks: 500, Verified: 500, Remaining: 0, State: "caught_up"}
	h := Assess(sched(st), defaultTh(), growing)
	if is := issueOf(h, IssueArchiveLag); is == nil || is.Severity != SeverityError || is.Table != export.TableFlows || h.Verdict != VerdictError {
		t.Fatalf("non-idle: %s %+v", h.Verdict, h.Issues)
	}
	if strings.Contains(issueOf(h, IssueArchiveLag).Title, "sflow and netflow") || !strings.Contains(issueOf(h, IssueArchiveLag).Title, "flow archive") {
		t.Errorf("title %q", issueOf(h, IssueArchiveLag).Title)
	}
	stream(st, export.StreamNetFlow).RecentRows = 0 // nothing received: the table is idle
	if h := Assess(sched(st), defaultTh(), growing); issueOf(h, IssueArchiveLag) == nil || h.Verdict != VerdictError {
		t.Fatalf("idle: %s %+v", h.Verdict, h.Issues)
	}
}

// TestAssess_StageFailing: a stage failing for a subject with no success in
// between is a warning from 30 min and an error from 2 h; a streak last seen
// over 3 h ago is over; the chunk stages of a table whose chunks wait for
// their retry are left to chunks_retrying.
func TestAssess_StageFailing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		stage    string
		since    time.Duration
		last     time.Duration
		retrying bool
		want     string
	}{
		{"plan 10 min", "plan", 10 * time.Minute, time.Minute, false, ""},
		{"plan 40 min", "plan", 40 * time.Minute, time.Minute, false, SeverityWarning},
		{"plan 3 h", "plan", 3 * time.Hour, 5 * time.Minute, false, SeverityError},
		{"plan last seen 4 h ago", "plan", 9 * time.Hour, 4 * time.Hour, false, ""},
		{"upload 3 h, chunks retrying", "upload", 3 * time.Hour, time.Minute, true, ""},
		{"upload 3 h, nothing retrying", "upload", 3 * time.Hour, time.Minute, false, SeverityError},
		{"count 3 h, a chunk parked", "count", 3 * time.Hour, time.Minute, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := healthyStatus()
			st.Worker.Failing = []Streak{{Stage: tc.stage, Subject: export.TableFlows, Since: at.Add(-tc.since), At: at.Add(-tc.last), Error: "archive: refused", Count: 9}}
			if tc.retrying {
				st.Retrying = []ChunkView{{ID: 3, Table: export.TableFlows, Error: "upload: 503"}}
			}
			if tc.stage == "count" {
				st.NeedsAttention = []ParkedChunk{{ID: 4, Table: export.TableFlows, Seq: 4, UpdatedAt: at}}
			}
			h := Assess(sched(st), defaultTh(), growing)
			is := issueOf(h, IssueStageFailing)
			if tc.want == "" {
				if is != nil {
					t.Fatalf("unexpected %+v", is)
				}
				return
			}
			if is == nil || is.Severity != tc.want || is.Table != export.TableFlows || is.Detail != "archive: refused" ||
				!strings.Contains(is.Title, tc.stage) || is.Action != IssueActions[IssueStageFailing] {
				t.Fatalf("issue %+v", is)
			}
			if sh := streamHealth(t, h, export.StreamNetFlow); tc.want == SeverityError && sh.State != "error" {
				t.Errorf("netflow %s", sh.State)
			}
		})
	}
}

// TestAssess_FirstChunkEscalates: a table without a chunk is a warning, and
// an error once the worker has seen it so for longer than its lag threshold
// (as ARCHIVE_LAG's no-chunk branch, which reads the same record).
func TestAssess_FirstChunkEscalates(t *testing.T) {
	for _, tc := range []struct {
		waited time.Duration
		want   string
	}{{time.Hour, SeverityWarning}, {4 * time.Hour, SeverityWarning}, {4*time.Hour + 20*time.Minute, SeverityError}} {
		st := healthyStatus()
		f := table(st, export.TableFlows)
		f.HasChunks, f.Backlog, f.LagSeconds, f.VerifiedThroughEnd = false, nil, nil, nil
		stream(st, export.StreamNetFlow).RecentChunks = 0
		st.Worker.NoChunkSince = map[string]time.Time{export.TableFlows: at.Add(-tc.waited)}
		h := Assess(sched(st), defaultTh(), growing)
		is := issueOf(h, IssueNoChunkYet)
		if is == nil || is.Severity != tc.want || is.Since == nil {
			t.Fatalf("waited %s: %+v", tc.waited, is)
		}
		// The alert agrees, from a fresh evaluator (a poller just restarted).
		c := conditionOf(t, NewEvaluator().Conditions(sched(st), defaultTh(), growing), models.AlertTypeArchiveLag, export.TableFlows)
		if c.Breached != (tc.want == SeverityError) || c.Fields["issue"] != IssueNoChunkYet || c.Fields["no_chunk"] != "true" {
			t.Errorf("waited %s: alert %+v", tc.waited, c)
		}
	}
}

// TestAlertsAgreeOnIdle: the alerts and the verdict agree whether a stream
// receives data or not — idle suppresses neither: a lagging table and an
// overdue month are reported by both.
func TestAlertsAgreeOnIdle(t *testing.T) {
	for _, withData := range []bool{false, true} {
		st := healthyStatus()
		c := table(st, export.TableCounters)
		c.LagSeconds = fptr(100 * 3600)
		s := stream(st, export.StreamSFlowCounters)
		s.OldestUnsealed, s.UnsealedDays = "2026-08", 30
		if withData {
			s.RecentRows = 5
		}
		h := Assess(sched(st), defaultTh(), growing)
		cs := NewEvaluator().Conditions(sched(st), defaultTh(), growing)
		lag := conditionOf(t, cs, models.AlertTypeArchiveLag, export.TableCounters)
		seal := conditionOf(t, cs, models.AlertTypeArchiveSealOverdue, export.StreamSFlowCounters)
		verdictLag, verdictSeal := issueOf(h, IssueArchiveLag) != nil, issueOf(h, IssueSealOverdue) != nil
		if !lag.Breached || !verdictLag || !seal.Breached || !verdictSeal {
			t.Errorf("with data %v: alert lag %v seal %v, verdict lag %v seal %v", withData, lag.Breached, seal.Breached, verdictLag, verdictSeal)
		}
	}
}

// TestRecorderRestore: a restart keeps the failures going on and their
// first instant; a new failure of the same stage and subject continues the
// streak; a success ends it; a streak last seen over a day ago is dropped.
func TestRecorderRestore(t *testing.T) {
	prev := NewRecorder("fw-example-01-1", "/tmp/x", 1)
	t0 := at.Add(-2 * time.Hour)
	prev.Fail("plan", export.TableFlows, errors.New("a"), t0)
	prev.Fail("mark", export.TableFlows, errors.New("old"), at.Add(-30*time.Hour))
	prev.SetNoChunk(export.TableSyslog, true, t0)
	old := prev.Snapshot(at.Add(-time.Minute))

	r := NewRecorder("fw-example-01-2", "/tmp/x", 1)
	r.Restore(&old, at, []string{export.TableSyslog, export.TableFlows})
	r.Fail("plan", export.TableFlows, errors.New("b"), at)
	snap := r.Snapshot(at)
	f := snap.Failing["plan/"+export.TableFlows]
	if !f.Since.Equal(t0) || f.Count != 2 || f.Error != "b" || snap.Stages["plan"].Since == nil || !snap.Stages["plan"].Since.Equal(t0) {
		t.Fatalf("restored streak %+v stage %+v", f, snap.Stages["plan"])
	}
	if _, ok := snap.Failing["mark/"+export.TableFlows]; ok {
		t.Error("a streak last seen 30 h ago was restored")
	}
	if !snap.NoChunkSince[export.TableSyslog].Equal(t0) {
		t.Errorf("no-chunk since %v", snap.NoChunkSince)
	}
	// No-chunk instants: only for a table archived now, and only from a
	// recent snapshot (switched off before its first chunk and on again
	// two months later is a fresh start, not an immediate error).
	for _, tc := range []struct {
		name   string
		tables []string
		age    time.Duration
		want   bool
	}{
		{"archived, recent snapshot", []string{export.TableSyslog}, time.Minute, true},
		{"not archived now", []string{export.TableFlows}, time.Minute, false},
		{"snapshot two months old", []string{export.TableSyslog}, 60 * 24 * time.Hour, false},
	} {
		x := NewRecorder("fw-example-01-3", "/tmp/x", 1)
		o := prev.Snapshot(at.Add(-tc.age))
		x.Restore(&o, at, tc.tables)
		if _, ok := x.Snapshot(at).NoChunkSince[export.TableSyslog]; ok != tc.want {
			t.Errorf("%s: restored %v, want %v", tc.name, ok, tc.want)
		}
	}
	r.OK("plan", export.TableFlows)
	r.Fail("plan", export.TableFlows, errors.New("c"), at.Add(time.Minute))
	if f := r.Snapshot(at).Failing["plan/"+export.TableFlows]; !f.Since.Equal(at.Add(time.Minute)) || f.Count != 1 {
		t.Errorf("after a success: %+v", f)
	}
}

// TestAssess_PreflightSinceFromStreak: the preflight's "since" is the
// current run of failures (the streak), not the stage's first failure ever
// recorded: a preflight that failed a day ago, passed, and fails again now
// is a warning, not at once an error.
func TestAssess_PreflightSinceFromStreak(t *testing.T) {
	st := healthyStatus()
	long := at.Add(-24 * time.Hour)
	st.Worker.PreflightOK = false
	st.Worker.Stages = []StageView{{Stage: "preflight", At: at, Since: &long, Error: "403 Forbidden"}}
	st.Worker.Failing = []Streak{{Stage: "preflight", Since: at.Add(-2 * time.Minute), At: at, Error: "403 Forbidden", Count: 2}}
	is := issueOf(Assess(sched(st), defaultTh(), growing), IssuePreflightFailing)
	if is == nil || is.Severity != SeverityWarning || !is.Since.Equal(at.Add(-2*time.Minute)) {
		t.Fatalf("%+v", is)
	}
}

// TestConditions_HeldActionSelfContained: the held-rows alert names its own
// gate stream in the override command, once, and says where to look —
// nothing refers to a page section "above".
func TestConditions_HeldActionSelfContained(t *testing.T) {
	st := healthyStatus()
	table(st, export.TableFlows).Retention.HeldSeconds = 8 * 3600
	c := conditionOf(t, NewEvaluator().Conditions(sched(st), defaultTh(), growing), models.AlertTypeRetentionHeld, export.TableFlows)
	if !c.Breached || strings.Count(c.Message, "--override") != 1 || !strings.Contains(c.Message, "--override flows --for 6h") ||
		strings.Contains(c.Message, "<stream>") || strings.Contains(c.Message, "above") {
		t.Fatalf("message %q", c.Message)
	}
	if is := issueOf(Assess(sched(st), defaultTh(), growing), IssueRetentionHeld); is == nil || !strings.Contains(is.Action, "--override flows --for 6h") {
		t.Errorf("the page's held-rows action: %+v", is)
	}
	for code, action := range IssueActions {
		if strings.Contains(action, "above") || strings.Contains(action, "below") {
			t.Errorf("%s's action refers to the page layout: %q", code, action)
		}
	}
}

// TestRecorderPrunesOldStreaks: a streak last seen over a day ago (its
// table switched off, the step no longer run) leaves the snapshot, so the
// map stays bounded in a long-running worker; a recent one stays.
func TestRecorderPrunesOldStreaks(t *testing.T) {
	r := NewRecorder("fw-example-01-1", "/tmp/x", 1)
	r.Fail("mark", export.TableCounters, errors.New("old"), at.Add(-25*time.Hour))
	r.Fail("plan", export.TableFlows, errors.New("new"), at.Add(-time.Hour))
	snap := r.Snapshot(at)
	if _, ok := snap.Failing["mark/"+export.TableCounters]; ok {
		t.Error("a streak last seen 25 h ago is kept")
	}
	if _, ok := snap.Failing["plan/"+export.TableFlows]; !ok || len(snap.Failing) != 1 {
		t.Errorf("failing %+v", snap.Failing)
	}
}

// prodDay is an install shaped like production with syslog on: daily
// syslog_messages (a heavy 8 M-row day exported at 4 200 rows/s, then read
// back) and flow_if_counters, hourly flow_samples, ARCHIVE_MIN_AGE_HOURS 2.
// syslogEnd and countersEnd are the ends of their verified data at now;
// flows are verified through the previous full hour.
func prodDay(now, syslogEnd, countersEnd time.Time, flowsEnd time.Time) *Status {
	st := healthyStatus()
	st.GeneratedAt = now
	st.Config.SyslogEnabled = true
	st.Gates[0] = GateView{Stream: database.ArchiveGateSyslog, Enabled: true, Gated: true}
	lag := func(end time.Time) *float64 { return fptr(now.Sub(end).Seconds()) }
	sl := table(st, export.TableSyslog)
	sl.Enabled, sl.HasChunks, sl.VerifiedThroughEnd, sl.LagSeconds = true, true, &syslogEnd, lag(syslogEnd)
	sl.LastVerifiedAt = tp(syslogEnd.Add(2*time.Hour + 50*time.Minute))
	sl.Backlog = &BacklogView{Chunks: 60, Verified: 59, Remaining: 1, RemainingRows: 8_000_000, State: "current"}
	sl.Retention = &RetentionView{Window: "30d", Cutoff: now.AddDate(0, 0, -30)}
	sy := stream(st, export.StreamSyslog)
	sy.Enabled, sy.RecentChunks, sy.RecentRows = true, 10, 60_000_000
	f := table(st, export.TableFlows)
	f.VerifiedThroughEnd, f.LagSeconds = &flowsEnd, lag(flowsEnd)
	c := table(st, export.TableCounters)
	c.VerifiedThroughEnd, c.LagSeconds = &countersEnd, lag(countersEnd)
	// Day D is being exported: 8 M rows at 4 200 rows/s.
	st.Worker.Activity = &ActivityView{Activity: Activity{Table: export.TableSyslog, Stage: "export", RowsDone: 4_200 * 1800, IDSpan: 8_000_000}}
	return st
}

// TestAssess_NormalDayIsHealthy walks a normal night with real timings:
// syslog's day D can be cut at D+1 02:00 and a heavy day is still being
// exported at 04:59 — HEALTHY, no ARCHIVE_LAG; at 05:30 with nothing
// verified it is over 3 h late — an error, and the alert fires. Hourly
// flows: 1.2 h old is on time, 4.5 h old is late. The review's cases: a
// 26.5 h raw age is on time, 30 h is late.
func TestAssess_NormalDayIsHealthy(t *testing.T) {
	d := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC) // midnight after day D (6 October)
	dayD := d.AddDate(0, 0, -1)
	for _, tc := range []struct {
		at          time.Duration // after midnight
		syslogEnd   time.Time
		countersEnd time.Time
		want        string
	}{
		{0, dayD, dayD, VerdictHealthy},
		{2 * time.Hour, dayD, dayD, VerdictHealthy},
		{150 * time.Minute, dayD, d, VerdictHealthy},            // counters' day verified at 02:15
		{4 * time.Hour, dayD, d, VerdictHealthy},                // syslog's day still exporting
		{4*time.Hour + 59*time.Minute, dayD, d, VerdictHealthy}, // still exporting: 2.8 h late
		{5*time.Hour + 30*time.Minute, dayD, d, VerdictError},   // nothing verified: 3.3 h late
	} {
		now := d.Add(tc.at)
		flowsEnd := now.Truncate(time.Hour).Add(-time.Hour)
		st := sched(prodDay(now, tc.syslogEnd, tc.countersEnd, flowsEnd))
		h := Assess(st, defaultTh(), growing)
		lag := conditionOf(t, NewEvaluator().Conditions(st, defaultTh(), growing), models.AlertTypeArchiveLag, export.TableSyslog)
		if h.Verdict != tc.want || lag.Breached != (tc.want == VerdictError) {
			t.Errorf("%s: verdict %s (want %s), ARCHIVE_LAG %v: %+v", now.Format("15:04"), h.Verdict, tc.want, lag.Breached, h.Issues)
		}
		if tc.want == VerdictError {
			if is := issueOf(h, IssueArchiveLag); is == nil || is.Table != export.TableSyslog || !strings.Contains(is.Title, "29.5 h behind") {
				t.Errorf("05:30: %+v", h.Issues)
			}
		}
	}
	for _, tc := range []struct {
		name  string
		table string
		age   time.Duration
		late  bool
	}{
		{"flows 1.2 h", export.TableFlows, 72 * time.Minute, false},
		{"flows 4.5 h", export.TableFlows, 270 * time.Minute, true},
		{"syslog 26.5 h", export.TableSyslog, 26*time.Hour + 30*time.Minute, false},
		{"syslog 30 h", export.TableSyslog, 30 * time.Hour, true},
	} {
		now := d.Add(4 * time.Hour)
		st := prodDay(now, dayD, d, now.Truncate(time.Hour).Add(-time.Hour))
		tv := table(st, tc.table)
		end := now.Add(-tc.age)
		tv.VerifiedThroughEnd, tv.LagSeconds = &end, fptr(tc.age.Seconds())
		st = sched(st)
		h := Assess(st, defaultTh(), growing)
		c := conditionOf(t, NewEvaluator().Conditions(st, defaultTh(), growing), models.AlertTypeArchiveLag, tc.table)
		got := issueOf(h, IssueArchiveLag) != nil
		if got != tc.late || c.Breached != tc.late || (h.Verdict == VerdictError) != tc.late {
			t.Errorf("%s: lag issue %v, alert %v, verdict %s; want late %v (%+v)", tc.name, got, c.Breached, h.Verdict, tc.late, h.Issues)
		}
	}
}

// TestSchedule: due = end + period + minimum age + settle slack; syslog's
// cut waits for ARCHIVE_WINDOW to open (also across midnight); flows use
// their fixed 5 minutes whatever ARCHIVE_MIN_AGE_HOURS says.
func TestSchedule(t *testing.T) {
	end := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		cfg   config.ArchiveConfig
		table string
		want  time.Time
	}{
		{"syslog", config.ArchiveConfig{MinAgeHours: 2}, export.TableSyslog, end.Add(26*time.Hour + 10*time.Minute)},
		{"syslog min age 4", config.ArchiveConfig{MinAgeHours: 4}, export.TableSyslog, end.Add(28*time.Hour + 10*time.Minute)},
		{"syslog window 03-05", config.ArchiveConfig{MinAgeHours: 2, Window: "03:00-05:00"}, export.TableSyslog, end.Add(27*time.Hour + 10*time.Minute)},
		{"syslog window 22-01", config.ArchiveConfig{MinAgeHours: 2, Window: "22:00-01:00"}, export.TableSyslog, end.Add(46*time.Hour + 10*time.Minute)},
		{"syslog window 22-03 open after midnight", config.ArchiveConfig{MinAgeHours: 2, Window: "22:00-03:00"}, export.TableSyslog, end.Add(26*time.Hour + 10*time.Minute)},
		{"syslog window open", config.ArchiveConfig{MinAgeHours: 2, Window: "01:00-06:00"}, export.TableSyslog, end.Add(26*time.Hour + 10*time.Minute)},
		{"counters ignore the window", config.ArchiveConfig{MinAgeHours: 2, Window: "03:00-05:00"}, export.TableCounters, end.Add(26*time.Hour + 10*time.Minute)},
		{"flows", config.ArchiveConfig{MinAgeHours: 4}, export.TableFlows, end.Add(time.Hour + 15*time.Minute)},
	} {
		s := scheduleOf(tc.cfg, tc.table)
		if got := s.DueAfter(end); !got.Equal(tc.want) {
			t.Errorf("%s: due %s, want %s", tc.name, got, tc.want)
		}
		if o := s.Overdue(end, tc.want.Add(-time.Minute)); o != 0 {
			t.Errorf("%s: overdue %s before due", tc.name, o)
		}
		if o := s.Overdue(end, tc.want.Add(time.Hour)); o != time.Hour {
			t.Errorf("%s: overdue %s an hour after due", tc.name, o)
		}
	}
}

// TestConditions_NoChunkCountsFromWorkerRecord: with the worker's record of
// when the table first had no chunk, ARCHIVE_LAG counts from it — as the
// verdict does — even when this process saw the table earlier (an older
// worker without the record, a configuration since switched): both agree.
func TestConditions_NoChunkCountsFromWorkerRecord(t *testing.T) {
	st := healthyStatus()
	f := table(st, export.TableFlows)
	f.HasChunks, f.Backlog, f.LagSeconds, f.VerifiedThroughEnd = false, nil, nil, nil
	stream(st, export.StreamNetFlow).RecentChunks = 0
	e := NewEvaluator()
	early := *st
	early.GeneratedAt = at.Add(-6 * time.Hour)
	e.Conditions(sched(&early), defaultTh(), growing) // first sight, no worker record yet
	st.Worker.NoChunkSince = map[string]time.Time{export.TableFlows: at.Add(-time.Hour)}
	c := conditionOf(t, e.Conditions(sched(st), defaultTh(), growing), models.AlertTypeArchiveLag, export.TableFlows)
	is := issueOf(Assess(sched(st), defaultTh(), growing), IssueNoChunkYet)
	if c.Breached || is == nil || is.Severity != SeverityWarning {
		t.Fatalf("alert %+v, verdict %+v", c, is)
	}
}
