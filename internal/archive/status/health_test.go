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
	countersEnd := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
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

// TestAssess_IdleCountersNeverWarn: an idle sflow-counters table far behind,
// with an overdue month, stays neutral — nothing of it is at risk.
func TestAssess_IdleCountersNeverWarn(t *testing.T) {
	st := healthyStatus()
	c := table(st, export.TableCounters)
	c.LagSeconds = fptr(200 * 3600)
	c.Backlog = &BacklogView{Chunks: 20, Verified: 15, Remaining: 5, RemainingRows: 0, State: "catching_up"}
	s := stream(st, export.StreamSFlowCounters)
	s.OldestUnsealed, s.UnsealedDays = "2026-08", 30
	h := Assess(st, defaultTh(), growing)
	if h.Verdict != VerdictHealthy {
		t.Fatalf("verdict %s: %+v", h.Verdict, h.Issues)
	}
	if sh := streamHealth(t, h, export.StreamSFlowCounters); sh.State != "idle" {
		t.Errorf("counters state %s", sh.State)
	}
	// The same stream with data is not idle: the overdue seal is an error.
	s.RecentRows = 10
	h = Assess(st, defaultTh(), growing)
	if is := issueOf(h, IssueSealOverdue); is == nil || is.Severity != SeverityError || h.Verdict != VerdictError {
		t.Fatalf("with data: %s %+v", h.Verdict, h.Issues)
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
		h := Assess(st, defaultTh(), growing)
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
	h := Assess(st, defaultTh(), growing)
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
		{"flows lag 2.9 h", func(st *Status) { table(st, export.TableFlows).LagSeconds = fptr(2.9 * 3600) }, nil, "", "", VerdictHealthy},
		{"flows lag 3.1 h", func(st *Status) { table(st, export.TableFlows).LagSeconds = fptr(3.1 * 3600) }, nil, IssueArchiveLag, SeverityError, VerdictError},
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
			h := Assess(st, defaultTh(), disk)
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
// first failure (or the last success after it); a blocking error comes
// before its effects and marks the streams with data stalled, not the idle
// ones.
func TestAssess_SinceAndOrder(t *testing.T) {
	st := healthyStatus()
	first := at.Add(-20 * time.Minute)
	st.Worker.PreflightOK = false
	st.Worker.Stages = []StageView{{Stage: "preflight", At: at, Since: &first, Error: "403 Forbidden"}}
	table(st, export.TableFlows).LagSeconds = fptr(4 * 3600)
	h := Assess(st, defaultTh(), growing)
	if len(h.Issues) < 2 || h.Issues[0].Code != IssuePreflightFailing || h.Issues[1].Code != IssueArchiveLag {
		t.Fatalf("order: %+v", h.Issues)
	}
	if h.Issues[0].Since == nil || !h.Issues[0].Since.Equal(first) || h.Issues[0].Detail != "403 Forbidden" || h.Issues[0].Fix == nil || h.Issues[0].Fix.Kind != "test" {
		t.Errorf("preflight issue: %+v", h.Issues[0])
	}
	if !strings.HasPrefix(h.Summary, "The archive target cannot be reached") || !strings.Contains(h.Summary, "1 more problem") {
		t.Errorf("summary %q", h.Summary)
	}
	if sh := streamHealth(t, h, export.StreamNetFlow); sh.State != "stalled" {
		t.Errorf("netflow %s, want stalled", sh.State)
	}
	if sh := streamHealth(t, h, export.StreamSFlow); sh.State != "idle" {
		t.Errorf("sflow %s, want idle", sh.State)
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
	h := Assess(st, defaultTh(), growing)
	if h.Verdict != VerdictDisabled || len(h.Issues) != 0 {
		t.Errorf("disabled: %s %+v", h.Verdict, h.Issues)
	}
	st.Config.Bucket = ""
	if h := Assess(st, defaultTh(), growing); h.Verdict != VerdictNotConfigured {
		t.Errorf("not configured: %s", h.Verdict)
	}
	st.Config.Target, st.Config.LocalDir = config.ArchiveTargetLocal, "/archive/fwmon"
	if h := Assess(st, defaultTh(), growing); h.Verdict != VerdictDisabled {
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
	table(st, export.TableFlows).LagSeconds = fptr(4 * 3600)
	st.NeedsAttention = []ParkedChunk{{ID: 9, Table: export.TableFlows, Seq: 9, UpdatedAt: at}}
	cs := NewEvaluator().Conditions(st, defaultTh(), growing)
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
	h := Assess(st, defaultTh(), growing)
	if is := issueOf(h, IssueMarkerMissing); is == nil || h.Verdict != VerdictError {
		t.Errorf("verdict %s %+v", h.Verdict, h.Issues)
	}
	if sh := streamHealth(t, h, export.StreamSFlow); sh.State != "idle" {
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

// TestAssess_LagWithoutBacklog: a table that receives data lags with no
// chunk left to export (its planner fails, so nothing new is cut): still an
// archive_lag error, not HEALTHY. An idle table in the same state is neutral.
func TestAssess_LagWithoutBacklog(t *testing.T) {
	st := healthyStatus()
	f := table(st, export.TableFlows)
	f.LagSeconds = fptr(5 * 3600)
	f.Backlog = &BacklogView{Chunks: 500, Verified: 500, Remaining: 0, State: "caught_up"}
	h := Assess(st, defaultTh(), growing)
	if is := issueOf(h, IssueArchiveLag); is == nil || is.Severity != SeverityError || is.Table != export.TableFlows || h.Verdict != VerdictError {
		t.Fatalf("non-idle: %s %+v", h.Verdict, h.Issues)
	}
	if strings.Contains(issueOf(h, IssueArchiveLag).Title, "sflow and netflow") || !strings.Contains(issueOf(h, IssueArchiveLag).Title, "flow archive") {
		t.Errorf("title %q", issueOf(h, IssueArchiveLag).Title)
	}
	stream(st, export.StreamNetFlow).RecentRows = 0 // nothing received: the table is idle
	if h := Assess(st, defaultTh(), growing); issueOf(h, IssueArchiveLag) != nil || h.Verdict != VerdictHealthy {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := healthyStatus()
			st.Worker.Failing = []Streak{{Stage: tc.stage, Subject: export.TableFlows, Since: at.Add(-tc.since), At: at.Add(-tc.last), Error: "archive: refused", Count: 9}}
			if tc.retrying {
				st.Retrying = []ChunkView{{ID: 3, Table: export.TableFlows, Error: "upload: 503"}}
			}
			h := Assess(st, defaultTh(), growing)
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
	}{{time.Hour, SeverityWarning}, {4 * time.Hour, SeverityError}} {
		st := healthyStatus()
		f := table(st, export.TableFlows)
		f.HasChunks, f.Backlog, f.LagSeconds, f.VerifiedThroughEnd = false, nil, nil, nil
		stream(st, export.StreamNetFlow).RecentChunks = 0
		st.Worker.NoChunkSince = map[string]time.Time{export.TableFlows: at.Add(-tc.waited)}
		h := Assess(st, defaultTh(), growing)
		is := issueOf(h, IssueNoChunkYet)
		if is == nil || is.Severity != tc.want || is.Since == nil {
			t.Fatalf("waited %s: %+v", tc.waited, is)
		}
		// The alert agrees, from a fresh evaluator (a poller just restarted).
		c := conditionOf(t, NewEvaluator().Conditions(st, defaultTh(), growing), models.AlertTypeArchiveLag, export.TableFlows)
		if c.Breached != (tc.want == SeverityError) || c.Fields["issue"] != IssueNoChunkYet || c.Fields["no_chunk"] != "true" {
			t.Errorf("waited %s: alert %+v", tc.waited, c)
		}
	}
}

// TestAlertsAgreeOnIdle: the alerts and the verdict apply the same idle
// rule — a stream (table) that receives no data neither lags nor has a seal
// overdue, in both; with data, both report it.
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
		h := Assess(st, defaultTh(), growing)
		cs := NewEvaluator().Conditions(st, defaultTh(), growing)
		// The lag of a daily table fires after DailySustain above the
		// threshold: evaluate again an hour later.
		e := NewEvaluator()
		e.Conditions(st, defaultTh(), growing)
		later := *st
		later.GeneratedAt = at.Add(DailySustain)
		cs2 := e.Conditions(&later, defaultTh(), growing)
		lag := conditionOf(t, cs2, models.AlertTypeArchiveLag, export.TableCounters)
		seal := conditionOf(t, cs, models.AlertTypeArchiveSealOverdue, export.StreamSFlowCounters)
		verdictLag, verdictSeal := issueOf(h, IssueArchiveLag) != nil, issueOf(h, IssueSealOverdue) != nil
		if lag.Breached != withData || verdictLag != withData || seal.Breached != withData || verdictSeal != withData {
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
	r.Restore(&old, at)
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
	is := issueOf(Assess(st, defaultTh(), growing), IssuePreflightFailing)
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
	c := conditionOf(t, NewEvaluator().Conditions(st, defaultTh(), growing), models.AlertTypeRetentionHeld, export.TableFlows)
	if !c.Breached || strings.Count(c.Message, "--override") != 1 || !strings.Contains(c.Message, "--override flows --for 6h") ||
		strings.Contains(c.Message, "<stream>") || strings.Contains(c.Message, "above") {
		t.Fatalf("message %q", c.Message)
	}
	if is := issueOf(Assess(st, defaultTh(), growing), IssueRetentionHeld); is == nil || !strings.Contains(is.Action, "--override flows --for 6h") {
		t.Errorf("the page's held-rows action: %+v", is)
	}
	for code, action := range IssueActions {
		if strings.Contains(action, "above") || strings.Contains(action, "below") {
			t.Errorf("%s's action refers to the page layout: %q", code, action)
		}
	}
}
