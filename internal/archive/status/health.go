package status

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The raw archive's health verdict (0.11.316): one answer to "is the backup
// working, and if not, what must someone do", computed here only. The admin
// status API and the CLI attach it to the Status (AttachHealth), the status
// card draws its banner and its "Action needed" list from it, and the
// poller's archive alerts name the same issue codes and actions
// (Evaluator.Conditions), so the three never disagree.
//
// Every condition comes from what Build already read — the manifest tables,
// the gate records and the worker's runtime snapshot — plus the alert
// thresholds (system settings) and the database volume's free-space trend
// (server_metrics). Nothing here scans a data table.
//
// Thresholds. The alert thresholds (Thresholds, the Alerting page) apply as
// they do to the alerts; the others are below.
//
//	condition                                     WARNING                      ERROR
//	worker snapshot missing or stale (enabled)    -                            at once (stale: StaleAfter, 15 min)
//	configuration the worker refuses              -                            at once
//	target preflight failing                      under PreflightErrorAfter    from PreflightErrorAfter (15 min)
//	local marker missing / another install's      -                            at once
//	uploads or read-backs failing, chunks retry   under TargetErrorAfter       from TargetErrorAfter (1 h) since the last success
//	other failed chunks waiting for their retry   at once                      -
//	any other stage failing without a success     from StageWarnAfter (30 min) from StageErrorAfter (2 h); a streak last seen
//	  (plan, mark, seal, settle, db, lock, ...)                                    over StageRecentWithin (3 h) ago is over
//	chunk parked in needs_attention               -                            at once
//	month not sealed past its seal time           -                            over archive_seal_overdue_alert_days (3)
//	gate holds rows past their retention          disk known not growing       over retention_held_alert_hours (6), disk growing or unknown
//	verified data older than the lag threshold    -                            over archive_lag_alert_hours_* (+ DailySustain for daily tables);
//	  (every table, idle or not)                                                   also with no chunk left to export (a planner failing);
//	                                                                               folded into its cause when the verdict knows it
//	backlog: more than one chunk left             at once                      -
//	enabled table without a chunk yet             at once                      over archive_lag_alert_hours_* since the worker first saw it
//	staging directory free space                  under StagingWarnFactor x floor   under the floor (nothing is exported)
//	gate override active (rows deleted unarchived) at once                     -
//	gate cannot read the stream switches          under GateUnreadableAfter    from GateUnreadableAfter (15 min)
//	export waits on a writer / leaf / timeout     over archive_unsettled_alert_hours (6)   -
//	Object Lock off on an S3 target               at once                      -
//	settings saved, not applied by the worker     at once                      -
//	part of the status could not be read          at once                      -
//	stream without rows in its recent chunks      info (presentation only: "No data received"; suppresses nothing)
//	sealed month marked partial                   info
//
// HEALTHY is the absence of every warning and error: every enabled table has
// chunks, at most its current period is left (caught up to the last closed
// hour or day), and its verified data is younger than its lag threshold.

// Thresholds of the verdict that are not alert settings.
const (
	// PreflightErrorAfter: a failing preflight is retried every minute; a
	// brief outage of the target is a warning until then.
	PreflightErrorAfter = 15 * time.Minute
	// TargetErrorAfter: chunks failing at the target (upload, read-back,
	// chunk.json) for this long since the last verified chunk.
	TargetErrorAfter = time.Hour
	// StagingWarnFactor: free staging space under this many times the
	// worker's floor is a warning (under the floor nothing is exported).
	StagingWarnFactor = 2
	// StageWarnAfter / StageErrorAfter: a stage that keeps failing for a
	// subject (Runtime.Failing) with no success in between. A streak whose
	// last failure is older than StageRecentWithin is over (its subject is
	// gone, or the stage has not run since).
	StageWarnAfter    = 30 * time.Minute
	StageErrorAfter   = 2 * time.Hour
	StageRecentWithin = 3 * time.Hour
)

// Verdicts (Health.Verdict).
const (
	VerdictHealthy       = "healthy"
	VerdictWarning       = "warning"
	VerdictError         = "error"
	VerdictDisabled      = "disabled"
	VerdictNotConfigured = "not_configured"
)

// Issue severities.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
	SeverityInfo    = "info"
)

// Issue codes, in the order the list shows issues of one severity (causes
// before their effects).
const (
	IssueWorkerNotRunning = "worker_not_running"
	IssueConfigInvalid    = "config_invalid"
	IssueMarkerMissing    = "marker_missing"
	IssueMarkerForeign    = "marker_foreign"
	IssuePreflightFailing = "preflight_failing"
	IssueTargetFailing    = "target_failing"
	IssueStagingFull      = "staging_full"
	IssueStageFailing     = "stage_failing"
	IssueNeedsAttention   = "needs_attention"
	IssueGateUnreadable   = "gate_unreadable"
	IssueRetentionHeld    = "retention_held"
	IssueArchiveLag       = "archive_lag"
	IssueSealOverdue      = "seal_overdue"
	IssueChunksRetrying   = "chunks_retrying"
	IssueOverrideActive   = "override_active"
	IssueStagingLow       = "staging_low"
	IssueUnsettledLong    = "unsettled_long"
	IssueBacklog          = "backlog"
	IssueNoChunkYet       = "first_chunk_pending"
	IssueObjectLockOff    = "object_lock_off"
	IssueConfigPending    = "config_pending"
	IssueStatusIncomplete = "status_incomplete"
	IssueStreamIdle       = "stream_idle"
	IssueMonthPartial     = "month_partial"
)

var issueOrder = func() map[string]int {
	m := map[string]int{}
	for i, c := range []string{IssueWorkerNotRunning, IssueConfigInvalid, IssueMarkerMissing, IssueMarkerForeign, IssuePreflightFailing,
		IssueTargetFailing, IssueStagingFull, IssueStageFailing, IssueNeedsAttention, IssueGateUnreadable, IssueRetentionHeld, IssueArchiveLag, IssueSealOverdue,
		IssueChunksRetrying, IssueOverrideActive, IssueStagingLow, IssueUnsettledLong, IssueBacklog, IssueNoChunkYet, IssueObjectLockOff,
		IssueConfigPending, IssueStatusIncomplete, IssueStreamIdle, IssueMonthPartial} {
		m[c] = i
	}
	return m
}()

// blocking are the issues that stop the whole archive: while one is an
// error, no stream is being backed up.
var blocking = map[string]bool{IssueWorkerNotRunning: true, IssueConfigInvalid: true, IssueMarkerMissing: true, IssueMarkerForeign: true,
	IssuePreflightFailing: true, IssueTargetFailing: true, IssueStagingFull: true}

// IssueActions is what to do about each issue, in one sentence: the status
// card and the alerts both say it.
var IssueActions = map[string]string{
	IssueWorkerNotRunning: "Check that the poller is running (docker compose ps) and read its log for lines starting with \"archive:\"; the worker restarts with the poller.",
	IssueConfigInvalid:    "Correct the setting the error names in Raw Archive Settings (Settings → Retention) or its ARCHIVE_* environment key and save; the poller applies it within a minute.",
	IssueMarkerMissing:    "Mount the share or partition that holds the archive at the archive directory (check the host's fstab and the container's bind mount); the worker retries every minute and catches up.",
	IssueMarkerForeign:    "Give this server its own archive directory or prefix in Raw Archive Settings: two servers must never write one archive.",
	IssuePreflightFailing: "Press Test connection in Raw Archive Settings (Settings → Retention) and fix what it reports: endpoint, key, bucket, Object Lock, permissions, or the mount.",
	IssueTargetFailing:    "Press Test connection in Raw Archive Settings (Settings → Retention) and fix what it reports; the failed chunks are retried automatically once the target answers.",
	IssueStagingFull:      "Free space on the staging directory's volume, or choose a larger one in Raw Archive Settings (Settings → Retention).",
	IssueStageFailing:     "Read the error (Settings → Retention → Raw Archive, or fwmon-api archive --status) and the poller's \"archive:\" log lines, and fix its cause (often the database: its connection, disk or locks); the worker retries on every pass.",
	IssueNeedsAttention:   "Read the chunk's error (Settings → Retention → Raw Archive → Needs attention, or fwmon-api archive --status), fix the cause, then Reset the chunk to export it again.",
	IssueGateUnreadable:   "Check the database connection and the poller's log; the gate retries every few seconds.",
	IssueRetentionHeld:    "Get the archive moving again (Settings → Retention → Raw Archive, or fwmon-api archive --status, says why it is stuck). Only if the disk is about to fill, release the gate for a few hours: fwmon-api archive --override <stream> --for 6h --reason \"...\" (rows deleted then are never archived).",
	IssueArchiveLag:       "Find out why no chunk is being verified (Settings → Retention → Raw Archive, or fwmon-api archive --status, and the poller's \"archive:\" log lines) and fix it; the worker then catches up on its own.",
	IssueSealOverdue:      "Read the month's seal error (Settings → Retention → Raw Archive → Months, or fwmon-api archive --status); a month is sealed only once every chunk of it is verified, so fix parked or failing chunks first.",
	IssueChunksRetrying:   "Nothing yet: the worker retries after 1, 5, 30 minutes, then every 2 hours. If the same error repeats, press Test connection.",
	IssueOverrideActive:   "Re-engage the gate as soon as the emergency is over: while it is released, raw rows are deleted whether or not they are archived.",
	IssueStagingLow:       "Free space on the staging directory's volume before it reaches the floor and exports stop.",
	IssueUnsettledLong:    "Find the session named in the detail (pg_stat_activity) and end it, or wait for the partition maintenance to finish.",
	IssueBacklog:          "Nothing, unless it stops shrinking: the worker catches up on its own. A long ETA can be shortened by raising the read rate in Schedule & limits.",
	IssueNoChunkYet:       "Nothing at first: the first chunk is cut once its first period has closed (an hour for flows, a day plus the minimum age for syslog and counters). If it takes longer, read the poller's \"archive:\" log lines.",
	IssueObjectLockOff:    "Turn on Object Lock for the bucket and set a retention (Bucket & Object Lock in Raw Archive Settings), so nobody holding the key can delete the archive.",
	IssueConfigPending:    "Nothing: the poller applies saved settings within a minute. If this stays, restart the poller.",
	IssueStatusIncomplete: "Reload in a minute; if it persists, check the database's health and the API's log.",
	IssueStreamIdle:       "Nothing, if this collector does not send it (sFlow switched off). Otherwise check that the devices still send it.",
	IssueMonthPartial:     "Nothing to repair: the seal records why rows of that month may be missing (an override or archiving switched off).",
}

// IssueFix is the control the status card offers with an issue.
type IssueFix struct {
	// Kind: test (Test connection), settings (Raw Archive Settings,
	// Target the field key), reengage (Target the gate stream),
	// needs_attention / retrying / months (the section below).
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Target string `json:"target,omitempty"`
}

// Issue is one condition someone may need to act on.
type Issue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	// Meaning: what it is, in plain words; Risk: what is at stake while it
	// lasts; Action: what to do (IssueActions).
	Meaning string `json:"meaning"`
	Risk    string `json:"risk,omitempty"`
	Action  string `json:"action"`
	// Since: when it began, when known.
	Since *time.Time `json:"since,omitempty"`
	// Table / Stream: what it concerns ("" = the whole archive).
	Table  string `json:"table,omitempty"`
	Stream string `json:"stream,omitempty"`
	// Detail: the underlying error or figures.
	Detail string    `json:"detail,omitempty"`
	Fix    *IssueFix `json:"fix,omitempty"`
}

// StreamHealth is one bucket stream's line of the status table.
type StreamHealth struct {
	Stream  string `json:"stream"`
	Table   string `json:"table"`
	Enabled bool   `json:"enabled"`
	// State: ok, catching_up, warning, error, stalled (a blocking issue
	// stops the archive), idle (no data received), pending (no chunk yet),
	// off. Label is its text.
	State string `json:"state"`
	Label string `json:"label"`
	// VerifiedThrough: the end of the table's verified data; LagSeconds how
	// old it is; LastVerifiedAt the last chunk verified.
	VerifiedThrough *time.Time `json:"verified_through,omitempty"`
	LagSeconds      *float64   `json:"lag_seconds,omitempty"`
	LastVerifiedAt  *time.Time `json:"last_verified_at,omitempty"`
	// Backlog*: the table's chunks not verified yet (the current period
	// counts one), the upper bound of their rows, the estimate.
	BacklogChunks int64    `json:"backlog_chunks"`
	BacklogRows   int64    `json:"backlog_rows"`
	ETASeconds    *float64 `json:"eta_seconds,omitempty"`
	// What the target holds verified for the stream, and the compression
	// of its recent objects (raw ÷ stored; nil without recent bytes).
	ArchivedRows     int64    `json:"archived_rows"`
	ArchivedBytes    int64    `json:"archived_bytes"`
	CompressionRatio *float64 `json:"compression_ratio,omitempty"`
}

// Health is the verdict.
type Health struct {
	Verdict string `json:"verdict"`
	Summary string `json:"summary"`
	// LastSuccessAt: the newest chunk verified (any enabled table).
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	// VerifiedThrough: the oldest end of verified data among the enabled
	// tables that receive data; BehindSeconds its age.
	VerifiedThrough *time.Time `json:"verified_through,omitempty"`
	BehindSeconds   *float64   `json:"behind_seconds,omitempty"`
	// BacklogChunks: chunks left beyond the current period, summed over
	// the tables catching up; ETASeconds the longest of their estimates.
	BacklogChunks int64    `json:"backlog_chunks"`
	ETASeconds    *float64 `json:"eta_seconds,omitempty"`
	Errors        int      `json:"errors"`
	Warnings      int      `json:"warnings"`
	// Issues: errors first, then warnings, then information.
	Issues  []Issue        `json:"issues"`
	Streams []StreamHealth `json:"streams"`
}

// HealthStore is what AttachHealth reads besides the Status.
type HealthStore interface {
	SettingValues(ctx context.Context, keys []string) (map[string]string, error)
	ServerDataDiskFreeAt(ctx context.Context, from, to time.Time) (*uint64, error)
}

// diskNowWithin: the newest server_metrics sample used as "now" by
// ReadDiskTrend (the poller writes one every 5 minutes).
const diskNowWithin = 15 * time.Minute

// ReadDiskTrend compares the database volume's free space in the newest
// server_metrics sample (at most 15 min old) with the newest one 1-3 h old,
// as the poller does with its live probe. now is the local clock:
// server_metrics.timestamp is written with time.Now().
func ReadDiskTrend(ctx context.Context, db HealthStore, now time.Time) DiskTrend {
	cur, err := db.ServerDataDiskFreeAt(ctx, now.Add(-diskNowWithin), now)
	if err != nil || cur == nil {
		return DiskTrend{Detail: "database volume not measured recently"}
	}
	past, err := db.ServerDataDiskFreeAt(ctx, now.Add(-3*time.Hour), now.Add(-time.Hour))
	if err != nil || past == nil {
		return DiskTrend{Detail: fmt.Sprintf("%.1f GiB free, no sample from an hour ago to compare", float64(*cur)/(1<<30))}
	}
	return DiskTrend{Known: true, Growing: *cur < *past,
		Detail: fmt.Sprintf("%.1f GiB free, %.1f GiB an hour or more ago", float64(*cur)/(1<<30), float64(*past)/(1<<30))}
}

// AttachHealth sets st.Health from the stored alert thresholds and the
// recorded disk trend (the API and the CLI; a read that fails uses the
// defaults / an unknown trend, which the verdict treats as growing).
func AttachHealth(ctx context.Context, st *Status, db HealthStore) {
	stored, _ := db.SettingValues(ctx, ThresholdKeys())
	st.Health = Assess(st, ReadThresholds(stored), ReadDiskTrend(ctx, db, time.Now()))
}

func tptr(t time.Time) *time.Time { t = t.UTC(); return &t }

// Assess is the verdict on st at st.GeneratedAt. Pure: the same Status,
// thresholds and disk trend always give the same Health.
func Assess(st *Status, th Thresholds, disk DiskTrend) *Health {
	h := &Health{Issues: []Issue{}, Streams: []StreamHealth{}}
	now := st.GeneratedAt
	add := func(is Issue) {
		if is.Action == "" {
			is.Action = IssueActions[is.Code]
		}
		h.Issues = append(h.Issues, is)
	}
	c := st.Config
	configured := c.Bucket != ""
	if c.Target == config.ArchiveTargetLocal {
		configured = c.LocalDir != ""
	}

	tables := map[string]TableView{}
	for _, t := range st.Tables {
		tables[t.Table] = t
	}
	idle, tableIdle := Idle(st)

	if st.Enabled {
		assessWorker(st, now, add)
		assessStages(st, now, add)
		assessTables(st, th, disk, now, add)
		assessStreams(st, th, idle, add)
		assessGates(st, add)
		if c.Target != config.ArchiveTargetLocal && c.ObjectLockDays == 0 {
			add(Issue{Code: IssueObjectLockOff, Severity: SeverityWarning, Title: "Object Lock is off",
				Meaning: "Objects are written without a retention period.",
				Risk:    "Anyone holding the bucket key (or a compromised server) can delete or overwrite the archive.",
				Fix:     &IssueFix{Kind: "settings", Label: "Open Bucket & Object Lock", Target: "ARCHIVE_OBJECT_LOCK_DAYS"}})
		}
		if st.ConfigPending {
			add(Issue{Code: IssueConfigPending, Severity: SeverityWarning, Title: "Saved settings are not applied yet",
				Meaning: "The archive worker still runs with the settings it had before the last save.",
				Risk:    "Until the poller picks them up, the old settings are in force."})
		}
		if len(st.Problems) > 0 {
			add(Issue{Code: IssueStatusIncomplete, Severity: SeverityWarning, Title: "Part of the status could not be read",
				Meaning: "Some archive records could not be read, so this page may be incomplete.",
				Detail:  strings.Join(st.Problems, "; ")})
		}
	}

	h.Issues = mergeLagIntoCause(h.Issues)
	sort.SliceStable(h.Issues, func(i, j int) bool {
		a, b := h.Issues[i], h.Issues[j]
		if ra, rb := sevRank(a.Severity), sevRank(b.Severity); ra != rb {
			return ra < rb
		}
		if oa, ob := issueOrder[a.Code], issueOrder[b.Code]; oa != ob {
			return oa < ob
		}
		return a.Table+a.Stream < b.Table+b.Stream
	})
	byTable := map[string]string{}  // table → worst severity of its own issues
	byStream := map[string]string{} // stream → worst severity
	stalled := false
	for _, is := range h.Issues {
		switch is.Severity {
		case SeverityError:
			h.Errors++
			if blocking[is.Code] {
				stalled = true
			}
		case SeverityWarning:
			h.Warnings++
		default:
			continue
		}
		if is.Stream != "" && worse(is.Severity, byStream[is.Stream]) {
			byStream[is.Stream] = is.Severity
		} else if is.Stream == "" && is.Table != "" && worse(is.Severity, byTable[is.Table]) {
			byTable[is.Table] = is.Severity
		}
	}

	for _, s := range st.Streams {
		t := tables[s.Table]
		sh := StreamHealth{Stream: s.Stream, Table: s.Table, Enabled: s.Enabled, VerifiedThrough: t.VerifiedThroughEnd, LagSeconds: t.LagSeconds,
			LastVerifiedAt: t.LastVerifiedAt, ArchivedRows: s.ArchivedRows, ArchivedBytes: s.ArchivedObjectBytes}
		if b := t.Backlog; b != nil {
			sh.BacklogChunks, sh.BacklogRows, sh.ETASeconds = b.Remaining, b.RemainingRows, b.ETASeconds
		}
		if s.RecentObjectBytes > 0 && s.RecentRawBytes > 0 {
			r := float64(s.RecentRawBytes) / float64(s.RecentObjectBytes)
			sh.CompressionRatio = &r
		}
		sev := byStream[s.Stream]
		if worse(byTable[s.Table], sev) {
			sev = byTable[s.Table]
		}
		switch {
		case !s.Enabled || !st.Enabled:
			sh.State, sh.Label = "off", "Off"
		case stalled:
			sh.State, sh.Label = "stalled", "Not being backed up"
		case sev == SeverityError:
			sh.State, sh.Label = "error", "Needs action"
		case idle[s.Stream]:
			// Presentation only: an idle stream without an error of its
			// own (or of its table) is neutral, not "up to date".
			sh.State, sh.Label = "idle", "No data received"
		case !t.HasChunks:
			sh.State, sh.Label = "pending", "Waiting for the first chunk"
		case t.Backlog != nil && t.Backlog.State == "catching_up" && t.Backlog.RemainingRows > 0:
			sh.State, sh.Label = "catching_up", "Catching up"
		case sev == SeverityWarning:
			sh.State, sh.Label = "warning", "Check"
		default:
			sh.State, sh.Label = "ok", "Up to date"
		}
		h.Streams = append(h.Streams, sh)
	}

	for _, t := range st.Tables {
		if !t.Enabled {
			continue
		}
		if t.LastVerifiedAt != nil && (h.LastSuccessAt == nil || t.LastVerifiedAt.After(*h.LastSuccessAt)) {
			h.LastSuccessAt = tptr(*t.LastVerifiedAt)
		}
		if tableIdle[t.Table] {
			continue
		}
		if t.VerifiedThroughEnd != nil && (h.VerifiedThrough == nil || t.VerifiedThroughEnd.Before(*h.VerifiedThrough)) {
			h.VerifiedThrough = tptr(*t.VerifiedThroughEnd)
			l := max(0, now.Sub(*t.VerifiedThroughEnd).Seconds())
			h.BehindSeconds = &l
		}
		if b := t.Backlog; b != nil && b.State == "catching_up" && b.Remaining > 1 {
			h.BacklogChunks += b.Remaining - 1
			if b.ETASeconds != nil && (h.ETASeconds == nil || *b.ETASeconds > *h.ETASeconds) {
				v := *b.ETASeconds
				h.ETASeconds = &v
			}
		}
	}

	switch {
	case !st.Enabled && !configured:
		h.Verdict, h.Summary = VerdictNotConfigured, "No archive target is configured: raw rows are deleted by retention without a copy."
	case !st.Enabled:
		h.Verdict, h.Summary = VerdictDisabled, "Archiving is off: raw rows are deleted by retention without a copy. What was archived before stays in the target."
	case h.Errors > 0:
		h.Verdict = VerdictError
		h.Summary = h.Issues[0].Title
		if h.Errors > 1 {
			h.Summary += fmt.Sprintf(" (and %d more problem%s)", h.Errors-1, plural(h.Errors-1))
		}
	case h.Warnings > 0:
		h.Verdict = VerdictWarning
		h.Summary = h.Issues[0].Title
		if h.Warnings > 1 {
			h.Summary += fmt.Sprintf(" (and %d more)", h.Warnings-1)
		}
	default:
		h.Verdict, h.Summary = VerdictHealthy, "Backups are working: every enabled stream is verified up to its last closed period."
	}
	return h
}

// Idle reports which streams receive no data — enabled, their table has
// verified chunks, and none of its RecentChunks holds a row of the stream
// (sFlow switched off) — and which tables only hold such streams. It is
// presentation only (the "No data received" state and note): it never
// suppresses a warning or an error. "Idle" looks back at verified chunks, so
// it lingers while nothing verifies — data that resumes while the target
// fails leaves the table idle — and only the lag, which applies to every
// table, tells.
func Idle(st *Status) (streams, tables map[string]bool) {
	streams, tables = map[string]bool{}, map[string]bool{}
	has := map[string]bool{}
	for _, t := range st.Tables {
		has[t.Table] = t.HasChunks
		tables[t.Table] = t.HasChunks
	}
	for _, s := range st.Streams {
		streams[s.Stream] = s.Enabled && has[s.Table] && s.RecentChunks > 0 && s.RecentRows == 0
		if !streams[s.Stream] {
			tables[s.Table] = false
		}
	}
	return streams, tables
}

// tableLabel names a table's data in an issue: the table holds the streams
// together, and an install may receive only one of them (NetFlow without
// sFlow), so it is "flow", not "sflow and netflow".
func tableLabel(table string) string {
	switch table {
	case export.TableSyslog:
		return "syslog"
	case export.TableFlows:
		return "flow"
	case export.TableCounters:
		return "sFlow counter"
	}
	return table
}

// mergeLagIntoCause folds a table's archive_lag issue into the error that
// causes it — a blocking error (the worker or the target) or a step failing
// for that table — so one cause is one error: the cause's text then says how
// far behind the table is. A lag with no such cause stays its own issue. The
// alerts keep ARCHIVE_LAG (annotated with the cause).
func mergeLagIntoCause(issues []Issue) []Issue {
	merged := map[int]bool{}
	for i, is := range issues {
		if is.Code != IssueArchiveLag {
			continue
		}
		if c := causeOf(issues, is.Table); c >= 0 {
			issues[c].Risk = strings.TrimSpace(issues[c].Risk + " " + is.Title + ".")
			merged[i] = true
		}
	}
	out := make([]Issue, 0, len(issues))
	for i, is := range issues {
		if !merged[i] {
			out = append(out, is)
		}
	}
	return out
}

// causeOf is the index of the error that stops table's archive (-1: none).
func causeOf(issues []Issue, table string) int {
	for i, is := range issues {
		if is.Severity == SeverityError && (blocking[is.Code] || (is.Code == IssueStageFailing && is.Table == table)) {
			return i
		}
	}
	return -1
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func sevRank(s string) int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarning:
		return 1
	}
	return 2
}

// worse reports whether severity a is worse than b ("" = none).
func worse(a, b string) bool {
	if a == "" {
		return false
	}
	return b == "" || sevRank(a) < sevRank(b)
}

func durText(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return hours(d)
}

// assessWorker: the worker's own state (snapshot, configuration, preflight,
// staging) and the chunks failing at the target.
func assessWorker(st *Status, now time.Time, add func(Issue)) {
	w := st.Worker
	nothing := "Nothing is being backed up; the retention gate keeps every unarchived row in the database, so it grows."
	if w == nil || w.Stale {
		is := Issue{Code: IssueWorkerNotRunning, Severity: SeverityError, Title: "The archive worker is not running",
			Meaning: "The poller's archive worker has not reported for over 15 minutes.", Risk: nothing}
		switch {
		case w != nil:
			is.Since = tptr(w.SeenAt)
			is.Detail = "Last report " + w.SeenAt.UTC().Format(time.RFC3339) + "."
		case st.WorkerError != "":
			is.Meaning, is.Detail = "The archive worker's state cannot be read.", st.WorkerError
		default:
			is.Meaning = "The poller's archive worker has never reported (is the poller running with archiving enabled?)."
		}
		add(is)
	} else if w.Runner == ConfigProblemRunner {
		is := Issue{Code: IssueConfigInvalid, Severity: SeverityError, Title: "The archive settings are refused",
			Meaning: "The poller cannot start the archive worker with the settings in effect.", Risk: nothing,
			Fix: &IssueFix{Kind: "settings", Label: "Open Raw Archive Settings"}}
		for _, e := range w.Stages {
			if e.Stage == "config" {
				is.Detail, is.Since = e.Error, firstOf(e)
			}
		}
		add(is)
		return
	}
	fresh := w != nil && !w.Stale
	if fresh && !w.PreflightOK {
		var pre *StageView
		for i := range w.Stages {
			if w.Stages[i].Stage == "preflight" {
				pre = &w.Stages[i]
			}
		}
		is := Issue{Risk: nothing, Fix: &IssueFix{Kind: "test", Label: "Test connection"}}
		if pre != nil {
			is.Detail, is.Since = pre.Error, firstOf(*pre)
		}
		// The streak (since this run of failures began) wins over the
		// stage's first failure ever recorded.
		for _, f := range w.Failing {
			if f.Stage == "preflight" {
				is.Since = tptr(f.Since)
			}
		}
		switch w.PreflightIssue {
		case PreflightMarkerMissing:
			is.Code, is.Severity, is.Title = IssueMarkerMissing, SeverityError, "The archive directory is not mounted"
			is.Meaning = "The archive directory has lost its marker file while the archive holds chunks: usually the share or partition is not mounted and the empty mount point shows instead."
		case PreflightMarkerForeign:
			is.Code, is.Severity, is.Title = IssueMarkerForeign, SeverityError, "The archive directory belongs to another server"
			is.Meaning = "The directory's marker was written by another installation; writing here would mix two archives."
			is.Fix = &IssueFix{Kind: "settings", Label: "Open Raw Archive Settings", Target: "ARCHIVE_LOCAL_DIR"}
		default:
			is.Code, is.Severity, is.Title = IssuePreflightFailing, SeverityWarning, "Checking the archive target"
			is.Meaning = "The worker's check of the target (reach it, write, read back) has not passed yet; it retries every minute."
			if is.Since != nil && now.Sub(*is.Since) >= PreflightErrorAfter {
				is.Severity, is.Title = SeverityError, "The archive target cannot be reached"
				is.Meaning = fmt.Sprintf("The worker's check of the target has failed for %s; it retries every minute.", durText(now.Sub(*is.Since)))
			}
		}
		add(is)
	}
	if fresh {
		stg := w.Staging
		switch {
		case stg.FreeBytes != nil && *stg.FreeBytes < stg.MinFreeBytes:
			add(Issue{Code: IssueStagingFull, Severity: SeverityError, Title: "The staging directory is full",
				Meaning: fmt.Sprintf("%s has %s free, under the %s the worker needs to export a chunk.", stg.Dir, gib(*stg.FreeBytes), gib(stg.MinFreeBytes)),
				Risk:    nothing, Fix: &IssueFix{Kind: "settings", Label: "Open Staging", Target: "ARCHIVE_STAGING_DIR"}})
		case stg.FreeBytes != nil && *stg.FreeBytes < StagingWarnFactor*stg.MinFreeBytes:
			add(Issue{Code: IssueStagingLow, Severity: SeverityWarning, Title: "Staging space is low",
				Meaning: fmt.Sprintf("%s has %s free; exports stop under %s.", stg.Dir, gib(*stg.FreeBytes), gib(stg.MinFreeBytes)),
				Risk:    "Once it drops under the floor nothing is exported.", Fix: &IssueFix{Kind: "settings", Label: "Open Staging", Target: "ARCHIVE_STAGING_DIR"}})
		case stg.Error != "":
			add(Issue{Code: IssueStagingLow, Severity: SeverityWarning, Title: "Staging free space is unknown",
				Meaning: "The worker cannot measure the staging directory's free space.", Detail: stg.Error,
				Fix: &IssueFix{Kind: "settings", Label: "Open Staging", Target: "ARCHIVE_STAGING_DIR"}})
		}
	}

	// Chunks waiting for their retry; failing at the target for over
	// TargetErrorAfter since the last success is an error.
	if len(st.Retrying) == 0 {
		return
	}
	var lastOK *time.Time
	for _, t := range st.Tables {
		if t.LastVerifiedAt != nil && (lastOK == nil || t.LastVerifiedAt.After(*lastOK)) {
			lastOK = t.LastVerifiedAt
		}
	}
	var target *StageView
	if w != nil {
		for i := range w.Stages {
			e := &w.Stages[i]
			if (e.Stage == "upload" || e.Stage == "verify" || e.Stage == "manifest") && (lastOK == nil || e.At.After(*lastOK)) &&
				(target == nil || e.At.After(target.At)) {
				target = e
			}
		}
	}
	first := st.Retrying[0]
	is := Issue{Code: IssueChunksRetrying, Severity: SeverityWarning,
		Title:   fmt.Sprintf("%d chunk%s failed and will be retried", len(st.Retrying), plural(len(st.Retrying))),
		Meaning: "The last attempt of these chunks failed; the worker tries them again after a backoff.",
		Risk:    "Their rows stay in the database until they are verified.",
		Table:   first.Table, Detail: first.Error, Fix: &IssueFix{Kind: "retrying", Label: "Show the retries"}}
	if len(st.Retrying) > 1 {
		is.Table = ""
	}
	if target != nil {
		since := firstOf(*target)
		if lastOK != nil && lastOK.After(*since) {
			since = tptr(*lastOK)
		}
		is.Since, is.Detail = since, target.Error
		if now.Sub(*since) >= TargetErrorAfter {
			is.Code, is.Severity, is.Title = IssueTargetFailing, SeverityError, "Uploads to the archive target are failing"
			is.Meaning = fmt.Sprintf("Writing or reading back objects has failed for %s, with no chunk verified since.", durText(now.Sub(*since)))
			is.Risk = "Nothing new is being backed up; the retention gate keeps the unarchived rows in the database, so it grows."
			is.Fix = &IssueFix{Kind: "test", Label: "Test connection"}
		}
	}
	add(is)
}

// assessStages: any other stage that keeps failing for a subject with no
// success in between (Runtime.Failing). The preflight, the configuration and
// the chunk stages of a table whose chunks are waiting for their retry have
// their own issues.
func assessStages(st *Status, now time.Time, add func(Issue)) {
	w := st.Worker
	if w == nil || w.Stale || w.Runner == ConfigProblemRunner {
		return
	}
	// Tables whose chunk failures already have an issue: waiting for a
	// retry (chunks_retrying / target_failing) or parked (needs_attention).
	retrying := map[string]bool{}
	for _, c := range st.Retrying {
		retrying[c.Table] = true
	}
	for _, p := range st.NeedsAttention {
		retrying[p.Table] = true
	}
	chunk := map[string]bool{}
	for _, s := range []string{"count", "db", "manifest", "read", "settle", "stage", "upload", "verify", "sealed"} {
		chunk[s] = true
	}
	for _, f := range w.Failing {
		if f.Stage == "preflight" || f.Stage == "config" || (chunk[f.Stage] && retrying[f.Subject]) {
			continue
		}
		failing := now.Sub(f.Since)
		if now.Sub(f.At) > StageRecentWithin || failing < StageWarnAfter {
			continue
		}
		what := f.Stage + " step keeps failing"
		if f.Subject != "" {
			what += " (" + f.Subject + ")"
		}
		is := Issue{Code: IssueStageFailing, Severity: SeverityWarning, Since: tptr(f.Since), Detail: f.Error,
			Title:   "The archive's " + what,
			Meaning: fmt.Sprintf("The worker's %s step has failed %d times over %s, with no success in between.", f.Stage, f.Count, durText(failing)),
			Risk:    "The archive does not advance past this step; its rows stay in the database."}
		for _, t := range Tables {
			if f.Subject == t {
				is.Table = t
			}
		}
		if failing >= StageErrorAfter {
			is.Severity = SeverityError
		}
		add(is)
	}
}

// firstOf is when a stage began failing (its first failure counted by this
// worker; the last one in a snapshot without it).
func firstOf(e StageView) *time.Time {
	if e.Since != nil {
		return tptr(*e.Since)
	}
	return tptr(e.At)
}

func gib(b uint64) string { return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30)) }

// assessTables: per enabled table, parked chunks, rows held past retention,
// the lag, the backlog, a first chunk still pending and a long wait.
func assessTables(st *Status, th Thresholds, disk DiskTrend, now time.Time, add func(Issue)) {
	gated := map[string]bool{}
	for _, g := range st.Gates {
		gated[g.Stream] = g.Gated
	}
	parked := map[string][]ParkedChunk{}
	for _, p := range st.NeedsAttention {
		parked[p.Table] = append(parked[p.Table], p)
	}
	fresh := st.Worker != nil && !st.Worker.Stale
	for _, t := range st.Tables {
		if !t.Enabled {
			continue
		}
		names := tableLabel(t.Table)
		if ps := parked[t.Table]; len(ps) > 0 {
			holding := 0
			oldest := ps[0].UpdatedAt
			for _, p := range ps {
				if p.HoldsGate {
					holding++
				}
				if p.UpdatedAt.Before(oldest) {
					oldest = p.UpdatedAt
				}
			}
			risk := "The worker no longer retries it: its rows are not archived."
			if holding > 0 {
				risk = "Its table's raw deletes wait for it, so the database keeps every newer unarchived row and grows."
			}
			add(Issue{Code: IssueNeedsAttention, Severity: SeverityError, Table: t.Table, Since: tptr(oldest),
				Title:   fmt.Sprintf("%d %s chunk%s parked in needs attention", len(ps), t.Table, plural(len(ps))),
				Meaning: "An export did not match the database (or wrote into a sealed month) twice; the worker stopped retrying it.",
				Risk:    risk, Detail: ps[0].Error, Fix: &IssueFix{Kind: "needs_attention", Label: "Review and reset"}})
		}
		if r := t.Retention; r != nil && gated[t.GateStream] && th.Held > 0 && r.HeldSeconds > th.Held.Seconds() {
			held := secs(r.HeldSeconds)
			is := Issue{Code: IssueRetentionHeld, Severity: SeverityWarning, Table: t.Table, Since: tptr(r.Cutoff.Add(-held)),
				Title:   "Unarchived " + names + " rows are held past retention",
				Meaning: fmt.Sprintf("Rows of %s up to %s older than their window (%s) are kept until the archive verifies them.", t.Table, hours(held), r.Window),
				Risk:    "The database keeps rows it would have deleted; its volume " + disk.Detail + ".",
				Detail:  disk.Detail, Action: strings.ReplaceAll(IssueActions[IssueRetentionHeld], "<stream>", t.GateStream)}
			if !disk.Known || disk.Growing {
				is.Severity = SeverityError
				is.Risk = "The database keeps rows it would have deleted and its volume is filling (" + disk.Detail + ")."
			}
			add(is)
		}
		// The lag: as ARCHIVE_LAG (0 turns it off), a daily table's
		// threshold plus DailySustain (its alert waits that long above it).
		// Every table, with or without chunks left to export (a planner
		// that keeps failing leaves none), idle or not: an idle table's
		// empty chunks are cut and verified like any other, so its lag grows
		// only when the worker is stuck — and data may be arriving again
		// that nothing verifies yet (the target failing).
		if limit, daily := th.lagOf(t.Table); limit > 0 && t.LagSeconds != nil {
			if daily {
				limit += DailySustain
			}
			if lag := secs(*t.LagSeconds); lag > limit {
				is := Issue{Code: IssueArchiveLag, Severity: SeverityError, Table: t.Table,
					Title:   fmt.Sprintf("The %s archive is %s behind", names, hours(lag)),
					Meaning: fmt.Sprintf("Its newest verified data is older than the %s threshold.", hours(limit)),
					Risk:    "Recent rows exist only in the database; the retention gate keeps them there until they are verified."}
				if t.VerifiedThroughEnd != nil {
					is.Since = tptr(*t.VerifiedThroughEnd)
				}
				add(is)
			}
		}
		if b := t.Backlog; b != nil && b.State == "catching_up" && b.Remaining > 1 && b.RemainingRows > 0 {
			eta := "no estimate yet"
			if b.ETASeconds != nil {
				eta = "about " + durText(secs(*b.ETASeconds)) + " of work"
			}
			is := Issue{Code: IssueBacklog, Severity: SeverityWarning, Table: t.Table,
				Title:   fmt.Sprintf("Catching up on the %s archive: %d chunks left", names, b.Remaining),
				Meaning: fmt.Sprintf("The worker is exporting a backlog (%s).", eta),
				Risk:    "Until it is done, the newest rows are only in the database."}
			if b.OldestRemaining != nil {
				is.Since = tptr(*b.OldestRemaining)
			}
			add(is)
		}
		if !t.HasChunks && fresh && st.Worker.PreflightOK {
			is := Issue{Code: IssueNoChunkYet, Severity: SeverityWarning, Table: t.Table,
				Title:   "Waiting for the first " + names + " chunk",
				Meaning: "Archiving of this table is on but no chunk has been cut yet.",
				Risk:    "Its raw rows are kept in the database until their first chunk is verified."}
			// As ARCHIVE_LAG's no-chunk branch: an error once it has waited
			// longer than the table's lag threshold.
			if since, ok := st.Worker.NoChunkSince[t.Table]; ok {
				is.Since = tptr(since)
				if limit, _ := th.lagOf(t.Table); limit > 0 && now.Sub(since) > limit {
					is.Severity = SeverityError
					is.Title = fmt.Sprintf("No %s chunk cut in %s", names, hours(now.Sub(since)))
					is.Meaning = fmt.Sprintf("Archiving of this table has been on for %s (threshold %s) without a single chunk.", hours(now.Sub(since)), hours(limit))
				}
			}
			add(is)
		}
		if u := t.Unsettled; u != nil && fresh && unsettledWaits[u.Reason] && th.Unsettled > 0 && u.ForSeconds > th.Unsettled.Seconds() {
			is := Issue{Code: IssueUnsettledLong, Severity: SeverityWarning, Table: t.Table,
				Title:   fmt.Sprintf("The %s export has waited %s", t.Table, hours(secs(u.ForSeconds))),
				Meaning: "The next chunk cannot be exported yet: " + strings.ReplaceAll(u.Reason, "_", " ") + ".",
				Risk:    "The table's archive falls behind while it waits.", Detail: u.Detail}
			if u.Since != nil {
				is.Since = tptr(*u.Since)
			}
			add(is)
		}
	}
}

// assessStreams: per enabled stream, an overdue seal, a partial month, no
// data received.
func assessStreams(st *Status, th Thresholds, idle map[string]bool, add func(Issue)) {
	for _, s := range st.Streams {
		if !s.Enabled {
			continue
		}
		if idle[s.Stream] {
			add(Issue{Code: IssueStreamIdle, Severity: SeverityInfo, Stream: s.Stream, Table: s.Table,
				Title:   "No " + s.Stream + " data received",
				Meaning: fmt.Sprintf("The last %d verified %s chunks hold no %s rows.", s.RecentChunks, s.Table, s.Stream)})
		}
		// An idle stream's months seal like any other (their chunks are
		// pinned as empty): an overdue seal is an error for it too.
		if th.SealOverdueDays > 0 && s.UnsealedDays > th.SealOverdueDays {
			is := Issue{Code: IssueSealOverdue, Severity: SeverityError, Stream: s.Stream, Table: s.Table,
				Title:   fmt.Sprintf("Month %s of %s is not sealed", s.OldestUnsealed, s.Stream),
				Meaning: fmt.Sprintf("It is %.1f days past its seal time (threshold %.0f days).", s.UnsealedDays, th.SealOverdueDays),
				Risk:    "The month's folder is not closed and checked: its completeness is not proven.",
				Fix:     &IssueFix{Kind: "months", Label: "Show the months"}}
			if end, err := monthEnd(s.OldestUnsealed); err == nil {
				is.Since = tptr(end.Add(secs(float64(st.Config.SealGraceHours) * 3600)))
			}
			for _, m := range s.Months {
				if m.Month == s.OldestUnsealed && m.Error != "" {
					is.Detail = m.Error
				}
			}
			add(is)
		}
		for _, m := range s.Months { // newest first: report the newest partial month
			if m.Status == models.ArchiveMonthSealed && m.Partial {
				add(Issue{Code: IssueMonthPartial, Severity: SeverityInfo, Stream: s.Stream, Table: s.Table,
					Title:   fmt.Sprintf("Month %s of %s was sealed partial", m.Month, s.Stream),
					Meaning: "Rows of that month may be missing from the archive.", Detail: m.PartialNote, Since: m.SealedAt,
					Fix: &IssueFix{Kind: "months", Label: "Show the months"}})
				break
			}
		}
	}
}

// assessGates: a released gate, a gate that cannot read its switches.
func assessGates(st *Status, add func(Issue)) {
	for _, g := range st.Gates {
		if !g.OverrideActive || !g.Enabled {
			continue
		}
		is := Issue{Code: IssueOverrideActive, Severity: SeverityWarning,
			Title:   "The retention gate of " + g.Stream + " is released",
			Meaning: "An administrator released the gate: raw " + g.Stream + " rows are deleted by retention whether or not they are archived.",
			Risk:    "Rows deleted while it is released may never reach the archive (their months are sealed partial).",
			Fix:     &IssueFix{Kind: "reengage", Label: "Re-engage now", Target: g.Stream}}
		if g.OverrideUntil != nil {
			is.Detail = "Until " + g.OverrideUntil.UTC().Format(time.RFC3339) + "."
		}
		add(is)
	}
	if gr := st.GateRead; gr != nil {
		is := Issue{Code: IssueGateUnreadable, Severity: SeverityWarning, Since: tptr(gr.FailingSince),
			Title:   "The retention gate cannot read the archive switches",
			Meaning: "The poller's retention gate fails to read which streams are archived.",
			Risk:    "It keeps the switches it read last: a change saved here is not applied.", Detail: gr.Error}
		if gr.HoldingAll {
			is.Risk = "It holds every archived table's deletes until a read succeeds, so the database grows."
		}
		if secs(gr.ForSeconds) > GateUnreadableAfter {
			is.Severity = SeverityError
		}
		add(is)
	}
}

// issueOfAlert maps an alert type to its issue code.
var issueOfAlert = map[models.AlertType]string{
	models.AlertTypeArchiveLag:            IssueArchiveLag,
	models.AlertTypeArchiveNeedsAttention: IssueNeedsAttention,
	models.AlertTypeArchiveSealOverdue:    IssueSealOverdue,
	models.AlertTypeRetentionHeld:         IssueRetentionHeld,
	models.AlertTypeArchiveUnsettledLong:  IssueUnsettledLong,
	models.AlertTypeArchiveGateUnreadable: IssueGateUnreadable,
}

// annotate names c's issue and its action in the alert (Fields "issue" and
// "verdict", and the message), and — for an alert that is the effect of a
// blocking error (the lag, a first chunk never cut, rows held) — the cause
// from h with its action, so the notification says what to do.
func annotate(c *Condition, h *Health) {
	code := issueOfAlert[c.Type]
	if c.Type == models.AlertTypeArchiveLag && c.Fields["no_chunk"] == "true" {
		code = IssueNoChunkYet
	}
	if code == "" {
		return
	}
	if c.Fields == nil {
		c.Fields = map[string]string{}
	}
	c.Fields["issue"] = code
	if h != nil {
		c.Fields["verdict"] = h.Verdict
	}
	if !c.Breached || c.Message == "" {
		return
	}
	if h != nil && (c.Type == models.AlertTypeArchiveLag || c.Type == models.AlertTypeRetentionHeld) {
		for _, is := range h.Issues {
			if is.Severity == SeverityError && (blocking[is.Code] || (is.Code == IssueStageFailing && is.Table == c.Fields["table"])) {
				c.Fields["cause"] = is.Code
				c.Message += " Cause: " + is.Title + " (" + is.Code + "). Action: " + is.Action
				return
			}
		}
	}
	c.Message += " Action: " + strings.ReplaceAll(IssueActions[code], "<stream>", gateOr(c.Fields["gate_stream"]))
}

func gateOr(s string) string {
	if s == "" {
		return "<stream>"
	}
	return s
}

// gateIssueAction is ARCHIVE_GATE_UNREADABLE's action (GateReadCondition has
// no status to assess).
func gateIssueAction(c *Condition) {
	c.Fields["issue"] = IssueGateUnreadable
	if c.Breached && c.Message != "" {
		c.Message += " Action: " + IssueActions[IssueGateUnreadable]
	}
}

// Compile-time check: *database.Database is a HealthStore.
var _ HealthStore = (*database.Database)(nil)
