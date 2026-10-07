// Package status assembles the raw archive's state (archive plan PR 8) for
// the admin status API (GET /admin/api/archive/status), its CLI twin
// (`fwmon-api archive --status`) and the archive alerts the poller evaluates
// on its server-health tick (alerts.go).
//
// Everything comes from the database: the manifest tables (chunks, months,
// id marks, gate events), the gate overrides, and the snapshot of the
// worker's runtime state (runtime.go) that the poller's archive worker writes
// there — the API runs in another process and cannot read the worker's
// memory or its /metrics. Nothing here writes, and nothing carries a secret:
// the bucket credentials appear only as the last four characters of the key
// id.
package status

import (
	"context"
	"fmt"
	"sort"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// Store is the slice of the database the status reads (database.Store and
// *database.Database satisfy it).
type Store interface {
	ArchiveGateOverrideState(stream string, now time.Time) (until time.Time, active bool, err error)
	ListArchiveChunksNeedingAttention(limit int) ([]models.ArchiveChunk, error)
	ArchiveTableProgress(ctx context.Context, table string) (database.ArchiveProgress, error)
	ArchiveChunkStatusCounts(ctx context.Context) (map[string]map[string]int64, error)
	ArchiveChunkMonths(ctx context.Context, table string) ([]string, error)
	ArchiveMonthRows(ctx context.Context, stream string) ([]models.ArchiveMonth, error)
	ArchiveTableTimes(ctx context.Context, table string) (database.ArchiveTableTimes, error)
	ArchiveGateEventsOverlapping(ctx context.Context, stream string, from, to time.Time) ([]models.ArchiveGateEvent, error)
	ArchiveWorkerState(ctx context.Context) (value string, ok bool, err error)
	ArchiveBacklogs(ctx context.Context) (map[string]database.ArchiveBacklog, error)
	RecentArchiveChunks(ctx context.Context, table string, limit int) ([]database.ArchiveChunkSummary, error)
	ArchiveChunksWithStatus(ctx context.Context, status string, limit int) ([]database.ArchiveChunkSummary, error)
	ArchiveVerifiedTotals(ctx context.Context, table, stream string, months []string) ([]database.ArchiveMonthTotal, error)
	ArchiveGateHealthRecord(ctx context.Context) (*database.ArchiveGateHealth, error)
	SyslogRetentionWindows(ret config.RetentionConfig) [database.SyslogSeverityCount]database.SyslogWindow
}

// Tables are the archived source tables, in display order.
var Tables = []string{export.TableSyslog, export.TableFlows, export.TableCounters}

// monthsShown bounds each stream's month table (the newest ones).
const monthsShown = 13

// parkedShown bounds the needs_attention list.
const parkedShown = 100

// recentShown bounds the recently verified chunks (overall, and per table
// for the throughput estimate); retryingShown the failed chunks listed.
const (
	recentShown   = 10
	retryingShown = 20
)

// Status is the whole picture.
type Status struct {
	GeneratedAt time.Time `json:"generated_at"`
	// Enabled: some stream's archiving is on (in the configuration this
	// process read; the poller reads the same environment).
	Enabled        bool          `json:"enabled"`
	Config         ConfigView    `json:"config"`
	Worker         *WorkerView   `json:"worker"`
	Gates          []GateView    `json:"gates"`
	Tables         []TableView   `json:"tables"`
	Streams        []StreamView  `json:"streams"`
	NeedsAttention []ParkedChunk `json:"needs_attention"`
	// Recent: the newest verified chunks of every table, newest first.
	Recent []ChunkView `json:"recent"`
	// Retrying: chunks whose last attempt failed, waiting for their retry
	// (RetryAt).
	Retrying []ChunkView `json:"retrying"`
	// GateRead: the retention gate (in the poller) cannot read the stream
	// switches (nil while it can, or when the poller's record is stale).
	GateRead *GateReadView `json:"gate_read,omitempty"`
	// OverrideMaxHours is the longest gate override accepted.
	OverrideMaxHours int `json:"override_max_hours"`
	// Problems lists the manifest reads that failed (the rest is still
	// reported); the alerts are not evaluated while there is one.
	Problems []string `json:"problems,omitempty"`
	// WorkerError: the worker's stored state could not be read (Worker is
	// then nil, as when none was written).
	WorkerError string `json:"worker_error,omitempty"`
}

// ConfigView is the archive configuration without its secret.
type ConfigView struct {
	SyslogEnabled bool `json:"syslog_enabled"`
	FlowsEnabled  bool `json:"flows_enabled"`
	// Endpoint is scheme://host[:port] only ("" when unset or invalid).
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	Prefix   string `json:"prefix"`
	// AccessKeyID is "…" + its last four characters ("" when unset).
	AccessKeyID    string `json:"access_key_id"`
	ObjectLockDays int    `json:"object_lock_days"`
	ObjectLockMode string `json:"object_lock_mode"`
	MinAgeHours    int    `json:"min_age_hours"`
	SealGraceHours int    `json:"seal_grace_hours"`
	SealReverify   string `json:"seal_reverify"`
	Window         string `json:"window"`
	StagingDir     string `json:"staging_dir"`
}

// WorkerView is the worker's runtime snapshot and how fresh it is.
type WorkerView struct {
	SeenAt      time.Time   `json:"seen_at"`
	AgeSeconds  float64     `json:"age_seconds"`
	Stale       bool        `json:"stale"`
	Runner      string      `json:"runner"`
	PreflightOK bool        `json:"preflight_ok"`
	Staging     Staging     `json:"staging"`
	Stages      []StageView `json:"stages"`
	// LastPassAt / NextPassAt: the worker's last pass and when it runs the
	// next (sooner when a waiting chunk becomes exportable).
	LastPassAt *time.Time `json:"last_pass_at,omitempty"`
	NextPassAt *time.Time `json:"next_pass_at,omitempty"`
	// Activity: the chunk being worked when the snapshot was written (nil
	// between chunks, and while the snapshot is stale).
	Activity *ActivityView `json:"activity,omitempty"`
}

// ActivityView is the worker's current chunk with its elapsed times and,
// where it can be told, the fraction of the stage done (0..1).
type ActivityView struct {
	Activity
	ElapsedSeconds      float64  `json:"elapsed_seconds"`
	StageElapsedSeconds float64  `json:"stage_elapsed_seconds"`
	Fraction            *float64 `json:"fraction,omitempty"`
}

// GateReadView: since when the retention gate has failed to read the
// archive's stream switches, and what it does meanwhile (HoldingAll: both
// streams' deletes wait; otherwise it keeps the switches it read last).
type GateReadView struct {
	FailingSince time.Time `json:"failing_since"`
	ForSeconds   float64   `json:"for_seconds"`
	Error        string    `json:"error"`
	HoldingAll   bool      `json:"holding_all"`
	SeenAt       time.Time `json:"seen_at"`
}

// ChunkView is one chunk in the recent or retrying list.
type ChunkView struct {
	ID          uint       `json:"id"`
	Table       string     `json:"table"`
	Seq         int64      `json:"seq"`
	PeriodStart time.Time  `json:"period_start"`
	PeriodEnd   time.Time  `json:"period_end"`
	Month       string     `json:"month"`
	Status      string     `json:"status"`
	Rows        int64      `json:"rows"`
	Objects     int64      `json:"objects"`
	ObjectBytes int64      `json:"object_bytes"`
	RawBytes    int64      `json:"raw_bytes"`
	Attempts    int        `json:"attempts"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	// DurationSeconds: from the last attempt's start to verified.
	DurationSeconds *float64 `json:"duration_seconds,omitempty"`
	Error           string   `json:"error,omitempty"`
	// RetryAt: when a failed chunk is attempted again (it is picked up by
	// the first pass from then).
	RetryAt *time.Time `json:"retry_at,omitempty"`
}

// BacklogView is how much of a table's planned work is left and when it
// should be done.
type BacklogView struct {
	// Chunks planned; Verified of them; Remaining the rest.
	Chunks    int64 `json:"chunks"`
	Verified  int64 `json:"verified"`
	Remaining int64 `json:"remaining"`
	// OldestRemaining: the period start of the oldest chunk not verified.
	OldestRemaining *time.Time `json:"oldest_remaining,omitempty"`
	// RemainingRows: the id span of the remaining chunks, an upper bound of
	// their rows.
	RemainingRows int64 `json:"remaining_rows"`
	// RateRowsPerSec: rows verified per second of work over the table's
	// recently verified chunks (nil: none timed yet); ETASeconds the
	// remaining rows at that rate (nil without a rate, or when caught up).
	RateRowsPerSec *float64 `json:"rate_rows_per_sec,omitempty"`
	ETASeconds     *float64 `json:"eta_seconds,omitempty"`
	// State: caught_up (nothing left), current (one chunk left: the newest
	// period, the steady state), catching_up (more).
	State string `json:"state"`
}

// NextSealView is the next month of a stream to seal and when it is due.
type NextSealView struct {
	Month string    `json:"month"`
	DueAt time.Time `json:"due_at"`
	// Due: the seal time has passed; the worker seals it after its next
	// pass once every chunk of the month is verified.
	Due bool `json:"due"`
}

// StageView is one stage's last failure.
type StageView struct {
	Stage string    `json:"stage"`
	At    time.Time `json:"at"`
	Error string    `json:"error"`
	Count int64     `json:"count"`
}

// GateView is one gate stream (syslog, flows): whether its deletes wait for
// the archive, and its override.
type GateView struct {
	Stream         string     `json:"stream"`
	Enabled        bool       `json:"enabled"`
	OverrideActive bool       `json:"override_active"`
	OverrideUntil  *time.Time `json:"override_until,omitempty"`
	// Gated: enabled and not overridden — its deletes take only rows <= V.
	Gated bool `json:"gated"`
}

// TableView is one source table's archive.
type TableView struct {
	Table      string   `json:"table"`
	GateStream string   `json:"gate_stream"`
	Streams    []string `json:"streams"`
	Enabled    bool     `json:"enabled"`
	// HasChunks: any chunk exists (V and the lag are meaningful).
	HasChunks bool `json:"has_chunks"`
	// VerifiedThroughID is V; VerifiedThroughEnd the period end of the chunk
	// it belongs to.
	VerifiedThroughID  int64      `json:"verified_through_id"`
	VerifiedThroughEnd *time.Time `json:"verified_through_end,omitempty"`
	// LagSeconds: now − VerifiedThroughEnd (or the first chunk's start while
	// none is verified), as fwmon_archive_lag_seconds; nil without chunks.
	LagSeconds     *float64         `json:"lag_seconds,omitempty"`
	Chunks         map[string]int64 `json:"chunks"`
	LastVerifiedAt *time.Time       `json:"last_verified_at,omitempty"`
	LastMarkAt     *time.Time       `json:"last_mark_at,omitempty"`
	// Unsettled: why the next chunk waits (from the worker's snapshot).
	Unsettled *UnsettledView `json:"unsettled,omitempty"`
	// Backlog: the planned work left and its estimate.
	Backlog *BacklogView `json:"backlog,omitempty"`
	// Retention: the table's raw delete cutoff and how far past it the gate
	// holds unarchived rows (nil when its rows are kept forever).
	Retention *RetentionView `json:"retention,omitempty"`
}

// UnsettledView is a table's wait reason.
type UnsettledView struct {
	Reason     string     `json:"reason"`
	Since      *time.Time `json:"since,omitempty"`
	ForSeconds float64    `json:"for_seconds"`
	Detail     string     `json:"detail,omitempty"`
	// Until / LeftSeconds: when a settling chunk's window ends and how long
	// that is from now (0 once passed: the worker exports it on its next
	// tick).
	Until       *time.Time `json:"until,omitempty"`
	LeftSeconds *float64   `json:"left_seconds,omitempty"`
}

// RetentionView: rows older than Cutoff are past the table's window (the
// shortest raw window for syslog; the rollup's age for raw flows). While the
// gate holds, rows newer than the verified-through end are kept whatever
// their age, so HeldSeconds = Cutoff − that end, when positive, is how far
// past retention the oldest unarchived rows are.
type RetentionView struct {
	Window      string    `json:"window"`
	Cutoff      time.Time `json:"cutoff"`
	HeldSeconds float64   `json:"held_seconds"`
}

// StreamView is one bucket stream (syslog, sflow, netflow, sflow-counters).
type StreamView struct {
	Stream     string   `json:"stream"`
	Table      string   `json:"table"`
	Enabled    bool     `json:"enabled"`
	LagSeconds *float64 `json:"lag_seconds,omitempty"`
	// OldestUnsealed is the oldest month due to be sealed that is not;
	// UnsealedDays how far past its seal time (fwmon_archive_month_unsealed_days).
	OldestUnsealed string      `json:"oldest_unsealed,omitempty"`
	UnsealedDays   float64     `json:"unsealed_days"`
	LastSealedAt   *time.Time  `json:"last_sealed_at,omitempty"`
	Months         []MonthView `json:"months"`
	// Archived*: what the bucket holds verified for the stream, every
	// month (the sealed ones from their seal's totals).
	ArchivedRows        int64 `json:"archived_rows"`
	ArchivedObjectBytes int64 `json:"archived_object_bytes"`
	// NextSeal: the oldest month not sealed yet (nil: none).
	NextSeal *NextSealView `json:"next_seal,omitempty"`
}

// MonthView is one month folder of a stream.
type MonthView struct {
	Month string `json:"month"`
	// Status: open, sealing, sealed or seal_failed (open when the worker has
	// not looked at it yet).
	Status      string `json:"status"`
	Due         bool   `json:"due"`
	Partial     bool   `json:"partial"`
	PartialNote string `json:"partial_note,omitempty"`
	// Degraded lists the gate events (override, disabled) that overlap the
	// month: rows deleted then may never have reached the archive. A sealed
	// month's _MONTH.json carries the authoritative list (clamped to its
	// archiving, plus before_archive / unrecorded).
	Degraded    []DegradedView `json:"degraded,omitempty"`
	ChunkCount  int64          `json:"chunk_count"`
	RowCount    int64          `json:"row_count"`
	ObjectBytes int64          `json:"object_bytes"`
	// Archived*: the verified objects of the month so far (before the
	// seal too; once sealed, the seal's RowCount / ObjectBytes).
	ArchivedRows        int64      `json:"archived_rows"`
	ArchivedObjectBytes int64      `json:"archived_object_bytes"`
	SealedAt            *time.Time `json:"sealed_at,omitempty"`
	Error               string     `json:"error,omitempty"`
}

// DegradedView is one gate event.
type DegradedView struct {
	Kind string     `json:"kind"`
	From time.Time  `json:"from"`
	To   *time.Time `json:"to,omitempty"`
}

// ParkedChunk is a chunk in needs_attention.
type ParkedChunk struct {
	ID          uint      `json:"id"`
	Table       string    `json:"table"`
	Seq         int64     `json:"seq"`
	IDLo        int64     `json:"id_lo"`
	IDHi        int64     `json:"id_hi"`
	PeriodStart time.Time `json:"period_start"`
	Month       string    `json:"month"`
	Attempts    int       `json:"attempts"`
	Mismatches  int       `json:"mismatches"`
	Error       string    `json:"error"`
	UpdatedAt   time.Time `json:"updated_at"`
	// HoldsGate: the chunk stops V while its stream is gated, so its table's
	// deletes wait for it; false for a parked chunk of a sealed month that V
	// passes (OPERATIONS.md), or while the stream is not gated.
	HoldsGate bool `json:"holds_gate"`
}

// tableEnabled reports whether table's stream is enabled in cfg.
func tableEnabled(cfg config.ArchiveConfig, table string) bool {
	if table == export.TableSyslog {
		return cfg.SyslogEnabled
	}
	return cfg.FlowsEnabled
}

// GateEnabled reports whether gate stream's archiving is enabled in cfg.
func GateEnabled(cfg config.ArchiveConfig, stream string) bool {
	switch stream {
	case database.ArchiveGateSyslog:
		return cfg.SyslogEnabled
	case database.ArchiveGateFlows:
		return cfg.FlowsEnabled
	}
	return false
}

// ChunkStatuses are the chunk statuses reported per table, in life-cycle
// order (superseded is not a chunk status in use).
var ChunkStatuses = []string{models.ArchiveChunkPending, models.ArchiveChunkExporting, models.ArchiveChunkUploading,
	models.ArchiveChunkVerifying, models.ArchiveChunkVerified, models.ArchiveChunkFailed, models.ArchiveChunkNeedsAttention}

func configView(a config.ArchiveConfig) ConfigView {
	v := ConfigView{
		SyslogEnabled: a.SyslogEnabled, FlowsEnabled: a.FlowsEnabled,
		Region: a.Region, Bucket: a.Bucket, Prefix: a.Prefix,
		ObjectLockDays: a.ObjectLockDays, ObjectLockMode: a.ObjectLockMode,
		MinAgeHours: a.MinAgeHours, SealGraceHours: int(a.SealGrace() / time.Hour), SealReverify: a.SealReverify,
		Window: a.Window, StagingDir: a.StagingDir,
	}
	if u, err := a.EndpointURL(); err == nil && u.Host != "" {
		v.Endpoint = u.Scheme + "://" + u.Host
	}
	if id := []rune(a.AccessKeyID); len(id) > 0 {
		v.AccessKeyID = "…" + string(id[max(0, len(id)-4):])
	}
	return v
}

// monthEnd is the instant month "YYYY-MM" ends (the 1st of the next, UTC).
func monthEnd(month string) (time.Time, error) {
	start, err := time.Parse("2006-01", month)
	if err != nil {
		return time.Time{}, fmt.Errorf("month %q: %w", month, err)
	}
	return start.AddDate(0, 1, 0), nil
}

// UnsealedDays is how many days month (a closed month that is not sealed) is
// past its seal time, the 1st of the next month + grace; 0 when it is not
// yet, or month is "" or malformed. fwmon_archive_month_unsealed_days and the
// ARCHIVE_SEAL_OVERDUE alert both use it.
func UnsealedDays(month string, grace time.Duration, now time.Time) float64 {
	if month == "" {
		return 0
	}
	end, err := monthEnd(month)
	if err != nil {
		return 0
	}
	return max(0, now.Sub(end.Add(grace)).Hours()/24)
}

// retentionOf is table's raw delete cutoff now, and its window as text
// (ok false when its rows are kept forever).
func retentionOf(db Store, ret config.RetentionConfig, table string, now time.Time) (cutoff time.Time, window string, ok bool) {
	switch table {
	case export.TableSyslog:
		// The first rows the gate holds past retention are those of the
		// shortest window: its cutoff is the newest.
		for _, w := range db.SyslogRetentionWindows(ret) {
			if w.Forever() {
				continue
			}
			if c := w.Cutoff(now); !ok || c.After(cutoff) {
				cutoff, window, ok = c, w.String(), true
			}
		}
		return cutoff, window, ok
	case export.TableFlows:
		return now.Add(-database.FlowRollupRawAge), fmt.Sprintf("rollup after %g h", database.FlowRollupRawAge.Hours()), true
	case export.TableCounters:
		d := ret.Days(ret.FlowDays)
		if d <= 0 {
			return time.Time{}, "", false
		}
		return now.AddDate(0, 0, -d), fmt.Sprintf("%dd", d), true
	}
	return time.Time{}, "", false
}

// Build reads the archive's state at now. A read that fails is listed in
// Problems and the rest is still filled in; only a cancelled ctx is an error.
func Build(ctx context.Context, db Store, cfg *config.Config, now time.Time) (*Status, error) {
	now = now.UTC()
	a := cfg.Archive
	st := &Status{GeneratedAt: now, Enabled: a.Enabled(), Config: configView(a), Tables: []TableView{}, Streams: []StreamView{},
		NeedsAttention: []ParkedChunk{}, Recent: []ChunkView{}, Retrying: []ChunkView{}, Gates: []GateView{},
		OverrideMaxHours: database.ArchiveGateOverrideMaxHours}
	problem := func(what string, err error) {
		st.Problems = append(st.Problems, what+": "+err.Error())
	}

	var rt *Runtime
	if raw, ok, err := db.ArchiveWorkerState(ctx); err != nil {
		st.WorkerError = err.Error()
	} else if ok {
		if rt, err = ParseRuntime(raw); err != nil {
			st.WorkerError = err.Error()
		}
	}
	if rt != nil {
		wv := &WorkerView{SeenAt: rt.SeenAt, AgeSeconds: max(0, now.Sub(rt.SeenAt).Seconds()), Runner: rt.Runner,
			PreflightOK: rt.PreflightOK, Staging: rt.Staging, Stages: []StageView{}}
		wv.Stale = now.Sub(rt.SeenAt) > StaleAfter
		for stage, e := range rt.Stages {
			wv.Stages = append(wv.Stages, StageView{Stage: stage, At: e.At, Error: e.Error, Count: e.Count})
		}
		sort.Slice(wv.Stages, func(i, j int) bool { return wv.Stages[i].At.After(wv.Stages[j].At) })
		wv.LastPassAt, wv.NextPassAt = rt.LastPassAt, rt.NextPassAt
		if a := rt.Activity; a != nil && !wv.Stale {
			wv.Activity = activityView(*a, now)
		}
		st.Worker = wv
	}
	if h, err := db.ArchiveGateHealthRecord(ctx); err != nil {
		problem("retention gate state", err)
	} else {
		st.GateRead = gateReadView(h, now)
	}

	gated := map[string]bool{}
	for _, s := range database.ArchiveGateStreams {
		g := GateView{Stream: s, Enabled: GateEnabled(a, s)}
		until, active, err := db.ArchiveGateOverrideState(s, now)
		if err != nil {
			problem("gate override of "+s, err)
		} else if active {
			u := until.UTC()
			g.OverrideActive, g.OverrideUntil = true, &u
		}
		g.Gated = g.Enabled && !g.OverrideActive
		gated[s] = g.Gated
		st.Gates = append(st.Gates, g)
	}

	counts, err := db.ArchiveChunkStatusCounts(ctx)
	if err != nil {
		problem("chunk counts", err)
	}
	backlogs, backlogErr := db.ArchiveBacklogs(ctx)
	if backlogErr != nil {
		problem("backlog", backlogErr)
	}
	var allRecent []database.ArchiveChunkSummary
	progress := map[string]database.ArchiveProgress{}
	lag := map[string]*float64{}
	for _, t := range Tables {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tv := TableView{Table: t, GateStream: database.ArchiveGateStreamOfTable(t), Streams: export.StreamsOf(t),
			Enabled: tableEnabled(a, t), Chunks: map[string]int64{}}
		for _, s := range ChunkStatuses {
			tv.Chunks[s] = counts[t][s]
		}
		p, err := db.ArchiveTableProgress(ctx, t)
		if err != nil {
			problem("progress of "+t, err)
		} else if p.Chunks {
			progress[t] = p
			tv.HasChunks = true
			tv.VerifiedThroughID, tv.VerifiedThroughEnd = p.VerifiedThroughID, p.VerifiedThroughEnd
			since := *p.FirstStart
			if p.VerifiedThroughEnd != nil {
				since = *p.VerifiedThroughEnd
			}
			l := max(0, now.Sub(since).Seconds())
			tv.LagSeconds, lag[t] = &l, &l
			if cutoff, window, ok := retentionOf(db, cfg.Retention, t, now); ok {
				tv.Retention = &RetentionView{Window: window, Cutoff: cutoff.UTC()}
				if gated[tv.GateStream] {
					tv.Retention.HeldSeconds = max(0, cutoff.Sub(since).Seconds())
				}
			}
		}
		if times, err := db.ArchiveTableTimes(ctx, t); err != nil {
			problem("times of "+t, err)
		} else {
			tv.LastVerifiedAt, tv.LastMarkAt = times.LastVerified, times.LastMark
		}
		if rt != nil {
			if u, ok := rt.Tables[t]; ok && u.Reason != "" {
				uv := &UnsettledView{Reason: u.Reason, Since: u.Since, Detail: u.Detail, Until: u.Until}
				if u.Since != nil {
					uv.ForSeconds = max(0, now.Sub(*u.Since).Seconds())
				}
				if u.Until != nil {
					left := max(0, u.Until.Sub(now).Seconds())
					uv.LeftSeconds = &left
				}
				tv.Unsettled = uv
			}
		}
		if tv.HasChunks {
			recent, err := db.RecentArchiveChunks(ctx, t, recentShown)
			if err != nil {
				problem("recent chunks of "+t, err)
			}
			allRecent = append(allRecent, recent...)
			if backlogErr == nil {
				tv.Backlog = backlogView(tv.Chunks, backlogs[t], recent, failedOrParked(tv.Chunks))
			}
		}
		st.Tables = append(st.Tables, tv)
	}
	sort.SliceStable(allRecent, func(i, j int) bool { return allRecent[i].Chunk.VerifiedAt.After(*allRecent[j].Chunk.VerifiedAt) })
	for i, r := range allRecent {
		if i == recentShown {
			break
		}
		st.Recent = append(st.Recent, chunkView(r))
	}
	// The snapshot is written at most every ProgressEvery: a chunk it shows
	// in progress may be verified since. Do not show it as current then.
	if w := st.Worker; w != nil && w.Activity != nil {
		for _, r := range allRecent {
			if r.Chunk.ID == w.Activity.ChunkID {
				w.Activity = nil
				break
			}
		}
	}
	if failed, err := db.ArchiveChunksWithStatus(ctx, models.ArchiveChunkFailed, retryingShown); err != nil {
		problem("failed chunks", err)
	} else {
		for _, f := range failed {
			cv := chunkView(f)
			at := f.Chunk.UpdatedAt.Add(database.ArchiveRetryBackoff(f.Chunk.Attempts)).UTC()
			cv.RetryAt = &at
			st.Retrying = append(st.Retrying, cv)
		}
	}

	grace := a.SealGrace()
	due := export.MonthOf(now.Add(-grace)) // months before it are due
	for _, t := range Tables {
		months, err := db.ArchiveChunkMonths(ctx, t)
		if err != nil {
			problem("months of "+t, err)
		}
		for _, s := range export.StreamsOf(t) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			sv := StreamView{Stream: s, Table: t, Enabled: tableEnabled(a, t), LagSeconds: lag[t], Months: []MonthView{}}
			rows, err := db.ArchiveMonthRows(ctx, s)
			if err != nil {
				problem("month rows of "+s, err)
			}
			byMonth := map[string]models.ArchiveMonth{}
			for _, r := range rows {
				byMonth[r.Month] = r
				if r.SealedAt != nil && (sv.LastSealedAt == nil || r.SealedAt.After(*sv.LastSealedAt)) {
					v := r.SealedAt.UTC()
					sv.LastSealedAt = &v
				}
			}
			// The archived totals: a sealed month's from its seal (fixed for
			// good), the others' from their verified objects — so the read
			// covers a month or two, however old the archive.
			monthTotals := map[string]database.ArchiveMonthTotal{}
			var open []string
			for _, m := range months {
				if r, ok := byMonth[m]; ok && r.Status == models.ArchiveMonthSealed {
					monthTotals[m] = database.ArchiveMonthTotal{Month: m, Rows: r.RowCount, ObjectBytes: r.ObjectBytes}
				} else {
					open = append(open, m)
				}
			}
			if totals, err := db.ArchiveVerifiedTotals(ctx, t, s, open); err != nil {
				problem("archived totals of "+s, err)
			} else {
				for _, m := range totals {
					monthTotals[m.Month] = m
				}
			}
			for _, m := range monthTotals {
				sv.ArchivedRows, sv.ArchivedObjectBytes = sv.ArchivedRows+m.Rows, sv.ArchivedObjectBytes+m.ObjectBytes
			}
			all := map[string]bool{}
			for _, m := range months {
				all[m] = true
			}
			for m := range byMonth {
				all[m] = true
			}
			list := make([]string, 0, len(all))
			for m := range all {
				list = append(list, m)
			}
			sort.Strings(list)
			for _, m := range months { // ascending: the oldest due month that is not sealed
				if m >= due {
					break
				}
				if r, ok := byMonth[m]; !ok || r.Status != models.ArchiveMonthSealed {
					sv.OldestUnsealed = m
					break
				}
			}
			sv.UnsealedDays = UnsealedDays(sv.OldestUnsealed, grace, now)
			for _, m := range months { // the oldest month not sealed: the next seal
				if r, ok := byMonth[m]; ok && r.Status == models.ArchiveMonthSealed {
					continue
				}
				if end, err := monthEnd(m); err == nil {
					sv.NextSeal = &NextSealView{Month: m, DueAt: end.Add(grace), Due: m < due}
				}
				break
			}
			if len(list) > monthsShown {
				list = list[len(list)-monthsShown:]
			}
			var events []models.ArchiveGateEvent
			if len(list) > 0 {
				from, _ := time.Parse("2006-01", list[0])
				to, _ := monthEnd(list[len(list)-1])
				if events, err = db.ArchiveGateEventsOverlapping(ctx, database.ArchiveGateStreamOfTable(t), from, to); err != nil {
					problem("gate events of "+s, err)
				}
			}
			for i := len(list) - 1; i >= 0; i-- { // newest first
				m := list[i]
				mv := MonthView{Month: m, Status: models.ArchiveMonthOpen, Due: m < due}
				if tot, ok := monthTotals[m]; ok {
					mv.ArchivedRows, mv.ArchivedObjectBytes = tot.Rows, tot.ObjectBytes
				}
				if r, ok := byMonth[m]; ok {
					mv.Status, mv.Partial, mv.PartialNote = r.Status, r.Partial, r.PartialNote
					mv.ChunkCount, mv.RowCount, mv.ObjectBytes, mv.Error = r.ChunkCount, r.RowCount, r.ObjectBytes, r.Error
					if r.SealedAt != nil {
						v := r.SealedAt.UTC()
						mv.SealedAt = &v
					}
				}
				if start, err := time.Parse("2006-01", m); err == nil {
					end := start.AddDate(0, 1, 0)
					for _, e := range events { // [From, To) overlaps [start, end)
						if !e.From.Before(end) || (e.To != nil && !e.To.After(start)) {
							continue
						}
						dv := DegradedView{Kind: e.Kind, From: e.From.UTC()}
						if e.To != nil {
							v := e.To.UTC()
							dv.To = &v
						}
						mv.Degraded = append(mv.Degraded, dv)
					}
				}
				sv.Months = append(sv.Months, mv)
			}
			st.Streams = append(st.Streams, sv)
		}
	}

	parked, err := db.ListArchiveChunksNeedingAttention(parkedShown)
	if err != nil {
		problem("chunks needing attention", err)
	}
	for _, c := range parked {
		pc := ParkedChunk{ID: c.ID, Table: c.SourceTable, Seq: c.Seq, IDLo: c.IDLo, IDHi: c.IDHi, PeriodStart: c.PeriodStart.UTC(),
			Month: c.Month, Attempts: c.Attempts, Mismatches: c.Mismatches, Error: c.Error, UpdatedAt: c.UpdatedAt.UTC()}
		// V passes a parked chunk only when it counts as verified (a sealed
		// month's, database.ArchiveTableProgress); otherwise V is below it.
		pc.HoldsGate = gated[database.ArchiveGateStreamOfTable(c.SourceTable)] && progress[c.SourceTable].VerifiedThroughID < c.IDHi
		st.NeedsAttention = append(st.NeedsAttention, pc)
	}
	return st, ctx.Err()
}

// activityView is a's view at now.
func activityView(a Activity, now time.Time) *ActivityView {
	v := &ActivityView{Activity: a, ElapsedSeconds: max(0, now.Sub(a.StartedAt).Seconds())}
	if !a.StageStartedAt.IsZero() {
		v.StageElapsedSeconds = max(0, now.Sub(a.StageStartedAt).Seconds())
	}
	var f float64
	switch {
	case a.Stage == "export" && a.IDSpan > 0:
		f = float64(a.IDsDone) / float64(a.IDSpan)
	case (a.Stage == "upload" || a.Stage == "verify") && a.BytesTotal > 0:
		f = float64(a.BytesDone) / float64(a.BytesTotal)
	case (a.Stage == "upload" || a.Stage == "verify") && a.ObjectsTotal > 0:
		f = float64(a.ObjectsDone) / float64(a.ObjectsTotal)
	default:
		return v
	}
	f = min(1, max(0, f))
	v.Fraction = &f
	return v
}

// gateReadView is the poller's record of the gate's switch reads as the
// status shows it: nil while the reads succeed, or when the record is older
// than StaleAfter (the poller is not writing it: nothing is known).
func gateReadView(h *database.ArchiveGateHealth, now time.Time) *GateReadView {
	if h == nil || h.FailingSince == nil || now.Sub(h.SeenAt) > StaleAfter {
		return nil
	}
	return &GateReadView{FailingSince: h.FailingSince.UTC(), ForSeconds: max(0, now.Sub(*h.FailingSince).Seconds()),
		Error: h.Error, HoldingAll: h.HoldingAll, SeenAt: h.SeenAt.UTC()}
}

// failedOrParked counts a table's chunks in failed or needs_attention.
func failedOrParked(chunks map[string]int64) int64 {
	return chunks[models.ArchiveChunkFailed] + chunks[models.ArchiveChunkNeedsAttention]
}

// backlogView is a table's backlog: counts from its chunk statuses, the rest
// from its unverified chunks (b) and the throughput of its recently verified
// ones (recent: rows over the time from each one's last attempt start to its
// verification).
func backlogView(counts map[string]int64, b database.ArchiveBacklog, recent []database.ArchiveChunkSummary, stuck int64) *BacklogView {
	v := &BacklogView{Verified: counts[models.ArchiveChunkVerified], Remaining: b.Chunks, OldestRemaining: b.OldestPeriod, RemainingRows: b.IDSpan}
	v.Chunks = v.Verified + v.Remaining
	var rows int64
	var secs float64
	for _, r := range recent {
		c := r.Chunk
		if c.StartedAt == nil || c.VerifiedAt == nil {
			continue
		}
		if d := c.VerifiedAt.Sub(*c.StartedAt).Seconds(); d > 0 {
			rows += c.RowCount
			secs += d
		}
	}
	if secs > 0 && rows > 0 {
		rate := float64(rows) / secs
		v.RateRowsPerSec = &rate
	}
	switch {
	case v.Remaining == 0:
		v.State = "caught_up"
	case v.Remaining == 1 && stuck == 0:
		v.State = "current"
	default:
		v.State = "catching_up"
	}
	if v.Remaining > 0 && v.RateRowsPerSec != nil {
		eta := float64(v.RemainingRows) / *v.RateRowsPerSec
		v.ETASeconds = &eta
	}
	return v
}

// chunkView is r for the recent and retrying lists.
func chunkView(r database.ArchiveChunkSummary) ChunkView {
	c := r.Chunk
	v := ChunkView{ID: c.ID, Table: c.SourceTable, Seq: c.Seq, PeriodStart: c.PeriodStart.UTC(), PeriodEnd: c.PeriodEnd.UTC(), Month: c.Month,
		Status: c.Status, Rows: c.RowCount, Objects: r.Objects, ObjectBytes: r.ObjectBytes, RawBytes: r.RawBytes, Attempts: c.Attempts,
		Error: c.Error}
	if c.StartedAt != nil {
		t := c.StartedAt.UTC()
		v.StartedAt = &t
	}
	if c.VerifiedAt != nil {
		t := c.VerifiedAt.UTC()
		v.VerifiedAt = &t
		if v.StartedAt != nil {
			d := max(0, t.Sub(*v.StartedAt).Seconds())
			v.DurationSeconds = &d
		}
	}
	return v
}
