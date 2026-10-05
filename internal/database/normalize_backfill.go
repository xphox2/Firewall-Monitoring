package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"

	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"
)

// The one-time normalized-event backfill (Phase 1, S-5; v0.11.297). See
// models.NormalizeBackfillJob for the row and its lifecycle.
//
// What it does: walks the syslog_messages rows whose message timestamp lies in
// [Since, Until) — Until is the normalize_ingest_started_at watermark the S-4
// ingest wrote once, Since at most NormalizeBackfillMaxDays back and never
// before the oldest net_events leaf — oldest first, one syslog_messages leaf at
// a time, in keyset-paged batches of normalizeBackfillBatchSize rows served by
// each leaf's (timestamp) index (`timestamp >= cursor AND (timestamp > cursor
// OR id > cursor_id) ORDER BY timestamp, id LIMIT n`; on PostgreSQL 16 the plan
// is an Index Scan on the leaf's (timestamp) index under an Incremental Sort
// presorted on timestamp — only the rows sharing one timestamp are sorted by
// id — and never a statement over the whole table). A leaf with no usable
// index — neither (timestamp) nor, for a device-scoped job, (device_id,
// timestamp) — stops the job with a WARNING, failed and resumable, its cursor
// parked at the start of that relation and the reason in its error, rather
// than seq-scanning it once per batch: create the index, resume, and the run
// continues there. Each row is normalized exactly as
// the ingest does it (normalizeStored: the stored format, v74, decides per row
// between normalize.NormalizeFramed and the re-framing fallback — a row with
// no stored format may be a pre-1.3.48 positional split) under its device's
// vendor, and the network class goes to net_events, every other
// class to sec_events, with raw_id / raw_ts naming the syslog row. The
// catalogs are fed too: fw_rules through the UpsertFwRules merge (LEAST /
// GREATEST on first_seen / last_seen, so replaying old rows can only widen the
// span, and an older sighting only fills attribute columns still NULL, so a
// month-old rule name never overwrites the live ingest's), inside the batch
// transaction, and
// device_field_observed with last_seen = the EVENT time, never "now" — a field
// a device sent a month ago must not read as observed today in the capability
// matrix. Nothing else: no denied_events projection and no alert rules — those
// are live-stream consumers and the rows are history.
//
// Exactly-once relative to the live ingest, in two layers. First the bounds: a
// raw row is in scope only when its message timestamp AND its created_at are
// both below the watermark, so a row the live ingest saved — including a
// collector spool replayed after the deploy with timestamps from before it —
// is never in scope. Second, per batch, a dedup probe: the batch's [min ts,
// max ts] window of net_events / sec_events (ts == raw_ts because the mappers
// never move an Event's Ts off the syslog row's timestamp), scoped to the
// job's device when it has one, is read for the batch's own raw_ids (see
// backfillProbeQuery for the bounds), and a raw row that already has a
// normalized row is skipped. That closes the race at the watermark itself (the batch that
// wrote it and any concurrent batch were saved a moment before it) and makes a
// re-run over an already backfilled window write nothing. Crash safety comes
// from the transaction: the COPY into net_events, the sec_events insert, the
// fw_rules upsert and the cursor / counter UPDATE on the job row commit
// together (one pgx transaction on PostgreSQL, one GORM transaction on the
// SQLite lane), so a crash resumes from the last committed batch with neither
// a gap nor a duplicate nor a lost catalog row; the UPDATE is guarded on the
// job still being live AND on this run's owner token (runner_id, set by the
// claim), so a job requeued and claimed elsewhere cannot be written by two
// runners.
//
// Throttle and control: the worker sleeps so the raw-row scan rate stays at
// RateRowsPerSec (default 2000: ~90 M rows in ~12.5 h) — the pace sleep
// re-reads the job every normalizeBackfillCancelPoll, so a cancel lands within
// about a second at any rate — checks between batches for a cancel
// (`cancelling` → finishes `cancelled`, cursor kept, resumable),
// for shutdown (ctx cancelled → back to `pending`, the next poller resumes),
// and for the optional local-time run window (outside it the job is `paused`
// and heartbeats until the window opens). A disk-headroom precheck refuses a
// job when the data volume's free space is under twice the estimated write
// (EstimateNormalizeBackfill; a resume re-runs it over the remaining window). Rollups: when a job that wrote rows ends, it
// leaves a `net_event_rollup_rewind_to` marker; the rollup cycle (which owns
// its cursors, under the maintenance lock) rewinds `net_event_rollup_closed_day`
// to the day before the backfill window on its next tick, so every backfilled
// day is recomputed exactly — a REPLACE of the day's rows, so the hour folds
// already taken for those days are never double counted.
const (
	NormalizeBackfillStatusPending    = "pending"
	NormalizeBackfillStatusRunning    = "running"
	NormalizeBackfillStatusPaused     = "paused"
	NormalizeBackfillStatusCancelling = "cancelling"
	NormalizeBackfillStatusDone       = "done"
	NormalizeBackfillStatusFailed     = "failed"
	NormalizeBackfillStatusCancelled  = "cancelled"

	// NormalizeIngestStartedSetting is the write-once watermark the S-4
	// ingest records on the first batch that landed normalized rows
	// (handlers.markNormalizeIngestStarted); the backfill's Until.
	NormalizeIngestStartedSetting = "normalize_ingest_started_at"
	// NormalizeBackfillWindowSetting is the operator's default run window
	// ("HH:MM-HH:MM", server local time) for a job whose request names none.
	NormalizeBackfillWindowSetting = "normalize_backfill_window"
	// netEventRollupRewindKey is the hand-off to the rollup cycle: the UTC day
	// (YYYY-MM-DD) to rewind net_event_rollup_closed_day to.
	netEventRollupRewindKey = "net_event_rollup_rewind_to"

	// NormalizeBackfillMaxDays bounds Since (roadmap §8: a 30-day backfill).
	NormalizeBackfillMaxDays = 30
	// NormalizeBackfillDefaultRate / Min / Max bound RateRowsPerSec.
	NormalizeBackfillDefaultRate = 2000
	NormalizeBackfillMinRate     = 100
	NormalizeBackfillMaxRate     = 100000
)

var (
	// normalizeBackfillBatchSize is the raw rows per batch (and per
	// transaction). A var so tests can walk a small fixture in many batches.
	normalizeBackfillBatchSize = 5000
	// normalizeBackfillStaleAfter is how old a running / paused job's heartbeat
	// may be before RequeueStaleNormalizeBackfillJobs puts it back to pending.
	normalizeBackfillStaleAfter = 2 * time.Minute
	// normalizeBackfillHeartbeat is the run's updated_at refresh cadence.
	normalizeBackfillHeartbeat = 30 * time.Second
	// normalizeBackfillPauseStep is how often a paused job re-checks the window
	// and its status.
	normalizeBackfillPauseStep = 30 * time.Second
	// normalizeBackfillObservedFlushEvery is the batch cadence of the
	// device_field_observed flush (and once more at the end).
	normalizeBackfillObservedFlushEvery = 20
	// normalizeBackfillBytesPerRow is the all-in net_events cost per raw row the
	// disk precheck assumes (plan §4: ~0.45-0.55 KB).
	normalizeBackfillBytesPerRow int64 = 512
	// normalizeBackfillBatchHook, when non-nil, runs after every committed
	// batch and can end the run (tests: cancel mid-way, simulate a crash).
	normalizeBackfillBatchHook func(job *models.NormalizeBackfillJob, batch int) error
	// normalizeBackfillTxHook, when non-nil, runs INSIDE the batch transaction
	// after the typed rows are written and before the cursor update; an error
	// rolls the whole batch back (tests: prove the coupling).
	normalizeBackfillTxHook func(batch int) error
	// normalizeBackfillNow is the clock the run window is evaluated with.
	normalizeBackfillNow = time.Now
	// normalizeBackfillCancelPoll is how often the pace sleep (and a paused
	// job's wait) re-reads the job for a cancel: the cancel latency bound.
	normalizeBackfillCancelPoll = time.Second
	// normalizeBackfillMetricMaxAge is the oldest server_metrics free-space
	// sample the disk precheck trusts; an older one counts as unknown.
	normalizeBackfillMetricMaxAge = 15 * time.Minute
	// backfillLeafIndexProbe reports whether a raw relation has an index the
	// keyset page can use (see leafHasUsableIndex). A var so the SQLite lane
	// can exercise the skip path.
	backfillLeafIndexProbe = (*Database).leafHasUsableIndex
)

var (
	// ErrNormalizeNotStarted: no normalize_ingest_started_at yet, so there is
	// no upper bound the backfill could stop at without overlapping live rows.
	ErrNormalizeNotStarted = errors.New("the normalizing ingest has not recorded its start yet (normalize_ingest_started_at is unset); nothing to backfill behind")
	// ErrNormalizeBackfillEmpty: the computed window is empty.
	ErrNormalizeBackfillEmpty = errors.New("the backfill window is empty (since is not before the ingest watermark)")
	// ErrNormalizeBackfillActive: a job is already pending / running / paused /
	// cancelling.
	ErrNormalizeBackfillActive = errors.New("a backfill job is already active")
	// errBackfillJobLost: the job row is no longer this runner's (requeued as
	// stale and claimed elsewhere, or finished by someone else).
	errBackfillJobLost = errors.New("backfill job is no longer running under this worker")
)

// normalizeBackfillActiveStatuses are the non-terminal states.
var normalizeBackfillActiveStatuses = []string{
	NormalizeBackfillStatusPending, NormalizeBackfillStatusRunning, NormalizeBackfillStatusPaused, NormalizeBackfillStatusCancelling,
}

// ── bounds and estimate ───────────────────────────────────────────────────────

// NormalizeBackfillBounds resolves the job window at `now`: Until is the
// ingest watermark (ErrNormalizeNotStarted without it); Since is sinceDays
// (clamped to 1..NormalizeBackfillMaxDays) before now, no earlier than the
// oldest net_events leaf — a row older than the retention lookback would land
// in net_events_default, where only the batched trim could ever remove it.
// ErrNormalizeBackfillEmpty when that leaves nothing.
func (d *Database) NormalizeBackfillBounds(sinceDays int, now time.Time) (since, until time.Time, err error) {
	v, ok := d.GetSettingValue(NormalizeIngestStartedSetting)
	if !ok || strings.TrimSpace(v) == "" {
		return time.Time{}, time.Time{}, ErrNormalizeNotStarted
	}
	until, err = time.Parse(time.RFC3339, strings.TrimSpace(v))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("setting %s = %q: %w", NormalizeIngestStartedSetting, v, err)
	}
	until = until.UTC()
	if sinceDays <= 0 || sinceDays > NormalizeBackfillMaxDays {
		sinceDays = NormalizeBackfillMaxDays
	}
	now = now.UTC()
	since = now.AddDate(0, 0, -sinceDays)
	if floor := d.netEventFloor(now); since.Before(floor) {
		since = floor
	}
	if !since.Before(until) {
		return since, until, ErrNormalizeBackfillEmpty
	}
	return since, until, nil
}

// netEventFloor is the start of the oldest net_events leaf at `now` (UTC
// midnight, retention lookback days back) — the same floor the rollup uses.
func (d *Database) netEventFloor(now time.Time) time.Time {
	return utcDay(now).AddDate(0, 0, -d.partitionLookbackDays(partitionDef{"net_events", "ts"}))
}

// NormalizeBackfillEstimate is the disk-headroom precheck's result.
type NormalizeBackfillEstimate struct {
	// From is where the estimate starts: the job's Since, or a resumed job's
	// cursor (only the remaining window is still to be written).
	From time.Time `json:"from"`
	// Rows is the syslog_ingest_hourly row count received in the window (every
	// severity, every device — an upper bound for a device-scoped job).
	Rows int64 `json:"rows"`
	// Bytes is Rows × normalizeBackfillBytesPerRow.
	Bytes int64 `json:"bytes"`
	// FreeBytes is the database volume's free space from the newest server
	// metrics sample of the last normalizeBackfillMetricMaxAge; FreeKnown is
	// false when no recent sample could see the volume (an external database,
	// or the metrics collector stopped), in which case the precheck cannot
	// refuse — a stale figure must not refuse, or pass, a job.
	FreeBytes int64 `json:"free_bytes"`
	FreeKnown bool  `json:"free_known"`
	// Enough is FreeBytes >= 2 × Bytes, or true when free space is unknown.
	Enough bool `json:"enough"`
}

// EstimateNormalizeBackfill sizes the window from the ingest meter (no table
// access: syslog_ingest_hourly is at most 192 rows/day) and compares it with
// the data volume's free space.
func (d *Database) EstimateNormalizeBackfill(since, until time.Time) (NormalizeBackfillEstimate, error) {
	est := NormalizeBackfillEstimate{From: since.UTC()}
	var rows *int64
	if err := d.db.Model(&models.SyslogIngestHourly{}).Select("SUM(row_count)").
		Where("timestamp >= ? AND timestamp < ?", since.UTC().Truncate(time.Hour), until.UTC()).Scan(&rows).Error; err != nil {
		return est, fmt.Errorf("estimate backfill rows: %w", err)
	}
	if rows != nil {
		est.Rows = *rows
	}
	est.Bytes = est.Rows * normalizeBackfillBytesPerRow
	// The newest recent server_metrics sample that could see the data volume
	// (the Retention page's source); only its free figure is needed here.
	var m models.ServerMetric
	if err := d.db.Where("data_disk_free_bytes IS NOT NULL AND timestamp >= ?", time.Now().Add(-normalizeBackfillMetricMaxAge)).
		Order("timestamp DESC").First(&m).Error; err == nil && m.DataDiskFreeBytes != nil {
		est.FreeBytes, est.FreeKnown = int64(*m.DataDiskFreeBytes), true
	}
	est.Enough = !est.FreeKnown || est.FreeBytes >= 2*est.Bytes
	return est, nil
}

// NormalizeBackfillRemaining is the part of a job's window still to be
// written: from its committed cursor (or Since, before the first batch) to
// Until. The resume paths re-run the disk precheck over it. (A cursor still in
// the DEFAULT child, which is walked first over the whole window, under-states
// the rest; that child is normally empty.)
func NormalizeBackfillRemaining(job *models.NormalizeBackfillJob) (from, until time.Time) {
	from = job.Since
	if job.CursorTs != nil && job.CursorTs.After(from) {
		from = *job.CursorTs
	}
	return from, job.Until
}

// NormalizeBackfillResumable reports whether a job can be resumed from its
// cursor, and the operator-facing next step the status views (API, CLI)
// print for it; "" for a job that needs none.
func NormalizeBackfillResumable(job *models.NormalizeBackfillJob) (bool, string) {
	switch job.Status {
	case NormalizeBackfillStatusFailed:
		return true, "failed: fix the cause shown in error (e.g. create the missing index), then resume — it continues from the cursor"
	case NormalizeBackfillStatusCancelled:
		return true, "cancelled: resume continues from the cursor"
	}
	return false, ""
}

// ── job rows ──────────────────────────────────────────────────────────────────

// CreateNormalizeBackfillJob enqueues a job (status pending, cursor cleared).
// The caller has resolved the bounds and verified no job is active; the
// check is repeated here under the same connection so two requests that both
// passed the handler's check cannot both enqueue.
func (d *Database) CreateNormalizeBackfillJob(job *models.NormalizeBackfillJob) error {
	if job.Since.IsZero() || job.Until.IsZero() || !job.Since.Before(job.Until) {
		return ErrNormalizeBackfillEmpty
	}
	if job.RateRowsPerSec <= 0 {
		job.RateRowsPerSec = NormalizeBackfillDefaultRate
	}
	if _, _, err := parseRunWindow(job.Window); err != nil {
		return err
	}
	job.ID = 0
	job.Status = NormalizeBackfillStatusPending
	job.CurrentPartition, job.RunnerID = "", ""
	job.CursorTs, job.CursorID = nil, 0
	job.RowsScanned, job.RowsWritten, job.RowsSkipped, job.RowsUnparsed = 0, 0, 0, 0
	job.Error = ""
	job.StartedAt, job.FinishedAt = nil, nil
	return d.db.Transaction(func(tx *gorm.DB) error {
		var live int64
		if err := tx.Model(&models.NormalizeBackfillJob{}).Where("status IN (?)", normalizeBackfillActiveStatuses).Count(&live).Error; err != nil {
			return err
		}
		if live > 0 {
			return ErrNormalizeBackfillActive
		}
		return tx.Create(job).Error
	})
}

// GetNormalizeBackfillJob returns one job (gorm.ErrRecordNotFound if absent).
func (d *Database) GetNormalizeBackfillJob(id uint) (*models.NormalizeBackfillJob, error) {
	var job models.NormalizeBackfillJob
	if err := d.db.First(&job, id).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

// GetLatestNormalizeBackfillJob returns the newest job in any state
// (gorm.ErrRecordNotFound when none was ever queued).
func (d *Database) GetLatestNormalizeBackfillJob() (*models.NormalizeBackfillJob, error) {
	var job models.NormalizeBackfillJob
	if err := d.db.Order("id DESC").First(&job).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

// GetActiveNormalizeBackfillJob returns the non-terminal job, or (nil, nil).
func (d *Database) GetActiveNormalizeBackfillJob() (*models.NormalizeBackfillJob, error) {
	var job models.NormalizeBackfillJob
	err := d.db.Where("status IN (?)", normalizeBackfillActiveStatuses).Order("id DESC").First(&job).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// ListNormalizeBackfillJobs returns the newest `limit` jobs, newest first.
func (d *Database) ListNormalizeBackfillJobs(limit int) ([]models.NormalizeBackfillJob, error) {
	var jobs []models.NormalizeBackfillJob
	if limit <= 0 {
		limit = 20
	}
	err := d.db.Order("id DESC").Limit(limit).Find(&jobs).Error
	return jobs, err
}

// CancelNormalizeBackfillJob requests a cancel, compare-and-set like the purge:
// pending → cancelled outright; running / paused → cancelling, which the
// worker observes between batches (or pause steps) and finishes as cancelled
// with the cursor kept. Returns the new status, or applied=false when the job
// is not cancellable (the caller answers 409).
func (d *Database) CancelNormalizeBackfillJob(id uint) (status string, applied bool, err error) {
	now := time.Now()
	res := d.db.Model(&models.NormalizeBackfillJob{}).
		Where("id = ? AND status = ?", id, NormalizeBackfillStatusPending).
		Updates(map[string]interface{}{"status": NormalizeBackfillStatusCancelled, "finished_at": now, "updated_at": now})
	if res.Error != nil {
		return "", false, res.Error
	}
	if res.RowsAffected == 1 {
		return NormalizeBackfillStatusCancelled, true, nil
	}
	res = d.db.Model(&models.NormalizeBackfillJob{}).
		Where("id = ? AND status IN (?)", id, []string{NormalizeBackfillStatusRunning, NormalizeBackfillStatusPaused}).
		Updates(map[string]interface{}{"status": NormalizeBackfillStatusCancelling, "updated_at": now})
	if res.Error != nil {
		return "", false, res.Error
	}
	if res.RowsAffected == 1 {
		return NormalizeBackfillStatusCancelling, true, nil
	}
	return "", false, nil
}

// ResumeNormalizeBackfillJob puts a cancelled or failed job back to pending
// with its cursor and counters intact, so the worker continues where it
// stopped. applied=false when the job is in another state; the single-active
// rule holds (ErrNormalizeBackfillActive when another job is live).
func (d *Database) ResumeNormalizeBackfillJob(id uint) (applied bool, err error) {
	now := time.Now()
	err = d.db.Transaction(func(tx *gorm.DB) error {
		var live int64
		if err := tx.Model(&models.NormalizeBackfillJob{}).Where("status IN (?)", normalizeBackfillActiveStatuses).Count(&live).Error; err != nil {
			return err
		}
		if live > 0 {
			return ErrNormalizeBackfillActive
		}
		res := tx.Model(&models.NormalizeBackfillJob{}).
			Where("id = ? AND status IN (?)", id, []string{NormalizeBackfillStatusCancelled, NormalizeBackfillStatusFailed}).
			Updates(map[string]interface{}{
				"status": NormalizeBackfillStatusPending, "finished_at": nil, "error": "", "runner_id": "", "updated_at": now,
			})
		if res.Error != nil {
			return res.Error
		}
		applied = res.RowsAffected == 1
		return nil
	})
	return applied, err
}

// ClaimNormalizeBackfillJob is the worker's compare-and-set claim (pending →
// running, owner token = runner): exactly one of two workers sees
// RowsAffected == 1, and every later write of the run is guarded on runner.
func (d *Database) ClaimNormalizeBackfillJob(id uint, runner string) (bool, error) {
	if runner == "" {
		return false, errors.New("backfill claim: empty runner id")
	}
	now := time.Now()
	res := d.db.Model(&models.NormalizeBackfillJob{}).
		Where("id = ? AND status = ?", id, NormalizeBackfillStatusPending).
		Updates(map[string]interface{}{"status": NormalizeBackfillStatusRunning, "runner_id": runner, "updated_at": now})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// ClaimNextNormalizeBackfillJob claims the oldest pending job for runner, or
// (nil, nil).
func (d *Database) ClaimNextNormalizeBackfillJob(runner string) (*models.NormalizeBackfillJob, error) {
	for {
		var job models.NormalizeBackfillJob
		err := d.db.Where("status = ?", NormalizeBackfillStatusPending).Order("id ASC").First(&job).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		won, err := d.ClaimNormalizeBackfillJob(job.ID, runner)
		if err != nil {
			return nil, err
		}
		if !won {
			continue
		}
		return d.GetNormalizeBackfillJob(job.ID)
	}
}

// newBackfillRunnerID is a fresh owner token for one claim: host, pid and 64
// random bits, so two runs never share one even in the same process.
func newBackfillRunnerID() string {
	host, _ := os.Hostname()
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s/%d/%s", host, os.Getpid(), hex.EncodeToString(b[:]))
}

// RequeueStaleNormalizeBackfillJobs puts a running / paused job whose
// heartbeat is older than staleAfter back to pending (its cursor is the
// checkpoint; the owner token is cleared, so the old runner's next write
// fails its guard even before the next claim) and finishes a stale cancelling job as cancelled. Returns the
// number requeued.
func (d *Database) RequeueStaleNormalizeBackfillJobs(staleAfter time.Duration) (int64, error) {
	now := time.Now()
	cutoff := now.Add(-staleAfter)
	res := d.db.Model(&models.NormalizeBackfillJob{}).
		Where("status IN (?) AND updated_at < ?", []string{NormalizeBackfillStatusRunning, NormalizeBackfillStatusPaused}, cutoff).
		Updates(map[string]interface{}{
			"status": NormalizeBackfillStatusPending, "runner_id": "", "updated_at": now, "error": "requeued: worker heartbeat lost",
		})
	if res.Error != nil {
		return 0, res.Error
	}
	requeued := res.RowsAffected
	res = d.db.Model(&models.NormalizeBackfillJob{}).
		Where("status = ? AND updated_at < ?", NormalizeBackfillStatusCancelling, cutoff).
		Updates(map[string]interface{}{
			"status": NormalizeBackfillStatusCancelled, "finished_at": now, "updated_at": now,
			"error": "cancelled: worker heartbeat lost while cancelling",
		})
	if res.Error != nil {
		return requeued, res.Error
	}
	return requeued, nil
}

// updateBackfillJob writes columns on the job row (progress, state) while it
// is still this runner's; errBackfillJobLost otherwise.
func (d *Database) updateBackfillJob(ctx context.Context, jobID uint, runner string, cols map[string]interface{}) error {
	if _, ok := cols["updated_at"]; !ok {
		cols["updated_at"] = time.Now()
	}
	res := d.db.WithContext(ctx).Model(&models.NormalizeBackfillJob{}).Where("id = ? AND runner_id = ?", jobID, runner).Updates(cols)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return errBackfillJobLost
	}
	return nil
}

// touchBackfillJob is the heartbeat: updated_at only, and only while the job
// is live and this runner's (a job finished or re-claimed elsewhere must not
// look alive on this run's behalf).
func (d *Database) touchBackfillJob(ctx context.Context, jobID uint, runner string) error {
	return d.db.WithContext(ctx).Model(&models.NormalizeBackfillJob{}).
		Where("id = ? AND runner_id = ? AND status IN (?)", jobID, runner, []string{NormalizeBackfillStatusRunning, NormalizeBackfillStatusPaused, NormalizeBackfillStatusCancelling}).
		Update("updated_at", time.Now()).Error
}

// finishBackfillJob ends the job in a terminal status and, when the job wrote
// rows, leaves the rollup rewind marker — in the same transaction, so a job
// that counts as finished always has its rewind queued. The marker keeps the
// EARLIER of an existing one and this job's (the day before the window).
// Guarded on the owner token: a runner that lost the job leaves it alone.
func (d *Database) finishBackfillJob(jobID uint, runner, status string, cause error) error {
	now := time.Now()
	msg := ""
	if cause != nil {
		msg = shortError(cause, 1000)
	}
	err := d.db.Transaction(func(tx *gorm.DB) error {
		var job models.NormalizeBackfillJob
		if err := tx.First(&job, jobID).Error; err != nil {
			return err
		}
		res := tx.Model(&models.NormalizeBackfillJob{}).Where("id = ? AND runner_id = ?", jobID, runner).Updates(map[string]interface{}{
			"status": status, "error": msg, "finished_at": now, "updated_at": now,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return errBackfillJobLost
		}
		if job.RowsWritten == 0 {
			return nil
		}
		day := utcDay(job.Since).AddDate(0, 0, -1)
		// Read on tx: a second connection against the SQLite lane's single
		// writer would deadlock here.
		if v, ok := getSettingOn(tx, netEventRollupRewindKey); ok && v != "" {
			if cur, perr := time.Parse("2006-01-02", v); perr == nil && !cur.After(day) {
				return nil // an earlier rewind is already queued
			}
		}
		return d.setSetting(tx, netEventRollupRewindKey, day.Format("2006-01-02"))
	})
	if err != nil {
		return fmt.Errorf("backfill job %d: finish as %s: %w (cause: %v)", jobID, status, err, cause)
	}
	if cause != nil {
		return fmt.Errorf("backfill job %d %s: %w", jobID, status, cause)
	}
	return nil
}

// applyNetEventRollupRewind consumes the backfill's rewind marker: the
// closed-day cursor moves back to the marker's day when it is past it, the
// close-failure count is cleared (it names a day that may now differ), and the
// marker is deleted — in one transaction, under the caller's maintenance lock,
// so a day close running concurrently cannot move the cursor forward past a
// rewind it never saw. Called by runNetEventRollupCycle before the day closes.
func (d *Database) applyNetEventRollupRewind() error {
	v, ok := d.GetSettingValue(netEventRollupRewindKey)
	if !ok || v == "" {
		return nil
	}
	day, err := time.Parse("2006-01-02", v)
	if err != nil {
		log.Printf("Net event rollup: ignoring unreadable rewind marker %s = %q", netEventRollupRewindKey, v)
		return d.db.Where("\"key\" = ?", netEventRollupRewindKey).Delete(&models.SystemSetting{}).Error
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		var closed time.Time
		v, ok := getSettingOn(tx, netEventRollupClosedDayKey)
		if ok && v != "" {
			if closed, err = time.Parse("2006-01-02", v); err != nil {
				return fmt.Errorf("setting %s = %q: %w", netEventRollupClosedDayKey, v, err)
			}
		} else {
			ok = false
		}
		if ok && closed.After(day) {
			if err := d.setSetting(tx, netEventRollupClosedDayKey, day.Format("2006-01-02")); err != nil {
				return err
			}
			if err := tx.Where("\"key\" = ?", netEventRollupCloseFailuresKey).Delete(&models.SystemSetting{}).Error; err != nil {
				return err
			}
			log.Printf("Net event rollup: closed-day cursor rewound from %s to %s after a backfill; the days in between are recomputed exactly over the next cycles",
				closed.Format("2006-01-02"), day.Format("2006-01-02"))
		}
		return tx.Where("\"key\" = ?", netEventRollupRewindKey).Delete(&models.SystemSetting{}).Error
	})
}

// getSettingOn is GetSettingValue on the given handle (a transaction).
func getSettingOn(tx *gorm.DB, key string) (string, bool) {
	var s models.SystemSetting
	if err := tx.Where("\"key\" = ?", key).First(&s).Error; err != nil {
		return "", false
	}
	return s.Value, true
}

// ── run window, pacing ────────────────────────────────────────────────────────

// runWindow is a daily local-time window in minutes since midnight; start >
// end wraps past midnight (22:00-06:00).
type runWindow struct{ start, end int }

// parseRunWindow parses "HH:MM-HH:MM". ok is false for the empty string
// (no window); an error for anything else that does not parse.
func parseRunWindow(s string) (w runWindow, ok bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return runWindow{}, false, nil
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return runWindow{}, false, fmt.Errorf("run window %q: want HH:MM-HH:MM", s)
	}
	hm := func(p string) (int, error) {
		t, err := time.Parse("15:04", strings.TrimSpace(p))
		if err != nil {
			return 0, fmt.Errorf("run window %q: %w", s, err)
		}
		return t.Hour()*60 + t.Minute(), nil
	}
	if w.start, err = hm(parts[0]); err != nil {
		return runWindow{}, false, err
	}
	if w.end, err = hm(parts[1]); err != nil {
		return runWindow{}, false, err
	}
	if w.start == w.end {
		return runWindow{}, false, fmt.Errorf("run window %q: start equals end", s)
	}
	return w, true, nil
}

// ValidateRunWindow is parseRunWindow for callers outside the package (the
// API / CLI validation): nil for the empty string or a well-formed window.
func ValidateRunWindow(s string) error {
	_, _, err := parseRunWindow(s)
	return err
}

// contains reports whether t (local time) falls inside the window.
func (w runWindow) contains(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	if w.start < w.end {
		return m >= w.start && m < w.end
	}
	return m >= w.start || m < w.end
}

// backfillPace is how long to sleep after a batch of `rows` that took
// `elapsed`, to hold ratePerSec; zero when the batch already took longer.
func backfillPace(rows, ratePerSec int, elapsed time.Duration) time.Duration {
	if rows <= 0 || ratePerSec <= 0 {
		return 0
	}
	want := time.Duration(float64(rows) / float64(ratePerSec) * float64(time.Second))
	if want <= elapsed {
		return 0
	}
	return want - elapsed
}

// ── raw-row ranges and paging ─────────────────────────────────────────────────

// backfillRange is one syslog_messages relation to walk and the half-open
// [lo, hi) slice of the job window it holds; isDefault marks a DEFAULT child
// (no bound of its own: it is walked over the whole window, first).
type backfillRange struct {
	table     string
	lo, hi    time.Time
	isDefault bool
}

// safeRelName is the shape every relation name read from pg_inherits must
// have before it is spliced into a FROM clause.
var safeRelName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// backfillRanges lists the relations to walk for [since, until): on a
// partitioned PostgreSQL syslog_messages, the DEFAULT child first (its rows
// have no leaf of their own; it is normally empty), then every leaf whose
// range overlaps the window, oldest first, each clipped to the window; on a
// plain table (or SQLite) the table itself.
func (d *Database) backfillRanges(since, until time.Time) ([]backfillRange, error) {
	whole := []backfillRange{{table: "syslog_messages", lo: since, hi: until}}
	if !d.dialect.IsPostgres() {
		return whole, nil
	}
	var isPartitioned bool
	if err := d.db.Raw(`SELECT EXISTS (
		SELECT 1 FROM pg_partitioned_table pt
		JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = 'syslog_messages')`).Scan(&isPartitioned).Error; err != nil {
		return nil, fmt.Errorf("backfill: is syslog_messages partitioned: %w", err)
	}
	if !isPartitioned {
		return whole, nil
	}
	var children []struct {
		Name  string
		Bound string
	}
	if err := d.db.Raw(`
		SELECT c.relname AS name, pg_get_expr(c.relpartbound, c.oid) AS bound
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class parent ON parent.oid = i.inhparent
		WHERE parent.relname = 'syslog_messages'`).Scan(&children).Error; err != nil {
		return nil, fmt.Errorf("backfill: list syslog_messages leaves: %w", err)
	}
	var leaves, defaults []backfillRange
	for _, ch := range children {
		if !safeRelName.MatchString(ch.Name) {
			return nil, fmt.Errorf("backfill: refusing relation name %q", ch.Name)
		}
		lo, okLo := parsePartitionBound(ch.Bound, "FROM ('")
		hi, okHi := parsePartitionUpperBound(ch.Bound)
		if !okLo || !okHi {
			defaults = append(defaults, backfillRange{table: ch.Name, lo: since, hi: until, isDefault: true})
			continue
		}
		if lo.Before(since) {
			lo = since
		}
		if hi.After(until) {
			hi = until
		}
		if !lo.Before(hi) {
			continue
		}
		leaves = append(leaves, backfillRange{table: ch.Name, lo: lo, hi: hi})
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].lo.Before(leaves[j].lo) })
	return append(defaults, leaves...), nil
}

// leafHasUsableIndex reports whether the keyset page can be served from an
// index of the raw relation `table`: a valid, non-partial index whose leading
// column is timestamp, or — for a device-scoped job, whose page has
// device_id = ? — one leading (device_id, timestamp). An empty relation counts
// as usable (scanning zero pages is free). Always true off PostgreSQL.
func (d *Database) leafHasUsableIndex(table string, deviceScoped bool) (bool, error) {
	if !d.dialect.IsPostgres() {
		return true, nil
	}
	var size int64
	if err := d.db.Raw("SELECT pg_relation_size(c.oid) FROM pg_class c WHERE c.relname = ? AND c.relnamespace = to_regnamespace(current_schema())", table).Scan(&size).Error; err != nil {
		return false, fmt.Errorf("size of %s: %w", table, err)
	}
	if size == 0 {
		return true, nil
	}
	var idx []struct {
		C0 string
		C1 *string
	}
	if err := d.db.Raw(`
		SELECT a0.attname AS c0, a1.attname AS c1
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_attribute a0 ON a0.attrelid = c.oid AND a0.attnum = i.indkey[0]
		LEFT JOIN pg_attribute a1 ON a1.attrelid = c.oid AND a1.attnum = i.indkey[1]
		WHERE c.relname = ? AND c.relnamespace = to_regnamespace(current_schema())
		  AND i.indisvalid AND i.indisready AND i.indpred IS NULL`, table).Scan(&idx).Error; err != nil {
		return false, fmt.Errorf("indexes of %s: %w", table, err)
	}
	for _, ix := range idx {
		if ix.C0 == "timestamp" {
			return true, nil
		}
		if deviceScoped && ix.C0 == "device_id" && ix.C1 != nil && *ix.C1 == "timestamp" {
			return true, nil
		}
	}
	return false, nil
}

// backfillPageQuery is the keyset page of range r after the cursor
// (exclusive), oldest first. Separate so the plan test EXPLAINs the exact
// statement the run executes.
func backfillPageQuery(tx *gorm.DB, r backfillRange, cursorTs time.Time, cursorID int64, until time.Time, deviceID *uint, limit int) *gorm.DB {
	q := tx.Table(r.table).
		Where("timestamp >= ? AND (timestamp > ? OR id > ?) AND timestamp < ? AND created_at < ?", cursorTs, cursorTs, cursorID, r.hi, until)
	if deviceID != nil {
		q = q.Where("device_id = ?", *deviceID)
	}
	return q.Order("timestamp, id").Limit(limit)
}

// backfillProbeQuery is the dedup probe of one normalized table for a batch:
// which of the batch's raw rows already have a normalized row. Two bounds:
//   - I/O: the [first, last] ts range of the batch, scoped to the job's
//     device when it has one (the per-leaf (device_id, ts) index). In scope,
//     that range holds about the batch's own rows — every in-scope raw row of
//     the range is in the batch except the ones received after the watermark
//     (normalized live) — however sparse the batch: a device-scoped batch
//     that spans weeks no longer reads everyone else's rows in between.
//   - result: `raw_id IN (the batch's ids)`, so what comes back — and lands in
//     the caller's map — is at most the batch size whatever the range holds
//     (a filter on the index scan; raw_id has no index of its own).
//
// Measured on PostgreSQL 16 (2 M rows of a dense device and 5 000 of a sparse
// one over three day leaves, a 5 000-row batch of the sparse one): 88 shared
// buffers against 22 786 (three Seq Scans) for the unscoped range; a dense
// all-device batch reads 101 buffers either way. Probing each distinct
// instant instead (`ts IN (...)`) read 15 045 buffers for that dense batch —
// one index descent per instant — and is not used.
func backfillProbeQuery(tx *gorm.DB, table string, rows []models.SyslogMessage, deviceID *uint) *gorm.DB {
	lo, hi := rows[0].Timestamp.UTC(), rows[len(rows)-1].Timestamp.UTC()
	ids := make([]int64, len(rows))
	for i := range rows {
		ids[i] = int64(rows[i].ID)
	}
	q := tx.Table(table).Where("ts >= ? AND ts <= ? AND raw_id IN ?", lo, hi, ids)
	if deviceID != nil {
		q = q.Where("device_id = ?", *deviceID)
	}
	return q
}

// normalizeStored normalizes a row read back from syslog_messages the way the
// live ingest normalized it (handlers.normalizeIngest): a row with a stored
// format (v74; only ever written for a framing-contract probe) gets its hint
// back and skips the re-framing join; a row without one — older than v74, a
// v5 probe's, a format-less spool replay — keeps the fallback. One case
// differs from the live path: a v6 row whose hint this server did not know
// was stored NULL, so it is re-framed here where the live ingest used
// NormalizeFramed. A v6 collector only emits the six known values (a new one
// is a relay schema bump), and re-framing is the conservative direction.
func normalizeStored(vendor string, msg *models.SyslogMessage) (normalize.Event, normalize.Outcome) {
	msg.Format = models.SyslogFormatName(msg.StoredFormat)
	if msg.Format != "" {
		return normalize.NormalizeFramed(vendor, msg)
	}
	return normalize.Normalize(vendor, msg)
}

// fetchBackfillBatch reads the next keyset page of range r and the raw_ids of
// that page that already have a normalized row (the dedup probe). One bounded
// read transaction (120 s statement_timeout on Postgres).
func (d *Database) fetchBackfillBatch(ctx context.Context, r backfillRange, cursorTs time.Time, cursorID int64, until time.Time, deviceID *uint, limit int) (rows []models.SyslogMessage, existing map[int64]struct{}, err error) {
	err = d.WithContext(ctx).boundedRead(func(tx *gorm.DB) error {
		if err := backfillPageQuery(tx, r, cursorTs, cursorID, until, deviceID, limit).Find(&rows).Error; err != nil {
			return fmt.Errorf("read %s after (%s, %d): %w", r.table, cursorTs.Format(time.RFC3339Nano), cursorID, err)
		}
		if len(rows) == 0 {
			return nil
		}
		existing = make(map[int64]struct{})
		for _, table := range []string{"net_events", "sec_events"} {
			var ids []int64
			if err := backfillProbeQuery(tx, table, rows, deviceID).Pluck("raw_id", &ids).Error; err != nil {
				return fmt.Errorf("dedup probe on %s [%s, %s]: %w", table,
					rows[0].Timestamp.Format(time.RFC3339Nano), rows[len(rows)-1].Timestamp.Format(time.RFC3339Nano), err)
			}
			for _, id := range ids {
				existing[id] = struct{}{}
			}
		}
		return nil
	})
	return rows, existing, err
}

// backfillProgress is what one committed batch records on the job row:
// the cursor (last raw row of the batch) and the running totals.
type backfillProgress struct {
	partition string
	cursorTs  time.Time
	cursorID  int64
	scanned   int64
	written   int64
	skipped   int64
	unparsed  int64
}

// commitBackfillBatch writes the batch's typed rows, its fw_rules catalog
// rows and the job's progress in ONE transaction (see the file comment). The
// progress UPDATE is guarded on the job still being running / cancelling AND
// on this run's owner token; zero rows affected rolls the batch back and
// reports errBackfillJobLost.
func (d *Database) commitBackfillBatch(ctx context.Context, jobID uint, runner string, batch int, nets []models.NetEvent, secs []models.SecEvent, rules []models.FwRule, p backfillProgress) error {
	now := time.Now()
	if d.pgxPool == nil {
		return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := insertInChunks(tx, "net_events", nets); err != nil {
				return err
			}
			if err := insertInChunks(tx, "sec_events", secs); err != nil {
				return err
			}
			if err := d.upsertFwRulesOn(tx, rules); err != nil {
				return fmt.Errorf("upsert fw_rules: %w", err)
			}
			if normalizeBackfillTxHook != nil {
				if err := normalizeBackfillTxHook(batch); err != nil {
					return err
				}
			}
			res := tx.Model(&models.NormalizeBackfillJob{}).
				Where("id = ? AND runner_id = ? AND status IN (?)", jobID, runner, []string{NormalizeBackfillStatusRunning, NormalizeBackfillStatusCancelling}).
				Updates(map[string]interface{}{
					"current_partition": p.partition, "cursor_ts": p.cursorTs, "cursor_id": p.cursorID,
					"rows_scanned": p.scanned, "rows_written": p.written, "rows_skipped": p.skipped, "rows_unparsed": p.unparsed,
					"updated_at": now,
				})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return errBackfillJobLost
			}
			return nil
		})
	}
	tx, err := d.pgxPool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '120s'"); err != nil {
		return err
	}
	if len(nets) > 0 {
		rows := make([][]any, len(nets))
		for i := range nets {
			rows[i] = netEventCopyRow(&nets[i])
		}
		n, err := tx.CopyFrom(ctx, pgx.Identifier{"net_events"}, netEventsCopyColumns, pgx.CopyFromRows(rows))
		if err != nil {
			return fmt.Errorf("COPY %d net_events rows: %w", len(nets), err)
		}
		if int(n) != len(nets) {
			return fmt.Errorf("COPY net_events short write: %d of %d", n, len(nets))
		}
	}
	if len(secs) > 0 {
		rows := make([][]any, len(secs))
		for i := range secs {
			rows[i] = secEventCopyRow(&secs[i])
		}
		n, err := tx.CopyFrom(ctx, pgx.Identifier{"sec_events"}, secEventsCopyColumns, pgx.CopyFromRows(rows))
		if err != nil {
			return fmt.Errorf("COPY %d sec_events rows: %w", len(secs), err)
		}
		if int(n) != len(secs) {
			return fmt.Errorf("COPY sec_events short write: %d of %d", n, len(secs))
		}
	}
	if err := upsertFwRulesPgx(ctx, tx, d.dialect, rules); err != nil {
		return err
	}
	if normalizeBackfillTxHook != nil {
		if err := normalizeBackfillTxHook(batch); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE normalize_backfill_jobs
		SET current_partition = $1, cursor_ts = $2, cursor_id = $3,
		    rows_scanned = $4, rows_written = $5, rows_skipped = $6, rows_unparsed = $7, updated_at = $8
		WHERE id = $9 AND runner_id = $10 AND status IN ($11, $12)`,
		p.partition, p.cursorTs, p.cursorID, p.scanned, p.written, p.skipped, p.unparsed, now,
		int64(jobID), runner, NormalizeBackfillStatusRunning, NormalizeBackfillStatusCancelling)
	if err != nil {
		return fmt.Errorf("record batch progress: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errBackfillJobLost
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// ── the run ───────────────────────────────────────────────────────────────────

// deviceVendors maps every device id (retired included — their history is
// still theirs) to its lowercased vendor; a device the row no longer names
// normalizes as generic, like handlers.deviceVendor.
func (d *Database) deviceVendors() (map[uint]string, error) {
	var rows []struct {
		ID     uint
		Vendor string
	}
	if err := d.db.Model(&models.Device{}).Select("id, vendor").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("load device vendors: %w", err)
	}
	m := make(map[uint]string, len(rows))
	for _, r := range rows {
		if v := strings.ToLower(strings.TrimSpace(r.Vendor)); v != "" {
			m[r.ID] = v
		}
	}
	return m, nil
}

// observedKey / observedAcc accumulate device_field_observed counts across
// batches (flushed every normalizeBackfillObservedFlushEvery batches and at
// the end), last_seen = the newest EVENT time seen.
type observedKey struct {
	dev   uint
	class normalize.Class
}

type observedAcc struct {
	counts [len(normalize.ObservedFields)]int64
	last   time.Time
}

// mergeObserved folds a committed batch's counts into the run's accumulator.
func mergeObserved(dst, src map[observedKey]*observedAcc) {
	for k, b := range src {
		a := dst[k]
		if a == nil {
			dst[k] = b
			continue
		}
		for i := range a.counts {
			a.counts[i] += b.counts[i]
		}
		if b.last.After(a.last) {
			a.last = b.last
		}
	}
}

func flushObserved(d *Database, acc map[observedKey]*observedAcc) {
	if len(acc) == 0 {
		return
	}
	rows := make([]models.DeviceFieldObserved, 0, len(acc)*8)
	for k, a := range acc {
		for i, n := range a.counts {
			if n == 0 {
				continue
			}
			rows = append(rows, models.DeviceFieldObserved{
				DeviceID: k.dev, Class: int16(k.class), Field: normalize.ObservedFields[i], Count: n, LastSeen: a.last,
			})
		}
	}
	if err := d.FlushFieldObserved(rows); err != nil {
		log.Printf("normalize-backfill: flush %d device_field_observed row(s): %v (counts for this stretch are lost; the matrix stays a lower bound)", len(rows), err)
	}
	for k := range acc {
		delete(acc, k)
	}
}

// backfillResumePosition is where a run starts: a fresh job (no cursor) at
// the first range's start; a resumed one in its partition after its cursor.
// When that partition no longer exists (dropped by retention since), the run
// continues at the first LEAF that starts after the cursor — a DEFAULT child
// is never skipped to (it was walked first, over the whole window), but the
// first leaf is a candidate like any other when there is no DEFAULT child.
// idx == len(ranges) means nothing is left.
func backfillResumePosition(ranges []backfillRange, partition string, cursor *time.Time, cursorID int64) (idx int, cursorTs time.Time, id int64) {
	if len(ranges) == 0 {
		return 0, time.Time{}, 0
	}
	if cursor == nil {
		return 0, ranges[0].lo, 0
	}
	cursorTs = cursor.UTC()
	for i, r := range ranges {
		if r.table == partition {
			return i, cursorTs, cursorID
		}
	}
	for i, r := range ranges {
		if !r.isDefault && r.lo.After(cursorTs) {
			return i, r.lo, 0
		}
	}
	return len(ranges), cursorTs, cursorID
}

// RunNormalizeBackfill executes one job CLAIMED by runner (status running,
// runner_id = runner) to its end — done, cancelled, failed, or (ctx
// cancelled: shutdown) back to pending. The returned error is the run's
// disposition for logging; the job row is the source of truth. See the file
// comment for the batch contract.
func (d *Database) RunNormalizeBackfill(ctx context.Context, jobID uint, runner string) error {
	job, err := d.GetNormalizeBackfillJob(jobID)
	if err != nil {
		return fmt.Errorf("backfill job %d: load: %w", jobID, err)
	}
	if job.Status != NormalizeBackfillStatusRunning || job.RunnerID != runner {
		return fmt.Errorf("backfill job %d: status %q runner %q, want running under %q (claim it first)", jobID, job.Status, job.RunnerID, runner)
	}
	window, hasWindow, err := parseRunWindow(job.Window)
	if err != nil {
		return d.finishBackfillJob(jobID, runner, NormalizeBackfillStatusFailed, err)
	}
	vendors, err := d.deviceVendors()
	if err != nil {
		return d.finishBackfillJob(jobID, runner, NormalizeBackfillStatusFailed, err)
	}
	ranges, err := d.backfillRanges(job.Since, job.Until)
	if err != nil {
		return d.finishBackfillJob(jobID, runner, NormalizeBackfillStatusFailed, err)
	}
	if len(ranges) == 0 {
		return d.finishBackfillJob(jobID, runner, NormalizeBackfillStatusDone, nil)
	}

	idx, cursorTs, cursorID := backfillResumePosition(ranges, job.CurrentPartition, job.CursorTs, job.CursorID)
	rate := job.RateRowsPerSec
	if rate <= 0 {
		rate = NormalizeBackfillDefaultRate
	}
	cols := map[string]interface{}{"error": ""}
	if job.StartedAt == nil {
		cols["started_at"] = time.Now()
	}
	if idx < len(ranges) && job.CurrentPartition == "" {
		cols["current_partition"] = ranges[idx].table
	}
	if err := d.updateBackfillJob(ctx, jobID, runner, cols); err != nil {
		if errors.Is(err, errBackfillJobLost) {
			return fmt.Errorf("backfill job %d: %w", jobID, err)
		}
		return d.finishBackfillJob(jobID, runner, NormalizeBackfillStatusFailed, err)
	}
	log.Printf("normalize-backfill: job %d %s window [%s, %s) over %d relation(s) at %d rows/s (cursor %s/%s/%d)",
		jobID, map[bool]string{true: "resuming", false: "starting"}[job.CursorTs != nil],
		job.Since.UTC().Format(time.RFC3339), job.Until.UTC().Format(time.RFC3339), len(ranges), rate,
		job.CurrentPartition, cursorTs.Format(time.RFC3339), cursorID)

	// Heartbeat: updated_at stays fresh through a long read or a pause so the
	// stale requeue never steals a live job.
	hbDone := make(chan struct{})
	go func() {
		t := time.NewTicker(normalizeBackfillHeartbeat)
		defer t.Stop()
		for {
			select {
			case <-hbDone:
				return
			case <-t.C:
				if err := d.touchBackfillJob(ctx, jobID, runner); err != nil && ctx.Err() == nil {
					log.Printf("normalize-backfill: job %d heartbeat: %v", jobID, err)
				}
			}
		}
	}()
	defer close(hbDone)

	progress := backfillProgress{
		partition: job.CurrentPartition, cursorTs: cursorTs, cursorID: cursorID,
		scanned: job.RowsScanned, written: job.RowsWritten, skipped: job.RowsSkipped, unparsed: job.RowsUnparsed,
	}
	observed := map[observedKey]*observedAcc{}
	batch := 0
	floorWarned := false
	checked := -1 // the range index whose index set has been verified
	finish := func(status string, cause error) error {
		flushObserved(d, observed)
		return d.finishBackfillJob(jobID, runner, status, cause)
	}
	// nextRange moves to range idx+1 (its own start) and records it.
	nextRange := func() error {
		idx++
		if idx >= len(ranges) {
			return nil
		}
		cursorTs, cursorID = ranges[idx].lo, 0
		progress.partition, progress.cursorTs, progress.cursorID = ranges[idx].table, cursorTs, cursorID
		return d.updateBackfillJob(ctx, jobID, runner, map[string]interface{}{
			"current_partition": ranges[idx].table, "cursor_ts": cursorTs, "cursor_id": cursorID,
		})
	}

	for idx < len(ranges) {
		// Between batches: shutdown, cancel, requeue, run window.
		stop, err := d.backfillCheckpoint(ctx, jobID, runner, window, hasWindow)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				flushObserved(d, observed)
				return err
			}
			if errors.Is(err, errBackfillJobLost) {
				flushObserved(d, observed)
				return fmt.Errorf("backfill job %d: %w", jobID, err)
			}
			return finish(NormalizeBackfillStatusFailed, err)
		}
		if stop {
			log.Printf("normalize-backfill: job %d cancelled by request after %d batch(es): %d raw rows scanned, %d written (cursor kept; resumable)",
				jobID, batch, progress.scanned, progress.written)
			return finish(NormalizeBackfillStatusCancelled, nil)
		}

		r := ranges[idx]
		if checked != idx {
			// Once per relation, before its first page: a relation the page
			// cannot be served from by index would be seq-scanned once per
			// batch. Stop instead — failed, resumable — with the cursor
			// parked at the start of this relation (or kept where it is
			// inside it), so that once the index exists `resume` continues
			// right here rather than a new job re-reading the whole window.
			ok, err := backfillLeafIndexProbe(d, r.table, job.DeviceID != nil)
			if err != nil {
				return finish(NormalizeBackfillStatusFailed, err)
			}
			checked = idx
			if !ok {
				want := "(timestamp)"
				if job.DeviceID != nil {
					want = "(timestamp) or (device_id, timestamp)"
				}
				log.Printf("normalize-backfill: WARNING: job %d: %s has no usable %s index; paging it would seq-scan it once per batch. Stopping (failed, resumable) with the cursor parked at it", jobID, r.table, want)
				if err := d.updateBackfillJob(ctx, jobID, runner, map[string]interface{}{
					"current_partition": r.table, "cursor_ts": cursorTs, "cursor_id": cursorID,
				}); err != nil {
					if errors.Is(err, errBackfillJobLost) {
						flushObserved(d, observed)
						return fmt.Errorf("backfill job %d: %w", jobID, err)
					}
					return finish(NormalizeBackfillStatusFailed, err)
				}
				return finish(NormalizeBackfillStatusFailed, fmt.Errorf(
					"%s has no usable %s index (paging it would seq-scan it once per batch); create the index on it, then resume this job — it continues from %s",
					r.table, want, r.table))
			}
		}
		started := time.Now()
		rows, existing, err := d.fetchBackfillBatch(ctx, r, cursorTs, cursorID, job.Until, job.DeviceID, normalizeBackfillBatchSize)
		if err != nil {
			if ctx.Err() != nil {
				flushObserved(d, observed)
				return d.backfillInterrupted(jobID, runner, ctx.Err())
			}
			return finish(NormalizeBackfillStatusFailed, err)
		}
		if len(rows) == 0 {
			// This relation is done: move to the next one.
			if err := nextRange(); err != nil {
				if errors.Is(err, errBackfillJobLost) {
					flushObserved(d, observed)
					return fmt.Errorf("backfill job %d: %w", jobID, err)
				}
				return finish(NormalizeBackfillStatusFailed, err)
			}
			continue
		}

		floor := d.netEventFloor(time.Now())
		var (
			nets  = make([]models.NetEvent, 0, len(rows))
			secs  []models.SecEvent
			rules []models.FwRule
			// This batch's device_field_observed counts: folded into the
			// run's accumulator only once the batch has committed, so a
			// rolled-back batch (counted again when it is redone) adds nothing.
			batchObs = map[observedKey]*observedAcc{}
		)
		for i := range rows {
			msg := &rows[i]
			progress.scanned++
			if _, dup := existing[int64(msg.ID)]; dup {
				progress.skipped++
				continue
			}
			if msg.Timestamp.Before(floor) {
				// Its day's leaf is gone (a job running across the retention
				// boundary); the row would land in net_events_default.
				progress.skipped++
				if !floorWarned {
					floorWarned = true
					log.Printf("normalize-backfill: job %d: skipping rows older than the net_events retention floor %s (their day leaf has been dropped)", jobID, floor.Format("2006-01-02"))
				}
				continue
			}
			vendor, ok := vendors[msg.DeviceID]
			if !ok {
				vendor = "generic"
			}
			ev, out := normalizeStored(vendor, msg)
			if out.Kind != normalize.OutcomeOK {
				progress.unparsed++
				continue
			}
			rawID := int64(msg.ID)
			if ev.Class == normalize.ClassNetwork {
				nets = append(nets, NetEventFromEvent(&ev, rawID, msg.Timestamp))
			} else {
				secs = append(secs, SecEventFromEvent(&ev, rawID, msg.Timestamp))
			}
			progress.written++
			if msg.DeviceID == 0 {
				continue
			}
			if p := ev.Present(); p != 0 {
				k := observedKey{dev: msg.DeviceID, class: ev.Class}
				a := batchObs[k]
				if a == nil {
					a = &observedAcc{}
					batchObs[k] = a
				}
				for fi := range normalize.ObservedFields {
					if p.Has(fi) {
						a.counts[fi]++
					}
				}
				if ev.Ts.After(a.last) {
					a.last = ev.Ts
				}
			}
			if fr, ok := FwRuleFromEvent(&ev, ev.Ts); ok {
				rules = append(rules, fr)
			}
		}
		last := rows[len(rows)-1]
		progress.partition, progress.cursorTs, progress.cursorID = r.table, last.Timestamp, int64(last.ID)
		if err := d.commitBackfillBatch(ctx, jobID, runner, batch+1, nets, secs, rules, progress); err != nil {
			if ctx.Err() != nil {
				flushObserved(d, observed)
				return d.backfillInterrupted(jobID, runner, ctx.Err())
			}
			if errors.Is(err, errBackfillJobLost) {
				flushObserved(d, observed)
				return fmt.Errorf("backfill job %d: %w", jobID, err)
			}
			return finish(NormalizeBackfillStatusFailed, err)
		}
		cursorTs, cursorID = last.Timestamp, int64(last.ID)
		batch++
		mergeObserved(observed, batchObs)

		// device_field_observed after the commit: an additive count, flushed
		// every few batches; a lost stretch only leaves the capability matrix
		// a lower bound (fw_rules, which a later batch could not restore, is
		// written inside the batch transaction).
		if batch%normalizeBackfillObservedFlushEvery == 0 {
			flushObserved(d, observed)
		}
		if normalizeBackfillBatchHook != nil {
			if err := normalizeBackfillBatchHook(job, batch); err != nil {
				return finish(NormalizeBackfillStatusFailed, err)
			}
		}
		if wait := backfillPace(len(rows), rate, time.Since(started)); wait > 0 {
			d.backfillSleep(ctx, jobID, wait)
		}
	}
	log.Printf("normalize-backfill: job %d done: %d raw rows scanned, %d written, %d skipped (already normalized), %d unparsed, %d batch(es)",
		jobID, progress.scanned, progress.written, progress.skipped, progress.unparsed, batch)
	return finish(NormalizeBackfillStatusDone, nil)
}

// backfillSleep waits up to `wait` (the pace sleep, or a paused job's step)
// but wakes early on shutdown and, re-reading the job's status every
// normalizeBackfillCancelPoll, as soon as it is no longer running / paused —
// a cancel, or the job lost — so the caller's checkpoint acts on it within
// about a second whatever the rate. A failed read just keeps waiting.
func (d *Database) backfillSleep(ctx context.Context, jobID uint, wait time.Duration) {
	deadline := time.Now().Add(wait)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return
		}
		step := normalizeBackfillCancelPoll
		if left < step {
			step = left
		}
		t := time.NewTimer(step)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		var status string
		if err := d.db.WithContext(ctx).Model(&models.NormalizeBackfillJob{}).Where("id = ?", jobID).Pluck("status", &status).Error; err == nil &&
			status != NormalizeBackfillStatusRunning && status != NormalizeBackfillStatusPaused {
			return
		}
	}
}

// backfillCheckpoint is the between-batches control point: a cancelled ctx
// (shutdown) flips the job back to pending and returns the ctx error; a job
// that is no longer running / paused under this worker reports
// errBackfillJobLost; `cancelling` reports stop; outside the run window the
// job is paused — heartbeating, re-checking the window and its status every
// normalizeBackfillPauseStep — until the window opens or it is cancelled.
func (d *Database) backfillCheckpoint(ctx context.Context, jobID uint, runner string, window runWindow, hasWindow bool) (stop bool, err error) {
	paused := false
	for {
		if ctx.Err() != nil {
			return false, d.backfillInterrupted(jobID, runner, ctx.Err())
		}
		job, err := d.GetNormalizeBackfillJob(jobID)
		if err != nil {
			return false, fmt.Errorf("re-read job: %w", err)
		}
		if job.RunnerID != runner {
			return false, errBackfillJobLost
		}
		switch job.Status {
		case NormalizeBackfillStatusCancelling:
			return true, nil
		case NormalizeBackfillStatusRunning, NormalizeBackfillStatusPaused:
		default:
			return false, errBackfillJobLost
		}
		inWindow := !hasWindow || window.contains(normalizeBackfillNow())
		if inWindow {
			if paused || job.Status == NormalizeBackfillStatusPaused {
				res := d.db.WithContext(ctx).Model(&models.NormalizeBackfillJob{}).
					Where("id = ? AND runner_id = ? AND status = ?", jobID, runner, NormalizeBackfillStatusPaused).
					Updates(map[string]interface{}{"status": NormalizeBackfillStatusRunning, "updated_at": time.Now()})
				if res.Error != nil {
					return false, res.Error
				}
				if res.RowsAffected != 1 {
					continue // status moved under us (cancel): re-read
				}
				log.Printf("normalize-backfill: job %d: run window open, resuming", jobID)
			}
			return false, nil
		}
		if !paused {
			res := d.db.WithContext(ctx).Model(&models.NormalizeBackfillJob{}).
				Where("id = ? AND runner_id = ? AND status = ?", jobID, runner, NormalizeBackfillStatusRunning).
				Updates(map[string]interface{}{"status": NormalizeBackfillStatusPaused, "updated_at": time.Now()})
			if res.Error != nil {
				return false, res.Error
			}
			if res.RowsAffected != 1 && job.Status != NormalizeBackfillStatusPaused {
				continue // status moved under us: re-read
			}
			paused = true
			log.Printf("normalize-backfill: job %d: outside the run window %s, paused", jobID, job.Window)
		}
		d.backfillSleep(ctx, jobID, normalizeBackfillPauseStep) // wakes on a cancel
		if ctx.Err() != nil {
			return false, d.backfillInterrupted(jobID, runner, ctx.Err())
		}
		if err := d.touchBackfillJob(ctx, jobID, runner); err != nil && ctx.Err() == nil {
			log.Printf("normalize-backfill: job %d heartbeat while paused: %v", jobID, err)
		}
	}
}

// backfillInterrupted puts a live job back to pending after a shutdown so
// the next poller resumes it from the committed cursor. Fresh short context:
// the run's own is already cancelled.
func (d *Database) backfillInterrupted(jobID uint, runner string, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := d.db.WithContext(ctx).Model(&models.NormalizeBackfillJob{}).
		Where("id = ? AND runner_id = ? AND status IN (?)", jobID, runner, []string{NormalizeBackfillStatusRunning, NormalizeBackfillStatusPaused}).
		Updates(map[string]interface{}{"status": NormalizeBackfillStatusPending, "runner_id": "", "updated_at": time.Now(), "error": "interrupted by shutdown; resumes on the next poller start"})
	if res.Error != nil {
		log.Printf("normalize-backfill: job %d: could not requeue after shutdown (%v); the stale-heartbeat requeue will pick it up", jobID, res.Error)
	}
	return cause
}

// ── worker ────────────────────────────────────────────────────────────────────

// NormalizeBackfillWorker is the poller's job runner: Tick is called every
// few seconds; one Tick requeues stale jobs, claims the oldest pending job and
// runs it to its end (jobs run one at a time). Cross-process safety is the
// purge worker's: an in-process single-flight, the CAS claim on the row, and a
// dedicated advisory lock held for the run — NOT the shared poller work lock,
// which is non-blocking and would make every monitoring tick during a
// multi-hour backfill a skipped one (see flowSummaryLockKey).
type NormalizeBackfillWorker struct {
	db           *Database
	running      atomic.Bool
	probeFailing bool
}

// NewNormalizeBackfillWorker binds the worker to the poller's Database.
func NewNormalizeBackfillWorker(db *Database) *NormalizeBackfillWorker {
	return &NormalizeBackfillWorker{db: db}
}

// Tick runs at most one job. Returns at once when a run is in flight in this
// process, when another process holds the backfill lock, or when the queue is
// empty. Errors are logged, never returned.
func (w *NormalizeBackfillWorker) Tick(ctx context.Context) {
	if !w.running.CompareAndSwap(false, true) {
		return
	}
	defer w.running.Store(false)
	if ctx.Err() != nil {
		return
	}
	var live int64
	if err := w.db.db.Model(&models.NormalizeBackfillJob{}).Where("status IN (?)", normalizeBackfillActiveStatuses).Count(&live).Error; err != nil {
		if !w.probeFailing {
			log.Printf("normalize-backfill: queue probe failed (logged once until it recovers): %v", err)
			w.probeFailing = true
		}
		return
	}
	if w.probeFailing {
		log.Printf("normalize-backfill: queue probe recovered")
		w.probeFailing = false
	}
	if live == 0 {
		return
	}
	release, acquired, err := w.db.AcquireNormalizeBackfillLock()
	if err != nil {
		log.Printf("normalize-backfill: advisory lock probe failed: %v", err)
		return
	}
	if !acquired {
		return
	}
	defer release()

	if n, err := w.db.RequeueStaleNormalizeBackfillJobs(normalizeBackfillStaleAfter); err != nil {
		log.Printf("normalize-backfill: stale-job requeue failed: %v", err)
	} else if n > 0 {
		log.Printf("normalize-backfill: requeued %d job(s) whose worker heartbeat was lost", n)
	}
	runner := newBackfillRunnerID()
	job, err := w.db.ClaimNextNormalizeBackfillJob(runner)
	if err != nil {
		log.Printf("normalize-backfill: claim failed: %v", err)
		return
	}
	if job == nil {
		return
	}
	if err := w.db.RunNormalizeBackfill(ctx, job.ID, runner); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("normalize-backfill: job %d ended: %v", job.ID, err)
	}
}

// normalizeBackfillLockKey is the advisory-lock key the poller's backfill
// worker holds for one run. ASCII "FWNBKFIL" packed into an int64.
const normalizeBackfillLockKey int64 = 0x46574e424b46494c

// AcquireNormalizeBackfillLock is AcquireDevicePurgeLock on the backfill's own
// key: non-blocking, session-scoped, pinned connection; acquired=false with
// err=nil means another session holds it.
func (d *Database) AcquireNormalizeBackfillLock() (release func(), acquired bool, err error) {
	return d.acquireJobLock("normalize-backfill", normalizeBackfillLockKey)
}

// parsePartitionBound pulls the date after `marker` ("FROM ('" or "TO ('")
// out of a RANGE partition's bound expression; see parsePartitionUpperBound
// for the renderings accepted.
func parsePartitionBound(bound, marker string) (time.Time, bool) {
	i := strings.Index(bound, marker)
	if i < 0 {
		return time.Time{}, false
	}
	rest := bound[i+len(marker):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return time.Time{}, false
	}
	val := rest[:j]
	for _, layout := range []string{
		"2006-01-02",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05-07:00",
	} {
		if t, err := time.Parse(layout, val); err == nil {
			return t, true
		}
	}
	if len(val) >= 10 {
		if t, err := time.Parse("2006-01-02", val[:10]); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// SinceDaysArg parses the CLI / API "since" forms: a bare day count or "<n>d".
func SinceDaysArg(s string) (int, error) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "d"))
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > NormalizeBackfillMaxDays {
		return 0, fmt.Errorf("since must be 1..%d days (got %q)", NormalizeBackfillMaxDays, s)
	}
	return n, nil
}
