package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"

	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Archive restore to staging (archive plan PR 9). See models.ArchiveRestoreJob
// for the row and its lifecycle.
//
// A restore selects the archived objects that hold rows of the requested
// message (sample) days — by each object's message-day histogram, in the
// database manifest (sealed and unsealed months alike: every verified object)
// or, with FromBucket, in the bucket's sealed _MONTH.json files — and the
// poller's restore worker (internal/archive/worker/restore.go) downloads each
// one by its recorded version id, verifies it (stored bytes against
// sha256_object, decompressed bytes against sha256_content, row count, every
// id in its chunk's range), and only then loads its rows of those days (and
// device) into the job's own staging table, restore_<job>_<source table>:
// the source table's columns (LIKE, no defaults: nothing in it depends on the
// source's sequence), the ORIGINAL ids as primary key, indexes on (timestamp)
// and (device_id, timestamp). Never into syslog_messages / flow_samples /
// flow_if_counters (operator decision).
//
// Loading is in short batches: each batch's rows, the object's cursor (the id
// of the last line read) and the job's counters commit in ONE transaction,
// guarded on the job's owner token, so a crash resumes after the last
// committed line with neither a gap nor a duplicate (the primary key would
// refuse one anyway). Short transactions also keep a restore from holding an
// xid the archive's settle guard would wait on.
//
// The staging tables are outside everything else: retention, the archive gate
// and the partition maintenance name their tables, and the archive exports
// only syslog_messages / flow_samples / flow_if_counters, so a staging table
// is never trimmed, gated or archived. It is dropped by request (--drop-restore,
// DELETE /admin/api/archive/restores/:id) or by the worker once the job's
// ExpiresAt has passed — never while a backfill over it is active. The device
// purge does not reach into them either (they are operator-requested copies
// with a TTL); drop a restore to remove its rows.
//
// Syslog only: Renormalize queues a normalized-event backfill
// (normalize_backfill.go, SourceTable) over the staging table once it is
// loaded; flows are staged only (re-rolling them up would double-count
// against flow_rollups).

const (
	ArchiveRestoreDefaultRate    = 5000
	ArchiveRestoreMinRate        = 100
	ArchiveRestoreMaxRate        = 100000
	ArchiveRestoreDefaultTTLDays = 7
	ArchiveRestoreMaxTTLDays     = 90
	// ArchiveRestoreMaxDays bounds one job's span of days (a month of syslog
	// is ~100 M rows; split a longer restore).
	ArchiveRestoreMaxDays = 31
)

var (
	// archiveRestoreBatchSize is the rows per load transaction; a var so a
	// test can walk an object in several batches.
	archiveRestoreBatchSize = 5000
	// archiveRestoreStaleAfter: a running job whose heartbeat is older is
	// requeued (pending); archiveRestoreHeartbeat is the heartbeat cadence.
	archiveRestoreStaleAfter = 2 * time.Minute
	archiveRestoreHeartbeat  = 30 * time.Second
	// archiveRestoreBytesPerRow is what one staged row costs on the database
	// volume with its three indexes (plan §5: syslog ~1.3 KB, flows ~0.4 KB).
	archiveRestoreBytesPerRow = map[string]int64{
		export.TableSyslog:   1300,
		export.TableFlows:    400,
		export.TableCounters: 250,
	}
)

var (
	// ErrArchiveRestoreBusy: the job is pending, running or cancelling (cancel
	// it first), or already dropped.
	ErrArchiveRestoreBusy = errors.New("the restore is not finished (cancel it first) or its staging table is already dropped")
	// ErrArchiveRestoreInUse: a normalized-event backfill over the staging
	// table is still active.
	ErrArchiveRestoreInUse = errors.New("a normalized-event backfill over this restore's staging table is still active (cancel it first)")
	// ErrArchiveRestoreNothing: no archived object holds rows of those days.
	ErrArchiveRestoreNothing = errors.New("no verified archive object holds rows of those days")
	// errArchiveRestoreLost: the job is no longer this runner's.
	errArchiveRestoreLost = errors.New("restore job is no longer running under this worker")
)

// ErrArchiveRestoreLost reports whether err is the "job is no longer this
// runner's" verdict of a guarded write.
func ErrArchiveRestoreLost(err error) bool { return errors.Is(err, errArchiveRestoreLost) }

// archiveRestoreTerminal are the states whose staging table may be dropped.
var archiveRestoreDroppable = []string{models.ArchiveRestoreDone, models.ArchiveRestoreFailed, models.ArchiveRestoreCancelled, models.ArchiveRestoreLoaded}

// ArchiveRestoreTableOf is the source table of a stream ("" if unknown).
func ArchiveRestoreTableOf(stream string) string {
	for _, t := range []string{export.TableSyslog, export.TableFlows, export.TableCounters} {
		for _, s := range export.StreamsOf(t) {
			if s == stream {
				return t
			}
		}
	}
	return ""
}

// archiveRestoreTableRe is the only shape of relation name the restore
// creates, loads, hands to a backfill or drops.
var archiveRestoreTableRe = regexp.MustCompile(`^restore_[0-9]+_(syslog_messages|flow_samples|flow_if_counters)$`)

// IsArchiveRestoreTable reports whether name is a restore staging table name.
func IsArchiveRestoreTable(name string) bool { return archiveRestoreTableRe.MatchString(name) }

// ArchiveRestoreTableName is job id's staging table for source table.
func ArchiveRestoreTableName(id uint, table string) string {
	return fmt.Sprintf("restore_%d_%s", id, table)
}

// ParseArchiveRestoreDay parses a YYYY-MM-DD UTC day.
func ParseArchiveRestoreDay(s string) (time.Time, error) {
	t, err := time.Parse(time.DateOnly, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, fmt.Errorf("day %q: want YYYY-MM-DD", s)
	}
	return t.UTC(), nil
}

// ArchiveRestoreRequest is a restore as the API and the CLI ask for it.
type ArchiveRestoreRequest struct {
	Stream      string
	From, To    time.Time // UTC days, inclusive
	DeviceID    *uint
	FromBucket  bool
	Renormalize bool
	Replace     bool
	// Force queues past a refused disk precheck (the caller re-authenticated
	// and audits it); the worker then does not refuse for disk either.
	Force       bool
	Rate        int // rows/s; 0 = default
	TTLDays     int // 0 = default
	RequestedBy string
}

// ErrArchiveRestoreInvalid wraps every request validation error.
var ErrArchiveRestoreInvalid = errors.New("invalid restore request")

// ErrArchiveRestoreDisk: the rows to stage would take half the database
// volume's free space or more.
var ErrArchiveRestoreDisk = errors.New("not enough free space on the database volume for the staged rows")

// Validate checks the request and fills the defaults; every error wraps
// ErrArchiveRestoreInvalid.
func (r *ArchiveRestoreRequest) Validate() error {
	if err := r.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrArchiveRestoreInvalid, err)
	}
	return nil
}

func (r *ArchiveRestoreRequest) validate() error {
	if ArchiveRestoreTableOf(r.Stream) == "" {
		return fmt.Errorf("unknown stream %q (syslog, sflow, netflow or sflow-counters)", r.Stream)
	}
	r.From, r.To = utcDay(r.From), utcDay(r.To)
	switch {
	case r.From.IsZero() || r.To.IsZero():
		return errors.New("from and to are required (YYYY-MM-DD)")
	case r.To.Before(r.From):
		return errors.New("to is before from")
	case r.To.Sub(r.From) >= ArchiveRestoreMaxDays*24*time.Hour:
		return fmt.Errorf("at most %d days per restore", ArchiveRestoreMaxDays)
	case r.Renormalize && r.Stream != export.StreamSyslog:
		return errors.New("only syslog can be re-normalized; flows are restored to staging only (re-rolling them up would double-count)")
	case r.Replace && !r.Renormalize:
		return errors.New("replace goes with renormalize")
	case r.DeviceID != nil && *r.DeviceID == 0:
		return errors.New("device_id must be positive")
	}
	if r.Rate == 0 {
		r.Rate = ArchiveRestoreDefaultRate
	}
	if r.Rate < ArchiveRestoreMinRate || r.Rate > ArchiveRestoreMaxRate {
		return fmt.Errorf("rate must be %d-%d rows/s", ArchiveRestoreMinRate, ArchiveRestoreMaxRate)
	}
	if r.TTLDays == 0 {
		r.TTLDays = ArchiveRestoreDefaultTTLDays
	}
	if r.TTLDays < 1 || r.TTLDays > ArchiveRestoreMaxTTLDays {
		return fmt.Errorf("ttl must be 1-%d days", ArchiveRestoreMaxTTLDays)
	}
	return nil
}

// ArchiveRestoreDayRows is the rows of [from, to] (UTC days, inclusive) in a
// message-day histogram ({"YYYY-MM-DD": rows}).
func ArchiveRestoreDayRows(hist map[string]int64, from, to time.Time) int64 {
	lo, hi := from.UTC().Format(time.DateOnly), to.UTC().Format(time.DateOnly)
	var n int64
	for d, c := range hist {
		if d >= lo && d <= hi {
			n += c
		}
	}
	return n
}

// SelectArchiveRestoreObjects lists the verified objects of stream (of
// deviceID's syslog when set; flow and counter objects hold every device)
// with rows of [from, to] by their message-day histogram, oldest chunk first,
// and the rows of those days they hold.
func (d *Database) SelectArchiveRestoreObjects(ctx context.Context, stream string, from, to time.Time, deviceID *uint) ([]models.ArchiveRestoreObject, int64, error) {
	table := ArchiveRestoreTableOf(stream)
	if table == "" {
		return nil, 0, fmt.Errorf("unknown stream %q", stream)
	}
	end := utcDay(to).AddDate(0, 0, 1)
	var rows []struct {
		models.ArchiveObject
		Seq  int64
		IDLo int64
		IDHi int64
	}
	q := d.db.WithContext(ctx).Table("archive_objects AS o").
		Select("o.*, c.seq AS seq, c.id_lo AS id_lo, c.id_hi AS id_hi").
		Joins("JOIN archive_chunks AS c ON c.id = o.chunk_id").
		Where("c.table_name = ? AND o.stream = ? AND o.status = ? AND o.row_count > 0 AND o.min_ts < ? AND o.max_ts >= ?",
			table, stream, models.ArchiveObjectVerified, end, utcDay(from))
	if deviceID != nil && stream == export.StreamSyslog {
		q = q.Where("o.device_id = ?", *deviceID)
	}
	if err := q.Order("c.seq, o.object_key").Scan(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("restore: select %s objects: %w", stream, err)
	}
	var out []models.ArchiveRestoreObject
	var total int64
	for _, r := range rows {
		hist := map[string]int64{}
		if r.MsgDayHistogram != nil {
			if err := json.Unmarshal([]byte(*r.MsgDayHistogram), &hist); err != nil {
				return nil, 0, fmt.Errorf("restore: histogram of %s: %w", r.ObjectKey, err)
			}
		}
		n := ArchiveRestoreDayRows(hist, from, to)
		if n == 0 {
			continue
		}
		total += n
		out = append(out, models.ArchiveRestoreObject{
			ChunkSeq: r.Seq, ChunkIDLo: r.IDLo, ChunkIDHi: r.IDHi, ObjectKey: r.ObjectKey, VersionID: r.VersionID,
			SchemaVersion: r.SchemaVersion, Compression: r.Compression, RowCount: r.RowCount, RawBytes: r.RawBytes,
			ObjectBytes: r.ObjectBytes, Sha256Content: r.Sha256Content, Sha256Object: r.Sha256Object, ETag: r.ETag,
			PartCount: r.PartCount, MinID: r.MinID, MaxID: r.MaxID, DayRows: n, Status: models.ArchiveRestoreObjectPending,
		})
	}
	return out, total, nil
}

// ArchiveRestoreCoverageNote says what a manifest restore of table's days up
// to `to` cannot cover: rows ingested after the archive's verified end are
// not in the bucket yet. "" when the verified run reaches past the day after
// `to` (a row of `to` is normally ingested by then).
func (d *Database) ArchiveRestoreCoverageNote(ctx context.Context, table string, to time.Time) (string, error) {
	p, err := d.ArchiveTableProgress(ctx, table)
	if err != nil {
		return "", err
	}
	if p.VerifiedThroughEnd != nil && !p.VerifiedThroughEnd.Before(utcDay(to).AddDate(0, 0, 2)) {
		return "", nil
	}
	through := "nothing yet"
	if p.VerifiedThroughEnd != nil {
		through = p.VerifiedThroughEnd.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("the archive of %s is verified through %s: rows of these days ingested later are not in it (they may still be in %s)", table, through, table), nil
}

// ArchiveRestoreEstimate is the disk precheck of a restore.
type ArchiveRestoreEstimate struct {
	Rows int64 `json:"rows"`
	// Bytes: the staged rows with their indexes plus, for a re-normalize,
	// the net_events / sec_events rows it may write (NormalizedBytes).
	Bytes           int64 `json:"bytes"`
	NormalizedBytes int64 `json:"normalized_bytes"`
	FreeBytes       int64 `json:"free_bytes"`
	// FreeKnown: a server_metrics sample of the last 15 minutes measured the
	// database volume. Without one the precheck refuses (Enough false).
	FreeKnown bool `json:"free_known"`
	// Enough: the free space is known and Bytes is under half of it.
	Enough bool `json:"enough"`
}

// EstimateArchiveRestore sizes rows staged rows of table (and, with
// renormalize, their normalized rows at the backfill's per-row cost) against
// the database volume's free space (the newest recent server_metrics sample,
// the backfill precheck's source). Unlike the backfill's precheck an unknown
// free space is not enough: a restore can stage tens of GB, and the staging
// directory's check refuses an unknown free space too.
func (d *Database) EstimateArchiveRestore(table string, rows int64, renormalize bool) ArchiveRestoreEstimate {
	est := ArchiveRestoreEstimate{Rows: rows, Bytes: rows * archiveRestoreBytesPerRow[table]}
	if renormalize {
		est.NormalizedBytes = rows * normalizeBackfillBytesPerRow
		est.Bytes += est.NormalizedBytes
	}
	est.FreeBytes, est.FreeKnown = d.recentDataDiskFree()
	est.Enough = est.FreeKnown && 2*est.Bytes < est.FreeBytes
	return est
}

// Refusal explains why est is not enough.
func (est ArchiveRestoreEstimate) Refusal() string {
	if !est.FreeKnown {
		return fmt.Sprintf("the database volume's free space is unknown (no server_metrics sample in the last 15 minutes) for ~%d MiB (%d rows); force it if you know there is room",
			est.Bytes>>20, est.Rows)
	}
	return fmt.Sprintf("%d rows (~%d MiB with what they are re-normalized into) need under half of the database volume's %d MiB free",
		est.Rows, est.Bytes>>20, est.FreeBytes>>20)
}

// ArchiveRestorePlan is a validated restore request with its selected
// objects (none yet for a FromBucket restore), the rows of the requested
// days they hold, the coverage note and the disk estimate.
type ArchiveRestorePlan struct {
	Request  ArchiveRestoreRequest
	Objects  []models.ArchiveRestoreObject
	Rows     int64
	Note     string
	Estimate ArchiveRestoreEstimate
}

// PlanArchiveRestore validates req, selects its objects from the database
// manifest (a FromBucket restore selects on the worker's first run) and runs
// the disk precheck. It writes nothing. Errors: ErrArchiveRestoreInvalid,
// ErrArchiveRestoreNothing, ErrArchiveRestoreDisk (the plan carries the
// estimate), or a database error.
func (d *Database) PlanArchiveRestore(ctx context.Context, req ArchiveRestoreRequest) (*ArchiveRestorePlan, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	p := &ArchiveRestorePlan{Request: req}
	table := ArchiveRestoreTableOf(req.Stream)
	if !req.FromBucket {
		var err error
		if p.Objects, p.Rows, err = d.SelectArchiveRestoreObjects(ctx, req.Stream, req.From, req.To, req.DeviceID); err != nil {
			return nil, err
		}
		if len(p.Objects) == 0 {
			return nil, ErrArchiveRestoreNothing
		}
		if p.Note, err = d.ArchiveRestoreCoverageNote(ctx, table, req.To); err != nil {
			return nil, err
		}
	}
	p.Estimate = d.EstimateArchiveRestore(table, p.Rows, req.Renormalize)
	// A bucket restore selects on the worker's first run, which prechecks
	// the disk then; here it has no rows to size.
	if !p.Estimate.Enough && !req.Force && !req.FromBucket {
		return p, fmt.Errorf("%w: %s", ErrArchiveRestoreDisk, p.Estimate.Refusal())
	}
	return p, nil
}

// QueueArchiveRestore is PlanArchiveRestore then CreateArchiveRestoreJob.
func (d *Database) QueueArchiveRestore(ctx context.Context, req ArchiveRestoreRequest, now time.Time) (*models.ArchiveRestoreJob, ArchiveRestoreEstimate, error) {
	p, err := d.PlanArchiveRestore(ctx, req)
	if err != nil {
		var est ArchiveRestoreEstimate
		if p != nil {
			est = p.Estimate
		}
		return nil, est, err
	}
	job, err := d.CreateArchiveRestoreJob(ctx, p, now)
	return job, p.Estimate, err
}

// CreateArchiveRestoreJob records a plan as a pending job with its staging
// table name and, for a manifest restore, its selected objects (one
// transaction). ExpiresAt is now + the TTL.
func (d *Database) CreateArchiveRestoreJob(ctx context.Context, p *ArchiveRestorePlan, now time.Time) (*models.ArchiveRestoreJob, error) {
	req := p.Request
	if err := req.Validate(); err != nil {
		return nil, err
	}
	table := ArchiveRestoreTableOf(req.Stream)
	job := &models.ArchiveRestoreJob{
		RequestedBy: req.RequestedBy, Stream: req.Stream, SourceTable: table,
		FromDay: req.From.Format(time.DateOnly), ToDay: req.To.Format(time.DateOnly), DeviceID: req.DeviceID,
		FromBucket: req.FromBucket, Renormalize: req.Renormalize, Replace: req.Replace, RateRowsPerSec: req.Rate, Force: req.Force,
		Status: models.ArchiveRestorePending, ExpiresAt: now.UTC().Add(time.Duration(req.TTLDays) * 24 * time.Hour), Note: p.Note,
	}
	objs := append([]models.ArchiveRestoreObject(nil), p.Objects...)
	if !req.FromBucket {
		if len(objs) == 0 {
			return nil, ErrArchiveRestoreNothing
		}
		at := now.UTC()
		job.SelectedAt, job.ObjectsTotal, job.RowsEstimate = &at, len(objs), p.Rows
	}
	err := d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(job).Error; err != nil {
			return err
		}
		job.StagingTable = ArchiveRestoreTableName(job.ID, table)
		if err := tx.Model(job).Update("staging_table", job.StagingTable).Error; err != nil {
			return err
		}
		return insertRestoreObjects(tx, job.ID, objs)
	})
	if err != nil {
		return nil, fmt.Errorf("restore: create job: %w", err)
	}
	return job, nil
}

func insertRestoreObjects(tx *gorm.DB, jobID uint, objs []models.ArchiveRestoreObject) error {
	for i := range objs {
		objs[i].ID, objs[i].JobID = 0, jobID
	}
	if len(objs) == 0 {
		return nil
	}
	return tx.CreateInBatches(objs, 200).Error
}

// GetArchiveRestoreJob returns one job (gorm.ErrRecordNotFound if absent).
func (d *Database) GetArchiveRestoreJob(id uint) (*models.ArchiveRestoreJob, error) {
	var job models.ArchiveRestoreJob
	if err := d.db.First(&job, id).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

// ListArchiveRestoreJobs returns the newest limit jobs, newest first.
func (d *Database) ListArchiveRestoreJobs(limit int) ([]models.ArchiveRestoreJob, error) {
	if limit <= 0 {
		limit = 50
	}
	var jobs []models.ArchiveRestoreJob
	err := d.db.Order("id DESC").Limit(limit).Find(&jobs).Error
	return jobs, err
}

// ArchiveRestoreObjects lists a job's objects in load order.
func (d *Database) ArchiveRestoreObjects(ctx context.Context, jobID uint) ([]models.ArchiveRestoreObject, error) {
	var objs []models.ArchiveRestoreObject
	err := d.db.WithContext(ctx).Where("job_id = ?", jobID).Order("chunk_seq, id").Find(&objs).Error
	return objs, err
}

// ArchiveRestoreTableBytes is the staging table's size with its indexes, or
// -1 when it does not exist (or off PostgreSQL).
func (d *Database) ArchiveRestoreTableBytes(ctx context.Context, name string) int64 {
	if !d.dialect.IsPostgres() || !IsArchiveRestoreTable(name) {
		return -1
	}
	var n *int64
	if err := d.db.WithContext(ctx).Raw("SELECT pg_total_relation_size(to_regclass(?))", name).Scan(&n).Error; err != nil || n == nil {
		return -1
	}
	return *n
}

// CancelArchiveRestoreJob: pending or loaded → cancelled at once; running →
// cancelling (the worker stops between batches, cursors kept). applied=false
// when the job is in another state.
func (d *Database) CancelArchiveRestoreJob(id uint) (status string, applied bool, err error) {
	now := time.Now()
	res := d.db.Model(&models.ArchiveRestoreJob{}).
		Where("id = ? AND status IN (?)", id, []string{models.ArchiveRestorePending, models.ArchiveRestoreLoaded}).
		Updates(map[string]interface{}{"status": models.ArchiveRestoreCancelled, "finished_at": now, "updated_at": now})
	if res.Error != nil {
		return "", false, res.Error
	}
	if res.RowsAffected == 1 {
		return models.ArchiveRestoreCancelled, true, nil
	}
	res = d.db.Model(&models.ArchiveRestoreJob{}).Where("id = ? AND status = ?", id, models.ArchiveRestoreRunning).
		Updates(map[string]interface{}{"status": models.ArchiveRestoreCancelling, "updated_at": now})
	if res.Error != nil {
		return "", false, res.Error
	}
	if res.RowsAffected == 1 {
		return models.ArchiveRestoreCancelling, true, nil
	}
	return "", false, nil
}

// ResumeArchiveRestoreJob puts a failed or cancelled job back to pending with
// its objects' cursors intact; applied=false in any other state.
func (d *Database) ResumeArchiveRestoreJob(id uint) (bool, error) {
	res := d.db.Model(&models.ArchiveRestoreJob{}).
		Where("id = ? AND status IN (?)", id, []string{models.ArchiveRestoreFailed, models.ArchiveRestoreCancelled}).
		Updates(map[string]interface{}{"status": models.ArchiveRestorePending, "runner_id": "", "error": "", "finished_at": nil, "updated_at": time.Now()})
	return res.RowsAffected == 1, res.Error
}

// DropArchiveRestore drops a finished job's staging table and marks the job
// dropped, in one transaction: refused (ErrArchiveRestoreBusy) unless the job
// is done / failed / cancelled / loaded, and (ErrArchiveRestoreInUse) while a
// normalized-event backfill over the table is active.
func (d *Database) DropArchiveRestore(ctx context.Context, id uint, now time.Time) (*models.ArchiveRestoreJob, error) {
	var job models.ArchiveRestoreJob
	err := d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// The job row's lock serializes this with RetryLoadedArchiveRestores,
		// which queues a backfill over the table under the same lock: the
		// backfill count below cannot miss one queued concurrently.
		if err := lockArchiveRestoreJob(tx, id, &job); err != nil {
			return err
		}
		if !IsArchiveRestoreTable(job.StagingTable) {
			return fmt.Errorf("restore %d: refusing staging table name %q", id, job.StagingTable)
		}
		if !slices.Contains(archiveRestoreDroppable, job.Status) {
			return ErrArchiveRestoreBusy
		}
		var live int64
		if err := tx.Model(&models.NormalizeBackfillJob{}).Where("source_table = ? AND status IN (?)", job.StagingTable, normalizeBackfillActiveStatuses).
			Count(&live).Error; err != nil {
			return err
		}
		if live > 0 {
			return ErrArchiveRestoreInUse
		}
		res := tx.Model(&models.ArchiveRestoreJob{}).Where("id = ? AND status IN (?)", id, archiveRestoreDroppable).
			Updates(map[string]interface{}{"status": models.ArchiveRestoreDropped, "dropped_at": now, "updated_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrArchiveRestoreBusy
		}
		// The name matched archiveRestoreTableRe above: safe to splice.
		return tx.Exec("DROP TABLE IF EXISTS " + job.StagingTable).Error
	})
	if err != nil {
		return nil, err
	}
	job.Status = models.ArchiveRestoreDropped
	job.DroppedAt = &now
	return &job, nil
}

// lockArchiveRestoreJob reads job id into job holding its row lock (SELECT
// ... FOR UPDATE on PostgreSQL; SQLite has one writer) until tx ends.
func lockArchiveRestoreJob(tx *gorm.DB, id uint, job *models.ArchiveRestoreJob) error {
	q := tx
	if tx.Dialector.Name() == "postgres" {
		q = tx.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return q.First(job, id).Error
}

// ExpiredArchiveRestoreJobs lists the jobs whose staging table is due to be
// dropped at now: done, failed or cancelled, past ExpiresAt. A loaded job is
// not: its re-normalize has not been queued yet (it is dropped once that
// backfill has run and the TTL has passed).
func (d *Database) ExpiredArchiveRestoreJobs(ctx context.Context, now time.Time) ([]models.ArchiveRestoreJob, error) {
	var jobs []models.ArchiveRestoreJob
	err := d.db.WithContext(ctx).Where("status IN (?) AND expires_at < ?",
		[]string{models.ArchiveRestoreDone, models.ArchiveRestoreFailed, models.ArchiveRestoreCancelled}, now).Order("id").Find(&jobs).Error
	return jobs, err
}

// ── worker side ───────────────────────────────────────────────────────────────

// archiveRestoreLockKey is the advisory-lock key the poller's restore worker
// holds for one tick. ASCII "FWRESTOR" packed into an int64.
const archiveRestoreLockKey int64 = 0x4657524553544f52

// AcquireArchiveRestoreLock is the restore worker's own non-blocking,
// session-scoped lock (never the shared poller work lock).
func (d *Database) AcquireArchiveRestoreLock() (release func(), acquired bool, err error) {
	return d.acquireJobLock("archive-restore", archiveRestoreLockKey)
}

// RequeueStaleArchiveRestoreJobs puts a running job whose heartbeat is older
// than staleAfter back to pending (its objects' cursors are the checkpoint)
// and finishes a stale cancelling job as cancelled.
func (d *Database) RequeueStaleArchiveRestoreJobs(ctx context.Context) (int64, error) {
	now := time.Now()
	cutoff := now.Add(-archiveRestoreStaleAfter)
	res := d.db.WithContext(ctx).Model(&models.ArchiveRestoreJob{}).Where("status = ? AND updated_at < ?", models.ArchiveRestoreRunning, cutoff).
		Updates(map[string]interface{}{"status": models.ArchiveRestorePending, "runner_id": "", "updated_at": now, "error": "requeued: worker heartbeat lost"})
	if res.Error != nil {
		return 0, res.Error
	}
	n := res.RowsAffected
	err := d.db.WithContext(ctx).Model(&models.ArchiveRestoreJob{}).Where("status = ? AND updated_at < ?", models.ArchiveRestoreCancelling, cutoff).
		Updates(map[string]interface{}{"status": models.ArchiveRestoreCancelled, "finished_at": now, "updated_at": now,
			"error": "cancelled: worker heartbeat lost while cancelling"}).Error
	return n, err
}

// ClaimNextArchiveRestoreJob claims the oldest pending job for runner
// (compare-and-set pending → running), or returns nil.
func (d *Database) ClaimNextArchiveRestoreJob(ctx context.Context, runner string) (*models.ArchiveRestoreJob, error) {
	if runner == "" {
		return nil, errors.New("restore claim: empty runner id")
	}
	for {
		var jobs []models.ArchiveRestoreJob
		if err := d.db.WithContext(ctx).Where("status = ?", models.ArchiveRestorePending).Order("id").Limit(1).Find(&jobs).Error; err != nil {
			return nil, err
		}
		if len(jobs) == 0 {
			return nil, nil
		}
		now := time.Now()
		cols := map[string]interface{}{"status": models.ArchiveRestoreRunning, "runner_id": runner, "updated_at": now}
		if jobs[0].StartedAt == nil {
			cols["started_at"] = now
		}
		res := d.db.WithContext(ctx).Model(&models.ArchiveRestoreJob{}).Where("id = ? AND status = ?", jobs[0].ID, models.ArchiveRestorePending).Updates(cols)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected == 1 {
			return d.GetArchiveRestoreJob(jobs[0].ID)
		}
	}
}

// UpdateArchiveRestoreJob writes cols on the job while it is runner's and
// running or cancelling.
func (d *Database) UpdateArchiveRestoreJob(ctx context.Context, id uint, runner string, cols map[string]interface{}) error {
	if _, ok := cols["updated_at"]; !ok {
		cols["updated_at"] = time.Now()
	}
	res := d.db.WithContext(ctx).Model(&models.ArchiveRestoreJob{}).
		Where("id = ? AND runner_id = ? AND status IN (?)", id, runner, []string{models.ArchiveRestoreRunning, models.ArchiveRestoreCancelling}).Updates(cols)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return errArchiveRestoreLost
	}
	return nil
}

// ArchiveRestoreHeartbeat is the restore worker's heartbeat cadence.
func ArchiveRestoreHeartbeat() time.Duration { return archiveRestoreHeartbeat }

// TouchArchiveRestoreJob is the heartbeat (updated_at only, while runner's).
func (d *Database) TouchArchiveRestoreJob(ctx context.Context, id uint, runner string) error {
	return d.UpdateArchiveRestoreJob(ctx, id, runner, map[string]interface{}{})
}

// ArchiveRestoreCheckpoint re-reads the job between batches: stop=true when
// a cancel was requested; errArchiveRestoreLost when it is no longer runner's.
func (d *Database) ArchiveRestoreCheckpoint(ctx context.Context, id uint, runner string) (stop bool, err error) {
	job, err := d.GetArchiveRestoreJob(id)
	if err != nil {
		return false, err
	}
	if job.RunnerID != runner {
		return false, errArchiveRestoreLost
	}
	switch job.Status {
	case models.ArchiveRestoreCancelling:
		return true, nil
	case models.ArchiveRestoreRunning:
		return false, nil
	}
	return false, errArchiveRestoreLost
}

// FinishArchiveRestoreJob ends a run in status (failed, cancelled; done and
// loaded go through CompleteArchiveRestoreJob) with cause as the error.
func (d *Database) FinishArchiveRestoreJob(ctx context.Context, id uint, runner, status string, cause error) error {
	msg := ""
	if cause != nil {
		msg = shortError(cause, 1000)
	}
	now := time.Now()
	return d.UpdateArchiveRestoreJob(context.WithoutCancel(ctx), id, runner, map[string]interface{}{
		"status": status, "error": msg, "finished_at": now, "updated_at": now,
	})
}

// InterruptArchiveRestoreJob puts a running job back to pending after a
// shutdown so the next poller resumes it.
func (d *Database) InterruptArchiveRestoreJob(id uint, runner string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d.db.WithContext(ctx).Model(&models.ArchiveRestoreJob{}).
		Where("id = ? AND runner_id = ? AND status = ?", id, runner, models.ArchiveRestoreRunning).
		Updates(map[string]interface{}{"status": models.ArchiveRestorePending, "runner_id": "", "updated_at": time.Now(),
			"error": "interrupted by shutdown; resumes on the next poller start"})
}

// RecordArchiveRestoreSelection stores the objects a bucket restore selected
// on its first run (guarded on runner).
func (d *Database) RecordArchiveRestoreSelection(ctx context.Context, job *models.ArchiveRestoreJob, runner string, objs []models.ArchiveRestoreObject, rows int64, note string) error {
	now := time.Now().UTC()
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("job_id = ?", job.ID).Delete(&models.ArchiveRestoreObject{}).Error; err != nil {
			return err
		}
		if err := insertRestoreObjects(tx, job.ID, objs); err != nil {
			return err
		}
		res := tx.Model(&models.ArchiveRestoreJob{}).Where("id = ? AND runner_id = ? AND status = ?", job.ID, runner, models.ArchiveRestoreRunning).
			Updates(map[string]interface{}{"selected_at": now, "objects_total": len(objs), "rows_estimate": rows, "note": note, "updated_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return errArchiveRestoreLost
		}
		job.SelectedAt, job.ObjectsTotal, job.RowsEstimate, job.Note = &now, len(objs), rows, note
		return nil
	})
}

// EnsureArchiveRestoreTable creates the job's staging table if it does not
// exist: the source table's columns (no defaults, so nothing depends on the
// source's id sequence), the original id as primary key, and the (timestamp)
// and (device_id, timestamp) indexes a backfill or a query pages by.
func (d *Database) EnsureArchiveRestoreTable(ctx context.Context, job *models.ArchiveRestoreJob) error {
	name := job.StagingTable
	if !IsArchiveRestoreTable(name) || !strings.HasSuffix(name, "_"+job.SourceTable) {
		return fmt.Errorf("restore %d: refusing staging table name %q for %s", job.ID, name, job.SourceTable)
	}
	src := job.SourceTable // one of the three, by the regexp above
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if tx.Migrator().HasTable(name) {
			return nil
		}
		if d.dialect.IsPostgres() {
			for _, stmt := range []string{
				fmt.Sprintf("CREATE TABLE %s (LIKE %s)", name, src),
				fmt.Sprintf("ALTER TABLE %s ADD PRIMARY KEY (id)", name),
			} {
				if err := tx.Exec(stmt).Error; err != nil {
					return fmt.Errorf("restore %d: %s: %w", job.ID, stmt, err)
				}
			}
		} else {
			// SQLite: the source's own CREATE statement under the new name
			// (CREATE TABLE AS would lose the declared types).
			var ddl string
			if err := tx.Raw("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", src).Scan(&ddl).Error; err != nil || ddl == "" {
				return fmt.Errorf("restore %d: the definition of %s: %v", job.ID, src, err)
			}
			i := strings.Index(ddl, src)
			if i < 0 {
				return fmt.Errorf("restore %d: unexpected definition of %s", job.ID, src)
			}
			if err := tx.Exec(ddl[:i] + name + ddl[i+len(src):]).Error; err != nil {
				return err
			}
		}
		for _, ix := range []struct{ suffix, cols string }{{"ts", "timestamp"}, {"dev_ts", "device_id, timestamp"}} {
			stmt := fmt.Sprintf("CREATE INDEX %s_%s ON %s (%s)", name, ix.suffix, name, ix.cols)
			if err := tx.Exec(stmt).Error; err != nil {
				return fmt.Errorf("restore %d: %s: %w", job.ID, stmt, err)
			}
		}
		return nil
	})
}

// PendingArchiveRestoreObjects lists the job's objects not yet loaded, in
// load order.
func (d *Database) PendingArchiveRestoreObjects(ctx context.Context, jobID uint) ([]models.ArchiveRestoreObject, error) {
	var objs []models.ArchiveRestoreObject
	err := d.db.WithContext(ctx).Where("job_id = ? AND status = ?", jobID, models.ArchiveRestoreObjectPending).Order("chunk_seq, id").Find(&objs).Error
	return objs, err
}

// ArchiveRestoreBatch is one load transaction of an object: the rows to
// stage (a []models.SyslogMessage, []models.FlowSample or
// []models.FlowInterfaceCounter of the job's table), the id of the last line
// read (the object's new cursor), the lines read since the previous batch,
// and whether the object is finished.
type ArchiveRestoreBatch struct {
	Rows     any
	CursorID int64
	Scanned  int64
	Done     bool
}

func restoreBatchLen(rows any) (int, error) {
	switch r := rows.(type) {
	case nil:
		return 0, nil
	case []models.SyslogMessage:
		return len(r), nil
	case []models.FlowSample:
		return len(r), nil
	case []models.FlowInterfaceCounter:
		return len(r), nil
	}
	return 0, fmt.Errorf("restore: rows of type %T", rows)
}

// archiveRestoreTxHook, when non-nil, runs inside a load transaction after
// the rows are written and before the progress update; an error rolls the
// batch back (tests: a crash mid-object).
var archiveRestoreTxHook func(obj *models.ArchiveRestoreObject, cursor int64) error

// LoadArchiveRestoreBatch commits one batch: the rows into the staging table,
// the object's cursor / rows / done, the job's counters — in one transaction,
// guarded on the job being runner's (errArchiveRestoreLost otherwise, nothing
// written).
func (d *Database) LoadArchiveRestoreBatch(ctx context.Context, job *models.ArchiveRestoreJob, runner string, obj *models.ArchiveRestoreObject, b ArchiveRestoreBatch) error {
	n, err := restoreBatchLen(b.Rows)
	if err != nil {
		return err
	}
	if !IsArchiveRestoreTable(job.StagingTable) {
		return fmt.Errorf("restore %d: refusing staging table name %q", job.ID, job.StagingTable)
	}
	now := time.Now()
	objStatus, doneObjs, doneBytes := models.ArchiveRestoreObjectPending, 0, int64(0)
	var doneAt *time.Time
	if b.Done {
		objStatus, doneObjs, doneBytes, doneAt = models.ArchiveRestoreObjectDone, 1, obj.ObjectBytes, &now
	}
	if d.pgxPool == nil {
		return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if n > 0 {
				if err := tx.Table(job.StagingTable).CreateInBatches(b.Rows, 100).Error; err != nil {
					return fmt.Errorf("stage %d rows: %w", n, err)
				}
			}
			if archiveRestoreTxHook != nil {
				if err := archiveRestoreTxHook(obj, b.CursorID); err != nil {
					return err
				}
			}
			if err := tx.Model(&models.ArchiveRestoreObject{}).Where("id = ?", obj.ID).Updates(map[string]interface{}{
				"cursor_id": b.CursorID, "rows_loaded": gorm.Expr("rows_loaded + ?", n), "status": objStatus, "done_at": doneAt,
			}).Error; err != nil {
				return err
			}
			res := tx.Model(&models.ArchiveRestoreJob{}).
				Where("id = ? AND runner_id = ? AND status IN (?)", job.ID, runner, []string{models.ArchiveRestoreRunning, models.ArchiveRestoreCancelling}).
				Updates(map[string]interface{}{
					"rows_loaded": gorm.Expr("rows_loaded + ?", n), "rows_scanned": gorm.Expr("rows_scanned + ?", b.Scanned),
					"objects_done": gorm.Expr("objects_done + ?", doneObjs), "bytes_downloaded": gorm.Expr("bytes_downloaded + ?", doneBytes),
					"updated_at": now,
				})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return errArchiveRestoreLost
			}
			return nil
		})
	}
	tx, err := d.pgxPool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin restore batch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '120s'"); err != nil {
		return err
	}
	if n > 0 {
		cols, rows := restoreCopyRows(b.Rows)
		got, err := tx.CopyFrom(ctx, pgx.Identifier{job.StagingTable}, cols, pgx.CopyFromRows(rows))
		if err != nil {
			return fmt.Errorf("COPY %d rows into %s: %w", n, job.StagingTable, err)
		}
		if int(got) != n {
			return fmt.Errorf("COPY into %s short write: %d of %d", job.StagingTable, got, n)
		}
	}
	if archiveRestoreTxHook != nil {
		if err := archiveRestoreTxHook(obj, b.CursorID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE archive_restore_objects SET cursor_id = $1, rows_loaded = rows_loaded + $2, status = $3, done_at = $4 WHERE id = $5`,
		b.CursorID, n, objStatus, doneAt, int64(obj.ID)); err != nil {
		return fmt.Errorf("record object progress: %w", err)
	}
	tag, err := tx.Exec(ctx, `UPDATE archive_restore_jobs SET rows_loaded = rows_loaded + $1, rows_scanned = rows_scanned + $2,
		objects_done = objects_done + $3, bytes_downloaded = bytes_downloaded + $4, updated_at = $5
		WHERE id = $6 AND runner_id = $7 AND status IN ($8, $9)`,
		n, b.Scanned, doneObjs, doneBytes, now, int64(job.ID), runner, models.ArchiveRestoreRunning, models.ArchiveRestoreCancelling)
	if err != nil {
		return fmt.Errorf("record restore progress: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errArchiveRestoreLost
	}
	return tx.Commit(ctx)
}

// restoreCopyRows is the COPY column list and rows of a batch: every
// archived column, the original id first.
func restoreCopyRows(rows any) ([]string, [][]any) {
	switch r := rows.(type) {
	case []models.SyslogMessage:
		out := make([][]any, len(r))
		for i := range r {
			m := &r[i]
			out[i] = []any{int64(m.ID), m.Timestamp, m.DeviceID, m.ProbeID, m.Hostname, m.AppName, m.ProcessID, m.MessageID,
				m.StructuredData, m.Message, m.Priority, m.Facility, m.Severity, m.SourceIP, m.CreatedAt, m.StoredFormat}
		}
		return []string{"id", "timestamp", "device_id", "probe_id", "hostname", "app_name", "process_id", "message_id",
			"structured_data", "message", "priority", "facility", "severity", "source_ip", "created_at", "format"}, out
	case []models.FlowSample:
		out := make([][]any, len(r))
		for i := range r {
			s := &r[i]
			out[i] = []any{int64(s.ID), s.Timestamp, s.DeviceID, s.ProbeID, s.SamplerAddress, s.SequenceNumber, s.SamplingRate,
				s.SrcAddr, s.DstAddr, s.SrcPort, s.DstPort, s.Protocol, s.Bytes, s.Packets, s.InputIfIndex, s.OutputIfIndex,
				s.TCPFlags, s.Drops, s.AppCategory, s.Direction, s.ServicePort, s.ClassRev, s.ScopeLocal, s.SrcCountry, s.DstCountry,
				s.SrcASN, s.DstASN, s.SrcASNOrg, s.DstASNOrg, s.ThreatFlag, s.ASPath, s.NextHop, s.FlowSource, s.FlowStart, s.FlowEnd,
				s.FirewallEvent, s.FlowEndReason, s.PostNATSrcAddr, s.PostNATDstAddr, s.PostNATSrcPort, s.PostNATDstPort,
				s.ICMPTypeCode, s.TOS, s.SrcVLAN, s.DstVLAN, s.AppName, s.CreatedAt}
		}
		return append([]string{"id"}, flowSamplesCopyColumns...), out
	case []models.FlowInterfaceCounter:
		out := make([][]any, len(r))
		for i := range r {
			c := &r[i]
			out[i] = []any{int64(c.ID), c.Timestamp, c.DeviceID, c.ProbeID, c.SamplerAddress, c.IfIndex, c.IfType, c.IfSpeed,
				c.IfDirection, c.IfStatus, c.InOctets, c.InErrors, c.InDiscards, c.OutOctets, c.OutErrors, c.OutDiscards, c.CreatedAt}
		}
		return []string{"id", "timestamp", "device_id", "probe_id", "sampler_address", "if_index", "if_type", "if_speed",
			"if_direction", "if_status", "in_octets", "in_errors", "in_discards", "out_octets", "out_errors", "out_discards", "created_at"}, out
	}
	return nil, nil
}

// CompleteArchiveRestoreJob ends a run whose objects are all loaded: done —
// or, for a Renormalize job, done with the normalized-event backfill over
// the staging table queued, or loaded when another backfill is active (the
// worker queues it on a later tick, RetryLoadedArchiveRestores).
func (d *Database) CompleteArchiveRestoreJob(ctx context.Context, job *models.ArchiveRestoreJob, runner string) (status string, err error) {
	err = d.db.WithContext(context.WithoutCancel(ctx)).Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		cols := map[string]interface{}{"status": models.ArchiveRestoreDone, "error": "", "finished_at": now, "updated_at": now}
		if job.Renormalize {
			id, err := enqueueRestoreBackfill(tx, job)
			if err != nil {
				return err
			}
			if id == nil {
				cols["status"], cols["runner_id"] = models.ArchiveRestoreLoaded, ""
				delete(cols, "finished_at")
			} else {
				cols["backfill_job_id"] = *id
			}
		}
		res := tx.Model(&models.ArchiveRestoreJob{}).
			Where("id = ? AND runner_id = ? AND status IN (?)", job.ID, runner, []string{models.ArchiveRestoreRunning, models.ArchiveRestoreCancelling}).Updates(cols)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return errArchiveRestoreLost
		}
		status = cols["status"].(string)
		return nil
	})
	return status, err
}

// RetryLoadedArchiveRestores queues the backfill of every loaded job whose
// turn has come (no other backfill active); returns how many were queued.
func (d *Database) RetryLoadedArchiveRestores(ctx context.Context) (int, error) {
	var jobs []models.ArchiveRestoreJob
	if err := d.db.WithContext(ctx).Where("status = ?", models.ArchiveRestoreLoaded).Order("id").Find(&jobs).Error; err != nil {
		return 0, err
	}
	n := 0
	for i := range jobs {
		job := &jobs[i]
		queued, busy := false, false
		err := d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Under the job row's lock (see DropArchiveRestore), still loaded.
			if err := lockArchiveRestoreJob(tx, job.ID, job); err != nil {
				return err
			}
			if job.Status != models.ArchiveRestoreLoaded {
				return errArchiveRestoreLost
			}
			id, err := enqueueRestoreBackfill(tx, job)
			if err != nil {
				return err
			}
			if id == nil {
				busy = true
				return nil
			}
			if archiveRestoreRetryHook != nil {
				archiveRestoreRetryHook(job)
			}
			now := time.Now()
			res := tx.Model(&models.ArchiveRestoreJob{}).Where("id = ? AND status = ?", job.ID, models.ArchiveRestoreLoaded).
				Updates(map[string]interface{}{"status": models.ArchiveRestoreDone, "backfill_job_id": *id, "finished_at": now, "updated_at": now})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return errArchiveRestoreLost // cancelled or dropped meanwhile: roll the backfill back
			}
			queued = true
			return nil
		})
		if err != nil && !errors.Is(err, errArchiveRestoreLost) {
			return n, err
		}
		if queued {
			n++
		}
		if busy {
			break // another backfill is active: the later loaded jobs wait too
		}
	}
	return n, nil
}

// archiveRestoreRetryHook, when non-nil, runs inside the queueing
// transaction of a loaded job after its backfill row is inserted (tests: a
// concurrent drop).
var archiveRestoreRetryHook func(job *models.ArchiveRestoreJob)

// enqueueRestoreBackfill queues the normalized-event backfill over job's
// staging table on tx: [FromDay, ToDay + 1 day), its device, replace mode.
// Returns nil (no error) when another backfill is active (one at a time).
func enqueueRestoreBackfill(tx *gorm.DB, job *models.ArchiveRestoreJob) (*uint, error) {
	var live int64
	if err := tx.Model(&models.NormalizeBackfillJob{}).Where("status IN (?)", normalizeBackfillActiveStatuses).Count(&live).Error; err != nil {
		return nil, err
	}
	if live > 0 {
		return nil, nil
	}
	from, err := ParseArchiveRestoreDay(job.FromDay)
	if err != nil {
		return nil, err
	}
	to, err := ParseArchiveRestoreDay(job.ToDay)
	if err != nil {
		return nil, err
	}
	id := job.ID
	bf := models.NormalizeBackfillJob{
		RequestedBy: fmt.Sprintf("archive restore %d (%s)", job.ID, job.RequestedBy), Status: NormalizeBackfillStatusPending,
		Since: from, Until: to.AddDate(0, 0, 1), DeviceID: job.DeviceID, RateRowsPerSec: NormalizeBackfillDefaultRate,
		SourceTable: job.StagingTable, RestoreJobID: &id, Replace: job.Replace,
	}
	if err := tx.Create(&bf).Error; err != nil {
		return nil, fmt.Errorf("queue the backfill over %s: %w", job.StagingTable, err)
	}
	return &bf.ID, nil
}

// ArchiveRestoreStatusCounts counts the restore jobs by status.
func (d *Database) ArchiveRestoreStatusCounts(ctx context.Context) (map[string]int64, error) {
	var rows []struct {
		Status string
		N      int64
	}
	if err := d.db.WithContext(ctx).Model(&models.ArchiveRestoreJob{}).Select("status, count(*) AS n").Group("status").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range rows {
		out[r.Status] = r.N
	}
	return out, nil
}

// ArchiveRestoreBatchSize is the lines per load transaction.
func ArchiveRestoreBatchSize() int { return archiveRestoreBatchSize }

// ArchiveRestoreIDConflict looks for a sign that the staged syslog rows'
// original ids are taken by OTHER rows in syslog_messages — a database
// rebuilt since the archive was written (a --from-bucket restore), whose id
// sequence restarted. Re-normalizing then would key net_events / sec_events
// rows by ids the live rows also use (the dedup probe would skip, and replace
// mode delete, the live rows' normalized rows). It reads the first live row
// with an id in the staged range (one primary-key descent per leaf) and the
// staged row of that id. It is a conflict when the two differ (received,
// device or message time), or when no row is staged with that id although
// the live row is of a day (and device) the restore covers. "" when none is
// seen. A heuristic, not a proof: it samples the range's first live row.
func (d *Database) ArchiveRestoreIDConflict(ctx context.Context, job *models.ArchiveRestoreJob) (string, error) {
	if job.SourceTable != export.TableSyslog || !IsArchiveRestoreTable(job.StagingTable) {
		return "", nil
	}
	var bounds struct{ Lo, Hi *int64 }
	if err := d.db.WithContext(ctx).Table(job.StagingTable).Select("min(id) AS lo, max(id) AS hi").Scan(&bounds).Error; err != nil {
		return "", err
	}
	if bounds.Lo == nil {
		return "", nil
	}
	var live []models.SyslogMessage
	if err := d.db.WithContext(ctx).Table(export.TableSyslog).Where("id >= ? AND id <= ?", *bounds.Lo, *bounds.Hi).Order("id").Limit(1).Find(&live).Error; err != nil {
		return "", err
	}
	if len(live) == 0 {
		return "", nil
	}
	var staged []models.SyslogMessage
	if err := d.db.WithContext(ctx).Table(job.StagingTable).Where("id = ?", live[0].ID).Limit(1).Find(&staged).Error; err != nil {
		return "", err
	}
	if len(staged) == 0 {
		// The live row is not staged: a conflict only if its message day is
		// one the restore covers (then the archive would have it).
		from, _ := ParseArchiveRestoreDay(job.FromDay)
		to, _ := ParseArchiveRestoreDay(job.ToDay)
		ts := live[0].Timestamp.UTC()
		if ts.Before(from) || !ts.Before(to.AddDate(0, 0, 1)) || (job.DeviceID != nil && *job.DeviceID != live[0].DeviceID) {
			return "", nil
		}
	} else if s := staged[0]; s.CreatedAt.Equal(live[0].CreatedAt) && s.DeviceID == live[0].DeviceID && s.Timestamp.Equal(live[0].Timestamp) {
		return "", nil
	}
	return fmt.Sprintf("syslog_messages id %d (received %s) is not the archived row with that id: this database's ids no longer match the archive's (rebuilt?), so re-normalizing the staged rows would mix their normalized rows with the live ones; the staged rows are kept for queries, re-normalize refused",
		live[0].ID, live[0].CreatedAt.UTC().Format(time.RFC3339)), nil
}
