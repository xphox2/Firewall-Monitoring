package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The archive worker's state machine on archive_chunks / archive_objects
// (archive plan PR 4). The worker (internal/archive/worker) runs in the poller
// under archiveLockKey; every function here is one short statement or
// transaction, so a crash between any two of them leaves a state the next run
// resumes from:
//
//	pending / failed / exporting / uploading → (re-)export: the chunk's earlier
//	    objects are superseded, the range is exported again (same id range,
//	    same bytes, same keys) and uploaded — except an object an earlier
//	    attempt already uploaded with identical bytes, which is not sent again;
//	verifying → every uploaded object is read back again; nothing re-uploaded.
//	    A transient failure (the service or the database) leaves the chunk in
//	    verifying, retried with backoff; only a mismatch (content or count)
//	    re-exports, at most models.ArchiveMaxMismatches times before the chunk
//	    is parked in needs_attention.
//
// Only a read-back that matches and a count check of "match" make a chunk
// verified, in one transaction with its objects. Every status change is a
// compare-and-set on (status, attempts, runner_id), so a worker holding a
// stale copy of a chunk cannot overwrite another's progress.

// archiveLockKey is the advisory-lock key the poller's archive worker holds
// for a tick: one worker cluster-wide takes id marks, plans, exports and
// verifies. ASCII "FWARCHIV" packed into an int64.
const archiveLockKey int64 = 0x4657415243484956

// AcquireArchiveLock is AcquireDevicePurgeLock on the archive's own key:
// non-blocking, session-scoped, on a pinned connection; acquired=false with
// err=nil means another session holds it. Never the shared poller work lock:
// an export of a syslog day runs for minutes.
func (d *Database) AcquireArchiveLock() (release func(), acquired bool, err error) {
	return d.acquireJobLock("archive", archiveLockKey)
}

// ArchiveRetryBackoff is how long a failed chunk waits before its next
// attempt: 1, 5 and 30 minutes, then every 2 hours.
func ArchiveRetryBackoff(attempts int) time.Duration {
	switch {
	case attempts <= 1:
		return time.Minute
	case attempts == 2:
		return 5 * time.Minute
	case attempts == 3:
		return 30 * time.Minute
	}
	return 2 * time.Hour
}

// archiveWorkScan bounds how many open chunks of a table one lookup reads.
const archiveWorkScan = 500

// NextArchiveChunk returns the oldest chunk of table there is work for at now:
// the lowest seq that is not verified, skipping a chunk that needs attention,
// a failed chunk until its backoff (by attempts, from its last failure,
// updated_at) has passed and a verifying chunk after a transient failure
// until its backoff (by verify_failures) has — later chunks may still
// proceed. nil when there is none.
func (d *Database) NextArchiveChunk(ctx context.Context, table string, now time.Time) (*models.ArchiveChunk, error) {
	var cs []models.ArchiveChunk
	if err := d.db.WithContext(ctx).Where("table_name = ? AND status NOT IN ?", table,
		[]string{models.ArchiveChunkVerified, models.ArchiveChunkSuperseded}).
		Order("seq").Limit(archiveWorkScan).Find(&cs).Error; err != nil {
		return nil, fmt.Errorf("archive: open %s chunks: %w", table, err)
	}
	for i := range cs {
		c := cs[i]
		switch {
		case c.Status == models.ArchiveChunkNeedsAttention:
			continue
		case c.Status == models.ArchiveChunkFailed && now.Before(c.UpdatedAt.Add(ArchiveRetryBackoff(c.Attempts))):
			continue
		case c.Status == models.ArchiveChunkVerifying && c.VerifyFailures > 0 && now.Before(c.UpdatedAt.Add(ArchiveRetryBackoff(c.VerifyFailures))):
			continue
		}
		return &c, nil
	}
	return nil, nil
}

// errArchiveChunkMoved: a compare-and-set on a chunk's status found another
// status (another writer; with the advisory lock held, a bug).
var errArchiveChunkMoved = errors.New("archive: chunk status changed underneath the worker")

// casChunk updates chunk c from the state the caller read (status, attempts
// and runner), refreshing c.
func casChunk(tx *gorm.DB, c *models.ArchiveChunk, set map[string]interface{}) error {
	res := tx.Model(&models.ArchiveChunk{}).Where("id = ? AND status = ? AND attempts = ? AND runner_id = ?",
		c.ID, c.Status, c.Attempts, c.RunnerID).Updates(set)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("%w (chunk %d, expected %s)", errArchiveChunkMoved, c.ID, c.Status)
	}
	return tx.Where("id = ?", c.ID).First(c).Error
}

// ClaimArchiveChunk records runner as the worker of c (status unchanged), so
// a stale worker's later write to c fails its compare-and-set.
func (d *Database) ClaimArchiveChunk(ctx context.Context, c *models.ArchiveChunk, runner string) error {
	if c.RunnerID == runner {
		return nil
	}
	return casChunk(d.db.WithContext(ctx), c, map[string]interface{}{"runner_id": runner})
}

// BeginArchiveChunkExport starts an export attempt of c: every object of an
// earlier attempt that is not already superseded becomes superseded (it was
// never verified), and the chunk moves to exporting with one more attempt.
// It returns the earlier attempt's objects that were uploaded (status
// uploaded at that point), by key: an object of the new export with the same
// key and stored bytes is already in the bucket and need not be sent again —
// the read-back verifies it like any other. A mismatch supersedes the
// objects it found (RecordArchiveMismatch), so a copy that failed its
// read-back is never reused.
func (d *Database) BeginArchiveChunkExport(ctx context.Context, c *models.ArchiveChunk, runner string, at time.Time) (map[string]models.ArchiveObject, error) {
	reuse := map[string]models.ArchiveObject{}
	err := d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var up []models.ArchiveObject
		if err := tx.Where("chunk_id = ? AND status = ?", c.ID, models.ArchiveObjectUploaded).Find(&up).Error; err != nil {
			return err
		}
		for _, o := range up {
			reuse[o.ObjectKey] = o
		}
		if err := tx.Model(&models.ArchiveObject{}).Where("chunk_id = ? AND status <> ?", c.ID, models.ArchiveObjectSuperseded).
			Updates(map[string]interface{}{"status": models.ArchiveObjectSuperseded, "updated_at": at}).Error; err != nil {
			return fmt.Errorf("archive: supersede the objects of chunk %d: %w", c.ID, err)
		}
		return casChunk(tx, c, map[string]interface{}{
			"status": models.ArchiveChunkExporting, "attempts": c.Attempts + 1, "runner_id": runner,
			"started_at": at, "error": "", "verify_failures": 0, "updated_at": at,
		})
	})
	if err != nil {
		return nil, err
	}
	return reuse, nil
}

// RecordArchiveExport stores the objects an export wrote (status pending, as
// exported: keys, sizes, hashes, id and time bounds) and moves c to uploading.
func (d *Database) RecordArchiveExport(ctx context.Context, c *models.ArchiveChunk, objs []models.ArchiveObject, at time.Time) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(objs) > 0 {
			if err := tx.Create(&objs).Error; err != nil {
				return fmt.Errorf("archive: record the objects of chunk %d: %w", c.ID, err)
			}
		}
		return casChunk(tx, c, map[string]interface{}{"status": models.ArchiveChunkUploading, "updated_at": at})
	})
}

// MarkArchiveObjectUploaded records what the service returned for object o.
func (d *Database) MarkArchiveObjectUploaded(ctx context.Context, o *models.ArchiveObject, etag, versionID string, parts int, lockUntil *time.Time, at time.Time) error {
	res := d.db.WithContext(ctx).Model(&models.ArchiveObject{}).Where("id = ? AND status = ?", o.ID, models.ArchiveObjectPending).
		Updates(map[string]interface{}{"status": models.ArchiveObjectUploaded, "etag": etag, "version_id": versionID,
			"part_count": parts, "lock_until": lockUntil, "updated_at": at})
	if res.Error != nil {
		return fmt.Errorf("archive: record the upload of object %d: %w", o.ID, res.Error)
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("archive: object %d is no longer pending", o.ID)
	}
	o.Status, o.ETag, o.VersionID, o.PartCount, o.LockUntil = models.ArchiveObjectUploaded, etag, versionID, parts, lockUntil
	return nil
}

// SetArchiveChunkStatus moves c from its current status to status.
func (d *Database) SetArchiveChunkStatus(ctx context.Context, c *models.ArchiveChunk, status string, at time.Time) error {
	return casChunk(d.db.WithContext(ctx), c, map[string]interface{}{"status": status, "updated_at": at})
}

// ArchiveChunkObjects returns the objects of chunk id that are not
// superseded, in id order.
func (d *Database) ArchiveChunkObjects(ctx context.Context, chunkID uint) ([]models.ArchiveObject, error) {
	var objs []models.ArchiveObject
	err := d.db.WithContext(ctx).Where("chunk_id = ? AND status <> ?", chunkID, models.ArchiveObjectSuperseded).Order("id").Find(&objs).Error
	return objs, err
}

// archiveErrorMax bounds the error text stored on a chunk.
const archiveErrorMax = 2000

// FailArchiveChunk marks c failed with msg at at (the backoff runs from it).
// Its objects stay as they are until the next attempt supersedes them.
func (d *Database) FailArchiveChunk(ctx context.Context, c *models.ArchiveChunk, msg string, at time.Time) error {
	if len(msg) > archiveErrorMax {
		msg = msg[:archiveErrorMax]
	}
	return casChunk(d.db.WithContext(ctx), c, map[string]interface{}{"status": models.ArchiveChunkFailed, "error": msg, "updated_at": at})
}

// RecordArchiveMismatch records an attempt whose read-back content or count
// did not match: the objects found are superseded (never reused), the
// mismatch counted, and the chunk is failed (re-exported after its backoff)
// or, at models.ArchiveMaxMismatches, parked in needs_attention. It reports
// whether the chunk was parked.
func (d *Database) RecordArchiveMismatch(ctx context.Context, c *models.ArchiveChunk, msg string, at time.Time) (parked bool, err error) {
	if len(msg) > archiveErrorMax {
		msg = msg[:archiveErrorMax]
	}
	status := models.ArchiveChunkFailed
	if c.Mismatches+1 >= models.ArchiveMaxMismatches {
		status = models.ArchiveChunkNeedsAttention
	}
	err = d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.ArchiveObject{}).Where("chunk_id = ? AND status <> ?", c.ID, models.ArchiveObjectSuperseded).
			Updates(map[string]interface{}{"status": models.ArchiveObjectSuperseded, "updated_at": at}).Error; err != nil {
			return err
		}
		return casChunk(tx, c, map[string]interface{}{"status": status, "mismatches": c.Mismatches + 1,
			"verify_failures": 0, "error": msg, "updated_at": at})
	})
	return status == models.ArchiveChunkNeedsAttention && err == nil, err
}

// DeferArchiveVerify records a transient verification failure of c (the
// service or the database failed, nothing was found wrong): c stays in
// verifying and is read back again after ArchiveRetryBackoff(verify_failures).
func (d *Database) DeferArchiveVerify(ctx context.Context, c *models.ArchiveChunk, msg string, at time.Time) error {
	if len(msg) > archiveErrorMax {
		msg = msg[:archiveErrorMax]
	}
	return casChunk(d.db.WithContext(ctx), c, map[string]interface{}{"verify_failures": c.VerifyFailures + 1, "error": msg, "updated_at": at})
}

// MarkArchiveChunkVerified marks c and its (non-superseded) objects verified
// in one transaction and stores the chunk's totals: rows, message-time bounds
// and day histogram summed over the objects. The caller has read every object
// back, counted the table and written the chunk manifests.
func (d *Database) MarkArchiveChunkVerified(ctx context.Context, c *models.ArchiveChunk, objs []models.ArchiveObject, at time.Time) error {
	var rows int64
	var minTs, maxTs *time.Time
	hist := map[string]int64{}
	for i := range objs {
		o := &objs[i]
		rows += o.RowCount
		if o.MinTs != nil && (minTs == nil || o.MinTs.Before(*minTs)) {
			minTs = o.MinTs
		}
		if o.MaxTs != nil && (maxTs == nil || o.MaxTs.After(*maxTs)) {
			maxTs = o.MaxTs
		}
		if o.MsgDayHistogram != nil {
			var h map[string]int64
			if err := json.Unmarshal([]byte(*o.MsgDayHistogram), &h); err != nil {
				return fmt.Errorf("archive: histogram of object %d: %w", o.ID, err)
			}
			for k, n := range h {
				hist[k] += n
			}
		}
	}
	hb, err := json.Marshal(hist)
	if err != nil {
		return err
	}
	hs := string(hb)
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		ids := make([]uint, len(objs))
		for i := range objs {
			ids[i] = objs[i].ID
		}
		if len(ids) > 0 {
			res := tx.Model(&models.ArchiveObject{}).Where("id IN ? AND chunk_id = ? AND status = ?", ids, c.ID, models.ArchiveObjectUploaded).
				Updates(map[string]interface{}{"status": models.ArchiveObjectVerified, "verified_at": at, "updated_at": at})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != int64(len(ids)) {
				return fmt.Errorf("archive: chunk %d: %d of %d objects were uploaded and could be verified", c.ID, res.RowsAffected, len(ids))
			}
		}
		return casChunk(tx, c, map[string]interface{}{
			"status": models.ArchiveChunkVerified, "verified_at": at, "error": "", "verify_failures": 0, "updated_at": at,
			"row_count": rows, "min_ts": minTs, "max_ts": maxTs, "msg_day_histogram": hs,
		})
	})
}

// ArchiveProgress is how far a table's archive has come.
type ArchiveProgress struct {
	// Chunks: whether any chunk of the table exists.
	Chunks bool
	// VerifiedThroughID is V: the id_hi of the last chunk of the gapless run
	// of verified chunks from seq 1 (0 when the first chunk is not verified).
	// The retention gate deletes no raw row above it.
	VerifiedThroughID int64
	// VerifiedThroughEnd is that chunk's period end; nil when none.
	VerifiedThroughEnd *time.Time
	// VerifiedMaxTs is the latest message (sample) time of any row in the
	// run (the chunks' max_ts): every row at or below V has a timestamp at
	// or before it — rows are immutable and the count check proved the
	// range complete. nil when the run holds no row, or a chunk of it with
	// rows has no max_ts (no bound is then known).
	VerifiedMaxTs *time.Time
	// FirstStart is the first chunk's period start (nil without chunks).
	FirstStart *time.Time
}

// ArchiveTableProgress derives V for table — never stored: the id_hi of the
// last chunk of the run that starts at seq 1 with id_lo 0 and continues while
// every chunk is verified, its seq is the previous one's + 1 and its id_lo the
// previous one's id_hi. The first chunk that is not verified (pending,
// exporting, uploading, verifying, failed, needs_attention, superseded) or
// that leaves a gap ends the run. The retention gate deletes only rows at or
// below it (archive_gate.go), so it reads every chunk of the table — a few
// hundred syslog days, 24 flow hours a day — rather than trust the planner's
// contiguity.
func (d *Database) ArchiveTableProgress(ctx context.Context, table string) (ArchiveProgress, error) {
	var p ArchiveProgress
	var cs []struct {
		Seq         int64
		IDLo        int64
		IDHi        int64
		Status      string
		PeriodStart time.Time
		PeriodEnd   time.Time
		RowCount    int64
		MaxTs       *time.Time
	}
	if err := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).
		Select("seq, id_lo, id_hi, status, period_start, period_end, row_count, max_ts").
		Where("table_name = ?", table).Order("seq").Scan(&cs).Error; err != nil {
		return p, err
	}
	if len(cs) == 0 {
		return p, nil
	}
	p.Chunks = true
	start := cs[0].PeriodStart.UTC()
	p.FirstStart = &start
	var prevSeq, prevHi int64
	var maxTs time.Time
	tsKnown := true
	for _, c := range cs {
		if c.Status != models.ArchiveChunkVerified || c.Seq != prevSeq+1 || c.IDLo != prevHi || c.IDHi < c.IDLo {
			break
		}
		prevSeq, prevHi = c.Seq, c.IDHi
		end := c.PeriodEnd.UTC()
		p.VerifiedThroughID, p.VerifiedThroughEnd = c.IDHi, &end
		switch {
		case c.MaxTs != nil && c.MaxTs.After(maxTs):
			maxTs = c.MaxTs.UTC()
		case c.MaxTs == nil && c.RowCount > 0:
			tsKnown = false
		}
	}
	if tsKnown && !maxTs.IsZero() {
		p.VerifiedMaxTs = &maxTs
	}
	return p, nil
}

// ArchiveChunkStatusCounts counts chunks by table and status.
func (d *Database) ArchiveChunkStatusCounts(ctx context.Context) (map[string]map[string]int64, error) {
	var rows []struct {
		TableName string
		Status    string
		N         int64
	}
	if err := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).Select("table_name, status, count(*) AS n").
		Group("table_name, status").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]map[string]int64{}
	for _, r := range rows {
		if out[r.TableName] == nil {
			out[r.TableName] = map[string]int64{}
		}
		out[r.TableName][r.Status] = r.N
	}
	return out, nil
}

// syslogFormatMigration is the migration that added syslog_messages.format.
const syslogFormatMigration = 74

// ArchiveSyslogFormatSince returns when migration v74 (the stored syslog
// `format`) was applied here, which picks the syslog archive schema of a
// month: rows of earlier months never had a format (schema v1), later months
// are v2. ok is false when this database has no record of it (a test schema
// without schema_migrations): every month is then v2.
func (d *Database) ArchiveSyslogFormatSince(ctx context.Context) (at time.Time, ok bool, err error) {
	if !d.db.Migrator().HasTable(&models.SchemaMigration{}) {
		return time.Time{}, false, nil
	}
	var m []models.SchemaMigration
	if err := d.db.WithContext(ctx).Where("version = ?", syslogFormatMigration).Limit(1).Find(&m).Error; err != nil {
		return time.Time{}, false, err
	}
	if len(m) == 0 {
		return time.Time{}, false, nil
	}
	return m[0].AppliedAt.UTC(), true, nil
}
