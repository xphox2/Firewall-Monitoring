package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5" // #nosec G501 -- the S3 ETag of a single-part object
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"
)

// The restore worker (archive plan PR 9): restores archived rows to a
// per-job staging table, never into the live tables (database/
// archive_restore.go has the job's contract). It runs in the poller beside
// the archive worker, under its own advisory lock, one job at a time:
//
//   - a bucket restore (FromBucket) first selects its objects from the
//     sealed months' _MONTH.json (each checked against its ETag and the
//     sha256 the seal recorded with it);
//   - the disk precheck: the rows still to stage × the table's bytes per row
//     must be under half the database volume's free space;
//   - per object, oldest chunk first: download the recorded version into the
//     staging directory while checking it (stored bytes against
//     sha256_object, decompressed bytes against sha256_content, row and byte
//     counts, every line JSON with an id in its chunk's range, in order). A
//     mismatch REFUSES the object: the job fails (resumable) and nothing of
//     it is loaded. Only a verified file is decoded — each line must
//     re-encode to itself (export.Decoder) — filtered to the requested days
//     and device, and loaded in batches that each commit with the object's
//     cursor (crash-safe, exactly once), paced at the job's rate;
//   - a cancel is honoured between batches; a shutdown requeues the job.
//
// It only reads the bucket (GETs).

// RestoreStore is the bucket as the restore worker reads it; *s3.Client
// implements it.
type RestoreStore interface {
	Key(rel string) (string, error)
	GetBytes(ctx context.Context, rel, versionID string, limit int64) ([]byte, s3.ObjectInfo, error)
	VerifyFull(ctx context.Context, want s3.PutResult, w io.Writer) error
}

// RestoreTickInterval is how often the poller calls RestoreWorker.Tick.
const RestoreTickInterval = 15 * time.Second

// restoreStagingMargin is the free space the staging directory must have
// beyond an object's size before it is downloaded.
var restoreStagingMargin uint64 = 512 << 20

// restoreEntry is the name of a job's download directory in the staging
// directory: the only entries the restore worker removes.
var restoreEntry = regexp.MustCompile(`^restore-[0-9]+$`)

// errRestoreCancelled ends a run on a cancel request.
var errRestoreCancelled = errors.New("restore cancelled")

// errRestoreRefused marks a downloaded object that does not match the
// manifest.
var errRestoreRefused = errors.New("REFUSED")

// RestoreWorker runs the archive restore jobs.
type RestoreWorker struct {
	db      *database.Database
	store   RestoreStore
	prefix  string
	staging string
	running atomic.Bool
	sleep   func(ctx context.Context, d time.Duration) error

	// afterBatch (tests): runs after every committed batch; an error ends
	// the run as a crash would (the job is left running).
	afterBatch func(job *models.ArchiveRestoreJob, obj *models.ArchiveRestoreObject) error
}

// NewRestoreWorker builds the restore worker over db with the S3 client
// from cfg (ARCHIVE_S3_* and ARCHIVE_STAGING_DIR are required; the streams
// need not be enabled). It clears download directories a previous run left
// and makes no network call.
func NewRestoreWorker(db *database.Database, cfg config.ArchiveConfig, opts ...s3.Option) (*RestoreWorker, error) {
	client, err := s3.New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	return newRestoreWorker(db, client, cfg)
}

func newRestoreWorker(db *database.Database, store RestoreStore, cfg config.ArchiveConfig) (*RestoreWorker, error) {
	if cfg.StagingDir == "" || !filepath.IsAbs(cfg.StagingDir) {
		return nil, errors.New("archive restore: ARCHIVE_STAGING_DIR must be an absolute directory")
	}
	r := &RestoreWorker{db: db, store: store, prefix: cfg.Prefix, staging: cfg.StagingDir, sleep: sleepCtx}
	if err := os.MkdirAll(r.staging, 0o700); err != nil {
		return nil, fmt.Errorf("archive restore: staging directory %s: %w", r.staging, err)
	}
	ents, err := os.ReadDir(r.staging)
	if err != nil {
		return nil, fmt.Errorf("archive restore: staging directory %s: %w", r.staging, err)
	}
	for _, e := range ents {
		if e.IsDir() && restoreEntry.MatchString(e.Name()) {
			if err := os.RemoveAll(filepath.Join(r.staging, e.Name())); err != nil {
				return nil, fmt.Errorf("archive restore: clear %s: %w", e.Name(), err)
			}
		}
	}
	return r, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Tick does the restore work that is due, under the restore lock: requeue a
// job whose worker died, drop the staging tables past their TTL, queue the
// backfills of loaded jobs, then run the oldest pending job to its end.
// Errors are logged, never returned.
func (r *RestoreWorker) Tick(ctx context.Context) {
	if !r.running.CompareAndSwap(false, true) {
		return
	}
	defer r.running.Store(false)
	if ctx.Err() != nil {
		return
	}
	release, acquired, err := r.db.AcquireArchiveRestoreLock()
	if err != nil {
		log.Printf("archive restore: advisory lock probe failed: %v", err)
		return
	}
	if !acquired {
		return
	}
	defer release()
	defer r.publish(ctx)

	if n, err := r.db.RequeueStaleArchiveRestoreJobs(ctx); err != nil {
		log.Printf("archive restore: stale-job requeue: %v", err)
	} else if n > 0 {
		log.Printf("archive restore: requeued %d job(s) whose worker heartbeat was lost", n)
	}
	r.dropExpired(ctx)
	if n, err := r.db.RetryLoadedArchiveRestores(ctx); err != nil {
		log.Printf("archive restore: queue the backfills of loaded restores: %v", err)
	} else if n > 0 {
		log.Printf("archive restore: queued the normalized-event backfill of %d loaded restore(s)", n)
	}
	runner := fmt.Sprintf("restore-%d-%d", os.Getpid(), time.Now().UnixNano())
	job, err := r.db.ClaimNextArchiveRestoreJob(ctx, runner)
	if err != nil {
		log.Printf("archive restore: claim: %v", err)
		return
	}
	if job == nil {
		return
	}
	if err := r.run(ctx, job, runner); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("archive restore: job %d ended: %v", job.ID, err)
	}
}

func (r *RestoreWorker) publish(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	counts, err := r.db.ArchiveRestoreStatusCounts(ctx)
	if err != nil {
		return
	}
	for _, s := range metrics.ArchiveRestoreStatuses {
		metrics.SetArchiveRestoreJobs(s, counts[s])
	}
}

// dropExpired drops the staging tables of finished jobs past ExpiresAt.
func (r *RestoreWorker) dropExpired(ctx context.Context) {
	now := time.Now()
	jobs, err := r.db.ExpiredArchiveRestoreJobs(ctx, now)
	if err != nil {
		log.Printf("archive restore: expired jobs: %v", err)
		return
	}
	for _, j := range jobs {
		if _, err := r.db.DropArchiveRestore(ctx, j.ID, now); err != nil {
			if errors.Is(err, database.ErrArchiveRestoreInUse) {
				continue // its backfill is still running: dropped on a later tick
			}
			log.Printf("archive restore: drop expired %s (job %d): %v", j.StagingTable, j.ID, err)
			continue
		}
		log.Printf("archive restore: dropped %s (job %d, expired %s)", j.StagingTable, j.ID, j.ExpiresAt.UTC().Format(time.RFC3339))
	}
}

// run executes one claimed job to its end.
func (r *RestoreWorker) run(ctx context.Context, job *models.ArchiveRestoreJob, runner string) error {
	fail := func(cause error) error {
		if err := r.db.FinishArchiveRestoreJob(ctx, job.ID, runner, models.ArchiveRestoreFailed, cause); err != nil {
			return fmt.Errorf("%w (and recording it: %v)", cause, err)
		}
		return cause
	}
	hbCtx, stopHB := context.WithCancel(ctx)
	defer stopHB()
	go func() {
		t := time.NewTicker(database.ArchiveRestoreHeartbeat())
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				_ = r.db.TouchArchiveRestoreJob(hbCtx, job.ID, runner)
			}
		}
	}()
	log.Printf("archive restore: job %d: %s %s..%s into %s", job.ID, job.Stream, job.FromDay, job.ToDay, job.StagingTable)

	if job.SelectedAt == nil {
		objs, rows, note, err := SelectRestoreFromBucket(ctx, r.store, job)
		if err != nil {
			return r.ended(ctx, job, runner, err, fail)
		}
		if len(objs) == 0 {
			return fail(fmt.Errorf("%w (in the sealed months of the bucket)%s", database.ErrArchiveRestoreNothing, noteSuffix(note)))
		}
		if err := r.db.RecordArchiveRestoreSelection(ctx, job, runner, objs, rows, note); err != nil {
			return r.ended(ctx, job, runner, err, fail)
		}
	}
	pending, err := r.db.PendingArchiveRestoreObjects(ctx, job.ID)
	if err != nil {
		return r.ended(ctx, job, runner, err, fail)
	}
	var left int64
	for _, o := range pending {
		left += o.DayRows
	}
	if est := r.db.EstimateArchiveRestore(job.SourceTable, left, job.Renormalize); !est.Enough && !job.Force {
		return fail(fmt.Errorf("disk precheck: %s", est.Refusal()))
	}
	if err := r.db.EnsureArchiveRestoreTable(ctx, job); err != nil {
		return r.ended(ctx, job, runner, err, fail)
	}
	from, err := database.ParseArchiveRestoreDay(job.FromDay)
	if err != nil {
		return fail(err)
	}
	to, err := database.ParseArchiveRestoreDay(job.ToDay)
	if err != nil {
		return fail(err)
	}
	f := restoreFilter{from: from, end: to.AddDate(0, 0, 1), device: job.DeviceID}
	for i := range pending {
		if err := r.loadObject(ctx, job, runner, &pending[i], f); err != nil {
			return r.ended(ctx, job, runner, err, fail)
		}
	}
	if job.Renormalize && job.FromBucket {
		// The manifest is not this database's: its ids may not be either.
		if msg, err := r.db.ArchiveRestoreIDConflict(ctx, job); err != nil {
			return r.ended(ctx, job, runner, err, fail)
		} else if msg != "" {
			return fail(errors.New(msg))
		}
	}
	status, err := r.db.CompleteArchiveRestoreJob(ctx, job, runner)
	if err != nil {
		return r.ended(ctx, job, runner, err, fail)
	}
	log.Printf("archive restore: job %d %s: %d objects into %s", job.ID, status, len(pending), job.StagingTable)
	return nil
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return "; " + note
}

// ended disposes of a run that stopped on err: a shutdown requeues the job,
// a cancel finishes it cancelled, a lost job is left to its new owner, any
// other error fails it (resumable).
func (r *RestoreWorker) ended(ctx context.Context, job *models.ArchiveRestoreJob, runner string, err error, fail func(error) error) error {
	switch {
	case ctx.Err() != nil:
		r.db.InterruptArchiveRestoreJob(job.ID, runner)
		return ctx.Err()
	case errors.Is(err, errRestoreCancelled):
		log.Printf("archive restore: job %d cancelled by request (cursors kept; resumable)", job.ID)
		return r.db.FinishArchiveRestoreJob(ctx, job.ID, runner, models.ArchiveRestoreCancelled, nil)
	case database.ErrArchiveRestoreLost(err):
		return err
	}
	return fail(err)
}

// restoreFilter is which decoded rows a job stages: message (sample) time in
// [from, end), the device when set.
type restoreFilter struct {
	from, end time.Time
	device    *uint
}

func (f restoreFilter) keep(ts time.Time, dev uint) bool {
	return !ts.Before(f.from) && ts.Before(f.end) && (f.device == nil || *f.device == dev)
}

// rel is a bucket key below the prefix.
func (r *RestoreWorker) rel(key string) (string, error) {
	rel, ok := strings.CutPrefix(key, r.prefix+"/")
	if !ok || rel == "" {
		return "", fmt.Errorf("object key %q is not under ARCHIVE_S3_PREFIX %q", key, r.prefix)
	}
	return rel, nil
}

// loadObject downloads, verifies and stages one object (see the file
// comment).
func (r *RestoreWorker) loadObject(ctx context.Context, job *models.ArchiveRestoreJob, runner string, obj *models.ArchiveRestoreObject, f restoreFilter) error {
	if stop, err := r.db.ArchiveRestoreCheckpoint(ctx, job.ID, runner); err != nil {
		return err
	} else if stop {
		return errRestoreCancelled
	}
	free, err := stagingFree(ctx, r.staging)
	switch {
	case err != nil:
		return fmt.Errorf("free space of the staging directory %s unknown: %w", r.staging, err)
	case free < uint64(obj.ObjectBytes)+restoreStagingMargin:
		return fmt.Errorf("staging directory %s has %d MiB free, %s needs %d MiB", r.staging, free>>20, obj.ObjectKey, (uint64(obj.ObjectBytes)+restoreStagingMargin)>>20)
	}
	rel, err := r.rel(obj.ObjectKey)
	if err != nil {
		return err
	}
	dir := filepath.Join(r.staging, "restore-"+strconv.FormatUint(uint64(job.ID), 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "object-"+strconv.FormatUint(uint64(obj.ID), 10)+".ndjson.gz")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600) // #nosec G304 -- a name built from ids under the staging directory
	if err != nil {
		return err
	}
	defer func() {
		file.Close()
		os.Remove(path)
	}()

	// Download and verify: nothing is decoded before every check passed.
	want := s3.PutResult{Rel: rel, Key: obj.ObjectKey, Size: obj.ObjectBytes, SHA256: obj.Sha256Object, ETag: obj.ETag,
		Parts: obj.PartCount, VersionID: obj.VersionID}
	chk := newContentCheck(&models.ArchiveChunk{IDLo: obj.ChunkIDLo, IDHi: obj.ChunkIDHi},
		&models.ArchiveObject{ObjectKey: obj.ObjectKey, Sha256Content: obj.Sha256Content, RowCount: obj.RowCount,
			RawBytes: obj.RawBytes, MinID: obj.MinID, MaxID: obj.MaxID})
	verr := r.store.VerifyFull(ctx, want, io.MultiWriter(file, chk))
	cerr := chk.finish()
	switch {
	case verr != nil && errors.Is(verr, s3.ErrMismatch):
		metrics.IncArchiveRestoreRefused(job.Stream)
		return fmt.Errorf("%w %s: the stored object does not match the manifest: %v", errRestoreRefused, obj.ObjectKey, verr)
	case verr != nil:
		return fmt.Errorf("download %s: %w", obj.ObjectKey, verr)
	case cerr != nil:
		metrics.IncArchiveRestoreRefused(job.Stream)
		return fmt.Errorf("%w %s: its content does not match the manifest: %v", errRestoreRefused, obj.ObjectKey, cerr)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return r.stage(ctx, job, runner, obj, f, file)
}

// eachLine gunzips an object file and hands every line (with its newline)
// to fn, in order.
func eachLine(file io.Reader, fn func(line []byte) error) error {
	zr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	zr.Multistream(false)
	br := bufio.NewReaderSize(zr, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if ferr := fn(line); ferr != nil {
				return ferr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// errDecode marks a line the decoder refused (wrapped with the line's error).
type errDecode struct{ err error }

func (e errDecode) Error() string { return e.err.Error() }

// stage decodes a verified object and loads its rows of the job's days and
// device, after the object's cursor, in batches. Every line is decoded once
// before the first batch: a line the decoder refuses (the row format drifted
// from what the archive wrote) refuses the whole object with nothing of it
// staged, rather than failing after earlier batches committed — a resume
// would stop at the same line again.
func (r *RestoreWorker) stage(ctx context.Context, job *models.ArchiveRestoreJob, runner string, obj *models.ArchiveRestoreObject, f restoreFilter, file io.ReadSeeker) error {
	dec, err := export.NewDecoder(job.SourceTable, obj.SchemaVersion)
	if err != nil {
		return err
	}
	b := rowBatch{table: job.SourceTable}
	refused := func(err error) error {
		metrics.IncArchiveRestoreRefused(job.Stream)
		return fmt.Errorf("%w %s: %v", errRestoreRefused, obj.ObjectKey, err)
	}
	if err := eachLine(file, func(line []byte) error {
		if _, _, _, derr := b.decode(dec, line); derr != nil {
			return errDecode{derr}
		}
		return nil
	}); err != nil {
		var de errDecode
		if errors.As(err, &de) {
			return refused(de.err)
		}
		return fmt.Errorf("read %s: %w", obj.ObjectKey, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	size := database.ArchiveRestoreBatchSize()
	var cursor, scanned int64 = obj.CursorID, 0
	started := time.Now()
	flush := func(done bool) error {
		n := b.len()
		if err := r.db.LoadArchiveRestoreBatch(ctx, job, runner, obj, database.ArchiveRestoreBatch{Rows: b.rows(), CursorID: cursor, Scanned: scanned, Done: done}); err != nil {
			return err
		}
		metrics.AddArchiveRestoreRows(job.SourceTable, n)
		obj.CursorID = cursor
		if r.afterBatch != nil {
			if err := r.afterBatch(job, obj); err != nil {
				return err
			}
		}
		lines := scanned
		b.reset()
		scanned = 0
		if done {
			return nil
		}
		if stop, err := r.db.ArchiveRestoreCheckpoint(ctx, job.ID, runner); err != nil {
			return err
		} else if stop {
			return errRestoreCancelled
		}
		if wait := restorePace(lines, job.RateRowsPerSec, time.Since(started)); wait > 0 {
			if err := r.sleep(ctx, wait); err != nil {
				return err
			}
		}
		started = time.Now()
		return nil
	}
	if err := eachLine(file, func(line []byte) error {
		id, ts, dev, derr := b.decode(dec, line)
		if derr != nil {
			return refused(derr) // the file changed since the validation pass
		}
		if id <= obj.CursorID {
			return nil
		}
		scanned++
		cursor = id
		if f.keep(ts, dev) {
			b.keep()
		}
		if scanned >= int64(size) {
			return flush(false)
		}
		return nil
	}); err != nil {
		return err
	}
	return flush(true)
}

// restorePace is how long to wait after lines read in elapsed to hold rate
// lines per second.
func restorePace(lines int64, rate int, elapsed time.Duration) time.Duration {
	if lines <= 0 || rate <= 0 {
		return 0
	}
	want := time.Duration(float64(lines) / float64(rate) * float64(time.Second))
	if want <= elapsed {
		return 0
	}
	return want - elapsed
}

// rowBatch accumulates the decoded rows of one table.
type rowBatch struct {
	table string
	s     models.SyslogMessage
	f     models.FlowSample
	c     models.FlowInterfaceCounter
	sys   []models.SyslogMessage
	flows []models.FlowSample
	ctrs  []models.FlowInterfaceCounter
}

// decode decodes line into the batch's scratch row and returns its id,
// message time and device; keep adds it to the batch.
func (b *rowBatch) decode(dec *export.Decoder, line []byte) (int64, time.Time, uint, error) {
	switch b.table {
	case export.TableSyslog:
		err := dec.Syslog(line, &b.s)
		return int64(b.s.ID), b.s.Timestamp, b.s.DeviceID, err
	case export.TableFlows:
		err := dec.Flow(line, &b.f)
		return int64(b.f.ID), b.f.Timestamp, b.f.DeviceID, err
	case export.TableCounters:
		err := dec.Counter(line, &b.c)
		return int64(b.c.ID), b.c.Timestamp, b.c.DeviceID, err
	}
	return 0, time.Time{}, 0, fmt.Errorf("restore: %q is not an archived table", b.table)
}

func (b *rowBatch) keep() {
	switch b.table {
	case export.TableSyslog:
		b.sys = append(b.sys, b.s)
	case export.TableFlows:
		b.flows = append(b.flows, b.f)
	case export.TableCounters:
		b.ctrs = append(b.ctrs, b.c)
	}
}

func (b *rowBatch) len() int { return len(b.sys) + len(b.flows) + len(b.ctrs) }

func (b *rowBatch) rows() any {
	switch b.table {
	case export.TableSyslog:
		return b.sys
	case export.TableFlows:
		return b.flows
	}
	return b.ctrs
}

func (b *rowBatch) reset() { b.sys, b.flows, b.ctrs = b.sys[:0], b.flows[:0], b.ctrs[:0] }

// SelectRestoreFromBucket selects a job's objects from the bucket alone: the
// _MONTH.json of every sealed month of the job's stream from the month before
// FromDay's to the month after ToDay's (a row of day D is in the ingest month
// of D or a later one, and a device clock running ahead puts some earlier).
// Each manifest must match its ETag and the sha256 the seal stored with it.
// note lists the months of that range without a sealed _MONTH.json (their
// rows, if any, are not restored: use the database manifest).
func SelectRestoreFromBucket(ctx context.Context, store RestoreStore, job *models.ArchiveRestoreJob) ([]models.ArchiveRestoreObject, int64, string, error) {
	from, err := database.ParseArchiveRestoreDay(job.FromDay)
	if err != nil {
		return nil, 0, "", err
	}
	to, err := database.ParseArchiveRestoreDay(job.ToDay)
	if err != nil {
		return nil, 0, "", err
	}
	first := time.Date(from.Year(), from.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
	last := time.Date(to.Year(), to.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	var objs []models.ArchiveRestoreObject
	var rows int64
	var missing []string
	for m := first; !m.After(last); m = m.AddDate(0, 1, 0) {
		month := export.MonthOf(m)
		mm, found, err := readSealedMonth(ctx, store, job.Stream, month)
		if err != nil {
			return nil, 0, "", err
		}
		if !found {
			missing = append(missing, month)
			continue
		}
		if mm.Table != job.SourceTable {
			return nil, 0, "", fmt.Errorf("%s %s _MONTH.json describes table %q, not %s", job.Stream, month, mm.Table, job.SourceTable)
		}
		for _, c := range mm.Chunks {
			for _, o := range c.Objects {
				if job.DeviceID != nil && o.DeviceID != nil && *o.DeviceID != *job.DeviceID {
					continue
				}
				n := database.ArchiveRestoreDayRows(o.MsgDayHistogram, from, to)
				if n == 0 {
					continue
				}
				rows += n
				objs = append(objs, models.ArchiveRestoreObject{
					ChunkSeq: c.Seq, ChunkIDLo: c.IDLo, ChunkIDHi: c.IDHi, ObjectKey: o.Key, VersionID: o.VersionID,
					SchemaVersion: mm.SchemaVersion, Compression: mm.Compression, RowCount: o.Rows, RawBytes: o.RawBytes,
					ObjectBytes: o.ObjectBytes, Sha256Content: o.Sha256Content, Sha256Object: o.Sha256Object, ETag: o.ETag,
					PartCount: o.PartCount, MinID: o.MinID, MaxID: o.MaxID, DayRows: n, Status: models.ArchiveRestoreObjectPending,
				})
			}
		}
	}
	note := ""
	if len(missing) > 0 {
		note = fmt.Sprintf("searched the sealed months only: %s not sealed in the bucket (rows of these days in them are not restored; restore without --from-bucket to use the database manifest)", strings.Join(missing, ", "))
	}
	return objs, rows, note, nil
}

// readSealedMonth downloads and checks stream's _MONTH.json of month (any
// schema version); found=false when the month is not sealed in the bucket.
func readSealedMonth(ctx context.Context, store RestoreStore, stream, month string) (*monthManifest, bool, error) {
	var out *monthManifest
	for _, sv := range export.SchemasOf(stream) {
		rel := export.MonthFolderRel(stream, sv, month) + "/" + export.MonthManifestName
		body, info, err := store.GetBytes(ctx, rel, "", manifestLimit)
		if errors.Is(err, s3.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if out != nil {
			return nil, false, fmt.Errorf("%s %s has a _MONTH.json under two schema versions", stream, month)
		}
		sum, sha := md5.Sum(body), sha256.Sum256(body) // #nosec G401 -- the S3 ETag of a single-part object
		if info.ETag != hex.EncodeToString(sum[:]) || info.Metadata[monthManifestShaMeta] != hex.EncodeToString(sha[:]) {
			return nil, false, fmt.Errorf("%w %s: it does not match its ETag / the sha256 recorded at the seal", errRestoreRefused, info.Key)
		}
		var m monthManifest
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return nil, false, fmt.Errorf("%s is not a month manifest: %w", info.Key, err)
		}
		if m.Kind != MonthManifestKind || m.Stream != stream || m.Month != month || m.SchemaVersion != sv {
			return nil, false, fmt.Errorf("%s describes %s %s schema %d", info.Key, m.Stream, m.Month, m.SchemaVersion)
		}
		out = &m
	}
	return out, out != nil, nil
}
