// Package worker is the raw archive's worker (archive plan PR 4): it runs in
// the poller and, for every enabled stream, takes id marks, cuts chunks,
// exports each chunk to gzip NDJSON in a staging directory, uploads the
// objects to the S3-compatible bucket, reads every object back in full,
// recounts the chunk's id range in the table and only then — and only on a
// count of "match" — marks the chunk verified, after writing a chunk.json
// manifest into each of its stream folders.
//
// It deletes nothing (the retention gate, database/archive_gate.go, lets the
// deletes take only what it verified) and, after each pass, seals the months
// that are due (seal.go): a sealed month's folder is never written again.
// With ARCHIVE_SYSLOG_ENABLED and ARCHIVE_FLOWS_ENABLED both off the poller
// does not start it.
//
// Exclusion: a tick runs under the archive's own advisory lock
// (database.AcquireArchiveLock), never the shared poller work lock, so an
// export that takes minutes skips no monitoring tick, and one worker in the
// cluster archives at a time.
//
// Crash safety: every step is a database state (see database/archive_worker.go)
// and every object key is a function of the chunk, so a restart at any point
// resumes: an unfinished export or upload is exported and uploaded again (the
// same bytes to the same keys; the earlier attempt's object rows are
// superseded), an unfinished verification reads the objects back again.
package worker

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- the S3 ETag of a single-part object
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"
)

// Store is the bucket as the worker uses it; *s3.Client implements it.
type Store interface {
	Key(rel string) (string, error)
	Put(ctx context.Context, rel string, body io.ReaderAt, size int64, meta map[string]string) (s3.PutResult, error)
	Head(ctx context.Context, rel, versionID string) (s3.ObjectInfo, error)
	VerifyHead(ctx context.Context, want s3.PutResult) error
	VerifyFull(ctx context.Context, want s3.PutResult, w io.Writer) error
	Preflight(ctx context.Context) error
}

// Cadence. The poller calls Tick every TickInterval; marks are taken on every
// tick (and every markEvery during a long pass), chunks are planned and
// exported every passEvery.
const (
	TickInterval = time.Minute
	passEvery    = 10 * time.Minute
	markEvery    = time.Minute
	// planBatch bounds the chunks planned per table per round (a long syslog
	// backlog is planned over several rounds).
	planBatch = 64
)

// stagingMinFree is the free space the staging directory must have before a
// chunk is exported (a day of syslog is ~0.3-0.7 GB compressed). A variable
// so tests can raise it.
var stagingMinFree uint64 = 2 << 30

// stagingFree reports the free bytes of dir's filesystem; a variable so tests
// can stand in for it.
var stagingFree = func(ctx context.Context, dir string) (uint64, error) {
	u, err := disk.UsageWithContext(ctx, dir)
	if err != nil {
		return 0, err
	}
	return u.Free, nil
}

// stagingEntry is the name of a chunk's staging directory: the only entries
// the worker ever removes from the staging directory (an operator may point
// ARCHIVE_STAGING_DIR at a shared directory).
var stagingEntry = regexp.MustCompile(`^chunk-[0-9]+$`)

// Worker archives the enabled streams. Tick is safe to call concurrently (a
// second call returns at once while one runs).
type Worker struct {
	db      *database.Database
	store   Store
	cfg     config.ArchiveConfig
	tables  []string // enabled tables, in pass order: flows first (their rows are rolled up after ~1 h)
	marks   []string // enabled tables cut by id marks
	staging string
	window  struct {
		start, end int
		on         bool
	}
	now    func() time.Time
	runner string

	running   atomic.Bool
	preflight bool
	lastPass  time.Time
	cooldown  map[string]time.Time // table (or "seal-"+stream) → no new attempt before (after a bucket failure)
	// sealFailures counts a stream's consecutive seal attempts the service or
	// the database failed (their backoff).
	sealFailures map[string]int
	formatOnce   struct {
		done  bool
		month string // first month of syslog schema v2 ("" = every month)
	}
	logMu   sync.Mutex
	lastLog map[string]string

	// Test hooks (nil in production): called after the step named, with the
	// pass context; an error is returned from the step as if it had failed.
	afterPut      func(ctx context.Context, c *models.ArchiveChunk, o *models.ArchiveObject) error
	afterUploaded func(ctx context.Context, c *models.ArchiveChunk) error
	afterExport   func(ctx context.Context, c *models.ArchiveChunk) error
	beforeCount   func(ctx context.Context, c *models.ArchiveChunk) error
	beforeVerify  func(ctx context.Context, c *models.ArchiveChunk) error
	beforeMark    func(ctx context.Context, c *models.ArchiveChunk) error
}

// New builds the worker for the enabled streams of cfg over db, with the S3
// client from cfg. It prepares the staging directory (removing chunk
// directories a previous run left behind) and makes no network call.
func New(db *database.Database, cfg config.ArchiveConfig, opts ...s3.Option) (*Worker, error) {
	client, err := s3.New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	return newWorker(db, client, cfg)
}

func newWorker(db *database.Database, store Store, cfg config.ArchiveConfig) (*Worker, error) {
	w := &Worker{
		db: db, store: store, cfg: cfg, now: time.Now,
		cooldown: map[string]time.Time{}, sealFailures: map[string]int{}, lastLog: map[string]string{},
	}
	if cfg.FlowsEnabled {
		w.tables = append(w.tables, export.TableFlows, export.TableCounters)
		w.marks = append(w.marks, export.TableFlows, export.TableCounters)
	}
	if cfg.SyslogEnabled {
		w.tables = append(w.tables, export.TableSyslog)
	}
	start, end, on, err := cfg.WindowMinutes()
	if err != nil {
		return nil, err
	}
	w.window.start, w.window.end, w.window.on = start, end, on
	host, _ := os.Hostname()
	w.runner = fmt.Sprintf("%s-%d", host, os.Getpid())
	w.staging = cfg.StagingDir
	if w.staging == "" {
		// Config.Validate requires it; a temp-directory default would land
		// in a container's writable layer, often the database's disk.
		return nil, errors.New("archive: ARCHIVE_STAGING_DIR is required")
	}
	if err := os.MkdirAll(w.staging, 0o700); err != nil {
		return nil, fmt.Errorf("archive: staging directory %s: %w", w.staging, err)
	}
	ents, err := os.ReadDir(w.staging)
	if err != nil {
		return nil, fmt.Errorf("archive: staging directory %s: %w", w.staging, err)
	}
	for _, e := range ents {
		if e.IsDir() && stagingEntry.MatchString(e.Name()) {
			if err := os.RemoveAll(filepath.Join(w.staging, e.Name())); err != nil {
				return nil, fmt.Errorf("archive: clear staging %s: %w", e.Name(), err)
			}
		}
	}
	return w, nil
}

// Tables returns the source tables the worker archives, in pass order.
func (w *Worker) Tables() []string { return append([]string(nil), w.tables...) }

// logf logs msg under key unless the previous message under key was the same
// (a failure repeating every pass is logged once until it changes).
func (w *Worker) logf(key, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	w.logMu.Lock()
	same := w.lastLog[key] == msg
	w.lastLog[key] = msg
	w.logMu.Unlock()
	if !same {
		log.Print("archive: " + msg)
	}
}

func (w *Worker) clearLog(key string) {
	w.logMu.Lock()
	delete(w.lastLog, key)
	w.logMu.Unlock()
}

// Tick does the archive's work that is due: under the archive lock it checks
// the bucket once (Preflight) and takes the due id marks; every passEvery it
// also plans and exports the due chunks (see pass). Errors are logged and
// counted, never returned.
func (w *Worker) Tick(ctx context.Context) {
	if len(w.tables) == 0 || !w.running.CompareAndSwap(false, true) {
		return
	}
	defer w.running.Store(false)
	if ctx.Err() != nil {
		return
	}
	release, acquired, err := w.db.AcquireArchiveLock()
	if err != nil {
		metrics.IncArchiveError("lock")
		w.logf("lock", "advisory lock probe failed: %v", err)
		return
	}
	if !acquired {
		return
	}
	defer release()
	w.clearLog("lock")

	if !w.preflight {
		if err := w.store.Preflight(ctx); err != nil {
			if ctx.Err() == nil {
				metrics.IncArchiveError("preflight")
				w.logf("preflight", "bucket preflight failed (nothing is archived until it passes): %v", err)
			}
			return
		}
		w.preflight = true
		w.clearLog("preflight")
		log.Printf("archive: bucket preflight passed; archiving %v", w.tables)
	}
	w.takeMarks(ctx)
	if now := w.now(); !w.lastPass.IsZero() && now.Sub(w.lastPass) < passEvery {
		return
	}
	w.lastPass = w.now()
	w.pass(ctx)
}

// takeMarks records the due id marks of the flow tables.
func (w *Worker) takeMarks(ctx context.Context) {
	for _, t := range w.marks {
		if _, err := w.db.TakeArchiveIDMarks(ctx, t, w.now()); err != nil {
			if ctx.Err() == nil {
				metrics.IncArchiveError("mark")
				w.logf("mark-"+t, "id marks of %s: %v", t, err)
			}
			continue
		}
		w.clearLog("mark-" + t)
	}
}

// pass plans and works chunks until none of the enabled tables has a chunk
// that can make progress now, then seals the months that are due. Tables take
// turns one chunk at a time, flows first, so a long syslog backlog does not
// hold the hourly flow chunks back by more than one syslog chunk. Marks keep
// being taken while it runs.
func (w *Worker) pass(ctx context.Context) {
	markCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(markEvery)
		defer t.Stop()
		for {
			select {
			case <-markCtx.Done():
				return
			case <-t.C:
				w.takeMarks(markCtx)
			}
		}
	}()
	defer func() {
		stop()
		wg.Wait()
		if ctx.Err() == nil {
			w.publishProgress(ctx)
		}
	}()

	skip := map[string]bool{} // tables done for this pass
	for ctx.Err() == nil {
		progressed := false
		for _, t := range w.tables {
			if skip[t] || ctx.Err() != nil {
				continue
			}
			if t == export.TableSyslog && !w.inWindow(w.now()) {
				skip[t] = true
				continue
			}
			if !w.plan(ctx, t) {
				skip[t] = true
				continue
			}
			if w.workOne(ctx, t) == progressMade {
				progressed = true
			} else {
				// Nothing workable, waiting, or failed (retried after its
				// backoff): the table is done for this pass.
				skip[t] = true
			}
		}
		if !progressed {
			break
		}
	}
	if ctx.Err() == nil {
		w.sealDue(ctx)
	}
}

// inWindow reports whether ARCHIVE_WINDOW (UTC) allows a syslog chunk to
// start at t.
func (w *Worker) inWindow(t time.Time) bool {
	if !w.window.on {
		return true
	}
	t = t.UTC()
	m := t.Hour()*60 + t.Minute()
	if w.window.start < w.window.end {
		return m >= w.window.start && m < w.window.end
	}
	return m >= w.window.start || m < w.window.end
}

// plan cuts the table's chunks that are due (up to planBatch). It returns
// false when nothing of the table can be exported at all this pass (no
// statement_timeout: no cut can ever settle).
func (w *Worker) plan(ctx context.Context, table string) bool {
	for range planBatch {
		c, err := w.db.PlanNextArchiveChunk(ctx, table, w.now(), time.Duration(w.cfg.MinAgeHours)*time.Hour)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			if errors.Is(err, database.ErrArchiveNoStatementTimeout) {
				metrics.SetArchiveUnsettled(table, "no_statement_timeout")
				w.logf("plan-"+table, "%v", err)
				return false
			}
			if errors.Is(err, database.ErrArchiveLeafMove) {
				metrics.SetArchiveUnsettled(table, "unattached_leaf")
				w.logf("plan-"+table, "%s waits: %v", table, err)
				return false
			}
			// Already planned chunks can still be worked.
			metrics.IncArchiveError("plan")
			w.logf("plan-"+table, "plan %s: %v", table, err)
			return true
		}
		w.clearLog("plan-" + table)
		if c == nil {
			return true
		}
		log.Printf("archive: planned %s chunk %d: ids (%d, %d], period from %s", table, c.Seq, c.IDLo, c.IDHi, c.PeriodStart.UTC().Format(time.RFC3339))
	}
	return true
}

type progress int

const (
	progressNone progress = iota
	progressMade
	progressFailed
)

// stageError is a failed step of a chunk attempt; stage labels the metric.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.stage + ": " + e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

// errMismatch marks a finding that the archived copy is not the table's
// range (read-back content, count verdict, staged bytes): the only failures
// after an upload that re-export the chunk.
var errMismatch = errors.New("archive mismatch")

func mismatchErr(stage string, err error) error {
	return &stageError{stage: stage, err: fmt.Errorf("%w: %w", errMismatch, err)}
}

func isMismatch(err error) bool { return errors.Is(err, errMismatch) || errors.Is(err, s3.ErrMismatch) }

func stageErr(stage string, err error) error {
	if err == nil {
		return nil
	}
	var se *stageError
	if errors.As(err, &se) {
		return err
	}
	return &stageError{stage: stage, err: err}
}

// bucketStage: a failure talking to the bucket, which every chunk of the
// table would hit too — the table rests until the failed chunk's retry.
func bucketStage(stage string) bool {
	return stage == "upload" || stage == "verify" || stage == "manifest"
}

// workOne advances the table's oldest workable chunk by one attempt.
func (w *Worker) workOne(ctx context.Context, table string) progress {
	now := w.now()
	if until, ok := w.cooldown[table]; ok && now.Before(until) {
		return progressNone
	}
	c, err := w.db.NextArchiveChunk(ctx, table, now)
	if err != nil {
		if ctx.Err() == nil {
			metrics.IncArchiveError("db")
			w.logf("next-"+table, "%v", err)
		}
		return progressNone
	}
	if c == nil {
		metrics.SetArchiveUnsettled(table, "")
		return progressNone
	}
	if c.Status != models.ArchiveChunkVerifying {
		// Exporting needs the cut settled; checking first keeps a chunk that
		// is merely waiting from counting an attempt.
		if err := w.db.ArchiveChunkSettled(ctx, c); err != nil {
			if ctx.Err() != nil {
				return progressNone
			}
			var un *database.ArchiveUnsettledError
			switch {
			case errors.As(err, &un) && un.SettleLeft > 0:
				metrics.SetArchiveUnsettled(table, "settling")
			case errors.As(err, &un):
				metrics.SetArchiveUnsettled(table, "open_writer")
				w.logf("settle-"+table, "%s chunk %d waits: %v", table, c.Seq, err)
			case errors.Is(err, database.ErrArchiveNoStatementTimeout):
				metrics.SetArchiveUnsettled(table, "no_statement_timeout")
				w.logf("settle-"+table, "%v", err)
			case errors.Is(err, database.ErrArchiveLeafMove):
				metrics.SetArchiveUnsettled(table, "unattached_leaf")
				w.logf("settle-"+table, "%s chunk %d waits: %v", table, c.Seq, err)
			default:
				metrics.IncArchiveError("settle")
				w.logf("settle-"+table, "%s chunk %d: settle check: %v", table, c.Seq, err)
			}
			return progressNone
		}
		w.clearLog("settle-" + table)
	}
	metrics.SetArchiveUnsettled(table, "")

	if err := w.db.ClaimArchiveChunk(ctx, c, w.runner); err != nil {
		if ctx.Err() == nil {
			metrics.IncArchiveError("db")
			w.logf("claim-"+table, "%s chunk %d: claim: %v", table, c.Seq, err)
		}
		return progressNone
	}
	err = w.process(ctx, c)
	if err == nil {
		delete(w.cooldown, table)
		return progressMade
	}
	if ctx.Err() != nil {
		// Shutdown: leave the chunk in its state; the next run resumes it.
		return progressNone
	}
	if errors.Is(err, errSealedWrite) {
		// A chunk of a sealed month is not verified (only by hand can that
		// be): no retry may write it, and the folder must not change.
		metrics.IncArchiveError("sealed")
		if perr := w.db.ParkArchiveChunk(ctx, c, err.Error(), w.now()); perr != nil {
			metrics.IncArchiveError("db")
			log.Printf("archive: %s chunk %d: park: %v", table, c.Seq, perr)
		} else {
			metrics.IncArchiveNeedsAttention(table)
		}
		log.Printf("archive: %s chunk %d NEEDS ATTENTION: %v", table, c.Seq, err)
		return progressFailed
	}
	if errors.Is(err, database.ErrArchiveLeafMove) {
		// Partition maintenance is (or was, during this export or count)
		// moving rows through a standalone leaf: a wait, not a failure.
		// The chunk keeps its state — an exporting one is exported again,
		// a verifying one read back again — once the move is over.
		metrics.SetArchiveUnsettled(table, "unattached_leaf")
		w.logf("leaf-"+table, "%s chunk %d waits: %v", table, c.Seq, err)
		return progressNone
	}
	w.clearLog("leaf-" + table)
	stage := "db"
	var se *stageError
	if errors.As(err, &se) {
		stage = se.stage
	}
	metrics.IncArchiveError(stage)
	at := w.now()
	var ferr error
	switch {
	case isMismatch(err):
		// The archived copy is wrong: re-export, a bounded number of times.
		var parked bool
		parked, ferr = w.db.RecordArchiveMismatch(ctx, c, err.Error(), at)
		if parked {
			metrics.IncArchiveNeedsAttention(table)
			log.Printf("archive: %s chunk %d NEEDS ATTENTION: %d exports did not match; it is no longer retried (last: %v)", table, c.Seq, c.Mismatches, err)
		} else {
			log.Printf("archive: %s chunk %d (attempt %d) mismatch, re-exported after its backoff: %v", table, c.Seq, c.Attempts, err)
		}
	case c.Status == models.ArchiveChunkVerifying:
		// Uploaded, and nothing found wrong: read it back again later
		// instead of writing another Object Lock-retained copy.
		ferr = w.db.DeferArchiveVerify(ctx, c, err.Error(), at)
		log.Printf("archive: %s chunk %d verification failed (%d in a row), retried after its backoff: %v", table, c.Seq, c.VerifyFailures, err)
		if bucketStage(stage) {
			w.cooldown[table] = at.Add(database.ArchiveRetryBackoff(c.VerifyFailures))
		}
	default:
		log.Printf("archive: %s chunk %d (attempt %d) failed at %v", table, c.Seq, c.Attempts, err)
		ferr = w.db.FailArchiveChunk(ctx, c, err.Error(), at)
		if bucketStage(stage) {
			w.cooldown[table] = at.Add(database.ArchiveRetryBackoff(c.Attempts))
		}
	}
	if ferr != nil {
		metrics.IncArchiveError("db")
		log.Printf("archive: %s chunk %d: record the failure: %v", table, c.Seq, ferr)
	}
	return progressFailed
}

// process runs one attempt of chunk c from its state to verified.
func (w *Worker) process(ctx context.Context, c *models.ArchiveChunk) error {
	if err := w.refuseSealed(ctx, c); err != nil {
		return err
	}
	if c.Status != models.ArchiveChunkVerifying {
		if err := w.exportUpload(ctx, c); err != nil {
			return err
		}
	}
	return w.verify(ctx, c)
}

// hourly reports whether table's chunks are hourly folders.
func hourly(table string) bool { return table == export.TableFlows }

// schemaFor is the schema version of every object and manifest of chunk c:
// flows and counters v1; syslog v1 for months before the stored `format`
// (migration v74) existed, v2 from the month it was applied.
func (w *Worker) schemaFor(ctx context.Context, c *models.ArchiveChunk) (int, error) {
	switch c.SourceTable {
	case export.TableFlows:
		return export.FlowSchemaV1, nil
	case export.TableCounters:
		return export.CounterSchemaV1, nil
	}
	if !w.formatOnce.done {
		at, ok, err := w.db.ArchiveSyslogFormatSince(ctx)
		if err != nil {
			return 0, fmt.Errorf("archive: when the syslog format column was added: %w", err)
		}
		if ok {
			w.formatOnce.month = export.MonthOf(at)
		}
		w.formatOnce.done = true
	}
	if w.formatOnce.month != "" && c.Month < w.formatOnce.month {
		return export.SyslogSchemaV1, nil
	}
	return export.SyslogSchemaV2, nil
}

// rel is an object's key below the prefix.
func (w *Worker) rel(key string) (string, error) {
	p := w.cfg.Prefix + "/"
	if len(key) <= len(p) || key[:len(p)] != p {
		return "", fmt.Errorf("object key %q is not under the prefix %q", key, w.cfg.Prefix)
	}
	return key[len(p):], nil
}

func (w *Worker) rate(table string) int {
	if table == export.TableSyslog {
		return w.cfg.SyslogRateRowsPerSec
	}
	return w.cfg.FlowRateRowsPerSec
}

// exportUpload exports c into its staging directory and uploads every object,
// leaving the chunk in verifying.
func (w *Worker) exportUpload(ctx context.Context, c *models.ArchiveChunk) error {
	free, err := stagingFree(ctx, w.staging)
	switch {
	case err != nil:
		return stageErr("stage", fmt.Errorf("free space of the staging directory %s unknown: %w", w.staging, err))
	case free < stagingMinFree:
		return stageErr("stage", fmt.Errorf("staging directory %s has %d MiB free, below the %d MiB floor", w.staging, free>>20, stagingMinFree>>20))
	}
	schema, err := w.schemaFor(ctx, c)
	if err != nil {
		return stageErr("db", err)
	}
	reuse, err := w.db.BeginArchiveChunkExport(ctx, c, w.runner, w.now())
	if err != nil {
		return stageErr("db", err)
	}
	dir := filepath.Join(w.staging, "chunk-"+strconv.FormatUint(uint64(c.ID), 10))
	if err := os.RemoveAll(dir); err != nil {
		return stageErr("stage", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return stageErr("stage", err)
	}
	defer os.RemoveAll(dir)
	files := map[export.ObjectID]*os.File{}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	open := func(id export.ObjectID) (io.Writer, error) {
		name := id.Stream
		if id.HasDevice {
			name += "-device-" + strconv.FormatUint(uint64(id.DeviceID), 10)
		}
		f, err := os.OpenFile(filepath.Join(dir, name+".ndjson.gz"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		files[id] = f
		return f, nil
	}
	// A partition move (rows leaving the DEFAULT child through a standalone
	// leaf, invisible through the parent) during the export could leave rows
	// out of it: read the move epoch around it and wait instead (see
	// database.ErrArchiveLeafMove). Never a mismatch: a routine partition
	// pass must not park a chunk in needs_attention.
	epoch, err := w.db.ArchiveLeafEpoch(ctx, c.SourceTable)
	if err != nil {
		return stageErr("settle", err)
	}
	res, err := w.db.ExportArchiveChunk(ctx, c, schema, database.ArchiveReadOptions{RowsPerSec: w.rate(c.SourceTable)}, open)
	if err != nil {
		var un *database.ArchiveUnsettledError
		if errors.As(err, &un) {
			return stageErr("settle", err)
		}
		return stageErr("read", err)
	}
	if w.afterExport != nil {
		if err := w.afterExport(ctx, c); err != nil {
			return stageErr("read", err)
		}
	}
	if after, err := w.db.ArchiveLeafEpoch(ctx, c.SourceTable); err != nil {
		return stageErr("settle", err)
	} else if after != epoch {
		return stageErr("settle", fmt.Errorf("%w: a partition move ran during the export of %s chunk %d", database.ErrArchiveLeafMove, c.SourceTable, c.Seq))
	}

	objs := make([]models.ArchiveObject, len(res.Objects))
	for i, o := range res.Objects {
		key, err := w.store.Key(export.ObjectRel(o.ID, schema, c.PeriodStart, hourly(c.SourceTable)))
		if err != nil {
			return stageErr("stage", err)
		}
		objs[i] = models.ArchiveObject{
			ChunkID: c.ID, Stream: o.ID.Stream, ObjectKey: key, SchemaVersion: o.SchemaVersion, Compression: o.Compression,
			RowCount: o.Rows, RawBytes: o.RawBytes, ObjectBytes: o.ObjectBytes,
			Sha256Content: o.Sha256Content, Sha256Object: o.Sha256Object,
			MinID: o.MinID, MaxID: o.MaxID, Status: models.ArchiveObjectPending,
		}
		if o.ID.HasDevice {
			dev := o.ID.DeviceID
			objs[i].DeviceID = &dev
		}
		if o.Rows > 0 {
			lo, hi := o.MinTs.UTC(), o.MaxTs.UTC()
			objs[i].MinTs, objs[i].MaxTs = &lo, &hi
		}
		h, err := histogramJSON(o.MsgDays)
		if err != nil {
			return stageErr("stage", err)
		}
		objs[i].MsgDayHistogram = &h
	}
	if err := w.db.RecordArchiveExport(ctx, c, objs, w.now()); err != nil {
		return stageErr("db", err)
	}

	for i, o := range res.Objects {
		obj := &objs[i]
		f := files[o.ID]
		if err := f.Sync(); err != nil {
			return stageErr("stage", err)
		}
		rel, err := w.rel(obj.ObjectKey)
		if err != nil {
			return stageErr("stage", err)
		}
		meta := map[string]string{
			"fwmon-archive-schema":         strconv.Itoa(obj.SchemaVersion),
			"fwmon-archive-stream":         obj.Stream,
			"fwmon-archive-sha256-content": obj.Sha256Content,
			"fwmon-archive-rows":           strconv.FormatInt(obj.RowCount, 10),
		}
		if old, ok := reuse[obj.ObjectKey]; ok && old.Sha256Object == obj.Sha256Object && old.ObjectBytes == obj.ObjectBytes && old.ETag != "" {
			// An earlier attempt uploaded these exact bytes (and its copy
			// never failed a read-back): do not write another retained
			// copy; the read-back below verifies the one there.
			if err := w.db.MarkArchiveObjectUploaded(ctx, obj, old.ETag, old.VersionID, old.PartCount, old.LockUntil, w.now()); err != nil {
				return stageErr("db", err)
			}
			continue
		}
		put, err := w.put(ctx, rel, f, obj.ObjectBytes, meta)
		if err != nil {
			return stageErr("upload", err)
		}
		if put.SHA256 != obj.Sha256Object {
			// The staged file is not the bytes the exporter hashed.
			return mismatchErr("stage", fmt.Errorf("staged %s hashed %s at upload, the export wrote %s", rel, put.SHA256, obj.Sha256Object))
		}
		if w.afterPut != nil {
			if err := w.afterPut(ctx, c, obj); err != nil {
				return stageErr("upload", err)
			}
		}
		var lockUntil *time.Time
		if !put.RetainUntil.IsZero() {
			lu := put.RetainUntil
			lockUntil = &lu
		}
		if err := w.db.MarkArchiveObjectUploaded(ctx, obj, put.ETag, put.VersionID, put.Parts, lockUntil, w.now()); err != nil {
			return stageErr("db", err)
		}
	}
	if w.afterUploaded != nil {
		if err := w.afterUploaded(ctx, c); err != nil {
			return stageErr("upload", err)
		}
	}
	if err := w.db.SetArchiveChunkStatus(ctx, c, models.ArchiveChunkVerifying, w.now()); err != nil {
		return stageErr("db", err)
	}
	return nil
}

// putResult is what the verify helpers compare a stored object against.
func (w *Worker) putResult(o *models.ArchiveObject) (s3.PutResult, error) {
	rel, err := w.rel(o.ObjectKey)
	if err != nil {
		return s3.PutResult{}, err
	}
	r := s3.PutResult{Rel: rel, Key: o.ObjectKey, Size: o.ObjectBytes, SHA256: o.Sha256Object, ETag: o.ETag, Parts: o.PartCount, VersionID: o.VersionID}
	if o.LockUntil != nil {
		r.RetainUntil = o.LockUntil.UTC()
	}
	return r, nil
}

// verify reads every uploaded object of c back in full (stored bytes against
// sha256_object, decompressed bytes against sha256_content, every line JSON
// with an id in the chunk's range, in order), recounts the chunk's id range in
// the table against what the bucket holds, writes the chunk manifests and
// marks the chunk verified. Any mismatch fails the attempt: the next one
// exports the chunk again and supersedes these objects.
func (w *Worker) verify(ctx context.Context, c *models.ArchiveChunk) error {
	if w.beforeVerify != nil {
		if err := w.beforeVerify(ctx, c); err != nil {
			return stageErr("verify", err)
		}
	}
	objs, err := w.db.ArchiveChunkObjects(ctx, c.ID)
	if err != nil {
		return stageErr("db", err)
	}
	var got export.ChunkResult
	for i := range objs {
		o := &objs[i]
		if o.Status != models.ArchiveObjectUploaded {
			return mismatchErr("verify", fmt.Errorf("object %s is %s, not uploaded", o.ObjectKey, o.Status))
		}
		want, err := w.putResult(o)
		if err != nil {
			return stageErr("verify", err)
		}
		if err := w.store.VerifyHead(ctx, want); err != nil {
			return stageErr("verify", err)
		}
		chk := newContentCheck(c, o)
		verr := w.store.VerifyFull(ctx, want, chk)
		cerr := chk.finish()
		if verr != nil {
			return stageErr("verify", verr)
		}
		if cerr != nil {
			return mismatchErr("verify", fmt.Errorf("%s: %w", o.ObjectKey, cerr))
		}
		got.Rows += chk.rows
		got.IDSum += chk.idSum
		got.IDHash += chk.idHash
	}
	if w.beforeCount != nil {
		if err := w.beforeCount(ctx, c); err != nil {
			return stageErr("count", err)
		}
	}
	cnt, err := w.db.CheckArchiveChunkCount(ctx, c, &got)
	if err != nil {
		return stageErr("db", err)
	}
	if !cnt.Verifiable() {
		return mismatchErr("count", fmt.Errorf("count check %s: the table holds %d rows (id sum %d) in (%d, %d], the bucket %d (id sum %d)",
			cnt.Verdict, cnt.Rows, cnt.IDSum, c.IDLo, c.IDHi, cnt.ExportedRows, cnt.ExportedIDSum))
	}
	schema, err := w.schemaFor(ctx, c)
	if err != nil {
		return stageErr("db", err)
	}
	for _, stream := range export.StreamsOf(c.SourceTable) {
		if err := w.putManifest(ctx, c, stream, schema, objs); err != nil {
			return stageErr("manifest", err)
		}
	}
	if w.beforeMark != nil {
		if err := w.beforeMark(ctx, c); err != nil {
			return stageErr("db", err)
		}
	}
	at := w.now()
	if err := w.db.MarkArchiveChunkVerified(ctx, c, objs, at); err != nil {
		return stageErr("db", err)
	}
	for i := range objs {
		metrics.AddArchiveVerifiedObject(objs[i].Stream, objs[i].RowCount, objs[i].RawBytes, objs[i].ObjectBytes)
	}
	for _, stream := range export.StreamsOf(c.SourceTable) {
		metrics.SetArchiveLastSuccess(stream, at)
	}
	log.Printf("archive: %s chunk %d verified (%s, %d rows, %d objects)", c.SourceTable, c.Seq, c.PeriodStart.UTC().Format(time.RFC3339), c.RowCount, len(objs))
	return nil
}

// putManifest uploads the chunk.json of one stream folder of c and reads it
// back.
func (w *Worker) putManifest(ctx context.Context, c *models.ArchiveChunk, stream string, schema int, objs []models.ArchiveObject) error {
	body, err := chunkManifestJSON(c, stream, schema, objs)
	if err != nil {
		return err
	}
	rel := export.FolderRel(stream, schema, c.PeriodStart, hourly(c.SourceTable)) + "/" + export.ChunkManifestName
	// A verification resumed after a crash or a transient failure may find
	// this exact manifest already stored: read that one back instead of
	// writing another retained copy.
	sum := md5.Sum(body) // #nosec G401 -- the S3 ETag of a single-part object
	if info, err := w.store.Head(ctx, rel, ""); err == nil && info.Size == int64(len(body)) && info.ETag == hex.EncodeToString(sum[:]) {
		sha := sha256.Sum256(body)
		return w.store.VerifyFull(ctx, s3.PutResult{Rel: rel, Key: info.Key, Size: info.Size, SHA256: hex.EncodeToString(sha[:]),
			ETag: info.ETag, VersionID: info.VersionID}, nil)
	} else if err != nil && !errors.Is(err, s3.ErrNotFound) {
		return err
	}
	put, err := w.put(ctx, rel, bytes.NewReader(body), int64(len(body)), map[string]string{
		"fwmon-archive-schema": strconv.Itoa(schema), "fwmon-archive-stream": stream,
	})
	if err != nil {
		return err
	}
	return w.store.VerifyFull(ctx, put, nil)
}

// publishProgress sets the lag, V and chunk-count gauges of every enabled
// table.
func (w *Worker) publishProgress(ctx context.Context) {
	counts, err := w.db.ArchiveChunkStatusCounts(ctx)
	if err != nil {
		w.logf("progress", "chunk counts: %v", err)
		return
	}
	now := w.now()
	for _, t := range w.tables {
		for _, s := range []string{models.ArchiveChunkPending, models.ArchiveChunkExporting, models.ArchiveChunkUploading,
			models.ArchiveChunkVerifying, models.ArchiveChunkVerified, models.ArchiveChunkFailed, models.ArchiveChunkNeedsAttention} {
			metrics.SetArchiveChunks(t, s, counts[t][s])
		}
		p, err := w.db.ArchiveTableProgress(ctx, t)
		if err != nil {
			w.logf("progress", "progress of %s: %v", t, err)
			return
		}
		if !p.Chunks {
			continue
		}
		metrics.SetArchiveVerifiedThrough(t, p.VerifiedThroughID)
		since := *p.FirstStart
		if p.VerifiedThroughEnd != nil {
			since = *p.VerifiedThroughEnd
		}
		for _, s := range export.StreamsOf(t) {
			metrics.SetArchiveLag(s, max(0, now.Sub(since)))
		}
	}
	w.clearLog("progress")
}
