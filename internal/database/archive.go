package database

import (
	"context"
	"fmt"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// The raw archive's chunk planner and export reads (archive plan PR 3, §2.1).
// Nothing here runs on its own: the archive worker that takes marks, plans,
// exports, uploads and verifies on a timer is a later release, so this
// release changes no behaviour.
//
// A chunk is an id range (id_lo, id_hi] of one table, cut at a UTC period
// boundary, contiguous with the previous chunk (the first starts at id 0):
//   - syslog_messages, daily: id_hi is the largest id whose created_at (the
//     ingest stamp) is before the day's end, found by binary search of the
//     primary key — about 40 one-row index probes, never a scan;
//   - flow_samples (hourly) and flow_if_counters (daily) have no ingest column
//     to search, so the worker records max(id) at each boundary
//     (archive_id_marks) and the chunk for [b - period, b) ends at the mark of
//     b. A mark taken late puts the rows that arrived meanwhile in the earlier
//     chunk; mark_late_by_ms records it.
//
// The month of a chunk is the ingest month of its period start, so every row
// lands in exactly one month folder.

// archiveTable is one archived table's cut rule.
type archiveTable struct {
	name   string
	period time.Duration
	// byMark: cut by archive_id_marks (the flow tables); otherwise by binary
	// search of created_at (syslog).
	byMark bool
	// minAge: how long after a period ends its chunk may be cut. Flows are
	// rolled up (and deleted) after about an hour, so theirs is fixed short;
	// syslog and counters default to ARCHIVE_MIN_AGE_HOURS' default.
	minAge      time.Duration
	minAgeFixed bool
}

var archiveTables = map[string]archiveTable{
	export.TableSyslog:   {name: export.TableSyslog, period: 24 * time.Hour, minAge: 2 * time.Hour},
	export.TableFlows:    {name: export.TableFlows, period: time.Hour, byMark: true, minAge: 5 * time.Minute, minAgeFixed: true},
	export.TableCounters: {name: export.TableCounters, period: 24 * time.Hour, byMark: true, minAge: 2 * time.Hour},
}

func archiveTableOf(name string) (archiveTable, error) {
	t, ok := archiveTables[name]
	if !ok {
		return archiveTable{}, fmt.Errorf("archive: %q is not an archived table", name)
	}
	return t, nil
}

// archiveMarkSettle: how long after a mark (database clock) its chunk may be
// cut. A transaction reserves an id (nextval) a moment before its first
// INSERT gives it a transaction id; a snapshot taken this long after the mark
// is certain to include the xid of every transaction that reserved an id at
// or below it.
const archiveMarkSettle = time.Second

// archiveMaxFirstAge bounds how far back the first syslog chunk may start. The
// oldest row's created_at should be the retention edge (about a month); one
// older than this is a forged or broken stamp (before 0.11.300 a probe body
// could set it), and planning would otherwise cut one chunk per day back to
// it. A variable so a test can shrink it.
var archiveMaxFirstAge = 400 * 24 * time.Hour

// archivePageSize is the keyset page of an export read.
const archivePageSize = 5000

// archivePeriodStart is the UTC period (day or hour) holding t.
func archivePeriodStart(t time.Time, period time.Duration) time.Time {
	t = t.UTC()
	if period == 24*time.Hour {
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
	return t.Truncate(period)
}

// ArchiveUnsettledError: a transaction that may still commit rows into the
// chunk's id range is open — one whose transaction id was assigned before the
// chunk was cut (GuardXmax) is still running (Xmin is the oldest running xid).
// The export waits; a later attempt retries. Read-only transactions (a
// pg_dump, a report) never hold a transaction id and never block.
type ArchiveUnsettledError struct {
	GuardXmax int64
	Xmin      int64
}

func (e *ArchiveUnsettledError) Error() string {
	return fmt.Sprintf("archive: a writing transaction older than the cut is still open (oldest running xid %d, cut at xid %d)", e.Xmin, e.GuardXmax)
}

// archiveSnapshot is the xmin / xmax of a fresh snapshot (pg_current_snapshot)
// and the database clock. Every transaction id below xmax had been assigned
// when it was taken; every one below xmin has finished. Transaction ids are
// assigned only to transactions that write, whatever their role, so this sees
// every writer and nothing else. xid8 (64-bit, no wraparound) fits a bigint.
type archiveSnapshot struct {
	Xmin, Xmax int64
	At         time.Time
}

func (d *Database) archiveSnapshot(ctx context.Context) (archiveSnapshot, error) {
	var s archiveSnapshot
	err := d.db.WithContext(ctx).Raw(`SELECT pg_snapshot_xmin(s)::text::bigint AS xmin, pg_snapshot_xmax(s)::text::bigint AS xmax,
		clock_timestamp() AS at FROM pg_current_snapshot() AS s`).Scan(&s).Error
	return s, err
}

// ArchiveChunkSettled returns *ArchiveUnsettledError while a transaction that
// was assigned its id before c was cut is still running: such a transaction
// may hold rows at or below id_hi that are not visible yet. Clear once the
// oldest running transaction id is at or above the cut's (guard_xmax). Always
// clear on SQLite (no concurrent writer in tests) and for a chunk without a
// guard.
func (d *Database) ArchiveChunkSettled(ctx context.Context, c *models.ArchiveChunk) error {
	if !d.dialect.IsPostgres() || c.GuardXmax == nil {
		return nil
	}
	s, err := d.archiveSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("archive: snapshot: %w", err)
	}
	if s.Xmin < *c.GuardXmax {
		return &ArchiveUnsettledError{GuardXmax: *c.GuardXmax, Xmin: s.Xmin}
	}
	return nil
}

// archiveMaxID is the table's unfiltered max(id) — a single backward probe of
// the primary key, cheap at any size (syslog_agg.go explains why only the
// unfiltered form is) — with the database clock at the read on PostgreSQL. It
// runs on a pooled connection under the DSN's 30 s statement_timeout, ample
// for one descent.
func (d *Database) archiveMaxID(ctx context.Context, t archiveTable) (int64, time.Time, error) {
	var r struct {
		MaxID   int64
		TakenAt time.Time
	}
	// t.name comes from archiveTables, never from input.
	if d.dialect.IsPostgres() {
		err := d.db.WithContext(ctx).Raw(fmt.Sprintf(`SELECT COALESCE(max(id), 0) AS max_id, clock_timestamp() AS taken_at FROM %s`, t.name)).Scan(&r).Error
		return r.MaxID, r.TakenAt.UTC(), err
	}
	err := d.db.WithContext(ctx).Raw(fmt.Sprintf(`SELECT COALESCE(max(id), 0) AS max_id FROM %s`, t.name)).Scan(&r).Error
	return r.MaxID, time.Now().UTC(), err
}

// TakeArchiveIDMarks records the id marks of a flow table due at now: every
// period boundary after its newest mark up to the period start of now (the
// very first mark: that boundary only), each with the current max(id) and the
// database clock. A boundary missed while the poller was down gets the same
// late mark, so the outage's rows land in the earliest open chunk. Returns how
// many marks were added. Idempotent per boundary.
//
// The archive worker calls it under its own advisory lock, so one caller
// reads the newest mark and inserts the next ones at a time. Two concurrent
// callers could not corrupt anything — the (table_name, boundary_ts) key and
// ON CONFLICT DO NOTHING keep the first mark of a boundary — but the loser's
// marks would be dropped silently, so the lock is relied on.
func (d *Database) TakeArchiveIDMarks(ctx context.Context, table string, now time.Time) (int, error) {
	t, err := archiveTableOf(table)
	if err != nil {
		return 0, err
	}
	if !t.byMark {
		return 0, fmt.Errorf("archive: %s is cut by created_at, not by id marks", table)
	}
	due := archivePeriodStart(now, t.period)
	var last []models.ArchiveIDMark
	if err := d.db.WithContext(ctx).Where("table_name = ?", table).Order("boundary_ts DESC").Limit(1).Find(&last).Error; err != nil {
		return 0, fmt.Errorf("archive: newest %s mark: %w", table, err)
	}
	var boundaries []time.Time
	if len(last) == 0 {
		boundaries = []time.Time{due}
	} else {
		for b := last[0].BoundaryTs.UTC().Add(t.period); !b.After(due); b = b.Add(t.period) {
			boundaries = append(boundaries, b)
		}
	}
	if len(boundaries) == 0 {
		return 0, nil
	}
	maxID, takenAt, err := d.archiveMaxID(ctx, t)
	if err != nil {
		return 0, fmt.Errorf("archive: max(id) of %s: %w", table, err)
	}
	// Ids are never reused, so a lower max(id) only means the newest rows were
	// purged since the last mark: keep the marks monotonic.
	if len(last) > 0 && maxID < last[0].MaxID {
		maxID = last[0].MaxID
	}
	marks := make([]models.ArchiveIDMark, len(boundaries))
	for i, b := range boundaries {
		marks[i] = models.ArchiveIDMark{SourceTable: table, BoundaryTs: b, MaxID: maxID, TakenAt: takenAt}
	}
	res := d.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&marks)
	if res.Error != nil {
		return 0, fmt.Errorf("archive: record %s marks: %w", table, res.Error)
	}
	return int(res.RowsAffected), nil
}

// archiveRowProbe is one primary-key probe of the syslog cut search.
type archiveRowProbe struct {
	ID        int64
	CreatedAt time.Time
}

// archiveSyslogProbeQuery is the first row at or after id x — one descent of
// the primary key (on a partitioned table, of each leaf's (id, timestamp)
// key under a Merge Append). Separate so the plan test EXPLAINs it.
func archiveSyslogProbeQuery(tx *gorm.DB, x int64) *gorm.DB {
	return tx.Table(export.TableSyslog).Select("id, created_at").Where("id >= ?", x).Order("id").Limit(1)
}

// archiveSyslogCut returns the largest syslog_messages id created before end,
// searching (lo, max(id)]: the smallest x whose first row at or after it was
// created at or after end (or does not exist), minus one. created_at is
// stamped just before the INSERT, so it rises with id up to concurrent
// batches interleaving by a second or so; wherever the search lands, the cut
// is a single id, so every row is still in exactly one chunk.
func (d *Database) archiveSyslogCut(ctx context.Context, lo int64, end time.Time) (int64, error) {
	t := archiveTables[export.TableSyslog]
	maxID, _, err := d.archiveMaxID(ctx, t)
	if err != nil {
		return 0, fmt.Errorf("archive: max(id) of syslog_messages: %w", err)
	}
	if maxID <= lo {
		return lo, nil
	}
	// Invariant: the answer x lies in [a, b]; P(b) holds (beyond max(id)
	// there is no row at planning time).
	a, b := lo+1, maxID+1
	err = d.boundedReadContext(ctx, func(tx *gorm.DB) error {
		for a < b {
			mid := a + (b-a)/2
			var row []archiveRowProbe
			if err := archiveSyslogProbeQuery(tx, mid).Scan(&row).Error; err != nil {
				return err
			}
			if len(row) == 0 || !row[0].CreatedAt.Before(end) {
				b = mid
				continue
			}
			// The first row at or after mid was created before end, so
			// every x up to its id fails too.
			a = min(row[0].ID+1, b)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("archive: syslog cut before %s: %w", end.UTC().Format(time.RFC3339), err)
	}
	return a - 1, nil
}

// PlanNextArchiveChunk cuts the next chunk of table if it is due at now and
// records it (status pending). It returns nil, nil when nothing is due: no row
// yet, the period not yet minAge old, or (flow tables) its closing mark not
// yet taken (or taken less than archiveMarkSettle ago).
//
// The cut is recorded with guard_xmax, the xmax of a snapshot taken after it:
// a transaction that may still commit rows at or below id_hi had its
// transaction id by then, so ArchiveChunkSettled holds the export until every
// such transaction has finished. Planning itself never waits on other
// sessions: a row created before the boundary that commits after the search
// simply has an id above id_hi and lands in the next chunk (still exactly one).
// The one window this leaves — an id reserved by nextval in the microseconds
// before its transaction got an xid, while a later id committed and was read
// as the cut — is what the post-export count check (late_commit) catches.
//
// Clocks: now and created_at are the application's clock; marks' taken_at is
// the database's. They are compared only to the hour-scale minimum ages, so
// a skew of seconds between the two is harmless.
//
// The archive worker calls this under its advisory lock, one caller at a
// time; a concurrent caller would fail on the (table_name, seq) and
// (table_name, period_start) unique keys rather than record an overlap.
//
// minAge applies to syslog and counters (ARCHIVE_MIN_AGE_HOURS; 0 = the 2 h
// default); flows always use 5 minutes, because the rollup deletes raw flows
// after about an hour.
func (d *Database) PlanNextArchiveChunk(ctx context.Context, table string, now time.Time, minAge time.Duration) (*models.ArchiveChunk, error) {
	t, err := archiveTableOf(table)
	if err != nil {
		return nil, err
	}
	if minAge <= 0 || t.minAgeFixed {
		minAge = t.minAge
	}
	var last []models.ArchiveChunk
	if err := d.db.WithContext(ctx).Where("table_name = ?", table).Order("seq DESC").Limit(1).Find(&last).Error; err != nil {
		return nil, fmt.Errorf("archive: last %s chunk: %w", table, err)
	}
	next := models.ArchiveChunk{SourceTable: table, Seq: 1, Status: models.ArchiveChunkPending}
	switch {
	case len(last) > 0:
		next.Seq, next.IDLo, next.PeriodStart = last[0].Seq+1, last[0].IDHi, last[0].PeriodEnd.UTC()
	case t.byMark:
		// The first chunk ends at the first mark ever taken and starts at id
		// 0: it holds every row still present then.
		var first []models.ArchiveIDMark
		if err := d.db.WithContext(ctx).Where("table_name = ?", table).Order("boundary_ts").Limit(1).Find(&first).Error; err != nil {
			return nil, fmt.Errorf("archive: first %s mark: %w", table, err)
		}
		if len(first) == 0 {
			return nil, nil
		}
		next.PeriodStart = first[0].BoundaryTs.UTC().Add(-t.period)
	default:
		// The first syslog chunk starts at id 0, in the ingest day of the
		// oldest row still present.
		var row []archiveRowProbe
		if err := archiveSyslogProbeQuery(d.db.WithContext(ctx), 1).Scan(&row).Error; err != nil {
			return nil, fmt.Errorf("archive: oldest syslog row: %w", err)
		}
		if len(row) == 0 {
			return nil, nil
		}
		first := row[0].CreatedAt
		if first.After(now.Add(time.Hour)) || first.Before(now.Add(-archiveMaxFirstAge)) {
			// Refuse rather than plan a chunk per day back to a forged stamp
			// (or wait forever for a future one); the operator decides.
			return nil, fmt.Errorf("archive: the oldest syslog row (id %d) has created_at %s, outside [now - %s, now]: not planning from it",
				row[0].ID, first.UTC().Format(time.RFC3339), archiveMaxFirstAge)
		}
		next.PeriodStart = archivePeriodStart(first, t.period)
	}
	next.PeriodEnd = next.PeriodStart.Add(t.period)
	next.Month = export.MonthOf(next.PeriodStart)
	if now.Before(next.PeriodEnd.Add(minAge)) {
		return nil, nil
	}

	var markTakenAt time.Time
	if t.byMark {
		var mark []models.ArchiveIDMark
		if err := d.db.WithContext(ctx).Where("table_name = ? AND boundary_ts = ?", table, next.PeriodEnd).Limit(1).Find(&mark).Error; err != nil {
			return nil, fmt.Errorf("archive: %s mark at %s: %w", table, next.PeriodEnd.Format(time.RFC3339), err)
		}
		if len(mark) == 0 {
			return nil, nil
		}
		m := mark[0]
		if m.MaxID < next.IDLo {
			return nil, fmt.Errorf("archive: %s mark at %s (max id %d) is below the previous chunk's end %d", table, next.PeriodEnd.Format(time.RFC3339), m.MaxID, next.IDLo)
		}
		late := m.TakenAt.Sub(next.PeriodEnd).Milliseconds()
		next.IDHi, next.MarkLateByMs, markTakenAt = m.MaxID, &late, m.TakenAt
	} else if next.IDHi, err = d.archiveSyslogCut(ctx, next.IDLo, next.PeriodEnd); err != nil {
		return nil, err
	}
	if d.dialect.IsPostgres() {
		snap, err := d.archiveSnapshot(ctx)
		if err != nil {
			return nil, fmt.Errorf("archive: snapshot after the %s cut: %w", table, err)
		}
		// Every id up to a mark was reserved before it was taken; the guard
		// snapshot must come after their xids were assigned.
		if t.byMark && snap.At.Before(markTakenAt.Add(archiveMarkSettle)) {
			return nil, nil
		}
		next.GuardXmax = &snap.Xmax
	}
	if err := d.db.WithContext(ctx).Create(&next).Error; err != nil {
		return nil, fmt.Errorf("archive: record %s chunk %d: %w", table, next.Seq, err)
	}
	return &next, nil
}

// ArchiveReadOptions bound the export's reads of a chunk's id range.
type ArchiveReadOptions struct {
	// PageSize rows per keyset page (default 5000).
	PageSize int
	// RowsPerSec paces the reads (ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC /
	// ARCHIVE_FLOW_RATE_ROWS_PER_SEC); 0 = unpaced.
	RowsPerSec int
}

// archiveSleep waits between paced pages; a variable so tests can record the
// pacing instead of sleeping.
var archiveSleep = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// archivePageQuery is one keyset page of a chunk: the rows after cursor up to
// id_hi, in id order — a primary-key range scan (on a partitioned table, each
// leaf's (id, timestamp) key under a Merge Append). Separate so the plan
// test EXPLAINs the exact statement.
func archivePageQuery(tx *gorm.DB, table string, cursor, idHi int64, limit int) *gorm.DB {
	return tx.Table(table).Where("id > ? AND id <= ?", cursor, idHi).Order("id").Limit(limit)
}

// archiveWalk reads (c.IDLo, c.IDHi] of c's table page by page, each page its
// own short transaction under boundedRead's timeouts (120 s statement, 5 s
// lock), and hands every page to add in id order.
func archiveWalk[T any](ctx context.Context, d *Database, c *models.ArchiveChunk, opts ArchiveReadOptions, idOf func(*T) int64, add func([]T) error) error {
	size := opts.PageSize
	if size <= 0 {
		size = archivePageSize
	}
	for cursor := c.IDLo; cursor < c.IDHi; {
		start := time.Now()
		var page []T
		if err := d.boundedReadContext(ctx, func(tx *gorm.DB) error {
			return archivePageQuery(tx, c.SourceTable, cursor, c.IDHi, size).Find(&page).Error
		}); err != nil {
			return fmt.Errorf("archive: read %s after id %d: %w", c.SourceTable, cursor, err)
		}
		if len(page) == 0 {
			return nil
		}
		if err := add(page); err != nil {
			return err
		}
		cursor = idOf(&page[len(page)-1])
		if len(page) < size {
			return nil
		}
		if wait := backfillPace(len(page), opts.RowsPerSec, time.Since(start)); wait > 0 {
			if err := archiveSleep(ctx, wait); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExportArchiveChunk reads chunk c's rows in id order and writes them through
// an export.ChunkWriter of the given schema version to the objects open
// returns. Nothing is recorded: the result is the caller's to store. It
// returns *ArchiveUnsettledError, reading nothing, while a writer older than
// the cut is still open (ArchiveChunkSettled).
func (d *Database) ExportArchiveChunk(ctx context.Context, c *models.ArchiveChunk, schema int, opts ArchiveReadOptions, open export.OpenFunc) (*export.ChunkResult, error) {
	if _, err := archiveTableOf(c.SourceTable); err != nil {
		return nil, err
	}
	if err := d.ArchiveChunkSettled(ctx, c); err != nil {
		return nil, err
	}
	w, err := export.NewChunkWriter(c.SourceTable, schema, open)
	if err != nil {
		return nil, err
	}
	switch c.SourceTable {
	case export.TableSyslog:
		err = archiveWalk(ctx, d, c, opts, func(m *models.SyslogMessage) int64 { return int64(m.ID) }, w.AddSyslog)
	case export.TableFlows:
		err = archiveWalk(ctx, d, c, opts, func(f *models.FlowSample) int64 { return int64(f.ID) }, w.AddFlows)
	case export.TableCounters:
		err = archiveWalk(ctx, d, c, opts, func(r *models.FlowInterfaceCounter) int64 { return int64(r.ID) }, w.AddCounters)
	}
	if err != nil {
		return nil, err
	}
	return w.Close()
}

// Count check verdicts (CheckArchiveChunkCount).
const (
	// ArchiveCountMatch: the table holds exactly the exported rows.
	ArchiveCountMatch = "match"
	// ArchiveCountLateCommit: the table holds MORE rows in the range than
	// were exported — a commit the guard missed. Re-export the chunk.
	ArchiveCountLateCommit = "late_commit"
	// ArchiveCountShortfall: FEWER — rows were deleted after the export (a
	// device purge, which is not gated). Record it and carry on.
	ArchiveCountShortfall = "shortfall"
)

// CheckArchiveChunkCount counts c's id range in its table now and compares it
// with the exported row count; a verdict other than ArchiveCountMatch is
// information for the caller, not an error. One index-only range count under
// boundedRead.
func (d *Database) CheckArchiveChunkCount(ctx context.Context, c *models.ArchiveChunk, exported int64) (int64, string, error) {
	t, err := archiveTableOf(c.SourceTable)
	if err != nil {
		return 0, "", err
	}
	var n int64
	if err := d.boundedReadContext(ctx, func(tx *gorm.DB) error {
		return archiveCountQuery(tx, t.name, c.IDLo, c.IDHi).Scan(&n).Error
	}); err != nil {
		return 0, "", fmt.Errorf("archive: count %s (%d, %d]: %w", t.name, c.IDLo, c.IDHi, err)
	}
	switch {
	case n > exported:
		return n, ArchiveCountLateCommit, nil
	case n < exported:
		return n, ArchiveCountShortfall, nil
	}
	return n, ArchiveCountMatch, nil
}

// archiveCountQuery counts the id range (lo, hi] of table (a primary-key
// range). Separate so the plan test EXPLAINs it.
func archiveCountQuery(tx *gorm.DB, table string, lo, hi int64) *gorm.DB {
	return tx.Table(table).Select("count(*)").Where("id > ? AND id <= ?", lo, hi)
}
