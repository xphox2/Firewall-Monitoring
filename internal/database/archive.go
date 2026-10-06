package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// The raw archive's chunk planner and export reads (archive plan PR 3, §2.1).
// Nothing here runs on its own: the archive worker (internal/archive/worker,
// in the poller, only for an enabled stream) takes the marks, plans, exports,
// uploads and verifies on a timer; its state machine is archive_worker.go.
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

// archiveMaxFirstAge bounds how far back the first syslog chunk may start. The
// oldest row's created_at should be the retention edge (about a month); one
// older than this is a forged or broken stamp (before 0.11.301 a probe body
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

// Settling a cut (why an export waits, and for how long).
//
// A chunk is cut at an instant cut_at (database clock): the moment its mark was
// taken, or the end of the syslog search. Every id at or below id_hi had been
// reserved (nextval) by then — ids are handed out in order, and id_hi itself
// was reserved before the mark read it / before the search saw it committed.
// A transaction that reserved one of those ids but has not committed is the
// late commit the archive must wait for. It gets its transaction id when its
// first tuple reaches the heap: right after nextval for a row-by-row or
// multi-row INSERT, but for a COPY only at the first multi-insert flush (1 000
// rows / 64 KB) or at the end of the data — a slowly streaming COPY can hold a
// reserved id with no xid for as long as its statement runs. That is bounded
// by statement_timeout (the DSN's, DB_STATEMENT_TIMEOUT; every writer of the
// three tables runs under it): within statement_timeout of reserving an id
// the statement has its xid, has failed (its rows abort) or has finished.
//
// So the guard snapshot is taken at least archiveSettle (statement_timeout +
// a margin, and never under a minute) after cut_at: any transaction that may
// still commit a row at or below id_hi then has an xid below that snapshot's
// xmax (guard_xmax), and the export waits until the oldest running xid is at
// or above it. Only writing transactions hold an xid, whatever their role, so
// a long read-only transaction (a pg_dump in REPEATABLE READ, a report) never
// blocks. With no statement_timeout the window is unbounded: nothing is
// planned or exported.
//
// The minimum ages (5 minutes for flows, 2 hours otherwise) exceed the
// default settle, so a healthy worker rarely waits on it.

// archiveSettleFloor and archiveSettleMargin set the settle window:
// max(floor, statement_timeout + margin). Variables so a test can shrink them.
var (
	archiveSettleFloor  = time.Minute
	archiveSettleMargin = 5 * time.Second
)

// archiveWriterStatementTimeout is this session's statement_timeout as the
// server reports it. A variable so a test can stand in for it.
var archiveWriterStatementTimeout = func(ctx context.Context, d *Database) (time.Duration, error) {
	var ms int64
	if err := d.db.WithContext(ctx).Raw(`SELECT setting::bigint FROM pg_settings WHERE name = 'statement_timeout'`).Scan(&ms).Error; err != nil {
		return 0, err
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// ErrArchiveNoStatementTimeout: with statement_timeout 0 a writer may hold a
// reserved id without a transaction id indefinitely, so no cut can be proven
// complete.
var ErrArchiveNoStatementTimeout = errors.New("archive: statement_timeout is 0 (unlimited): a COPY could hold reserved ids indefinitely, so no chunk can be settled — set DB_STATEMENT_TIMEOUT")

// archiveSettle is the settle window, or ErrArchiveNoStatementTimeout. The
// writers (the GORM and pgx pools) run under DB_STATEMENT_TIMEOUT when it is
// set — Connect puts it in both pools' startup options — and under the server
// default when it is not, which is what this session observes then. The
// window covers the larger of the two: max(1 min, max(observed, configured) +
// 5 s). Unbounded writers (configured 0 and a server default of 0) refuse.
func (d *Database) archiveSettle(ctx context.Context) (time.Duration, error) {
	observed, err := archiveWriterStatementTimeout(ctx, d)
	if err != nil {
		return 0, fmt.Errorf("archive: read statement_timeout: %w", err)
	}
	if d.statementTimeout <= 0 && observed <= 0 {
		return 0, ErrArchiveNoStatementTimeout
	}
	return max(archiveSettleFloor, max(observed, d.statementTimeout)+archiveSettleMargin), nil
}

// ArchiveXidHolder is the session holding the oldest running transaction id,
// where pg_stat_activity shows it (it does not for a prepared transaction, and
// shows a session of another role without state or timing unless this role
// has pg_read_all_stats).
type ArchiveXidHolder struct {
	PID             int64      `gorm:"column:pid"`
	Datname         string     `gorm:"column:datname"`
	BackendType     string     `gorm:"column:backend_type"`
	ApplicationName string     `gorm:"column:application_name"`
	State           string     `gorm:"column:state"`
	XactStart       *time.Time `gorm:"column:xact_start"`
}

// ArchiveUnsettledError: c cannot be exported yet. Either the settle window
// after its cut has not passed (SettleLeft > 0, no guard yet), or a writing
// transaction that may hold rows in the range is still running (Xmin, the
// oldest running xid, is below GuardXmax; Holder names it when visible). A
// later attempt retries; the worker logs it and the lag metric shows it.
type ArchiveUnsettledError struct {
	SettleLeft time.Duration
	GuardXmax  int64
	Xmin       int64
	Holder     *ArchiveXidHolder
}

func (e *ArchiveUnsettledError) Error() string {
	if e.SettleLeft > 0 {
		return fmt.Sprintf("archive: the cut is settling (%s left)", e.SettleLeft.Round(time.Second))
	}
	msg := fmt.Sprintf("archive: a writing transaction older than the cut is still open (oldest running xid %d, guard xid %d)", e.Xmin, e.GuardXmax)
	if h := e.Holder; h != nil {
		msg += fmt.Sprintf("; held by pid %d (%s, database %q, application %q, state %q", h.PID, h.BackendType, h.Datname, h.ApplicationName, h.State)
		if h.XactStart != nil {
			msg += fmt.Sprintf(", transaction open since %s", h.XactStart.UTC().Format(time.RFC3339))
		}
		msg += ")"
	}
	return msg
}

// archiveSnapshot is the xmin / xmax of a fresh snapshot (pg_current_snapshot)
// and the database clock. Every transaction id below xmax had been assigned
// when it was taken; every one below xmin has finished (in any database of
// the cluster). xid8 (64-bit, no wraparound) fits a bigint.
type archiveSnapshot struct {
	Xmin, Xmax int64
	At         time.Time
}

func (d *Database) archiveSnapshot(ctx context.Context) (archiveSnapshot, error) {
	var s archiveSnapshot
	err := d.db.WithContext(ctx).Raw(`SELECT pg_snapshot_xmin(s)::text::bigint AS xmin, pg_snapshot_xmax(s)::text::bigint AS xmax,
		statement_timestamp() AS at FROM pg_current_snapshot() AS s`).Scan(&s).Error
	return s, err
}

// archiveOldestXidHolder is the visible session whose transaction id is the
// oldest running one (nil when none is visible).
func (d *Database) archiveOldestXidHolder(ctx context.Context) *ArchiveXidHolder {
	var h []ArchiveXidHolder
	if err := d.db.WithContext(ctx).Raw(`SELECT pid, COALESCE(datname, '') AS datname, COALESCE(backend_type, '') AS backend_type,
			COALESCE(application_name, '') AS application_name, COALESCE(state, '') AS state, xact_start
		FROM pg_stat_activity WHERE backend_xid IS NOT NULL ORDER BY age(backend_xid) DESC LIMIT 1`).Scan(&h).Error; err != nil || len(h) == 0 {
		return nil
	}
	return &h[0]
}

// ArchiveChunkSettled returns nil once chunk c may be exported: its settle
// window has passed, its guard snapshot is recorded, and every transaction id
// below the guard has finished. Otherwise *ArchiveUnsettledError (or
// ErrArchiveNoStatementTimeout). The first call after the window records
// guard_xmax on the chunk. Always clear on SQLite (no concurrent writer in
// tests).
func (d *Database) ArchiveChunkSettled(ctx context.Context, c *models.ArchiveChunk) error {
	if !d.dialect.IsPostgres() {
		return nil
	}
	settle, err := d.archiveSettle(ctx)
	if err != nil {
		return err
	}
	if _, err := d.archiveLeafsClear(ctx, c.SourceTable); err != nil {
		return err
	}
	s, err := d.archiveSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("archive: snapshot: %w", err)
	}
	if c.GuardXmax == nil {
		if left := c.CutAt.Add(settle).Sub(s.At); left > 0 {
			return &ArchiveUnsettledError{SettleLeft: left}
		}
		guard := s.Xmax
		res := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).Where("id = ? AND guard_xmax IS NULL", c.ID).Update("guard_xmax", guard)
		if res.Error != nil {
			return fmt.Errorf("archive: record the guard of chunk %d: %w", c.ID, res.Error)
		}
		if res.RowsAffected == 0 {
			// Recorded meanwhile by another caller: use theirs.
			if err := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).Where("id = ?", c.ID).Pluck("guard_xmax", &guard).Error; err != nil {
				return err
			}
		}
		c.GuardXmax = &guard
		if s, err = d.archiveSnapshot(ctx); err != nil {
			return fmt.Errorf("archive: snapshot: %w", err)
		}
	}
	if s.Xmin < *c.GuardXmax {
		return &ArchiveUnsettledError{GuardXmax: *c.GuardXmax, Xmin: s.Xmin, Holder: d.archiveOldestXidHolder(ctx)}
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
		err := d.db.WithContext(ctx).Raw(fmt.Sprintf(`SELECT COALESCE(max(id), 0) AS max_id, statement_timestamp() AS taken_at FROM %s`, t.name)).Scan(&r).Error
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
// yet taken.
//
// The cut instant is recorded (cut_at); the export waits until the cut has
// settled (ArchiveChunkSettled: the settle window, then every writer that
// could still commit a row at or below id_hi). Planning itself never waits on
// other sessions: a row that commits after the cut with a higher id lands in
// the next chunk — still exactly one. With statement_timeout 0 nothing is
// planned (ErrArchiveNoStatementTimeout).
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
	if d.dialect.IsPostgres() {
		if _, err := d.archiveSettle(ctx); err != nil {
			return nil, err
		}
	}
	if _, err := d.archiveLeafsClear(ctx, table); err != nil {
		return nil, err
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
		next.IDHi, next.MarkLateByMs, next.CutAt = m.MaxID, &late, m.TakenAt
	} else if next.IDHi, err = d.archiveSyslogCut(ctx, next.IDLo, next.PeriodEnd); err != nil {
		return nil, err
	}
	if !t.byMark {
		// Syslog: the cut is fixed now. Every id at or below id_hi was
		// reserved before id_hi was, and the search saw id_hi committed, so
		// before this instant. A syslog INSERT (one or many rows) gets its
		// xid at the heap insert right after its first nextval, a COPY within
		// statement_timeout of it; so CutAt + the settle window (statement_
		// timeout + margin) bounds when every writer that could still commit
		// a row at or below id_hi holds an xid — the guard snapshot is taken
		// after that (ArchiveChunkSettled). This does not depend on how long
		// after created_at a row was inserted: a row created before the end
		// of the day but inserted after the search has a higher id and lands
		// in the next chunk.
		next.CutAt = time.Now().UTC()
		if d.dialect.IsPostgres() {
			snap, err := d.archiveSnapshot(ctx)
			if err != nil {
				return nil, fmt.Errorf("archive: clock after the syslog cut: %w", err)
			}
			next.CutAt = snap.At
		}
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
	// Progress, when set, is called after every page with the rows read so
	// far and the last id read (no database call of its own: the caller
	// throttles what it does with it).
	Progress func(rows, lastID int64)
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
	var read int64
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
		if read += int64(len(page)); opts.Progress != nil {
			opts.Progress(read, cursor)
		}
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

// Count check verdicts (CheckArchiveChunkCount). Only ArchiveCountMatch lets
// a chunk be marked verified; any other verdict means the chunk is exported
// again (its earlier objects superseded) — the verdict only says why.
const (
	// ArchiveCountMatch: the table holds exactly the exported rows (same
	// count and same sum of ids).
	ArchiveCountMatch = "match"
	// ArchiveCountLateCommit: rows the export did not see are in the range
	// (more rows, or as many with other ids) — a commit after the read.
	ArchiveCountLateCommit = "late_commit"
	// ArchiveCountShortfall: fewer rows and a smaller id sum — what deletions
	// (a device purge, which is not gated) look like, though a late commit
	// beside a larger purge can look the same. Harmless: like every verdict
	// but match it means a re-export, which must then match.
	ArchiveCountShortfall = "shortfall"
)

// ArchiveCountCheck is a chunk's id range as the table holds it now, against
// what an export wrote.
type ArchiveCountCheck struct {
	Rows, IDSum, IDHash                         int64
	ExportedRows, ExportedIDSum, ExportedIDHash int64
	Verdict                                     string
}

// Verifiable reports whether the export may be marked verified.
func (c ArchiveCountCheck) Verifiable() bool { return c.Verdict == ArchiveCountMatch }

// CheckArchiveChunkCount recounts c's id range in its table — row count, sum
// of ids and a sum of per-id hashes (export.IDHashTerm), so neither one late
// row replacing one purged row nor a coincidental pair of such swaps is a
// match — and compares it with the export's result. A verdict other than
// ArchiveCountMatch is information for the caller, not an error. One
// index-only range scan under boundedRead.
func (d *Database) CheckArchiveChunkCount(ctx context.Context, c *models.ArchiveChunk, res *export.ChunkResult) (ArchiveCountCheck, error) {
	t, err := archiveTableOf(c.SourceTable)
	if err != nil {
		return ArchiveCountCheck{}, err
	}
	// No count while partition maintenance is moving rows through a
	// standalone leaf (archive_gate.go): before, no unattached leaf; after,
	// still none and the same move epoch — so no move ran during the count,
	// and every row of the range was visible to it.
	before, err := d.archiveLeafsClear(ctx, t.name)
	if err != nil {
		return ArchiveCountCheck{}, err
	}
	var r struct{ N, S, H int64 }
	if err := d.boundedReadContext(ctx, func(tx *gorm.DB) error {
		return archiveCountQuery(tx, t.name, c.IDLo, c.IDHi).Scan(&r).Error
	}); err != nil {
		return ArchiveCountCheck{}, fmt.Errorf("archive: count %s (%d, %d]: %w", t.name, c.IDLo, c.IDHi, err)
	}
	if archiveCountHook != nil {
		archiveCountHook()
	}
	if after, err := d.archiveLeafsClear(ctx, t.name); err != nil {
		return ArchiveCountCheck{}, err
	} else if after.epoch != before.epoch {
		return ArchiveCountCheck{}, fmt.Errorf("%w: a move started during the count of %s (%d, %d]", ErrArchiveLeafMove, t.name, c.IDLo, c.IDHi)
	}
	chk := ArchiveCountCheck{Rows: r.N, IDSum: r.S, IDHash: r.H, ExportedRows: res.Rows, ExportedIDSum: res.IDSum, ExportedIDHash: res.IDHash}
	switch {
	case chk.Rows == chk.ExportedRows && chk.IDSum == chk.ExportedIDSum && chk.IDHash == chk.ExportedIDHash:
		chk.Verdict = ArchiveCountMatch
	case chk.Rows < chk.ExportedRows && chk.IDSum < chk.ExportedIDSum:
		chk.Verdict = ArchiveCountShortfall
	default:
		chk.Verdict = ArchiveCountLateCommit
	}
	return chk, nil
}

// archiveCountHook, when non-nil, runs between the count and the leaf re-check
// of CheckArchiveChunkCount (test seam: a leaf move starting there). Never set
// in production.
var archiveCountHook func()

// archiveCountQuery counts the range (lo, hi] of table and sums its ids and
// their hash terms (a primary-key range; both sums stay far below 2^63 for a
// day's rows). Separate so the
// plan test EXPLAINs it.
func archiveCountQuery(tx *gorm.DB, table string, lo, hi int64) *gorm.DB {
	return tx.Table(table).Select("count(*) AS n, CAST(COALESCE(sum(id), 0) AS BIGINT) AS s, CAST(COALESCE(sum("+export.IDHashSQL+"), 0) AS BIGINT) AS h").
		Where("id > ? AND id <= ?", lo, hi)
}
