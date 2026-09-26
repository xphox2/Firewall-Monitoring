package database

import (
	"errors"
	"log"
	"sync"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Syslog ingest meter.
//
// The Retention page needs each severity's ingest RATE (rows/day, bytes/day) to
// project where the table is heading at the configured window — the figure the
// 2026-09-05 disk-growth diagnosis found missing: "131 GB today" said nothing
// about "190 GB where this is heading".
//
// Counting the last 24 h with `SELECT severity, COUNT(*) … WHERE timestamp > ?`
// is millions of index tuples per severity on production, no loose index scan
// in Postgres, and the same 30 s statement_timeout background workers share.
// Every syslog row instead enters through one function, SaveSyslogMessages, so
// the rows are in hand at zero cost: count them there, per severity, and
// persist hourly buckets in a tiny table (syslog_ingest_hourly) so restarts
// (several per day on the reference deployment) and the poller can see them.

// syslogIngestFlushInterval bounds how long counts live only in memory.
const syslogIngestFlushInterval = 60 * time.Second

// syslogIngestRetentionDays is how long the hourly buckets are kept. It must
// cover the longest window the Syslog stats accept (ParseHours caps at 8760 h).
const syslogIngestRetentionDays = 400

// syslogIngestRateWindow is how far back the rate looks.
const syslogIngestRateWindow = 24 * time.Hour

// ingestCount is one (hour, severity) cell.
type ingestCount struct {
	rows, bytes int64
}

// syslogIngestMeter accumulates accepted rows per (hour, severity) and flushes
// them to syslog_ingest_hourly. Rows are keyed by the hour they were COUNTED
// in, which removes any rollover protocol: whatever a concurrent flush is doing,
// a row is either in the live map or in exactly one swapped map, and a failed
// flush merges its map back additively — exactly-once against every in-process
// interleaving. An ambiguous commit (server committed, client saw an error) is
// at-least-once, bounded to one flush window, which a rate estimate tolerates;
// cancellation errors are deliberately NOT treated as success — that would only
// trade a rare double-count for a rare loss.
type syslogIngestMeter struct {
	mu        sync.Mutex
	buckets   map[time.Time]*[SyslogSeverityCount]ingestCount
	lastFlush time.Time
	// inFlight is only a throttle: at most one flush runs at a time, and the
	// lock is never held across the database round-trip (gin runs the ingest
	// handler concurrently; a stalled Postgres must not stall every syslog POST
	// behind a 30 s statement_timeout).
	inFlight bool
	// pending is the map a running flush swapped out, held here until its
	// upsert has either committed or failed, so a reader (meterHours) can see
	// counts that are in neither the live map nor the table yet. Three rules
	// keep a reader from missing or double-counting a cell:
	//   (i)  on failure the merge-back into buckets and the clear of pending
	//        happen in the same lock section;
	//   (ii) flushGen is bumped after every flush, success AND failure — a
	//        failed flush also moves cells, from pending back to buckets;
	//   (iii) one pending map is enough: the inFlight throttle lets only one
	//        non-final flush run at a time, and the final flush runs from Close,
	//        after server.Shutdown has normally drained them. Shutdown is capped
	//        at 10 s while a stalled upsert can run to the 30 s statement
	//        timeout, so at worst a shutdown loses one flush window, as it did
	//        before pending existed — and nothing reads the meter by then.
	pending  map[time.Time]*[SyslogSeverityCount]ingestCount
	flushGen uint64
	now      func() time.Time
	// beforeUpsert, when set, runs between the swap and the upsert. Tests use
	// it to hold a flush in flight; nil in production.
	beforeUpsert func()
	// afterSnapshot, when set, runs in meterHours between copying memory and
	// reading the table — the window a concurrent flush can land in. Tests use
	// it to prove the retry; nil in production.
	afterSnapshot func()
}

func newSyslogIngestMeter(now func() time.Time) *syslogIngestMeter {
	if now == nil {
		now = time.Now
	}
	return &syslogIngestMeter{
		buckets: make(map[time.Time]*[SyslogSeverityCount]ingestCount),
		now:     now,
	}
}

// syslogIngestBytes is the payload size the meter attributes to one row.
func syslogIngestBytes(m *models.SyslogMessage) int64 {
	return int64(len(m.Message) + len(m.StructuredData) + len(m.Hostname) + len(m.AppName))
}

// meterSyslog counts rows that actually landed. Severity outside 0..7 is
// clamped into bucket 7 — never dropped, never a panic. When a flush is due it
// runs one on the caller's goroutine, outside the lock.
func (d *Database) meterSyslog(saved []models.SyslogMessage) {
	m := d.ingest
	if m == nil || len(saved) == 0 {
		return
	}
	now := m.now()
	hour := now.UTC().Truncate(time.Hour)

	m.mu.Lock()
	b := m.buckets[hour]
	if b == nil {
		b = new([SyslogSeverityCount]ingestCount)
		m.buckets[hour] = b
	}
	for i := range saved {
		sev := saved[i].Severity
		if sev < 0 || sev >= SyslogSeverityCount {
			sev = SyslogSeverityCount - 1
		}
		b[sev].rows++
		b[sev].bytes += syslogIngestBytes(&saved[i])
	}
	due := !m.inFlight && now.Sub(m.lastFlush) >= syslogIngestFlushInterval
	m.mu.Unlock()

	if due {
		_ = d.flushSyslogIngest(false) // logged inside; a failure merges back
	}
}

// flushSyslogIngest persists the accumulated buckets. final=true is the Close
// path: it bypasses the inFlight throttle and does not merge back on error,
// because nothing will retry.
func (d *Database) flushSyslogIngest(final bool) error {
	m := d.ingest
	if m == nil {
		return nil
	}

	m.mu.Lock()
	if m.inFlight && !final {
		m.mu.Unlock()
		return nil
	}
	swapped := m.buckets
	m.buckets = make(map[time.Time]*[SyslogSeverityCount]ingestCount)
	m.pending = swapped
	m.inFlight = true
	m.lastFlush = m.now()
	hook := m.beforeUpsert
	m.mu.Unlock()

	if hook != nil {
		hook()
	}
	err := d.upsertSyslogIngest(swapped)

	m.mu.Lock()
	m.inFlight = false
	m.pending = nil
	m.flushGen++
	if err != nil && !final {
		// Additive merge: counts that arrived meanwhile for the same hour are
		// kept, and the swapped ones are retried on the next flush.
		for hour, counts := range swapped {
			live := m.buckets[hour]
			if live == nil {
				m.buckets[hour] = counts
				continue
			}
			for sev := range counts {
				live[sev].rows += counts[sev].rows
				live[sev].bytes += counts[sev].bytes
			}
		}
	}
	m.mu.Unlock()

	if err != nil {
		log.Printf("syslog ingest meter: flush failed (%v); counts retained for the next flush", err)
	}
	return err
}

// upsertSyslogIngest writes every non-zero (hour, severity) cell, adding onto
// any row already there for that hour — two flushes in one hour, or a restart
// mid-hour, accumulate into one row. GORM emits
// `DO UPDATE SET "row_count"=syslog_ingest_hourly.row_count + excluded.row_count`,
// valid on Postgres and SQLite alike.
func (d *Database) upsertSyslogIngest(buckets map[time.Time]*[SyslogSeverityCount]ingestCount) error {
	var rows []models.SyslogIngestHourly
	for hour, counts := range buckets {
		for sev := range counts {
			c := counts[sev]
			if c.rows == 0 && c.bytes == 0 {
				continue
			}
			rows = append(rows, models.SyslogIngestHourly{
				Timestamp: hour,
				Severity:  sev,
				RowCount:  c.rows,
				ByteCount: c.bytes,
			})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	return d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "timestamp"}, {Name: "severity"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"row_count":  gorm.Expr("syslog_ingest_hourly.row_count + excluded.row_count"),
			"byte_count": gorm.Expr("syslog_ingest_hourly.byte_count + excluded.byte_count"),
		}),
	}).Create(&rows).Error
}

// SyslogIngestTotals is one severity's accepted ingest over the rate window.
type SyslogIngestTotals struct {
	Rows, Bytes int64
}

// SyslogIngestRate sums the buckets of the last 24 h per severity and reports
// how many hours of buckets that sum actually covers, so a caller can
// extrapolate (rows/day = Rows × 24 / hours) during the first day after
// install. hours is 0 when the table is empty — rate unavailable — and never
// less than 1 otherwise, since a bucket covers up to an hour.
//
// One indexed read over a ≤ 192-row window plus the oldest bucket; never the
// syslog table itself.
func (d *Database) SyslogIngestRate(now time.Time) (perSev [SyslogSeverityCount]SyslogIngestTotals, hours float64) {
	now = now.UTC()
	cutoff := now.Add(-syslogIngestRateWindow)

	var oldest models.SyslogIngestHourly
	if err := d.db.Order("timestamp ASC").First(&oldest).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("syslog ingest meter: oldest bucket lookup failed: %v", err)
		}
		return perSev, 0
	}

	var sums []struct {
		Severity int
		NRows    int64
		NBytes   int64
	}
	if err := d.db.Raw(`SELECT severity, SUM(row_count) AS n_rows, SUM(byte_count) AS n_bytes
		FROM syslog_ingest_hourly WHERE timestamp >= ? GROUP BY severity`, cutoff).
		Scan(&sums).Error; err != nil {
		log.Printf("syslog ingest meter: rate window read failed: %v", err)
		return perSev, 0
	}
	for _, s := range sums {
		sev := s.Severity
		if sev < 0 || sev >= SyslogSeverityCount {
			sev = SyslogSeverityCount - 1
		}
		perSev[sev].Rows += s.NRows
		perSev[sev].Bytes += s.NBytes
	}

	start := oldest.Timestamp.UTC()
	if start.Before(cutoff) {
		start = cutoff
	}
	hours = now.Sub(start).Hours()
	if hours < 1 {
		hours = 1
	}
	return perSev, hours
}

// meterHours returns rows accepted per UTC hour and severity for every hour at
// or after from: the persisted buckets plus the counts still in memory — the
// live map and a flush in flight (see the pending rules on syslogIngestMeter).
//
// Only cmd/api records into the meter (ReceiveSyslogMessages is the sole
// caller of SaveSyslogMessages); the poller builds one but never records. So
// this process's buffer is the whole picture of what has not reached the
// table, and a request-scoped copy of Database shares the same meter pointer.
//
// The read is optimistic: snapshot memory under the lock, read the table
// without it, and if a flush finished in between (flushGen moved) the cells it
// carried may now be in both places, so read once more. A second flush cannot
// land within one read — the next is at least syslogIngestFlushInterval away —
// so one retry settles it.
func (d *Database) meterHours(from time.Time) (map[time.Time]*[SyslogSeverityCount]int64, error) {
	from = from.UTC()
	for attempt := 0; ; attempt++ {
		gen, mem := d.meterMemory(from)
		if d.ingest != nil && d.ingest.afterSnapshot != nil && attempt == 0 {
			d.ingest.afterSnapshot()
		}
		// The column is UTC by its only writer (upsertSyslogIngest stores the
		// UTC hour), so the bound is UTC too: SQLite compares rendered text.
		var rows []models.SyslogIngestHourly
		if err := d.db.Where("timestamp >= ?", from).Find(&rows).Error; err != nil {
			return nil, err
		}
		if attempt == 0 && d.ingest != nil {
			d.ingest.mu.Lock()
			moved := d.ingest.flushGen != gen
			d.ingest.mu.Unlock()
			if moved {
				continue
			}
		}
		for _, r := range rows {
			sev := r.Severity
			if sev < 0 || sev >= SyslogSeverityCount {
				sev = SyslogSeverityCount - 1
			}
			h := r.Timestamp.UTC()
			b := mem[h]
			if b == nil {
				b = new([SyslogSeverityCount]int64)
				mem[h] = b
			}
			b[sev] += r.RowCount
		}
		return mem, nil
	}
}

// meterMemory copies the not-yet-persisted counts at or after from, and the
// flush generation they belong to.
func (d *Database) meterMemory(from time.Time) (uint64, map[time.Time]*[SyslogSeverityCount]int64) {
	out := make(map[time.Time]*[SyslogSeverityCount]int64)
	m := d.ingest
	if m == nil {
		return 0, out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, src := range []map[time.Time]*[SyslogSeverityCount]ingestCount{m.buckets, m.pending} {
		for h, counts := range src {
			if h.Before(from) {
				continue
			}
			b := out[h]
			if b == nil {
				b = new([SyslogSeverityCount]int64)
				out[h] = b
			}
			for sev := range counts {
				b[sev] += counts[sev].rows
			}
		}
	}
	return m.flushGen, out
}

// oldestMeterHour is the first hour the meter holds anything for, persisted or
// in memory; ok is false when it holds nothing at all. Order().First rather
// than MIN(): an aggregate over a timestamp comes back as text on SQLite and
// will not scan into time.Time.
func (d *Database) oldestMeterHour() (time.Time, bool, error) {
	var oldest time.Time
	ok := false
	var row models.SyslogIngestHourly
	err := d.db.Order("timestamp ASC").First(&row).Error
	switch {
	case err == nil:
		oldest, ok = row.Timestamp.UTC(), true
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return time.Time{}, false, err
	}
	_, mem := d.meterMemory(time.Time{})
	for h := range mem {
		if !ok || h.Before(oldest) {
			oldest, ok = h, true
		}
	}
	return oldest, ok, nil
}
