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
	now      func() time.Time
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
	m.inFlight = true
	m.lastFlush = m.now()
	m.mu.Unlock()

	err := d.upsertSyslogIngest(swapped)

	m.mu.Lock()
	m.inFlight = false
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
