package database

import (
	"time"

	"gorm.io/gorm"
)

// Time-window aggregation driver (AUDIT-204), shared by the syslog and flow
// aggregation passes.
//
// The passes used to page their GROUP BY with LIMIT/OFFSET. The bucket
// expression (to_char/strftime) is unindexable, so every page forced the FULL
// backlog to be aggregated and sorted before the page was sliced out —
// O(pages × backlog) — and once a real backlog accumulated, the FIRST page
// alone exceeded the connection's 30s statement_timeout: a 57014 rollback,
// retried identically every 5 minutes forever, while CleanupOldData kept
// deleting never-summarised raw rows past their retention window (permanent
// silent history loss). Lifting the timeout (SET LOCAL statement_timeout=0)
// was evaluated and REJECTED: one unbounded sort over the 124GB production
// syslog heap risks a temp-file spill on the nearly-full data volume and pins
// xmin for the whole multi-hour statement.
//
// Instead each pass walks FORWARD in bounded time windows from its oldest
// eligible row: every window's SELECT/DELETE carries a `timestamp >= ? AND
// timestamp < ?` range an existing index serves, so per-transaction work is
// bounded by one window's rows, far under the timeout.

// walkAggregationWindows opens ONE transaction per [winStart, winEnd) slice,
// calling aggregateWindow inside it, and advances until cutoff. Each window
// commits independently, so a failure mid-backlog KEEPS every earlier window's
// insert+delete (forward progress — the old all-or-nothing transaction redid
// the whole backlog from scratch on any error); the error is returned along
// with the group total committed so far. The per-window atomicity invariant is
// the callback's contract: a window's raw-row DELETE must share its
// transaction with that window's summary INSERT.
//
// Window bounds are aligned with time.Truncate, so a bucket expression whose
// unit divides the window never straddles two windows. A straddled bucket (a
// test-shrunk window) writes two summary rows for the same group — untidy but
// never wrong: every reader and the next promotion tier merge them by SUM.
//
// nextEligible bounds the walk by NON-EMPTY windows, not by time span
// (review fix on AUDIT-204): after each window the walker asks for the oldest
// eligible row at-or-after the window's end (a first-tuple index stop, same
// shape as the caller's start probe) and JUMPS there. Without this, one
// pathologically ancient row — e.g. the year-0 timestamps the collector's
// generic BSD syslog parser emits for Cisco/PA/legacy-OPNsense (the layout
// has no year, and only past/zero values escaped the ingest clamp before its
// AUDIT-204 lower bound) — degenerated a cycle into ~17.8M empty-window
// transactions (measured: hours on prod-class hardware) while holding the
// shared poller work lock. With the jump, per-pass cost is proportional to
// windows that actually contain rows, plus one cheap probe each.
func walkAggregationWindows(db *gorm.DB, window time.Duration, start, cutoff time.Time,
	nextEligible func(after time.Time) (time.Time, bool, error),
	aggregateWindow func(tx *gorm.DB, winStart, winEnd time.Time) (int, error)) (int, error) {
	if window <= 0 {
		window = time.Hour
	}
	total := 0
	// Truncate preserves start's zone deliberately — do NOT normalize to UTC
	// here. SQLite compares timestamp text lexicographically in whatever zone
	// each value was rendered with, so the window bounds must render in the
	// same zone the driver handed back for MIN(timestamp) or a UTC-rendered
	// bound sorts against local-rendered rows by its digits, silently missing
	// them. Postgres binds are typed timestamptz, where the zone is irrelevant.
	winStart := start.Truncate(window)
	for winStart.Before(cutoff) {
		winEnd := winStart.Add(window)
		if winEnd.After(cutoff) {
			winEnd = cutoff
		}
		groups := 0
		if err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			groups, err = aggregateWindow(tx, winStart, winEnd)
			return err
		}); err != nil {
			return total, err
		}
		total += groups
		if !winEnd.Before(cutoff) {
			break
		}
		// Jump to the next populated window instead of crawling empty ones.
		next, ok, err := nextEligible(winEnd)
		if err != nil {
			return total, err
		}
		if !ok {
			break // nothing eligible remains before cutoff
		}
		if next.Before(winEnd) {
			// Defensive: a probe must never move backwards; fall back to the
			// adjacent window rather than loop on the same range.
			next = winEnd
		}
		winStart = next.Truncate(window)
	}
	return total, nil
}

// oldestEligibleTimestamp returns MIN(timestamp) for the prepared (already
// filtered) query — the window walk's starting point. ok is false when no row
// matches.
//
// Planner note: this is the first-tuple index stop, NOT the filtered-MAX(id)
// trap the watermark comments document. Each caller's predicates are anchored
// by an index whose leading columns the filter pins (severity via
// idx_syslog_sev_ts, interval_type via idx_rollup_interval_ts, or the bare
// timestamp index), so the forward walk satisfies the residual predicates at
// its very first tuple — the oldest rows are exactly the ones that pass
// `timestamp < cutoff AND id <= watermark`.
//
// Scanned through database/sql into `any` (the coerceDBTime pattern from
// GetLatestVPNStatuses): an aggregate loses the column's declared type, so the
// SQLite driver returns a string while Postgres returns time.Time, and GORM
// can map neither into a portable struct field.
func oldestEligibleTimestamp(q *gorm.DB) (time.Time, bool, error) {
	rows, err := q.Select("MIN(timestamp)").Rows()
	if err != nil {
		return time.Time{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return time.Time{}, false, rows.Err()
	}
	var raw any
	if err := rows.Scan(&raw); err != nil {
		return time.Time{}, false, err
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, false, err
	}
	ts, ok := coerceDBTime(raw) // MIN over zero rows is NULL → raw nil → ok false
	return ts, ok, nil
}
