package database

// estimateRowCount reports the planner's row estimate for a table without
// touching a single heap page.
//
// This exists because `SELECT COUNT(*)` on the telemetry tables is not a cheap
// query at production scale: on a 99M-row, 88GB syslog_messages it is a
// multi-second index-only scan even warm, and far worse once the page cache is
// cold. Any dashboard figure that is only ever rendered as a rounded "how much
// have we ingested" number does not justify that cost — the catalog estimate is
// accurate to a few percent and is a single catalog lookup.
//
// Returns ok=false when there is no usable statistic, in which case the caller
// must fall back to an exact count rather than render a fake zero:
//
//   - non-Postgres (SQLite dev/test), which keeps no equivalent catalog
//   - a table that has never been analyzed, where reltuples is the -1 sentinel
//     (true of EVERY table for a while after a dump/restore, and on a fresh
//     install's first minutes)
//   - a genuinely empty table, which is indistinguishable from the above here
//     and is trivially cheap to count exactly anyway
//   - an unknown table name, where to_regclass yields NULL
//
// The table is resolved with to_regclass so it goes through search_path and
// yields an oid, rather than matching pg_class.relname across every schema —
// which would pick up a same-named relation in another schema.
func (d *Database) estimateRowCount(table string) (int64, bool) {
	if d == nil || d.db == nil || !d.dialect.IsPostgres() {
		return 0, false
	}

	// Partitions OR the relation — never both.
	//
	// A partitioned parent stores its rows in the children, so the parent alone
	// reports ~0. But summing parent AND children double-counts: an explicit
	// ANALYZE on a partitioned parent also populates its own reltuples with the
	// whole total. GREATEST additionally absorbs the never-analyzed -1 sentinel
	// so one un-analyzed leaf cannot drag the sum negative.
	var est int64
	if err := d.db.Raw(`
		SELECT COALESCE(CASE
			WHEN EXISTS (SELECT 1 FROM pg_inherits WHERE inhparent = to_regclass(?))
			THEN (SELECT SUM(GREATEST(c.reltuples, 0))
			      FROM pg_inherits i
			      JOIN pg_class c ON c.oid = i.inhrelid
			      WHERE i.inhparent = to_regclass(?))
			ELSE (SELECT GREATEST(c.reltuples, 0)
			      FROM pg_class c WHERE c.oid = to_regclass(?))
		END, 0)::bigint`, table, table, table).Scan(&est).Error; err != nil {
		return 0, false
	}
	if est <= 0 {
		return 0, false
	}
	return est, true
}
