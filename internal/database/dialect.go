package database

import (
	"fmt"
	"strings"
)

// Dialect abstracts SQL differences between PostgreSQL and other databases.
type Dialect interface {
	// TimeBucket returns a SQL expression that truncates column to the given
	// unit ("minute", "hour", or "day") and formats it as a string.
	TimeBucket(unit, column string) string

	// QuoteIdent returns name wrapped in the dialect's identifier-quoting characters.
	QuoteIdent(name string) string

	// IsPostgres reports whether this dialect targets PostgreSQL.
	IsPostgres() bool

	// MinutesBetween returns a SQL expression yielding the number of minutes
	// (a floating-point value, may be negative) from startCol to endCol. Both
	// arguments must reference timestamp columns.
	MinutesBetween(endCol, startCol string) string

	// AddrInCIDR returns a SQL predicate (with one bind placeholder, taking the
	// CIDR as text) that is TRUE when the address in column falls inside it.
	// ok is false when the dialect cannot express containment exactly, in which
	// case callers must fall back to prefix matching and accept a superset.
	AddrInCIDR(column string) (expr string, ok bool)

	// CastText returns a SQL expression rendering expr as text. Postgres will
	// not implicitly concatenate an integer, so numeric dimension values have to
	// be cast explicitly before they can share a text column.
	CastText(expr string) string

	// Concat joins its arguments into one text value. Postgres and SQLite both
	// spell this `||`, but it is behind the interface so a future dialect that
	// does not is a compile error rather than a runtime surprise.
	Concat(parts ...string) string
}

// ---------- PostgreSQL ----------

type postgresDialect struct{}

func (postgresDialect) TimeBucket(unit, column string) string {
	switch unit {
	case "minute":
		return fmt.Sprintf("to_char(date_trunc('minute', %s), 'YYYY-MM-DD HH24:MI')", column)
	case "5min":
		return fmt.Sprintf("to_char(date_trunc('hour', %s) + INTERVAL '5 min' * FLOOR(EXTRACT(MINUTE FROM %s)/5), 'YYYY-MM-DD HH24:MI')", column, column)
	case "hour":
		return fmt.Sprintf("to_char(date_trunc('hour', %s), 'YYYY-MM-DD HH24:00')", column)
	case "6hour":
		return fmt.Sprintf("to_char(date_trunc('day', %s) + INTERVAL '6 hour' * FLOOR(EXTRACT(HOUR FROM %s)/6), 'YYYY-MM-DD HH24:00')", column, column)
	case "day":
		return fmt.Sprintf("to_char(date_trunc('day', %s), 'YYYY-MM-DD')", column)
	default:
		return fmt.Sprintf("to_char(date_trunc('hour', %s), 'YYYY-MM-DD HH24:00')", column)
	}
}

func (postgresDialect) QuoteIdent(name string) string {
	return `"` + name + `"`
}

func (postgresDialect) IsPostgres() bool { return true }

func (postgresDialect) MinutesBetween(endCol, startCol string) string {
	return fmt.Sprintf("(EXTRACT(EPOCH FROM (%s - %s)) / 60.0)", endCol, startCol)
}

// AddrInCIDR uses the inet containment operator, which is exact for any mask
// length and for both address families (a v4 address is simply not contained in
// a v6 prefix).
//
// NULLIF(col,”) is load-bearing, not defensive tidiness. Production carries
// 2,377 rows in flow_rollups whose src_addr and dst_addr are the empty string
// (protocol 0, all in the 1d tier, so every window over 30 days reads them), and
// ”::inet raises "invalid input syntax for type inet" — which aborts the whole
// statement, not just that row. NULL is simply not contained by any prefix, so
// those rows are excluded, which is the right answer for a row with no address.
func (postgresDialect) AddrInCIDR(column string) (string, bool) {
	return fmt.Sprintf("NULLIF(%s, '')::inet <<= ?::inet", column), true
}

func (postgresDialect) CastText(expr string) string { return fmt.Sprintf("CAST(%s AS TEXT)", expr) }

func (postgresDialect) Concat(parts ...string) string { return strings.Join(parts, " || ") }

// ---------- SQLite (test only) ----------

type sqliteDialect struct{}

func (sqliteDialect) TimeBucket(unit, column string) string {
	switch unit {
	case "minute":
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:%%M', %s)", column)
	case "5min":
		return sqliteEpochBucket(column, 300, "%Y-%m-%d %H:%M")
	case "hour":
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:00', %s)", column)
	case "6hour":
		return sqliteEpochBucket(column, 21600, "%Y-%m-%d %H:00")
	case "day":
		return fmt.Sprintf("strftime('%%Y-%%m-%%d', %s)", column)
	default:
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:00', %s)", column)
	}
}

// sqliteEpochBucket truncates to an arbitrary number of seconds by flooring the
// Unix epoch, which plain strftime cannot express.
//
// Both of its callers used to return a strftime one unit FINER than they
// claimed: "5min" was a minute bucket and "6hour" an hour bucket, while the
// Postgres forms bucket at the real width. That is not a harmless dev-lane
// approximation. The raw→5m promotion groups by this expression, so on SQLite it
// emitted one rollup row per MINUTE under the interval_type "5m" — five times the
// rows, each labelled with a bucket that no reader's bucket arithmetic agrees
// with, and it made the ladder's whole-bucket property impossible to test at the
// tier where promotion runs most often.
//
// strftime('%s', …) resolves the column's own offset to UTC, so this buckets in
// UTC exactly as Postgres does under the DSN's pinned TimeZone=UTC.
func sqliteEpochBucket(column string, seconds int, layout string) string {
	return fmt.Sprintf("strftime('%s', (CAST(strftime('%%s', %s) AS INTEGER) / %d) * %d, 'unixepoch')",
		layout, column, seconds, seconds)
}

func (sqliteDialect) QuoteIdent(name string) string { return `"` + name + `"` }
func (sqliteDialect) IsPostgres() bool              { return false }

func (sqliteDialect) MinutesBetween(endCol, startCol string) string {
	return fmt.Sprintf("((julianday(%s) - julianday(%s)) * 1440.0)", endCol, startCol)
}

// AddrInCIDR is not expressible in SQLite without an extension, so callers fall
// back to prefix matching. SQLite is the dev/test lane only; production is
// PostgreSQL, where containment is exact.
func (sqliteDialect) AddrInCIDR(string) (string, bool) { return "", false }

func (sqliteDialect) CastText(expr string) string { return fmt.Sprintf("CAST(%s AS TEXT)", expr) }

func (sqliteDialect) Concat(parts ...string) string { return strings.Join(parts, " || ") }
