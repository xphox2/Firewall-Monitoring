package database

import "fmt"

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

// ---------- SQLite (test only) ----------

type sqliteDialect struct{}

func (sqliteDialect) TimeBucket(unit, column string) string {
	switch unit {
	case "minute":
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:%%M', %s)", column)
	case "5min":
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:%%M', %s)", column)
	case "hour":
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:00', %s)", column)
	case "6hour":
		// SQLite is dev/test only — approximate 6-hour buckets at hour
		// resolution (Postgres does true 6-hour bucketing in prod).
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:00', %s)", column)
	case "day":
		return fmt.Sprintf("strftime('%%Y-%%m-%%d', %s)", column)
	default:
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:00', %s)", column)
	}
}

func (sqliteDialect) QuoteIdent(name string) string { return `"` + name + `"` }
func (sqliteDialect) IsPostgres() bool              { return false }

func (sqliteDialect) MinutesBetween(endCol, startCol string) string {
	return fmt.Sprintf("((julianday(%s) - julianday(%s)) * 1440.0)", endCol, startCol)
}
