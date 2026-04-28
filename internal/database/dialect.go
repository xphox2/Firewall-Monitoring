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
	case "day":
		return fmt.Sprintf("strftime('%%Y-%%m-%%d', %s)", column)
	default:
		return fmt.Sprintf("strftime('%%Y-%%m-%%d %%H:00', %s)", column)
	}
}

func (sqliteDialect) QuoteIdent(name string) string { return `"` + name + `"` }
func (sqliteDialect) IsPostgres() bool              { return false }
