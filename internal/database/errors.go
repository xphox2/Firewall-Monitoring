package database

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// IsUniqueViolation reports whether err is a unique-constraint violation on
// either supported backend: Postgres SQLSTATE 23505 (pgx surfaces it as a
// *pgconn.PgError, unwrapped through any %w chain) or SQLite's
// "UNIQUE constraint failed" message. Handlers use it to turn a duplicate
// device/site name into a 409 instead of an opaque 500. gorm.ErrDuplicatedKey
// is accepted too for drivers configured with TranslateError.
func IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// sqlState returns the Postgres SQLSTATE code carried by err (unwrapped through
// any %w chain), or "" when err is nil or not a Postgres driver error (SQLite
// never sets one). The purge worker branches on it: 57014 statement timeout,
// 55P03 lock timeout, 42P01 relation vanished (a partition dropped by retention).
func sqlState(err error) string {
	if err == nil {
		return ""
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// isRelationNameConflict reports whether err is the PostgreSQL 23505 raised when
// two processes race to CREATE the same catalog relation under the same name
// (e.g. a leaf index in ensureLeafIndexes): `CREATE INDEX IF NOT EXISTS` checks
// the catalog before creating, but that check is not serialized against a
// sibling's create, so the loser fails on pg_class_relname_nsp_index — the
// catalog's unique index over relation names — rather than being caught by the
// IF NOT EXISTS guard. It means a sibling process already created (or is
// creating) the relation, so the caller treats the CREATE as success. Scoped to
// that exact constraint name so a genuine 23505 on a data index (a unique
// constraint over rows) is never mistaken for it.
func isRelationNameConflict(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == "pg_class_relname_nsp_index"
}
