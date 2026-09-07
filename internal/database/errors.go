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
