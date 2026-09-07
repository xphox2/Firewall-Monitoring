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
