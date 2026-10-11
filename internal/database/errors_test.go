package database

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// TestIsRelationNameConflict pins the classification that makes leaf-index
// creation race-safe (the v0.11.321 fix): a 23505 on the catalog's
// pg_class_relname_nsp_index means a sibling process created the same index
// between our IF NOT EXISTS check and the CREATE, so it is success — while a
// 23505 on any other constraint (a real unique violation over data) is not.
func TestIsRelationNameConflict(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"name conflict", &pgconn.PgError{Code: "23505", ConstraintName: "pg_class_relname_nsp_index"}, true},
		{"wrapped name conflict", fmt.Errorf("create: %w", &pgconn.PgError{Code: "23505", ConstraintName: "pg_class_relname_nsp_index"}), true},
		{"unique violation on a data index", &pgconn.PgError{Code: "23505", ConstraintName: "devices_name_key"}, false},
		{"23505 with no constraint name", &pgconn.PgError{Code: "23505"}, false},
		{"different SQLSTATE", &pgconn.PgError{Code: "55P03", ConstraintName: "pg_class_relname_nsp_index"}, false},
		{"gorm duplicated key", gorm.ErrDuplicatedKey, false},
		{"plain error", errors.New("plain"), false},
		{"nil", nil, false},
	} {
		if got := isRelationNameConflict(tc.err); got != tc.want {
			t.Errorf("%s: isRelationNameConflict(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}
