package handlers

import (
	"database/sql"
	"strings"
	"testing"

	"gorm.io/gorm"
)

// cloneRows seeds many rows fast by copying one template row (written through
// GORM, so every column holds GORM's own zero values and the timestamp format
// of the real writers) with a prepared INSERT … SELECT in one transaction.
// Only the columns in override change per row; vals(i) returns their values
// for the i-th clone, bound as driver arguments exactly as GORM binds them.
//
// GORM's CreateInBatches spends ~8 ms a row in reflection under -race: 5,040
// status rows took 40 s, and four such tests pushed this package past CI's
// 10-minute -race timeout. This path is ~100x faster with identical rows.
func cloneRows(t *testing.T, gdb *gorm.DB, table string, templateID uint, override []string, n int, vals func(i int) []any) {
	t.Helper()
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := sqlDB.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		if c != "id" {
			cols = append(cols, c)
		}
	}
	rows.Close()
	if len(cols) == 0 {
		t.Fatalf("no columns for %s", table)
	}
	isOverride := map[string]bool{}
	for _, c := range override {
		isOverride[c] = true
	}
	quoted := make([]string, len(cols))
	sel := make([]string, len(cols))
	var order []string
	for i, c := range cols {
		quoted[i] = `"` + c + `"`
		if isOverride[c] {
			sel[i] = "?"
			order = append(order, c)
		} else {
			sel[i] = `"` + c + `"`
		}
	}
	if len(order) != len(override) {
		t.Fatalf("override columns %v not all in %s", override, table)
	}
	q := `INSERT INTO "` + table + `" (` + strings.Join(quoted, ",") + `) SELECT ` + strings.Join(sel, ",") + ` FROM "` + table + `" WHERE id = ?`
	tx, err := sqlDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(q)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		byName := map[string]any{}
		v := vals(i)
		for j, c := range override {
			byName[c] = v[j]
		}
		args := make([]any, 0, len(order)+1)
		for _, c := range order {
			args = append(args, byName[c])
		}
		args = append(args, templateID)
		if _, err := stmt.Exec(args...); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := closeCommit(stmt, tx); err != nil {
		t.Fatal(err)
	}
}

func closeCommit(stmt *sql.Stmt, tx *sql.Tx) error {
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
