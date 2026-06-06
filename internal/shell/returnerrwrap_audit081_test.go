package shell

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestNoBareReturnErrInDatabase_AUDIT081 pins that database.go no longer
// returns GORM's `tx.Error` raw. The audit found 46 sites of bare `return err`
// where a transaction/query error propagated with no operation context, so a
// caller (and an operator reading a log) could not tell "not found in a tx"
// from "constraint violation in a tx". The fix wraps each with
// `fmt.Errorf("operation: %w", err)` — `%w` (not `%v`) so callers keep working
// errors.Is / errors.As against the underlying gorm sentinel.
//
// This is a static guard: a future edit that reintroduces a bare `return err`
// (dropping the context) fails here. Only database.go itself is the audited
// surface.
func TestNoBareReturnErrInDatabase_AUDIT081(t *testing.T) {
	const path = "../../internal/database/database.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("database.go not found at %s; err: %v", path, err)
	}
	body := string(data)

	// A bare `return err` (only whitespace before, end of statement after).
	bare := regexp.MustCompile(`(?m)^\s*return err\s*$`)
	if locs := bare.FindAllStringIndex(body, -1); len(locs) > 0 {
		var lines []string
		for _, loc := range locs {
			lines = append(lines, strconv.Itoa(1+strings.Count(body[:loc[0]], "\n")))
		}
		t.Errorf("database.go has %d bare `return err` site(s) (AUDIT-081): wrap with fmt.Errorf(\"operation: %%w\", err) so callers keep operation context and errors.Is/As. Lines: %s",
			len(locs), strings.Join(lines, ", "))
	}

	// And the wrapping must use %w (errors.Is-preserving), not %v, for the
	// gorm error path. At least one such wrap should exist.
	if !regexp.MustCompile(`fmt\.Errorf\([^)]*%w[^)]*err\)`).MatchString(body) {
		t.Error("database.go no longer wraps any error with fmt.Errorf(... %w ..., err) (AUDIT-081): the wrap must use %w so errors.Is/As still unwrap to the gorm sentinel.")
	}
}
