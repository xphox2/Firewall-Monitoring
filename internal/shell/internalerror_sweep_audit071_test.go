package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInternalErrorSweep_AUDIT071 pins that the handler layer no longer uses the
// bare `c.JSON(http.StatusInternalServerError, models.ErrorResponse(...))`
// boilerplate the audit flagged (134 sites that returned a 500 without logging
// the cause). Every 500 must now go through httputil.InternalError, which logs
// the underlying err. This guard fails if a future handler reintroduces the
// silent form.
func TestInternalErrorSweep_AUDIT071(t *testing.T) {
	const dir = "../../internal/api/handlers"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s (AUDIT-071): %v", dir, err)
	}

	const banned = "StatusInternalServerError, models.ErrorResponse"
	var offenders []string
	var sawHelperCall bool

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("cannot read %s (AUDIT-071): %v", name, err)
		}
		body := string(data)
		if strings.Contains(body, banned) {
			offenders = append(offenders, name)
		}
		if strings.Contains(body, "httputil.InternalError(c,") {
			sawHelperCall = true
		}
	}

	if len(offenders) > 0 {
		t.Errorf("these handler files still emit a 500 via the silent boilerplate %q (AUDIT-071): route them through httputil.InternalError(c, msg, err) so the cause is logged. Files: %s",
			banned, strings.Join(offenders, ", "))
	}
	if !sawHelperCall {
		t.Error("no handler calls httputil.InternalError (AUDIT-071): the logging 500 helper appears unused — the sweep may have regressed.")
	}
}
