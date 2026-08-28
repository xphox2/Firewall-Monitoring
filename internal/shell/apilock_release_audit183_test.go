package shell

import (
	"os"
	"strings"
	"testing"
)

// TestAcquireAPISingletonLock_NeverReturnsNilRelease_AUDIT183 pins that
// every return path of AcquireAPISingletonLock yields a CALLABLE release
// func. main.go's lockErr branch deliberately proceeds as primary and
// registers `defer releaseSingleton()` with whatever the function returned;
// the pre-fix error paths returned a nil func, so a transient DB error
// during the startup probe (pool exhaustion, reset, statement_timeout)
// armed a nil-func panic that fired at the first graceful shutdown — every
// redeploy — instead of the clean "Server exited" path.
//
// The error paths need a live Postgres failure to exercise, so this is a
// source-level guard in the repo's established internal/shell style: the
// function body must contain no `return nil,` and must carry the AUDIT-183
// marker documenting the total-contract requirement.
func TestAcquireAPISingletonLock_NeverReturnsNilRelease_AUDIT183(t *testing.T) {
	const path = "../../internal/database/database.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("database.go not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	start := strings.Index(body, "func (d *Database) AcquireAPISingletonLock()")
	if start < 0 {
		t.Fatal("AcquireAPISingletonLock not found in internal/database/database.go — update this guard alongside the move (AUDIT-183).")
	}
	// Bound the scan at the next top-level func declaration.
	rest := body[start:]
	if end := strings.Index(rest[1:], "\nfunc "); end >= 0 {
		rest = rest[:end+1]
	}

	if strings.Contains(rest, "return nil,") {
		t.Error("AcquireAPISingletonLock has a `return nil, ...` path: the release func must be callable on EVERY path (use `return func() {}, false, err`), or main's `defer releaseSingleton()` panics at graceful shutdown after a transient lock-probe error (AUDIT-183).")
	}
	// The marker lives in the doc comment preceding the declaration, so
	// check the whole file rather than the bounded body.
	if !strings.Contains(body, "AUDIT-183") {
		t.Error("internal/database/database.go is missing the AUDIT-183 marker comment documenting the always-callable release contract.")
	}
}
