package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"
)

// AUDIT-188 (2026-08-27 audit): the daily retention cleanup can run for hours
// against a large backlog on the non-partitioned production syslog heap, and it
// used to run INLINE in the poller's single select loop — parking the loop so
// serverHealthTicker was never serviced and checkServerHealth (the 2026-07-26
// postmortem's disk-full detector) could not fire for the whole cleanup,
// exactly while large DELETEs were transiently growing WAL + dead-tuple usage.
// The fix mirrors the M9 threat-feed shape (async launch, single-flight guard)
// PLUS two subtleties these tests pin:
//   - server-health must NOT go through the shared advisory work lock: the
//     async cleanup holds that single lock for its whole run and a second
//     acquire from the SAME process contends, so a locked disk check would be
//     rejected for the entire cleanup — the blindness merely relocated.
//   - the async goroutine must not stamp the M30 loop-liveness heartbeat,
//     which would mask a genuinely hung select loop.

// TestStartRetentionCleanupAsync_OffLoopAndCleansUp mirrors the M9 async test:
// the launch must not block the caller, and the in-flight guard must clear once
// the cleanup finishes. A nil-db poller's runRetentionCleanup is a fast no-op.
func TestStartRetentionCleanupAsync_OffLoopAndCleansUp(t *testing.T) {
	p := &Poller{} // db nil ⇒ runRetentionCleanup is a fast no-op

	done := make(chan struct{})
	go func() { p.startRetentionCleanupAsync(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("startRetentionCleanupAsync blocked the caller — it must run off the loop")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !p.cleanupRunning.Load() {
			return // cleaned up as expected
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("cleanupRunning never cleared — the guard would wedge all future cleanups")
}

// TestStartRetentionCleanupAsync_NoStacking verifies the single-flight guard:
// while one cleanup is in flight, a second launch is a no-op — a cleanup slower
// than the 24h cadence must not stack a competitor onto the same tables.
func TestStartRetentionCleanupAsync_NoStacking(t *testing.T) {
	p := &Poller{}
	p.cleanupRunning.Store(true) // simulate an in-flight cleanup

	p.startRetentionCleanupAsync()
	if !p.cleanupRunning.Load() {
		t.Error("a re-entrant launch cleared the in-flight guard — cleanups could stack")
	}
	p.cleanupRunning.Store(false) // cleanup
}

// TestServerHealthCase_NotUnderSharedWorkLock pins that the run loop's
// server-health case calls checkServerHealth DIRECTLY, never through
// runUnderLeaderLock/runUnderLeaderLockNoHeartbeat. The shared advisory lock is
// held by the async cleanup for its whole (potentially multi-hour) run — and it
// is per-connection, so a second acquire from this same process is rejected
// like another poller's — meaning a locked disk check would be skipped for the
// entire cleanup: the exact postmortem failure shape, relocated.
func TestServerHealthCase_NotUnderSharedWorkLock(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var healthCases, healthCalls, lockedCalls int
	ast.Inspect(file, func(n ast.Node) bool {
		comm, ok := n.(*ast.CommClause)
		if !ok || comm.Comm == nil {
			return true
		}
		// Only the case that receives from the server-health ticker's channel.
		recvsHealthTicker := false
		ast.Inspect(comm.Comm, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok && sel.Sel.Name == "C" {
				if id, ok := sel.X.(*ast.Ident); ok && strings.Contains(strings.ToLower(id.Name), "health") {
					recvsHealthTicker = true
				}
			}
			return true
		})
		if !recvsHealthTicker {
			return true
		}
		healthCases++
		for _, stmt := range comm.Body {
			ast.Inspect(stmt, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := ""
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				case *ast.Ident:
					name = fn.Name
				}
				switch name {
				case "checkServerHealth":
					healthCalls++
				case "runUnderLeaderLock", "runUnderLeaderLockNoHeartbeat":
					lockedCalls++
				}
				return true
			})
		}
		return true
	})

	if healthCases == 0 {
		t.Fatal("no select case receives from the server-health ticker — the disk-full detector is unwired (the 2026-07-26 incident shape)")
	}
	if healthCalls == 0 {
		t.Error("the server-health select case does not call checkServerHealth")
	}
	if lockedCalls > 0 {
		t.Error("the server-health select case routes through the shared work lock — " +
			"the async retention cleanup holds that lock for its whole run, so the disk " +
			"check would be rejected for hours (AUDIT-188: call checkServerHealth directly)")
	}
}

// TestRetentionCleanup_DoesNotStampLoopHeartbeat pins the M30 interaction:
// runRetentionCleanup executes on a background goroutine, so it must take the
// NoHeartbeat lock variant and never call markLoopAlive itself. Stamping the
// loop beat from off-loop work would keep /readyz green while the select loop
// was genuinely hung — the staleness M30 exists to expose.
func TestRetentionCleanup_DoesNotStampLoopHeartbeat(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "runRetentionCleanup" {
			continue
		}
		var noHeartbeat, heartbeatLock, stamps int
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "runUnderLeaderLockNoHeartbeat":
				noHeartbeat++
			case "runUnderLeaderLock":
				heartbeatLock++
			case "markLoopAlive":
				stamps++
			}
			return true
		})
		if noHeartbeat == 0 {
			t.Error("runRetentionCleanup does not use runUnderLeaderLockNoHeartbeat — cross-process leader gating for the cleanup is gone or on the wrong variant")
		}
		if heartbeatLock > 0 || stamps > 0 {
			t.Error("runRetentionCleanup stamps the M30 loop heartbeat (directly or via runUnderLeaderLock) — from the async goroutine that masks a hung select loop")
		}
		return
	}
	t.Fatal("no (*Poller).runRetentionCleanup method found")
}
