package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"
)

// Retention silently never ran in production.
//
// CleanupOldData was reachable only from a `time.NewTicker(24 * time.Hour)`, and
// a Ticker counts from process start. On a deployment that restarts more often
// than once a day — several releases most days, plus every crash and reboot —
// the ticker never reached its first tick, so no retention policy was ever
// applied. Production accumulated 45 days of syslog under a 30-day policy,
// filled a 98GB volume, and Postgres crash-looped on "No space left on device".
//
// These pin the schedule itself, because the failure is invisible in any test
// that simply calls the cleanup function: the bug was never in the cleanup, only
// in whether anything called it.

func TestRetentionCleanup_FirstRunIsNotAFullInterval(t *testing.T) {
	if initialCleanupDelay >= cleanupInterval {
		t.Fatalf("initialCleanupDelay = %v, cleanupInterval = %v — the first run must not "+
			"wait a whole interval, or a process restarted more often than that never "+
			"runs retention at all", initialCleanupDelay, cleanupInterval)
	}
	// Long enough not to fight startup, short enough that a frequently-restarted
	// process still reaches it.
	if initialCleanupDelay > 30*time.Minute {
		t.Errorf("initialCleanupDelay = %v is too long to be reliably reached between "+
			"deployments", initialCleanupDelay)
	}
	if initialCleanupDelay <= 0 {
		t.Errorf("initialCleanupDelay = %v would run cleanup during startup", initialCleanupDelay)
	}
}

// GAP A: the tests above all pass if the select case is DELETED outright while
// the timer declaration stays (the `defer Stop()` keeps it compiling). That is
// the literal incident — "nothing calls the cleanup" — surviving a green suite.
// So pin the call site and the re-arm, not just the timer's construction.
func TestRetentionCleanup_RunLoopCallsItAndReArms(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var calls, rearms int
	ast.Inspect(file, func(n ast.Node) bool {
		comm, ok := n.(*ast.CommClause)
		if !ok {
			return true
		}
		// Comm is nil for a `default:` clause, and ast.Inspect panics on nil.
		if comm.Comm == nil {
			return true
		}
		// Only the case that receives from the cleanup timer's channel.
		recvsCleanupTimer := false
		ast.Inspect(comm.Comm, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok && sel.Sel.Name == "C" {
				if id, ok := sel.X.(*ast.Ident); ok && strings.Contains(strings.ToLower(id.Name), "cleanup") {
					recvsCleanupTimer = true
				}
			}
			return true
		})
		if !recvsCleanupTimer {
			return true
		}
		for _, stmt := range comm.Body {
			ast.Inspect(stmt, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					if fn.Sel.Name == "runRetentionCleanup" {
						calls++
					}
					if fn.Sel.Name == "Reset" {
						rearms++
					}
				case *ast.Ident:
					if fn.Name == "runRetentionCleanup" {
						calls++
					}
				}
				return true
			})
		}
		return true
	})

	if calls == 0 {
		t.Error("the cleanup timer's select case does not call runRetentionCleanup — " +
			"retention never runs. This is the incident: the cleanup code was correct " +
			"and well covered, and nothing invoked it.")
	}
	if rearms == 0 {
		t.Error("the cleanup timer's select case never calls Reset — a Timer fires ONCE, " +
			"so retention would run a single time per process and never again")
	}
}

// The regression guard proper: the run loop must not go back to arming retention
// with a bare Ticker, whose first fire is one full interval after start.
//
// GAP C: keyed on the DURATION, not the variable name — an innocent rename to
// `retentionTicker` evaded the name-keyed version of this check.
func TestRetentionCleanup_RunLoopDoesNotUseATicker(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var offenders []string
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "time" && sel.Sel.Name == "NewTicker" {
			// Only retention-cadence tickers. The poll ticker is legitimate.
			for _, arg := range call.Args {
				if id, ok := arg.(*ast.Ident); ok && id.Name == "cleanupInterval" {
					offenders = append(offenders, ident.Name)
				}
			}
			if strings.Contains(strings.ToLower(ident.Name), "cleanup") ||
				strings.Contains(strings.ToLower(ident.Name), "retention") {
				offenders = append(offenders, ident.Name)
			}
		}
		return true
	})

	if len(offenders) > 0 {
		t.Errorf("%v armed with time.NewTicker — a Ticker's first fire is one full interval "+
			"after process start, so retention never runs on a process that restarts more "+
			"often than that. Use a Timer with a short initial delay, then Reset.", offenders)
	}
}

// The cleanup body must live somewhere callable, not be inlined in the select
// case — otherwise the "run it at startup too" fix cannot be applied without
// duplicating it, which is how the two paths drift apart.
func TestRetentionCleanup_IsAReusableFunction(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "runRetentionCleanup" && fn.Recv != nil {
			return
		}
	}
	t.Error("no (*Poller).runRetentionCleanup method — the cleanup body must be callable " +
		"from both the startup path and the periodic one")
}
