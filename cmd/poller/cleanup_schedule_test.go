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

// The regression guard proper: the run loop must not go back to arming retention
// with a bare Ticker, whose first fire is one full interval after start.
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
		if !ok || !strings.Contains(strings.ToLower(ident.Name), "cleanup") {
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
			offenders = append(offenders, ident.Name)
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
