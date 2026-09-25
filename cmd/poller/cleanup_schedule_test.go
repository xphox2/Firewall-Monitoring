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
// AUDIT-188: the pinned call is now startRetentionCleanupAsync — the cleanup
// launches off the select loop so a multi-hour backlog clear cannot park the
// loop and starve the server-health disk check.
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
					if fn.Sel.Name == "startRetentionCleanupAsync" {
						calls++
					}
					if fn.Sel.Name == "Reset" {
						rearms++
					}
				case *ast.Ident:
					if fn.Name == "startRetentionCleanupAsync" {
						calls++
					}
				}
				return true
			})
		}
		return true
	})

	if calls == 0 {
		t.Error("the cleanup timer's select case does not call startRetentionCleanupAsync — " +
			"retention never runs. This is the incident: the cleanup code was correct " +
			"and well covered, and nothing invoked it. (AUDIT-188: the call must be the " +
			"async launcher, not a synchronous runRetentionCleanup that parks the loop.)")
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

// Third variant of the same failure: retention not running, for a third reason.
//
// The first was a Ticker that never reached its first tick across restarts. The
// second was a statement timeout abandoning a table for the day (v0.11.254). This
// is the one that made the second so rare — the work lock is NON-BLOCKING and the
// next attempt was 24h away, so losing a race forfeited the entire day. And the
// race was not chance, it was arithmetic: the monitoring ticker is
// SNMP.PollInterval (60s on prod) and both cleanup periods are exact multiples of
// it, so every attempt fired on the same instant as a monitoring tick. Observed on
// production 2026-09-25, five minutes after a deploy:
//
//	01:00:15 main.go:1070: Monitoring cycle: 5 device(s)
//	01:00:15 main.go:460: Skipping cleanup: another poller holds the work lock
//
// syslog_messages was at 37 days under a 30-day policy, 161 GB.

func TestRetentionCleanup_RetriesRatherThanForfeitingTheDay(t *testing.T) {
	origTry, origSleep, origNow := tryPollerWorkLock, sleepFor, timeNow
	defer func() { tryPollerWorkLock, sleepFor, timeNow = origTry, origSleep, origNow }()

	now := time.Now()
	timeNow = func() time.Time { return now }
	sleepFor = func(d time.Duration) { now = now.Add(d) }

	// Contended for the first two attempts, then free.
	attempts := 0
	tryPollerWorkLock = func(*Poller) (func(), bool) {
		attempts++
		if attempts < 3 {
			return nil, false
		}
		return func() {}, true
	}

	ran := false
	p := &Poller{}
	p.runRetentionCleanupFor(func() { ran = true })

	if !ran {
		t.Error("cleanup never ran: losing the non-blocking work lock must be retried, " +
			"not forfeited until the next daily tick 24h later")
	}
	if attempts != 3 {
		t.Errorf("lock attempts = %d, want 3 (two contended, then acquired)", attempts)
	}
}

func TestRetentionCleanup_LockRetryIsBounded(t *testing.T) {
	origTry, origSleep, origNow := tryPollerWorkLock, sleepFor, timeNow
	defer func() { tryPollerWorkLock, sleepFor, timeNow = origTry, origSleep, origNow }()

	now := time.Now()
	start := now
	timeNow = func() time.Time { return now }
	sleepFor = func(d time.Duration) { now = now.Add(d) }

	attempts := 0
	tryPollerWorkLock = func(*Poller) (func(), bool) { attempts++; return nil, false }

	ran := false
	p := &Poller{}
	p.runRetentionCleanupFor(func() { ran = true })

	if ran {
		t.Error("cleanup ran without holding the lock")
	}
	if elapsed := now.Sub(start); elapsed > cleanupLockRetryWindow+cleanupLockRetryInterval {
		t.Errorf("retried for %v, beyond the %v window — an unbounded retry would hold the "+
			"goroutine past the next daily tick", elapsed, cleanupLockRetryWindow)
	}
	if attempts < 2 {
		t.Errorf("attempts = %d, want more than one before giving up", attempts)
	}
}

// TestRetentionCleanup_RetryIntervalDoesNotAlignWithTheTickers pins the ROOT
// CAUSE, which is arithmetic rather than timing luck: a retry cadence that is a
// multiple of the tickers it is losing to re-collides on every attempt.
func TestRetentionCleanup_RetryIntervalDoesNotAlignWithTheTickers(t *testing.T) {
	// The cadences cleanup contends with: the 5-minute rollup/detect/ipsec
	// tickers (the actual holders — the select loop is serial, so the monitoring
	// cycle has already released by the time the cleanup case is serviced) and the
	// per-minute monitoring tick.
	//
	// Non-divisibility is NOT enough, and asserting only that was the first
	// version of this test. 90s is not a multiple of 60s yet alternates between
	// just two phases of it, so it re-collides every other retry; 150s visits two
	// phases of 300s. The property that matters is coprimality: gcd == 1s means
	// successive retries visit EVERY second-phase of the contending period, so a
	// gap cannot be missed systematically. 97 is prime, hence chosen.
	for _, contender := range []time.Duration{5 * time.Minute, time.Minute} {
		if g := gcdDuration(cleanupLockRetryInterval, contender); g != time.Second {
			t.Errorf("gcd(cleanupLockRetryInterval %v, %v) = %v, want 1s. Retries then visit "+
				"only %d of the %d phases of that ticker and can re-collide with it "+
				"systematically — which is how the original collision was arithmetic "+
				"rather than unlucky.", cleanupLockRetryInterval, contender, g,
				int(contender/g), int(contender/time.Second))
		}
	}
	if cleanupLockRetryWindow <= cleanupLockRetryInterval {
		t.Errorf("retry window %v allows no second attempt", cleanupLockRetryWindow)
	}
}

// gcdDuration is the greatest common divisor of two durations, used to check that
// the retry cadence is coprime with the tickers it contends with.
func gcdDuration(a, b time.Duration) time.Duration {
	for b != 0 {
		a, b = b, a%b
	}
	if a < 0 {
		a = -a
	}
	return a
}
