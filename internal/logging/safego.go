package logging

import (
	"fmt"
	"log/slog"
	"runtime/debug"
)

// SafeGo runs fn in a new goroutine guarded by panic recovery (REL-01).
//
// A panic in a long-lived daemon goroutine — the poller cycle, the report
// scheduler, the syslog/sFlow accept loops, the IRC manager loops, the batch
// flusher — is otherwise unrecoverable and crashes the ENTIRE process: Go has
// no process-wide panic handler, so one bad iteration in any background loop
// takes down every other subsystem sharing the binary. SafeGo contains the
// panic to its own goroutine, logs it with a stack trace at error level, and
// lets the rest of the daemon keep running.
//
// The goroutine still exits after a panic — SafeGo converts a fatal
// whole-process crash into a loud, contained, logged subsystem failure. It does
// not restart fn. Callers whose loop must survive a single bad iteration should
// recover per-iteration with Recover instead.
func SafeGo(name string, fn func()) {
	go func() {
		defer Recover(name)
		fn()
	}()
}

// Recover is the deferred panic handler used by SafeGo. Call it directly as the
// first statement of a goroutine that manages its own lifecycle — one whose
// existing defers (WaitGroup.Done, channel close) must still run in order:
//
//	go func() {
//	    defer logging.Recover("irc-bot")
//	    defer wg.Done()
//	    ...
//	}()
//
// It logs any in-flight panic with a stack trace and swallows it, so the
// goroutine unwinds cleanly instead of crashing the process. A deferred recover
// catches the panic regardless of its position among sibling defers, so the
// other defers still run.
func Recover(name string) {
	if r := recover(); r != nil {
		slog.Error("recovered from panic in goroutine",
			"goroutine", name,
			"panic", fmt.Sprintf("%v", r),
			"stack", string(debug.Stack()),
		)
	}
}
