package guardrails

import (
	"strings"
	"testing"
)

// TestNormalizeObservedFlush_AwaitedAtShutdown pins the shutdown order the
// observed-field counters depend on (S-4 review): the flusher loop signals
// its exit on a done channel, and main waits for it AFTER server.Shutdown has
// drained the in-flight syslog batches, then flushes once more — otherwise
// counts recorded between bgCancel and the last request are lost, and the
// loop's own final flush races the drain.
func TestNormalizeObservedFlush_AwaitedAtShutdown(t *testing.T) {
	src := readFile(t, "../../cmd/api/main.go")
	for _, needle := range []string{
		"observedFlushDone := make(chan struct{})",
		"defer close(observedFlushDone)",
		"handler.RunObservedFlusher(bgCtx)",
	} {
		if !strings.Contains(src, needle) {
			t.Errorf("cmd/api/main.go missing %q (observed-field flusher wiring)", needle)
		}
	}
	shutdown := strings.Index(src, "server.Shutdown(ctx)")
	wait := strings.Index(src, "case <-observedFlushDone:")
	final := strings.LastIndex(src, "handler.FlushFieldObserved()")
	if shutdown < 0 || wait < 0 || final < 0 {
		t.Fatalf("main.go: Shutdown=%d wait=%d finalFlush=%d — one of the shutdown steps is missing", shutdown, wait, final)
	}
	if !(shutdown < wait && wait < final) {
		t.Errorf("main.go shutdown order must be server.Shutdown → <-observedFlushDone → handler.FlushFieldObserved(); got offsets %d, %d, %d", shutdown, wait, final)
	}
}
