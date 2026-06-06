package metrics

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// TestRegistry_IncAndSnapshot covers the basic Inc / Snapshot round
// trip on the AUDIT-070 probe_batch_dedup_total counter: the counter
// is 0 before any increment, 1 after one, N after N, and labels are
// isolated from each other (inc on "syslog" must not bump "traps").
func TestRegistry_IncAndSnapshot(t *testing.T) {
	r := NewRegistry()

	if got := r.BatchDedupSnapshot("syslog"); got != 0 {
		t.Fatalf("initial: snapshot=%d, want 0", got)
	}

	r.IncBatchDedup("syslog")
	if got := r.BatchDedupSnapshot("syslog"); got != 1 {
		t.Errorf("after 1 inc: snapshot=%d, want 1", got)
	}

	r.IncBatchDedup("syslog")
	r.IncBatchDedup("syslog")
	if got := r.BatchDedupSnapshot("syslog"); got != 3 {
		t.Errorf("after 3 incs: snapshot=%d, want 3", got)
	}

	// Label isolation: a different endpoint's counter must stay
	// at 0.
	if got := r.BatchDedupSnapshot("traps"); got != 0 {
		t.Errorf("cross-label leak: traps=%d, want 0", got)
	}
	r.IncBatchDedup("traps")
	if got := r.BatchDedupSnapshot("traps"); got != 1 {
		t.Errorf("traps after 1 inc: %d, want 1", got)
	}
	if got := r.BatchDedupSnapshot("syslog"); got != 3 {
		t.Errorf("syslog leaked by traps inc: %d, want 3", got)
	}
}

// TestRegistry_ConcurrentInc verifies the atomic counter is safe
// under concurrent Inc calls. The final value must equal the total
// number of calls — a missing atomic would race and produce a
// smaller value (or, with -race, a data race).
func TestRegistry_ConcurrentInc(t *testing.T) {
	r := NewRegistry()

	const goroutines = 50
	const perGoroutine = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				r.IncBatchDedup("syslog")
			}
		}()
	}
	wg.Wait()

	want := uint64(goroutines * perGoroutine)
	if got := r.BatchDedupSnapshot("syslog"); got != want {
		t.Errorf("concurrent inc: snapshot=%d, want %d", got, want)
	}
}

// TestRegistry_PrometheusTextFormat pins the Prometheus text exposition
// format for the probe_batch_dedup_total counter — the contract the
// server's /api/metrics endpoint exposes. A scraper is hard-coded to
// parse this exact shape, so a future refactor that accidentally
// renames the metric, drops the # HELP / # TYPE headers, or changes
// the label syntax would silently break dashboards.
func TestRegistry_PrometheusTextFormat(t *testing.T) {
	r := NewRegistry()
	r.IncBatchDedup("syslog")
	r.IncBatchDedup("syslog")
	r.IncBatchDedup("traps")

	var buf bytes.Buffer
	if err := r.WritePrometheusText(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	body := buf.String()

	// Per-metric HELP + TYPE headers. The "counter" type
	// matches the metric's semantic (monotonically increasing).
	if !regexp.MustCompile(`(?m)^# HELP probe_batch_dedup_total `).MatchString(body) {
		t.Errorf("missing # HELP for probe_batch_dedup_total:\n%s", body)
	}
	if !regexp.MustCompile(`(?m)^# TYPE probe_batch_dedup_total counter$`).MatchString(body) {
		t.Errorf("missing # TYPE for probe_batch_dedup_total:\n%s", body)
	}

	// Sample lines. The exact ordering is not part of the
	// Prometheus contract, but our implementation sorts
	// labelKeys so the output is deterministic for diffs/tests.
	// Each label appears as its own sample line.
	if !strings.Contains(body, `probe_batch_dedup_total{endpoint="syslog"} 2`) {
		t.Errorf("missing/wrong syslog sample (want 2):\n%s", body)
	}
	if !strings.Contains(body, `probe_batch_dedup_total{endpoint="traps"} 1`) {
		t.Errorf("missing/wrong traps sample (want 1):\n%s", body)
	}
}

// TestRegistry_Reset verifies the test-helper Reset() method clears
// every counter, so tests calling Reset() in their setup don't see
// counts carried over from earlier tests in the same process.
func TestRegistry_Reset(t *testing.T) {
	r := NewRegistry()
	r.IncBatchDedup("syslog")
	r.IncBatchDedup("traps")
	if r.BatchDedupSnapshot("syslog") == 0 {
		t.Fatalf("pre-reset: syslog is 0 (Inc didn't take)")
	}
	r.Reset()
	if got := r.BatchDedupSnapshot("syslog"); got != 0 {
		t.Errorf("post-Reset: r/syslog=%d, want 0", got)
	}
	if got := r.BatchDedupSnapshot("traps"); got != 0 {
		t.Errorf("post-Reset: r/traps=%d, want 0", got)
	}

	// Also exercise the package-global Reset path that the
	// handler tests rely on (they reset DefaultRegistry between
	// tests so a process-wide counter doesn't leak).
	DefaultRegistry.IncBatchDedup("syslog")
	DefaultRegistry.Reset()
	if got := DefaultRegistry.BatchDedupSnapshot("syslog"); got != 0 {
		t.Errorf("post-DefaultRegistry.Reset: syslog=%d, want 0", got)
	}
}
