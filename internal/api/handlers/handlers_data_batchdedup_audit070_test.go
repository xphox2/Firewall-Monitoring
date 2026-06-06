package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// probeTestKey is the seed key used by testhelper_test.go's
// setupProbeAndDevice. Hard-coding the same string here keeps the
// AUDIT-070 test file self-contained without exporting the constant.
const probeTestKey = "test-key-abc123"

// sendBatchWithID is the AUDIT-070 test helper: POSTs a one-row syslog
// batch to /api/probes/:id/syslog with the given X-Probe-Batch-ID header
// (empty string omits the header — opt-out of idempotency, used by tests
// that want a guaranteed-new baseline). Returns the recorder so the
// caller can assert on status / headers / body.
func sendBatchWithID(t *testing.T, h *Handler, probeID uint, batchID string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/api/probes/:id/syslog", h.ReceiveSyslogMessages)
	body, _ := json.Marshal([]models.SyslogMessage{{Message: "audit-070", SourceIP: "10.0.0.1"}})
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/syslog", probeID), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+probeTestKey)
	req.Header.Set("Content-Type", "application/json")
	if batchID != "" {
		req.Header.Set("X-Probe-Batch-ID", batchID)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// countSyslogRows is a small helper used by the AUDIT-070 tests to
// assert "no duplicate was inserted" without dragging the gorm
// boilerplate into every test.
func countSyslogRows(t *testing.T, db *database.Database) int64 {
	t.Helper()
	var n int64
	if err := db.Gorm().Model(&models.SyslogMessage{}).Count(&n).Error; err != nil {
		t.Fatalf("count syslog: %v", err)
	}
	return n
}

// TestBatchDedup_DuplicateWithin5Min_ReturnsDuplicateStatus verifies the
// core AUDIT-070 contract: a retry of the same X-Probe-Batch-ID within
// the TTL window returns 200 with X-Probe-Server-Batch-Status: duplicate
// and does NOT re-insert the row. The "new" path on the first send
// returns 200 with X-Probe-Server-Batch-Status: new.
func TestBatchDedup_DuplicateWithin5Min_ReturnsDuplicateStatus(t *testing.T) {
	// Per-test counter reset so the metric assertion
	// (TestBatchDedup_MetricIncrements) doesn't see a count
	// carried over from an earlier test in the same process —
	// the metrics registry is process-global, not per-handler.
	metrics.DefaultRegistry.Reset()
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	// Set the TTL explicitly so the test isn't coupled to the
	// default value; the test is asserting the BEHAVIOUR (a
	// retry within the window is deduped) not the SPECIFIC
	// 5-minute value.
	h.config.Server.BatchDedupTTL = 5 * time.Minute

	// 1) First send of batch B1 → 200, status=new, row inserted.
	w1 := sendBatchWithID(t, h, probe.ID, "B1")
	if w1.Code != http.StatusOK {
		t.Fatalf("first send: status=%d body=%s", w1.Code, w1.Body.String())
	}
	if got := w1.Header().Get("X-Probe-Server-Batch-Status"); got != "new" {
		t.Errorf("first send: X-Probe-Server-Batch-Status=%q, want %q", got, "new")
	}
	if n := countSyslogRows(t, db); n != 1 {
		t.Fatalf("first send: rows=%d, want 1", n)
	}

	// 2) Retry of the SAME batch B1 (within TTL) → 200,
	// status=duplicate, body contains "deduped", no new row.
	w2 := sendBatchWithID(t, h, probe.ID, "B1")
	if w2.Code != http.StatusOK {
		t.Fatalf("retry: status=%d body=%s", w2.Code, w2.Body.String())
	}
	if got := w2.Header().Get("X-Probe-Server-Batch-Status"); got != "duplicate" {
		t.Errorf("retry: X-Probe-Server-Batch-Status=%q, want %q", got, "duplicate")
	}
	if !strings.Contains(w2.Body.String(), "deduped") {
		t.Errorf("retry: body missing deduped marker: %s", w2.Body.String())
	}
	if n := countSyslogRows(t, db); n != 1 {
		t.Errorf("retry inserted a duplicate: rows=%d, want 1", n)
	}
}

// TestBatchDedup_DuplicateAfterTTL_Inserted verifies that a retry of a
// batch whose record has aged past the TTL is treated as new: the dedup
// read must not short-circuit, the status header is "new", and a new
// row appears. We simulate "aged past the TTL" by backdating the
// processed_batches row to before the cutoff (faster and more reliable
// than sleeping through the TTL).
func TestBatchDedup_DuplicateAfterTTL_Inserted(t *testing.T) {
	metrics.DefaultRegistry.Reset()
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	// Tight 5-second TTL so the backdate is obviously "before
	// the cutoff" but the test still exercises the real
	// `timestamp >= ?` predicate in BatchAlreadyProcessed.
	h.config.Server.BatchDedupTTL = 5 * time.Second

	// 1) First send → recorded.
	if w := sendBatchWithID(t, h, probe.ID, "B-ttl"); w.Code != http.StatusOK {
		t.Fatalf("first send: status=%d body=%s", w.Code, w.Body.String())
	}
	if n := countSyslogRows(t, db); n != 1 {
		t.Fatalf("first send: rows=%d, want 1", n)
	}

	// 2) Backdate the processed_batches row to 1 hour ago —
	// well past the 5s TTL. The dedup read should now see
	// "no recent match" and let the next request through.
	old := time.Now().Add(-1 * time.Hour)
	if err := db.Gorm().Model(&models.ProcessedBatch{}).
		Where("probe_id = ? AND batch_id = ?", probe.ID, "B-ttl").
		Update("timestamp", old).Error; err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// 3) Retry with the same batch ID — must be treated as new
	// (status=new, 2nd row inserted).
	w2 := sendBatchWithID(t, h, probe.ID, "B-ttl")
	if w2.Code != http.StatusOK {
		t.Fatalf("post-TTL retry: status=%d body=%s", w2.Code, w2.Body.String())
	}
	if got := w2.Header().Get("X-Probe-Server-Batch-Status"); got != "new" {
		t.Errorf("post-TTL retry: X-Probe-Server-Batch-Status=%q, want %q", got, "new")
	}
	if n := countSyslogRows(t, db); n != 2 {
		t.Errorf("post-TTL retry not inserted: rows=%d, want 2", n)
	}
}

// TestBatchDedup_MetricIncrements verifies the AUDIT-070
// `probe_batch_dedup_total{endpoint="..."}` counter ticks on a dedup
// hit and stays at 0 on a successful first-send. This is the test
// that would catch a "counter incremented on the new path" or
// "counter not incremented on the dup path" regression — both of
// which would silently break operator visibility into how often the
// central server is deduping (i.e. how flaky the upstream is).
func TestBatchDedup_MetricIncrements(t *testing.T) {
	metrics.DefaultRegistry.Reset()
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	h.config.Server.BatchDedupTTL = 5 * time.Minute

	const endpoint = "syslog"
	if got := metrics.DefaultRegistry.BatchDedupSnapshot(endpoint); got != 0 {
		t.Fatalf("pre-test: counter=%d, want 0", got)
	}

	// First send → new path → counter MUST stay at 0 (a
	// successful save is the desired outcome, not a dedup hit).
	if w := sendBatchWithID(t, h, probe.ID, "B-met"); w.Code != http.StatusOK {
		t.Fatalf("first send: status=%d body=%s", w.Code, w.Body.String())
	}
	if got := metrics.DefaultRegistry.BatchDedupSnapshot(endpoint); got != 0 {
		t.Errorf("first send (new path): counter=%d, want 0", got)
	}

	// Retry → duplicate path → counter MUST increment to 1.
	if w := sendBatchWithID(t, h, probe.ID, "B-met"); w.Code != http.StatusOK {
		t.Fatalf("retry: status=%d body=%s", w.Code, w.Body.String())
	}
	if got := metrics.DefaultRegistry.BatchDedupSnapshot(endpoint); got != 1 {
		t.Errorf("retry (dup path): counter=%d, want 1", got)
	}

	// Second retry → another dup hit → counter MUST increment to 2.
	if w := sendBatchWithID(t, h, probe.ID, "B-met"); w.Code != http.StatusOK {
		t.Fatalf("second retry: status=%d body=%s", w.Code, w.Body.String())
	}
	if got := metrics.DefaultRegistry.BatchDedupSnapshot(endpoint); got != 2 {
		t.Errorf("second retry: counter=%d, want 2", got)
	}
}

// TestGetMetrics_RendersPrometheusText is a smoke test for the
// /api/metrics endpoint that AUDIT-070 introduces. The full text
// format is the standard Prometheus contract; the regex pins the
// metric NAME + TYPE + endpoint label so a future refactor can't
// silently change the metric name and break dashboards.
func TestGetMetrics_RendersPrometheusText(t *testing.T) {
	metrics.DefaultRegistry.Reset()
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	h.config.Server.BatchDedupTTL = 5 * time.Minute

	// Drive a dedup hit so there's something to scrape.
	_ = sendBatchWithID(t, h, probe.ID, "B-prom")
	_ = sendBatchWithID(t, h, probe.ID, "B-prom")

	router := gin.New()
	router.GET("/api/metrics", h.GetMetrics)
	req := httptest.NewRequest("GET", "/api/metrics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()

	wantHelp := regexp.MustCompile(`(?m)^# HELP probe_batch_dedup_total `)
	if !wantHelp.MatchString(body) {
		t.Errorf("missing # HELP line for probe_batch_dedup_total:\n%s", body)
	}
	wantType := regexp.MustCompile(`(?m)^# TYPE probe_batch_dedup_total counter$`)
	if !wantType.MatchString(body) {
		t.Errorf("missing # TYPE counter line:\n%s", body)
	}
	wantSample := regexp.MustCompile(`(?m)^probe_batch_dedup_total\{endpoint="syslog"\} 1$`)
	if !wantSample.MatchString(body) {
		t.Errorf("missing/incorrect counter sample for endpoint=syslog (want 1):\n%s", body)
	}
}

// TestBatchDedup_DefaultTTL_AppliesWhenZero is a guardrail: a Handler
// constructed with the zero-value Config (or an operator who
// explicitly set BATCH_DEDUP_TTL=0 in the env) MUST still get a sane
// TTL — the dedup window must not silently become 0 (= "let every
// duplicate through") or MaxDuration (= "dedupe forever"). The
// default is 5 minutes (see the constant in handlers_data.go and
// the equivalent fallback in BatchAlreadyProcessed).
func TestBatchDedup_DefaultTTL_AppliesWhenZero(t *testing.T) {
	metrics.DefaultRegistry.Reset()
	_, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	// Build a handler with a Config whose BatchDedupTTL is
	// zero — this is what BATCH_DEDUP_TTL=0 in the env
	// produces.
	cfg := &config.Config{} // Server.BatchDedupTTL is 0
	h := NewHandler(cfg, nil, db)

	// Pre-seed a processed_batches row that's 30 seconds old —
	// well inside any sane default TTL, well outside a
	// misconfigured "0" (which would let it through).
	old := time.Now().Add(-30 * time.Second)
	if err := db.Gorm().Create(&models.ProcessedBatch{
		ProbeID: probe.ID, BatchID: "B-zero", Timestamp: old,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := sendBatchWithID(t, h, probe.ID, "B-zero")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Probe-Server-Batch-Status"); got != "duplicate" {
		t.Errorf("zero-TTL config: X-Probe-Server-Batch-Status=%q, want %q (the default TTL must still apply)", got, "duplicate")
	}
}
