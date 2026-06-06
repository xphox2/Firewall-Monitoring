package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestReceiveBatch_Idempotent_AUDIT042 verifies probe batch endpoints dedupe on
// X-Probe-Batch-ID. A timed-out-but-saved batch that the collector retries with
// the same id must not create duplicate rows (the ping case double-counted
// downtime). Idempotency is opt-in: no header → always saved.
func TestReceiveBatch_Idempotent_AUDIT042(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db) // approved; key "test-key-abc123"

	send := func(batchID, msg string) *httptest.ResponseRecorder {
		router := gin.New()
		router.POST("/api/probes/:id/syslog", h.ReceiveSyslogMessages)
		body, _ := json.Marshal([]models.SyslogMessage{{Message: msg, SourceIP: "10.0.0.1"}})
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/syslog", probe.ID), bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+probe.RegistrationKey)
		req.Header.Set("Content-Type", "application/json")
		if batchID != "" {
			req.Header.Set("X-Probe-Batch-ID", batchID)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	count := func() int64 {
		var n int64
		db.Gorm().Model(&models.SyslogMessage{}).Count(&n)
		return n
	}

	// 1) First send of batch B1 → saved.
	if w := send("B1", "first"); w.Code != http.StatusOK {
		t.Fatalf("send B1: %d %s", w.Code, w.Body.String())
	}
	if c := count(); c != 1 {
		t.Fatalf("after first send, rows=%d want 1", c)
	}

	// 2) Retry of the SAME batch B1 → deduped, no new rows.
	w2 := send("B1", "first")
	if w2.Code != http.StatusOK {
		t.Fatalf("retry B1: %d %s", w2.Code, w2.Body.String())
	}
	if c := count(); c != 1 {
		t.Errorf("retry of batch B1 duplicated rows: rows=%d want 1", c)
	}
	if !strings.Contains(w2.Body.String(), "deduped") {
		t.Errorf("retry response not marked deduped: %s", w2.Body.String())
	}

	// 3) A genuinely new batch B2 → saved (not over-deduped).
	if w := send("B2", "second"); w.Code != http.StatusOK {
		t.Fatalf("send B2: %d %s", w.Code, w.Body.String())
	}
	if c := count(); c != 2 {
		t.Errorf("new batch B2 not saved: rows=%d want 2", c)
	}

	// 4) No batch header → always saved (idempotency is opt-in).
	if w := send("", "third"); w.Code != http.StatusOK {
		t.Fatalf("headerless send: %d %s", w.Code, w.Body.String())
	}
	if c := count(); c != 3 {
		t.Errorf("headerless send not saved: rows=%d want 3", c)
	}
}
