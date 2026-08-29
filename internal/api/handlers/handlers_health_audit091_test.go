package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestGetHealth_HealthyDB_Returns200_AUDIT091 — the headline regression
// for AUDIT-091: GetHealth must actually probe the DB, not just return
// {"status":"healthy"} unconditionally. With a working SQLite in-memory
// DB, the endpoint must return 200 and the body must include
// "status":"healthy" and "database":true.
func TestGetHealth_HealthyDB_Returns200_AUDIT091(t *testing.T) {
	h, _ := setupTestHandler(t)
	w := doHealthRequest(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	resp := decodeHealthResponse(t, w)
	if got, want := resp["status"], "healthy"; got != want {
		t.Errorf("status = %v, want %q", got, want)
	}
	if got, want := resp["database"], true; got != want {
		t.Errorf("database = %v, want %v (DB ping should have succeeded)", got, want)
	}
	if _, hasErr := resp["db_error"]; hasErr {
		t.Errorf("db_error should be absent on a healthy DB; got: %v", resp["db_error"])
	}
}

// TestGetHealth_NilDB_Returns503_AUDIT091 — when the Handler is
// constructed without a DB (startup race during a panic, or a test
// harness that forgot to wire the DB), the endpoint must return 503
// rather than 200. The pre-fix GetHealth would have returned 200 with
// "database":false, which is a "healthy" status with a hand-wavy
// caveat — exactly the silent-failure pattern the audit flagged.
// AUDIT-192: the endpoint is unauthenticated, so the body must carry
// ONLY booleans — no db_error/encryption_error detail keys, ever.
func TestGetHealth_NilDB_Returns503_AUDIT091(t *testing.T) {
	h := &Handler{} // no db wired
	w := doHealthRequest(t, h)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", w.Code, w.Body.String())
	}
	resp := decodeHealthResponse(t, w)
	if got, want := resp["status"], "unhealthy"; got != want {
		t.Errorf("status = %v, want %q", got, want)
	}
	if got, want := resp["database"], false; got != want {
		t.Errorf("database = %v, want %v", got, want)
	}
	assertNoHealthErrorDetail(t, resp)
}

// TestGetHealth_DBPingFails_Returns503_AUDIT091 — when the DB is
// present but the SELECT 1 ping fails (closed connection, bad DSN,
// disk full), the endpoint must return 503. We simulate by closing the
// underlying sql.DB so the next query errors out.
//
// This is the scenario AUDIT-045 was about: the pre-fix code would
// have reported "healthy" with no warning, leaving the operator
// wondering why their dashboard is blank. AUDIT-192 tightened the
// contract: the failure is reported as database=false + 503 ONLY — the
// raw driver error (which embeds host/user/database) stays in the
// server log, never in the anonymous response body.
func TestGetHealth_DBPingFails_Returns503_AUDIT091(t *testing.T) {
	h, db := setupTestHandler(t)
	// Force-close the underlying sql.DB. Subsequent queries (including
	// the SELECT 1 in GetHealth) will fail with "sql: database is closed".
	if sqlDB, err := db.Gorm().DB(); err == nil && sqlDB != nil {
		_ = sqlDB.Close()
	}

	w := doHealthRequest(t, h)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", w.Code, w.Body.String())
	}
	resp := decodeHealthResponse(t, w)
	if got, want := resp["status"], "unhealthy"; got != want {
		t.Errorf("status = %v, want %q", got, want)
	}
	if got, want := resp["database"], false; got != want {
		t.Errorf("database = %v, want %v", got, want)
	}
	assertNoHealthErrorDetail(t, resp)
}

// assertNoHealthErrorDetail pins AUDIT-192: no failure-detail key may ever
// appear in the unauthenticated health body, on any path.
func assertNoHealthErrorDetail(t *testing.T, resp map[string]interface{}) {
	t.Helper()
	for _, key := range []string{"db_error", "encryption_error"} {
		if v, leaked := resp[key]; leaked {
			t.Errorf("%s leaked to the unauthenticated health body (AUDIT-192): %v", key, v)
		}
	}
}

// doHealthRequest wires the handler into a real gin engine and issues
// the request. We can't call h.GetHealth() directly because it expects
// a *gin.Context (which has methods we don't want to mock), and the
// health endpoint reads c.Request.Context() to set the DB-ping
// deadline, which requires a real request to flow through.
func doHealthRequest(t *testing.T, h *Handler) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.GET("/api/health", h.GetHealth)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/health", nil)
	r.ServeHTTP(w, req)
	return w
}

func decodeHealthResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode body: %v; body = %s", err, w.Body.String())
	}
	if resp.Data == nil {
		t.Fatalf("response has no data field; body = %s", w.Body.String())
	}
	return resp.Data
}
