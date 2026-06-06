package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// TestRequestID_GeneratesWhenAbsent_AUDIT135: with no inbound header, the
// middleware mints an ID, exposes it on the context, and echoes it in the
// X-Request-ID response header.
func TestRequestID_GeneratesWhenAbsent_AUDIT135(t *testing.T) {
	r := gin.New()
	r.Use(RequestID())
	var ctxID any
	r.GET("/", func(c *gin.Context) {
		ctxID, _ = c.Get(RequestIDKey)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	hdr := w.Header().Get("X-Request-ID")
	if hdr == "" {
		t.Fatal("X-Request-ID response header was not set (AUDIT-135).")
	}
	if ctxID != hdr {
		t.Errorf("context request_id %q != response header %q (AUDIT-135): they must match.", ctxID, hdr)
	}
	if len(hdr) != 32 { // 16 random bytes as hex
		t.Errorf("generated request ID %q is not 32 hex chars (AUDIT-135).", hdr)
	}
}

// TestRequestID_ReusesSafeInbound_AUDIT135: a safe-looking inbound
// X-Request-ID (proxy/trace correlation) is preserved.
func TestRequestID_ReusesSafeInbound_AUDIT135(t *testing.T) {
	r := gin.New()
	r.Use(RequestID())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "trace-abc_123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("X-Request-ID"); got != "trace-abc_123" {
		t.Errorf("safe inbound X-Request-ID not preserved: got %q (AUDIT-135).", got)
	}
}

// TestRequestID_RejectsHostileInbound_AUDIT135: a header with disallowed
// characters (log-forging attempt) or excessive length is discarded and a
// fresh ID minted instead.
func TestRequestID_RejectsHostileInbound_AUDIT135(t *testing.T) {
	for _, bad := range []string{
		"evil\nINJECTED 200 GET /admin",          // newline injection
		"01234567890123456789012345678901234567890123456789012345678901234567890", // >64 chars
		"has space",
		"semi;colon",
	} {
		r := gin.New()
		r.Use(RequestID())
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Request-ID", bad)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		got := w.Header().Get("X-Request-ID")
		if got == bad {
			t.Errorf("hostile inbound X-Request-ID %q was echoed back (AUDIT-135 log-forging guard).", bad)
		}
		if len(got) != 32 {
			t.Errorf("expected a freshly-minted 32-char ID for hostile input %q, got %q (AUDIT-135).", bad, got)
		}
	}
}
