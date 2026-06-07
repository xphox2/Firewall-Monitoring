package httputil

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestInternalError_AUDIT071 pins the behaviour the audit asked for: a 500
// helper that (1) writes the standard ErrorResponse JSON with ONLY the
// operator-supplied message (never the raw err — no internal-detail leak), and
// (2) LOGS the underlying err so the failure isn't invisible. The 134 handler
// sites used to do (1) without (2).
func TestInternalError_AUDIT071(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("writes 500 with message, logs err, never leaks err to body", func(t *testing.T) {
		var logBuf bytes.Buffer
		log.SetOutput(&logBuf)
		defer log.SetOutput(os.Stderr) // restore default (stderr)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/api/devices", nil)

		secret := "pq: password authentication failed for user \"admin\""
		InternalError(c, "Failed to get devices", errors.New(secret))

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "Failed to get devices") {
			t.Errorf("response body %q missing the operator message", body)
		}
		if strings.Contains(body, secret) {
			t.Errorf("response body leaks the raw error to the client (AUDIT-071): %q", body)
		}
		logged := logBuf.String()
		if !strings.Contains(logged, "Failed to get devices") || !strings.Contains(logged, secret) {
			t.Errorf("the underlying err was not logged (AUDIT-071): log=%q", logged)
		}
		if !strings.Contains(logged, "500") {
			t.Errorf("log line should mark the 500: log=%q", logged)
		}
	})

	t.Run("nil err logs the message without crashing", func(t *testing.T) {
		var logBuf bytes.Buffer
		log.SetOutput(&logBuf)
		defer log.SetOutput(os.Stderr)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/admin/api/auth/login", nil)

		InternalError(c, "Authentication not configured", nil)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", w.Code)
		}
		if !strings.Contains(logBuf.String(), "Authentication not configured") {
			t.Errorf("nil-err path did not log the message: log=%q", logBuf.String())
		}
	})

	t.Run("includes X-Request-ID in the log when present", func(t *testing.T) {
		var logBuf bytes.Buffer
		log.SetOutput(&logBuf)
		defer log.SetOutput(os.Stderr)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
		c.Writer.Header().Set("X-Request-ID", "abc123")

		InternalError(c, "boom", errors.New("e"))

		if !strings.Contains(logBuf.String(), "abc123") {
			t.Errorf("log line did not correlate the request id: log=%q", logBuf.String())
		}
	})
}
