package handlers

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestReportClientError_AUDIT129 covers the browser-error beacon: a usable
// report is logged server-side and acked 204, an empty message is dropped
// (204, no log line), malformed JSON is 400, and oversized fields are truncated
// before they reach the log.
func TestReportClientError_AUDIT129(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{} // ReportClientError uses no handler fields
	r := gin.New()
	r.POST("/api/client-error", h.ReportClientError)

	post := func(body string) (*httptest.ResponseRecorder, string) {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer log.SetOutput(os.Stderr)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/client-error", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w, buf.String()
	}

	t.Run("valid report is logged and acked 204", func(t *testing.T) {
		w, logged := post(`{"message":"TypeError: x is undefined","source":"/admin/js/admin-main.js","line":42,"col":7,"stack":"at f (a.js:1)","url":"https://h/admin"}`)
		if w.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", w.Code)
		}
		for _, want := range []string{"client-error", "TypeError: x is undefined", "admin-main.js", ":42:7"} {
			if !strings.Contains(logged, want) {
				t.Errorf("log missing %q; got: %s", want, logged)
			}
		}
	})

	t.Run("empty message is dropped without a log line", func(t *testing.T) {
		w, logged := post(`{"message":"   "}`)
		if w.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", w.Code)
		}
		if strings.Contains(logged, "client-error") {
			t.Errorf("empty-message report should not be logged; got: %s", logged)
		}
	})

	t.Run("malformed JSON is 400", func(t *testing.T) {
		w, _ := post(`{not json`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})

	t.Run("oversized message is truncated", func(t *testing.T) {
		big := strings.Repeat("A", 5000)
		_, logged := post(`{"message":"` + big + `"}`)
		if !strings.Contains(logged, "…(truncated)") {
			t.Error("oversized message should be truncated before logging (AUDIT-129)")
		}
		if strings.Count(logged, "A") >= 5000 {
			t.Error("full 5000-char message reached the log — truncation failed (AUDIT-129)")
		}
	})
}
