package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/api/middleware"

	"github.com/gin-gonic/gin"
)

// TestGetCSRFToken_D13: the endpoint mints a token that verifies against the
// caller's own auth cookie, a fresh one per call, and refuses a caller
// without a session.
func TestGetCSRFToken_D13(t *testing.T) {
	h, _ := setupTestHandler(t)
	h.config.Server.JWTSecretKey = "0123456789abcdef0123456789abcdef-d13"
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/api/csrf-token", h.GetCSRFToken)

	get := func(cookie string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/csrf-token", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "auth_token", Value: cookie})
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Token string `json:"csrf_token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body.Token
	}

	if code, _ := get(""); code != http.StatusForbidden {
		t.Errorf("no session: status = %d, want 403", code)
	}
	code, a := get("session-A")
	_, b := get("session-A")
	if code != http.StatusOK || a == "" || a == b {
		t.Fatalf("tokens: status=%d a=%q b=%q (want 200, two distinct tokens)", code, a, b)
	}
	secret := h.config.Server.JWTSecretKey
	if !middleware.ValidCSRFToken(a, "session-A", secret) || !middleware.ValidCSRFToken(b, "session-A", secret) {
		t.Error("a minted token does not verify for its session")
	}
	if middleware.ValidCSRFToken(a, "session-B", secret) {
		t.Error("a token verified for another session")
	}
}
