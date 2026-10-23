package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestLoginCSRFProtection pins M-4: the login page issues a pre-auth CSRF
// cookie, and the login POST must echo it back as the X-CSRF-Token header
// (double-submit cookie) or it is refused.
func TestLoginCSRFProtection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/admin/login", func(c *gin.Context) {
		SetPreauthCSRFCookie(c)
		c.Status(http.StatusOK)
	})
	r.POST("/auth/login", LoginCSRFProtection(), func(c *gin.Context) { c.Status(http.StatusOK) })

	// Issue the cookie.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != preauthCSRFCookieName {
		t.Fatalf("expected one %s cookie, got %v", preauthCSRFCookieName, cookies)
	}
	token := cookies[0].Value
	if token == "" {
		t.Fatal("preauth CSRF cookie is empty")
	}

	// POST with the matching header passes.
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.AddCookie(&http.Cookie{Name: preauthCSRFCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", token)
	if rec := httptest.NewRecorder(); rec.Code == 0 {
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("POST with matching CSRF token: got %d, want 200", rec.Code)
		}
	}

	// POST without the header is refused.
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req2.AddCookie(&http.Cookie{Name: preauthCSRFCookieName, Value: token})
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF header: got %d, want 403", rec2.Code)
	}

	// POST with a mismatched header is refused.
	req3 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req3.AddCookie(&http.Cookie{Name: preauthCSRFCookieName, Value: token})
	req3.Header.Set("X-CSRF-Token", "wrong")
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusForbidden {
		t.Errorf("POST with wrong CSRF header: got %d, want 403", rec3.Code)
	}
}
