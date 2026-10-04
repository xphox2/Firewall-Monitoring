package handlers

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/api/middleware"

	"github.com/gin-gonic/gin"
)

// cookieSecureRouter mounts the password login behind the production
// middleware order (RequestOrigin built from TRUSTED_PROXIES = proxies) so the
// cookie Secure flag is decided exactly as cmd/api wires it.
func cookieSecureRouter(h *Handler, proxies ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.RequestOrigin(middleware.NewTrustedProxySet(proxies)))
	r.POST("/api/auth/login", h.Login)
	r.POST("/api/auth/logout", h.Logout)
	return r
}

func loginVia(r *gin.Engine, remoteAddr string, overTLS bool, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"root","password":"correct-horse"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	if overTLS {
		req.TLS = &tls.ConnectionState{}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// passwordOnlyHandler is a 2FA-free admin so Login issues the session itself.
func passwordOnlyHandler(t *testing.T) *Handler {
	t.Helper()
	h, store := totpTestHandler(t, "")
	store.admin.TOTPEnabled = false
	return h
}

func assertCookieSecure(t *testing.T, rec *httptest.ResponseRecorder, want bool) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d (body=%s)", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"auth_token", "csrf_token"} {
		ck := cookieByName(rec, name)
		if ck == nil {
			t.Fatalf("%s cookie missing: %v", name, rec.Result().Cookies())
		}
		if ck.Secure != want {
			t.Errorf("%s Secure = %v, want %v", name, ck.Secure, want)
		}
	}
}

// TestLoginCookies_SecureFollowsRequestOrigin: with COOKIE_SECURE unset the
// Secure flag follows how the request arrived — Secure through a trusted
// TLS-terminating proxy or in-process TLS, not Secure for a direct plain-HTTP
// login (which must keep working), and never on the strength of an
// X-Forwarded-Proto that did not come from the trusted proxy.
func TestLoginCookies_SecureFollowsRequestOrigin(t *testing.T) {
	xfpHTTPS := map[string]string{"X-Forwarded-Proto": "https"}
	cases := []struct {
		name    string
		proxies []string
		peer    string
		tls     bool
		hdr     map[string]string
		want    bool
	}{
		{"direct plain HTTP", nil, "203.0.113.9:40000", false, nil, false},
		{"direct plain HTTP claiming https", nil, "203.0.113.9:40000", false, xfpHTTPS, false},
		{"in-process TLS", nil, "203.0.113.9:40000", true, nil, true},
		{"trusted proxy, https", []string{"192.0.2.10"}, "192.0.2.10:40000", false, xfpHTTPS, true},
		{"trusted proxy, http", []string{"192.0.2.10"}, "192.0.2.10:40000", false, map[string]string{"X-Forwarded-Proto": "http"}, false},
		{"untrusted peer claiming https", []string{"192.0.2.10"}, "203.0.113.9:40000", false, xfpHTTPS, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := passwordOnlyHandler(t)
			rec := loginVia(cookieSecureRouter(h, tc.proxies...), tc.peer, tc.tls, tc.hdr)
			assertCookieSecure(t, rec, tc.want)
		})
	}
}

// TestLoginCookies_ExplicitCookieSecureWins: an explicit COOKIE_SECURE
// overrides the per-request rule in both directions.
func TestLoginCookies_ExplicitCookieSecureWins(t *testing.T) {
	// Explicit true on a direct plain-HTTP login: Secure (the operator's
	// choice; Validate() warns about it at startup).
	h := passwordOnlyHandler(t)
	h.config.Server.CookieSecure, h.config.Server.CookieSecureExplicit = true, true
	assertCookieSecure(t, loginVia(cookieSecureRouter(h), "203.0.113.9:40000", false, nil), true)

	// Explicit false behind a trusted TLS-terminating proxy: not Secure.
	h = passwordOnlyHandler(t)
	h.config.Server.CookieSecure, h.config.Server.CookieSecureExplicit = false, true
	assertCookieSecure(t, loginVia(cookieSecureRouter(h, "192.0.2.10"), "192.0.2.10:40000", false, map[string]string{"X-Forwarded-Proto": "https"}), false)

	// CookieSecure=true WITHOUT the explicit marker (the old SERVER_ENABLE_TLS
	// inheritance) no longer forces Secure on a plain-HTTP request.
	h = passwordOnlyHandler(t)
	h.config.Server.CookieSecure, h.config.Server.CookieSecureExplicit = true, false
	assertCookieSecure(t, loginVia(cookieSecureRouter(h), "203.0.113.9:40000", false, nil), false)
}

// TestLogoutCookies_SecureFollowsRequestOrigin: the clearing cookies carry the
// same Secure decision, so a Secure session cookie is actually overwritten.
func TestLogoutCookies_SecureFollowsRequestOrigin(t *testing.T) {
	h := passwordOnlyHandler(t)
	r := cookieSecureRouter(h, "192.0.2.10")
	for _, tc := range []struct {
		peer string
		hdr  map[string]string
		want bool
	}{
		{"192.0.2.10:40000", map[string]string{"X-Forwarded-Proto": "https"}, true},
		{"203.0.113.9:40000", map[string]string{"X-Forwarded-Proto": "https"}, false},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.RemoteAddr = tc.peer
		for k, v := range tc.hdr {
			req.Header.Set(k, v)
		}
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: "whatever"})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("logout from %s: status=%d", tc.peer, rec.Code)
		}
		for _, name := range []string{"auth_token", "csrf_token"} {
			ck := cookieByName(rec, name)
			if ck == nil || ck.MaxAge != -1 {
				t.Fatalf("logout from %s: %s not cleared: %+v", tc.peer, name, ck)
			}
			if ck.Secure != tc.want {
				t.Errorf("logout from %s: %s Secure = %v, want %v", tc.peer, name, ck.Secure, tc.want)
			}
		}
	}
}
