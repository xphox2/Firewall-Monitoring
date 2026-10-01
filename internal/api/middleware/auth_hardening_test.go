package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"

	"github.com/gin-gonic/gin"
)

// TestSessionToken_EmptyRoleNotAdmin_D5: a full-session JWT whose role claim
// is empty or unknown must not authenticate (pre-fix EffectiveRole mapped ""
// to admin). AdminAuth rejects it; CheckAdminAuth does not grant is_admin.
func TestSessionToken_EmptyRoleNotAdmin_D5(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = "test-secret-key-that-is-long-enough-32b"
	am := auth.NewAuthManager(cfg, &pendingFakeAuthDB{version: 1})

	for _, role := range []string{"", "superuser"} {
		if got := (&auth.Claims{Role: role}).EffectiveRole(); got != "" {
			t.Errorf("EffectiveRole(%q) = %q, want \"\"", role, got)
		}
		tok, err := am.GenerateToken("admin", 1, 1, role)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}

		r := gin.New()
		var reached bool
		r.Use(AdminAuth(am, nil))
		r.GET("/admin/api/devices", func(c *gin.Context) { reached = true; c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/admin/api/devices", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: tok})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || reached {
			t.Errorf("role %q: AdminAuth status = %d reached=%v, want 401 and not reached", role, rec.Code, reached)
		}

		pub := gin.New()
		var sawAdmin bool
		pub.Use(CheckAdminAuth(am))
		pub.GET("/api/public/devices", func(c *gin.Context) { sawAdmin = c.GetBool("is_admin"); c.Status(http.StatusOK) })
		req = httptest.NewRequest(http.MethodGet, "/api/public/devices", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: tok})
		pub.ServeHTTP(httptest.NewRecorder(), req)
		if sawAdmin {
			t.Errorf("role %q: CheckAdminAuth granted is_admin", role)
		}
	}

	// Control: a valid role still authenticates and carries that role.
	tok, _ := am.GenerateToken("admin", 1, 1, auth.RoleViewer)
	r := gin.New()
	var gotRole string
	r.Use(AdminAuth(am, nil))
	r.GET("/admin/api/devices", func(c *gin.Context) { gotRole = c.GetString("role"); c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/admin/api/devices", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: tok})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotRole != auth.RoleViewer {
		t.Errorf("viewer token: status = %d role = %q", rec.Code, gotRole)
	}
}

// clientIPFor serves one request through an engine configured with raw
// TRUSTED_PROXIES from TCP peer `peer`, with optional forwarding headers.
func clientIPFor(t *testing.T, raw, peer string, headers map[string]string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	ConfigureTrustedProxies(r, raw)
	var ip string
	r.GET("/ip", func(c *gin.Context) { ip = c.ClientIP() })
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = peer + ":40000"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	r.ServeHTTP(httptest.NewRecorder(), req)
	return ip
}

// TestTrustedProxies_D3 pins the TRUSTED_PROXIES contract.
func TestTrustedProxies_D3(t *testing.T) {
	xff := map[string]string{"X-Forwarded-For": "203.0.113.9"}

	// Empty (default) = historical behaviour: forwarding headers ignored.
	if got := clientIPFor(t, "", "10.1.2.3", xff); got != "10.1.2.3" {
		t.Errorf("empty setting: ClientIP = %s, want the TCP peer", got)
	}
	if got := clientIPFor(t, "", "10.1.2.3", map[string]string{"X-Real-IP": "203.0.113.9"}); got != "10.1.2.3" {
		t.Errorf("empty setting: X-Real-IP honoured (%s)", got)
	}

	// Trusted proxy → client IP from X-Forwarded-For.
	if got := clientIPFor(t, "10.0.0.0/8", "10.1.2.3", xff); got != "203.0.113.9" {
		t.Errorf("trusted proxy: ClientIP = %s, want 203.0.113.9", got)
	}
	// Right-most untrusted hop wins: a client-prepended spoof is ignored.
	if got := clientIPFor(t, "10.0.0.0/8", "10.1.2.3", map[string]string{"X-Forwarded-For": "1.1.1.1, 203.0.113.9"}); got != "203.0.113.9" {
		t.Errorf("trusted proxy with prepended spoof: ClientIP = %s, want 203.0.113.9", got)
	}
	// Only X-Forwarded-For is read, even from a trusted proxy.
	if got := clientIPFor(t, "10.0.0.0/8", "10.1.2.3", map[string]string{"X-Real-IP": "203.0.113.9"}); got != "10.1.2.3" {
		t.Errorf("trusted proxy: X-Real-IP honoured (%s)", got)
	}

	// Untrusted peer with a spoofed X-Forwarded-For → ignored.
	if got := clientIPFor(t, "10.0.0.0/8", "198.51.100.7", xff); got != "198.51.100.7" {
		t.Errorf("untrusted peer: ClientIP = %s, want the TCP peer", got)
	}

	// Invalid entries are skipped (never fatal); the valid ones still apply.
	if got := ParseTrustedProxies(" not-an-ip , 10.0.0.0/8,,300.1.1.1, 192.0.2.10 ,10.0.0.0/33"); !reflect.DeepEqual(got, []string{"10.0.0.0/8", "192.0.2.10"}) {
		t.Errorf("ParseTrustedProxies = %v", got)
	}
	if got := clientIPFor(t, "garbage, 10.0.0.0/8", "10.1.2.3", xff); got != "203.0.113.9" {
		t.Errorf("mixed valid/invalid: ClientIP = %s, want 203.0.113.9", got)
	}
	// Only invalid entries → trust nothing.
	if got := clientIPFor(t, "garbage", "10.1.2.3", xff); got != "10.1.2.3" {
		t.Errorf("all-invalid: ClientIP = %s, want the TCP peer", got)
	}
}
