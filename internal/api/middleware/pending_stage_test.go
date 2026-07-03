package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"

	"github.com/gin-gonic/gin"
)

// pendingFakeAuthDB satisfies auth.Database for the pending-token tests.
type pendingFakeAuthDB struct{ version uint }

func (f *pendingFakeAuthDB) GetAdminByUsername(string) (*auth.AdminAuth, error) { return nil, nil }
func (f *pendingFakeAuthDB) UpdateAdminPassword(uint, string) error             { return nil }
func (f *pendingFakeAuthDB) GetAdminTokenVersion(uint) (uint, error)            { return f.version, nil }
func (f *pendingFakeAuthDB) IncrementAdminTokenVersion(uint) error              { return nil }

// TestPendingStage_RejectedEverywhere pins the P0-3 invariant: a Stage=totp
// pending token is NOT a session — AdminAuth must 401 it and CheckAdminAuth
// must not grant is_admin, while a full token passes both.
func TestPendingStage_RejectedEverywhere(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = "test-secret-key-that-is-long-enough-32b"
	am := auth.NewAuthManager(cfg, &pendingFakeAuthDB{version: 1})

	pending, err := am.GeneratePendingToken("admin", 1, 1)
	if err != nil {
		t.Fatalf("GeneratePendingToken: %v", err)
	}
	full, err := am.GenerateToken("admin", 1, 1, auth.RoleAdmin)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	r := gin.New()
	r.Use(AdminAuth(am, nil))
	r.GET("/admin/api/devices", func(c *gin.Context) { c.Status(http.StatusOK) })

	pub := gin.New()
	var sawAdmin bool
	pub.Use(CheckAdminAuth(am))
	pub.GET("/api/public/devices", func(c *gin.Context) {
		sawAdmin = c.GetBool("is_admin")
		c.Status(http.StatusOK)
	})

	do := func(router *gin.Engine, path, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: cookie})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(r, "/admin/api/devices", pending); rec.Code != http.StatusUnauthorized {
		t.Errorf("AdminAuth with pending token: got %d, want 401", rec.Code)
	}
	if rec := do(r, "/admin/api/devices", full); rec.Code != http.StatusOK {
		t.Errorf("AdminAuth with full token: got %d, want 200", rec.Code)
	}

	if rec := do(pub, "/api/public/devices", pending); rec.Code != http.StatusOK || sawAdmin {
		t.Errorf("CheckAdminAuth with pending token: code=%d is_admin=%v, want 200/false", rec.Code, sawAdmin)
	}
	if rec := do(pub, "/api/public/devices", full); rec.Code != http.StatusOK || !sawAdmin {
		t.Errorf("CheckAdminAuth with full token: code=%d is_admin=%v, want 200/true", rec.Code, sawAdmin)
	}
}
