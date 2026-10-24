package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestIsAdmin_ReflectsRole_L8: the is_admin context flag must mean "holds the
// RBAC admin role" on every path that sets it — the session cookie (AdminAuth
// and CheckAdminAuth) and the API-token bearer. Pre-fix every authenticated
// caller, viewer included, read as is_admin=true.
func TestIsAdmin_ReflectsRole_L8(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	cfg.Server.JWTSecretKey = "test-secret-key-that-is-long-enough-32b"
	am := auth.NewAuthManager(cfg, &pendingFakeAuthDB{version: 1})

	var sawAdmin bool
	capture := func(c *gin.Context) { sawAdmin = c.GetBool("is_admin"); c.Status(http.StatusOK) }
	adminR := gin.New()
	adminR.Use(AdminAuth(am, nil))
	adminR.GET("/admin/api/me", capture)
	pubR := gin.New()
	pubR.Use(CheckAdminAuth(am))
	pubR.GET("/api/public/display-settings", capture)

	for _, role := range []string{auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin} {
		tok, err := am.GenerateToken("u", 1, 1, role)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		for name, r := range map[string]*gin.Engine{"AdminAuth": adminR, "CheckAdminAuth": pubR} {
			path := "/admin/api/me"
			if name == "CheckAdminAuth" {
				path = "/api/public/display-settings"
			}
			sawAdmin = role != auth.RoleAdmin // poison: the handler must overwrite it
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(&http.Cookie{Name: "auth_token", Value: tok})
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s role %q: status %d", name, role, rec.Code)
			}
			if want := role == auth.RoleAdmin; sawAdmin != want {
				t.Errorf("%s role %q: is_admin = %v, want %v", name, role, sawAdmin, want)
			}
		}
	}

	// Bearer path: the scope's role (capped by the creator's) decides.
	store := &fakeTokenStore{byPlaintext: map[string]*models.ApiToken{
		"fwm_read":  {ID: 1, Name: "ro", Scope: "read", CreatedByID: 100},
		"fwm_admin": {ID: 2, Name: "root", Scope: "admin", CreatedByID: 100},
	}, admins: enabledAdminCreator()}
	tokR := gin.New()
	tokR.Use(AdminAuth(nil, store))
	tokR.GET("/admin/api/me", capture)
	for bearer, want := range map[string]bool{"fwm_read": false, "fwm_admin": true} {
		sawAdmin = !want
		rec := doTokenReq(tokR, http.MethodGet, "/admin/api/me", bearer)
		if rec.Code != http.StatusOK || sawAdmin != want {
			t.Errorf("token %s: status %d is_admin = %v, want 200/%v", bearer, rec.Code, sawAdmin, want)
		}
	}
}
