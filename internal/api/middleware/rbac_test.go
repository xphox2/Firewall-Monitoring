package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/auth"

	"github.com/gin-gonic/gin"
)

// TestRequireRole_Matrix pins the RBAC ladder (P0-1): viewer reads, operator
// mutates, admin touches settings/users; self-service routes bypass the
// ladder; unknown/empty roles fail closed.
func TestRequireRole_Matrix(t *testing.T) {
	gin.SetMode(gin.TestMode)

	selfService := map[string]bool{"/admin/api/logout": true}
	adminOnly := map[string]bool{
		"/admin/api/settings":  true,
		"/admin/api/users":     true,
		"/admin/api/users/:id": true,
		// LC-17: the IRC credential-bearing family mirrors main.go's
		// adminOnlyRoutes — server/channel config carries passwords, and
		// the test endpoint dials a request-supplied host with request-
		// supplied credentials (sibling of settings/test-email and
		// test-webhook). Connect/disconnect/send/commands stay at the
		// operator mutation default.
		"/admin/api/irc/servers":      true,
		"/admin/api/irc/servers/:id":  true,
		"/admin/api/irc/servers/test": true,
		"/admin/api/irc/channels":     true,
		"/admin/api/irc/channels/:id": true,
	}

	newRouter := func(role string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			if role != "-" { // "-" = no role on context (e.g. middleware bug)
				c.Set("role", role)
			}
			c.Next()
		})
		r.Use(RequireRole(selfService, adminOnly))
		ok := func(c *gin.Context) { c.Status(http.StatusOK) }
		r.GET("/admin/api/devices", ok)
		r.POST("/admin/api/devices", ok)
		r.DELETE("/admin/api/devices/:id", ok)
		r.GET("/admin/api/settings", ok)
		r.POST("/admin/api/settings", ok)
		r.GET("/admin/api/users", ok)
		r.POST("/admin/api/users", ok)
		r.PUT("/admin/api/users/:id", ok)
		r.POST("/admin/api/logout", ok)
		r.GET("/admin/dashboard", ok) // SPA page load
		r.GET("/admin/api/irc/servers", ok)
		r.POST("/admin/api/irc/servers", ok)
		r.PUT("/admin/api/irc/servers/:id", ok)
		r.POST("/admin/api/irc/servers/test", ok)
		r.POST("/admin/api/irc/servers/:id/connect", ok)
		r.POST("/admin/api/irc/channels", ok)
		r.POST("/admin/api/irc/send", ok)
		return r
	}

	cases := []struct {
		role   string
		method string
		path   string
		want   int
	}{
		// viewer: read yes, mutate no, admin-only no (even GET).
		{auth.RoleViewer, http.MethodGet, "/admin/api/devices", 200},
		{auth.RoleViewer, http.MethodGet, "/admin/dashboard", 200},
		{auth.RoleViewer, http.MethodPost, "/admin/api/devices", 403},
		{auth.RoleViewer, http.MethodDelete, "/admin/api/devices/1", 403},
		{auth.RoleViewer, http.MethodGet, "/admin/api/settings", 403},
		{auth.RoleViewer, http.MethodGet, "/admin/api/users", 403},
		{auth.RoleViewer, http.MethodPost, "/admin/api/logout", 200}, // self-service

		// operator: mutate yes, admin-only no.
		{auth.RoleOperator, http.MethodPost, "/admin/api/devices", 200},
		{auth.RoleOperator, http.MethodDelete, "/admin/api/devices/1", 200},
		{auth.RoleOperator, http.MethodGet, "/admin/api/settings", 403},
		{auth.RoleOperator, http.MethodPost, "/admin/api/settings", 403},
		{auth.RoleOperator, http.MethodPut, "/admin/api/users/1", 403},

		// admin: everything.
		{auth.RoleAdmin, http.MethodPost, "/admin/api/settings", 200},
		{auth.RoleAdmin, http.MethodGet, "/admin/api/users", 200},
		{auth.RoleAdmin, http.MethodPut, "/admin/api/users/1", 200},
		{auth.RoleAdmin, http.MethodDelete, "/admin/api/devices/1", 200},

		// LC-17: IRC credential family is admin-only (incl. GET, like
		// settings); connect and send stay operator; viewer gets nothing.
		{auth.RoleOperator, http.MethodPost, "/admin/api/irc/servers/test", 403},
		{auth.RoleOperator, http.MethodPost, "/admin/api/irc/servers", 403},
		{auth.RoleOperator, http.MethodPut, "/admin/api/irc/servers/1", 403},
		{auth.RoleOperator, http.MethodPost, "/admin/api/irc/channels", 403},
		{auth.RoleOperator, http.MethodGet, "/admin/api/irc/servers", 403},
		{auth.RoleOperator, http.MethodPost, "/admin/api/irc/servers/1/connect", 200},
		{auth.RoleOperator, http.MethodPost, "/admin/api/irc/send", 200},
		{auth.RoleViewer, http.MethodPost, "/admin/api/irc/send", 403},
		{auth.RoleAdmin, http.MethodPost, "/admin/api/irc/servers/test", 200},
		{auth.RoleAdmin, http.MethodPost, "/admin/api/irc/servers", 200},

		// unknown / missing role: fail closed on everything but self-service.
		{"ghost", http.MethodGet, "/admin/api/devices", 403},
		{"ghost", http.MethodPost, "/admin/api/logout", 200},
		{"-", http.MethodGet, "/admin/api/devices", 403},
		{"-", http.MethodPost, "/admin/api/devices", 403},
	}

	for _, tc := range cases {
		r := newRouter(tc.role)
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("role=%s %s %s: got %d, want %d", tc.role, tc.method, tc.path, rec.Code, tc.want)
		}
	}
}
