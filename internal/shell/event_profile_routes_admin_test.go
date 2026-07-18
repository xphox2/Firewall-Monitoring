package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEventProfileRoutesAdminOnly pins that every Event Rule Profile route
// (v48) is registered under the admin group AND present in adminOnlyRoutes —
// a toggle Off silences an alert type for a whole scope, and assignments
// decide what gets suppressed where; if an entry drifts, RequireRole falls to
// the mutation=operator / GET=viewer defaults. Same wiring-guard pattern as
// TestSuggestedRuleRouteAdminOnly.
func TestEventProfileRoutesAdminOnly(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)

	registered := []string{
		`admin.GET("/api/event-rule-profiles"`,
		`admin.POST("/api/event-rule-profiles"`,
		`admin.GET("/api/event-rule-profiles/:id"`,
		`admin.PUT("/api/event-rule-profiles/:id"`,
		`admin.DELETE("/api/event-rule-profiles/:id"`,
		`admin.POST("/api/event-rule-profiles/:id/clone"`,
		`admin.PUT("/api/event-rule-profiles/:id/toggles"`,
		`admin.PUT("/api/event-rule-profiles/:id/assignments"`,
		`admin.GET("/api/alert-types"`,
		`admin.PUT("/api/devices/:id/event-profile"`,
		`admin.PUT("/api/sites/:id/event-profile"`,
		`admin.GET("/api/event-config/effective"`,
	}
	for _, r := range registered {
		if !strings.Contains(body, r) {
			t.Errorf("route not registered under the admin group in main.go: %s", r)
		}
	}

	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatalf("adminOnlyRoutes map comment marker not found in main.go")
	}
	end := strings.Index(body[start:], "))")
	if end < 0 {
		t.Fatalf("end of RequireRole registration not found in main.go")
	}
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")
	for _, p := range []string{
		"/admin/api/event-rule-profiles",
		"/admin/api/event-rule-profiles/:id",
		"/admin/api/event-rule-profiles/:id/clone",
		"/admin/api/event-rule-profiles/:id/toggles",
		"/admin/api/event-rule-profiles/:id/assignments",
		"/admin/api/alert-types",
		"/admin/api/devices/:id/event-profile",
		"/admin/api/sites/:id/event-profile",
		"/admin/api/event-config/effective",
	} {
		if !strings.Contains(adminOnly, `"`+p+`":true`) {
			t.Errorf("adminOnlyRoutes in main.go missing %s — event profile management must stay admin-only", p)
		}
	}
}
