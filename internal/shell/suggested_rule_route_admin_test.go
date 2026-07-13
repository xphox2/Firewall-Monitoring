package shell

import (
	"os"
	"strings"
	"testing"
)

// TestSuggestedRuleRouteAdminOnly pins that GET /admin/api/alerts/:id/suggested-rule
// stays in cmd/api/main.go's adminOnlyRoutes map. It reads raw syslog content and
// backs the admin-only "create rule from alert" flow; if the entry drifts from the
// registered route template, RequireRole falls to the GET=viewer default and any
// viewer could read the derived rule payload. Same wiring-guard pattern as
// TestRevealSecretRouteAdminOnly.
func TestSuggestedRuleRouteAdminOnly(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, `admin.GET("/api/alerts/:id/suggested-rule"`) {
		t.Fatalf("suggested-rule route not registered under the admin group in main.go")
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
	if !strings.Contains(adminOnly, `"/admin/api/alerts/:id/suggested-rule":true`) {
		t.Error("adminOnlyRoutes in main.go missing /admin/api/alerts/:id/suggested-rule — it reads raw syslog and must stay admin-only")
	}
}
