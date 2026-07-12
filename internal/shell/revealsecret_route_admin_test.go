package shell

import (
	"os"
	"strings"
	"testing"
)

// TestRevealSecretRouteAdminOnly pins that the device credential reveal route
// stays in cmd/api/main.go's adminOnlyRoutes map. RequireRole keys on the route
// template (c.FullPath()); if this entry is dropped or its string drifts from
// the registered route, the endpoint silently falls to the operator default and
// any operator could reveal stored SSH/SNMP credentials. The middleware
// semantics are covered in internal/api/middleware/rbac_test.go; this guards the
// wiring (same pattern as TestIRCRoutesAdminOnly_LC17).
func TestRevealSecretRouteAdminOnly(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)

	// The route must actually be registered...
	if !strings.Contains(body, `admin.POST("/api/devices/:id/reveal-secret"`) {
		t.Fatalf("reveal-secret route not registered under the admin group in main.go")
	}

	// ...AND listed in the adminOnlyRoutes literal (scoped so a registration
	// line elsewhere can't satisfy the assertion).
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatalf("adminOnlyRoutes map comment marker not found in main.go")
	}
	end := strings.Index(body[start:], "))")
	if end < 0 {
		t.Fatalf("end of RequireRole registration not found in main.go")
	}
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")
	if !strings.Contains(adminOnly, `"/admin/api/devices/:id/reveal-secret":true`) {
		t.Error("adminOnlyRoutes in main.go missing /admin/api/devices/:id/reveal-secret — credential reveal must stay admin-only")
	}
}
