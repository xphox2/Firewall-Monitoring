package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDeviceRetireRoutes pins the v0.11.239 device lifecycle wiring in
// cmd/api/main.go: DELETE /api/devices/:id must run the RETIRE handler (a
// stale client gets the safe, history-preserving behavior), the explicit
// retire/restore routes must be registered, and — unlike reveal-secret and
// the purge that follows in a later release — they stay OPERATOR-level, so
// they must NOT appear in adminOnlyRoutes (same wiring-guard pattern as
// TestRevealSecretRouteAdminOnly).
func TestDeviceRetireRoutes(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)

	for _, want := range []string{
		`admin.DELETE("/api/devices/:id", handler.RetireDevice)`,
		`admin.POST("/api/devices/:id/retire", handler.RetireDevice)`,
		`admin.POST("/api/devices/:id/restore", handler.RestoreDevice)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("main.go missing route registration %s", want)
		}
	}
	if strings.Contains(body, "handler.DeleteDevice)") {
		t.Error("main.go still routes handler.DeleteDevice — DELETE /api/devices/:id must retire, not hard-delete")
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
	for _, route := range []string{"/admin/api/devices/:id/retire", "/admin/api/devices/:id/restore"} {
		if strings.Contains(adminOnly, `"`+route+`"`) {
			t.Errorf("%s is listed in adminOnlyRoutes — retire/restore are operator-level like the rest of device CRUD", route)
		}
	}
}
