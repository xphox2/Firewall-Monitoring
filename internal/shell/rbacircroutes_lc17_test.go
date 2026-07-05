package shell

import (
	"os"
	"strings"
	"testing"
)

// TestIRCRoutesAdminOnly_LC17 pins that cmd/api/main.go keeps the IRC
// credential-bearing route family in the adminOnlyRoutes map. LC-17 found the
// copy-paste siblings diverged after RBAC: settings/test-email and
// settings/test-webhook were admin-only while POST /admin/api/irc/servers/test
// (same shape — outbound connection to a request-supplied host with
// request-supplied credentials) and every IRC server/channel credential
// mutation fell to the operator default. The RequireRole middleware semantics
// themselves are covered in internal/api/middleware/rbac_test.go; this test
// guards the actual wiring.
func TestIRCRoutesAdminOnly_LC17(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s (LC-17): %v", path, err)
	}
	body := string(data)

	// Scope the assertion to the adminOnlyRoutes literal so a route string
	// elsewhere (the registration lines) can't satisfy it.
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatalf("adminOnlyRoutes map comment marker not found in main.go (LC-17)")
	}
	end := strings.Index(body[start:], "))")
	if end < 0 {
		t.Fatalf("end of RequireRole registration not found in main.go (LC-17)")
	}
	// Collapse whitespace so gofmt re-aligning the map values can't break
	// the assertion.
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")

	required := []string{
		`"/admin/api/irc/servers":true`,
		`"/admin/api/irc/servers/:id":true`,
		`"/admin/api/irc/servers/test":true`,
		`"/admin/api/irc/channels":true`,
		`"/admin/api/irc/channels/:id":true`,
		// The siblings the IRC family must stay aligned with.
		`"/admin/api/settings/test-email":true`,
		`"/admin/api/settings/test-webhook":true`,
	}
	for _, needle := range required {
		if !strings.Contains(adminOnly, needle) {
			t.Errorf("adminOnlyRoutes in main.go missing %q — IRC credential routes must stay admin-only (LC-17)", needle)
		}
	}
}
