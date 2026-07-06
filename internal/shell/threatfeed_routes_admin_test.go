package shell

import (
	"os"
	"strings"
	"testing"
)

// TestThreatFeedControlRoutesAdminOnly pins that the v0.11.46 threat-feed control
// routes stay admin-only in cmd/api/main.go's adminOnlyRoutes map. Disabling a
// feed PURGES its indicators, the master switch turns all matching off, and the
// storm threshold retunes detection — destructive config that must not fall to the
// operator default. The RequireRole semantics are covered in
// internal/api/middleware/rbac_test.go; this guards the wiring.
func TestThreatFeedControlRoutesAdminOnly(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatalf("adminOnlyRoutes map comment marker not found in main.go")
	}
	end := strings.Index(body[start:], "))")
	if end < 0 {
		t.Fatalf("end of RequireRole registration not found in main.go")
	}
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")

	for _, needle := range []string{
		`"/admin/api/threat-intel/feeds/:source":true`,
		`"/admin/api/threat-intel/global":true`,
		`"/admin/api/threat-intel/storm-tuning":true`,
	} {
		if !strings.Contains(adminOnly, needle) {
			t.Errorf("adminOnlyRoutes missing %q — threat-feed control must stay admin-only (v0.11.46)", needle)
		}
	}
}
