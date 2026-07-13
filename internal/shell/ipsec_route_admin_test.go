package shell

import (
	"os"
	"strings"
	"testing"
)

// TestIPSecRoutesAdminOnly pins that the IPSec provisioning mutation routes stay
// in cmd/api/main.go's adminOnlyRoutes map. Tunnels carry PSK credential
// material, so create/update/delete must be admin-only; if the entries drift the
// endpoints fall to the operator default. Same guard pattern as
// TestIRCRoutesAdminOnly_LC17 / the reveal-secret guard.
func TestIPSecRoutesAdminOnly(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, `admin.POST("/api/ipsec/tunnels"`) {
		t.Fatalf("IPSec tunnel routes not registered under the admin group")
	}
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatalf("adminOnlyRoutes map marker not found in main.go")
	}
	end := strings.Index(body[start:], "))")
	if end < 0 {
		t.Fatalf("end of RequireRole registration not found in main.go")
	}
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")
	for _, needle := range []string{
		`"/admin/api/ipsec/capabilities":true`,
		`"/admin/api/ipsec/preview":true`,
		`"/admin/api/ipsec/tunnels":true`,
		`"/admin/api/ipsec/tunnels/:id":true`,
		`"/admin/api/ipsec/tunnels/:id/preview":true`,
	} {
		if !strings.Contains(adminOnly, needle) {
			t.Errorf("adminOnlyRoutes missing %q — IPSec provisioning carries PSK material and must stay admin-only", needle)
		}
	}
}
