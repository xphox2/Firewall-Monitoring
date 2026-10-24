package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestSystemHealthRouteAdminOnly pins M-13: the standalone /api/system endpoint
// exposes DB internals — connection-pool stats, database size, the on-disk
// data_directory — so it must stay in adminOnlyRoutes. Without the entry,
// RequireRole defaults GET to the lowest "viewer" role and any read-only
// account could enumerate the server's database layout. Same source-scan
// pattern as TestConfigHistoryReadRoutesAdminOnly.
func TestSystemHealthRouteAdminOnly(t *testing.T) {
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

	if !strings.Contains(adminOnly, `"/admin/api/system":true`) {
		t.Errorf("adminOnlyRoutes missing \"/admin/api/system\" — DB internals must stay admin-only (M-13)")
	}
}
