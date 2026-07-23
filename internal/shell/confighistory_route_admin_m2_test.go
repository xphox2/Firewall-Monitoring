package shell

import (
	"os"
	"strings"
	"testing"
)

// TestConfigHistoryReadRoutesAdminOnly pins AUDIT M2: reading a device's raw
// config revision (or its diff) exposes vendor config that embeds credentials
// (SNMP communities, IPSec PSK/admin hashes), so those read routes must stay in
// adminOnlyRoutes. Without the entries, RequireRole defaults GET to the lowest
// "viewer" role and any read-only account could download full firewall configs.
// The metadata LIST route (/config-history, no :revId/diff) is intentionally NOT
// required here — it stays viewer-visible. Same source-scan pattern as
// TestRevealSecretRouteAdminOnly.
func TestConfigHistoryReadRoutesAdminOnly(t *testing.T) {
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

	for _, route := range []string{
		`"/admin/api/devices/:id/config-history/diff":true`,
		`"/admin/api/devices/:id/config-history/:revId":true`,
		`"/admin/api/devices/:id/config-history/:revId/view":true`,
	} {
		if !strings.Contains(adminOnly, route) {
			t.Errorf("adminOnlyRoutes missing %s — raw config reads must stay admin-only (M2)", route)
		}
	}
}
