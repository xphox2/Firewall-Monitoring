package shell

import (
	"os"
	"strings"
	"testing"
)

// TestFlowInternalNetworksRouteAdminOnly: the effective internal-network list
// reveals the operator's network layout, so it must stay in adminOnlyRoutes —
// RequireRole otherwise defaults a GET to the viewer role. Same source-scan
// pattern as TestConfigHistoryReadRoutesAdminOnly.
func TestFlowInternalNetworksRouteAdminOnly(t *testing.T) {
	data, err := os.ReadFile("../../cmd/api/main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatal("adminOnlyRoutes marker not found")
	}
	end := strings.Index(body[start:], "))")
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")
	if !strings.Contains(adminOnly, `"/admin/api/flows/internal-networks":true`) {
		t.Error("/admin/api/flows/internal-networks must be in adminOnlyRoutes")
	}
	if !strings.Contains(body, `admin.GET("/api/flows/internal-networks", handler.GetFlowInternalNetworks)`) {
		t.Error("the internal-networks route is not registered")
	}
}
