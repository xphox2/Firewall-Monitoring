package guardrails

import (
	"os"
	"strings"
	"testing"
)

// The device-side discovery reads the device's API with the stored credentials
// and reports what it holds — admin-only, like the rollback it feeds. It is
// also READ-ONLY: it must never carry a write step, because a probe that
// mutated the device would be a rollback without the safeguards.
func TestIPSecDiscoveryRouteAdminOnly(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)

	for _, want := range []string{
		`admin.POST("/api/ipsec/tunnels/:id/discover", handler.DiscoverIPSecTunnel)`,
		`admin.GET("/api/ipsec/tunnels/:id/discover", handler.GetIPSecDiscovery)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("cmd/api/main.go missing %q — the discovery routes must be registered", want)
		}
	}
	adminOnly := adminOnlyMapLiteral(t, body)
	if !strings.Contains(adminOnly, `"/admin/api/ipsec/tunnels/:id/discover": true`) &&
		!strings.Contains(adminOnly, `"/admin/api/ipsec/tunnels/:id/discover":true`) {
		t.Errorf("adminOnlyRoutes missing /admin/api/ipsec/tunnels/:id/discover — the probe reads the device with the stored credentials and must stay admin-only")
	}
}

// The V2 console must offer the discovery (the operator has no other route to
// it) and must show the report BEFORE anything is removed.
func TestIPSecDiscoveryUI(t *testing.T) {
	const path = "../../ui-v2/src/pages/TopologyWorkspace.tsx"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ui-v2/src/pages/TopologyWorkspace.tsx not found at %s: %v", path, err)
	}
	body := string(data)

	for _, needle := range []string{
		// The action.
		"discoverMutation.mutate(row.original)",
		"/discover`",
		// The report the operator reviews.
		"IPSecDiscoveryReport",
		"setDiscovery(rep)",
		"discovery.found.length > 0",
		"discovery.unresolved.length > 0",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("TopologyWorkspace.tsx missing %q — the operator must be able to find the tunnel's objects on the device and review them", needle)
		}
	}
}
