package guardrails

import (
	"os"
	"strings"
	"testing"
)

// The bulk orphaned-rollback endpoint removes configuration from LIVE devices
// across every tunnel whose far end is a decommissioned device. It carries
// credential material into the collector and mutates device state, so it must
// be admin-only like the per-tunnel rollback it batches.
func TestIPSecRollbackOrphanedRouteAdminOnly(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, `admin.POST("/api/ipsec/rollback-orphaned"`) {
		t.Fatalf("the bulk orphaned-rollback route is not registered under the admin group")
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
	if !strings.Contains(adminOnly, `"/admin/api/ipsec/rollback-orphaned":true`) {
		t.Errorf("adminOnlyRoutes missing /admin/api/ipsec/rollback-orphaned — the bulk rollback mutates live devices and must stay admin-only")
	}
}

// The V2 console is the operator's only route to a rollback (the legacy
// console has one, the V2 IPSec tab had only preflight/deploy/recheck) and it
// must not draw a phantom branch for a tunnel whose peer was decommissioned.
func TestIPSecRollbackAndPhantomPeerUI(t *testing.T) {
	const path = "../../ui-v2/src/pages/TopologyWorkspace.tsx"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ui-v2/src/pages/TopologyWorkspace.tsx not found at %s: %v", path, err)
	}
	body := string(data)

	for _, needle := range []string{
		// The Rollback action, behind a confirm dialog.
		"setTunnelToRollback(row.original)",
		"/admin/api/ipsec/tunnels/${tunnel.id}/rollback",
		"tunnelToRollback",
		// The status set that mirrors the server's rollback fromStatuses.
		"IPSEC_ROLLBACKABLE",
		"rollback_failed",
		"deploying",
		// The poll that drives the saga to its terminal.
		"/admin/api/ipsec/tunnels/${tunnel.id}/deploy",
		"IPSEC_ROLLBACK_TERMINAL",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("TopologyWorkspace.tsx missing %q — the operator must be able to run a rollback from the V2 console", needle)
		}
	}
	// A decommissioned peer must NOT be drawn as a phantom external node.
	for _, needle := range []string{
		"peer_state",
		"peer_name",
		"'retired'",
		"'removed'",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("TopologyWorkspace.tsx missing %q — a retired/removed peer must be skipped, not drawn as a phantom branch", needle)
		}
	}
	if strings.Contains(body, "tunnel.peer_state === 'retired' || tunnel.peer_state === 'removed'") {
		t.Errorf("TopologyWorkspace.tsx must not hardcode the peer-state comparison inline; keep the peerState variable so both the node and the edge are skipped")
	}
}
