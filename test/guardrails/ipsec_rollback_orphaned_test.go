package guardrails

import (
	"os"
	"strings"
	"testing"
)

// adminOnlyMapLiteral returns the body of cmd/api/main.go's adminOnlyRoutes map
// literal.
//
// It brace-matches from the literal's opening brace instead of slicing to the
// first "))": a reformatted map, or a "))" inside a value expression, must not
// truncate the region the guard checks (and must not make the guard pass
// vacuously).
func adminOnlyMapLiteral(t *testing.T, body string) string {
	t.Helper()
	marker := strings.Index(body, "adminOnlyRoutes — role=admin")
	if marker < 0 {
		t.Fatalf("adminOnlyRoutes map marker not found in main.go")
	}
	// The marker sits in the trailing comment of the literal's opening line
	// (`map[string]bool{ // adminOnlyRoutes — role=admin, any method`), so the
	// literal's '{' is the LAST one before the marker.
	open := strings.LastIndex(body[:marker], "{")
	if open < 0 {
		t.Fatalf("adminOnlyRoutes map literal not found in main.go")
	}
	depth := 0
	inStr, inComment := false, false
	for i := open; i < len(body); i++ {
		c := body[i]
		switch {
		case inComment:
			if c == '\n' {
				inComment = false
			}
			continue
		case inStr:
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '/':
			if i+1 < len(body) && body[i+1] == '/' {
				inComment = true
				i++
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return body[open : i+1]
			}
		}
	}
	t.Fatalf("adminOnlyRoutes map literal is not closed in main.go")
	return ""
}

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

	// The exact registration line — pins the route AND its handler, so a
	// comment or a different handler cannot satisfy the check.
	const wantRoute = `admin.POST("/api/ipsec/rollback-orphaned", handler.RollbackOrphanedIPSecTunnels)`
	if !strings.Contains(body, wantRoute) {
		t.Fatalf("the bulk orphaned-rollback route is not registered as %q under the admin group", wantRoute)
	}
	adminOnly := adminOnlyMapLiteral(t, body)
	if !strings.Contains(adminOnly, `"/admin/api/ipsec/rollback-orphaned": true`) &&
		!strings.Contains(adminOnly, `"/admin/api/ipsec/rollback-orphaned":true`) {
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
