package guardrails

import (
	"os"
	"strings"
	"testing"
)

// The V2 console must offer the operator the FULL set of tunnel actions. The
// legacy console (cmd/api/static/js/admin-ipsec.js) has Delete; the V2 IPSec tab
// did not, so a tunnel could be rolled back but never removed from the list.
//
// The delete is gated by the SERVER'S rule, which the list response states per
// row (`deletable` = the tunnel carries no deployment). The button is shown
// DISABLED with the reason, not hidden — the operator must be able to see what
// a delete needs first.
//
// The assertions below are deliberately about the GATE, not just the strings:
// a guardrail that only checked for the presence of identifiers would pass on
// an inverted gate or one wired to the wrong endpoint.
func TestIPSecTunnelActionsUI(t *testing.T) {
	const path = "../../ui-v2/src/pages/TopologyWorkspace.tsx"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ui-v2/src/pages/TopologyWorkspace.tsx not found at %s: %v", path, err)
	}
	body := string(data)

	for _, needle := range []string{
		// The delete action and its confirm gate.
		"setTunnelToDelete(row.original)",
		"deleteTunnelMutation.mutate(tunnelToDelete.id)",
		"apiFetch(`/admin/api/ipsec/tunnels/${id}`, { method: 'DELETE' })",
		"tunnelToDelete",
		// The gate: the server's own rule, with the legacy status set only as
		// the fallback for a server that predates the field.
		"if (typeof t.deletable === 'boolean') return t.deletable;",
		"disabled={!ipsecTunnelDeletable(row.original)}",
		"Roll back before deleting",
		"A deploy or rollback is in flight",
		// The rollback it depends on.
		"setTunnelToRollback(row.original)",
		"/rollback`",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("TopologyWorkspace.tsx missing %q — the V2 console must offer the same tunnel actions as the legacy one", needle)
		}
	}
	// The delete must be gated by the SERVER's rule. A gate that consults only
	// the status set is the approximation the legacy console makes, and it
	// enables a delete the server refuses with a 409 for a partially-deployed
	// `error` tunnel.
	if !strings.Contains(body, "deletable?: boolean;") {
		t.Errorf("TopologyWorkspace.tsx missing the `deletable` field — the delete must be gated by the server's rule (no deploy record), not by the status")
	}
}
