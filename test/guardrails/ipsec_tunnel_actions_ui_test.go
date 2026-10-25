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
// The delete is gated the same way the server gates it: the intent row may only
// be removed once the tunnel carries no deployment (a rollback clears the
// deploy record). The button is therefore shown DISABLED with the reason, not
// hidden — the operator must be able to see what a delete needs.
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
		"/admin/api/ipsec/tunnels/${id}`",
		"tunnelToDelete",
		// The delete's gate and the reason shown when it is disabled.
		"IPSEC_DELETABLE",
		"Roll back before deleting",
		// The rollback it depends on.
		"setTunnelToRollback(row.original)",
		"/rollback`",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("TopologyWorkspace.tsx missing %q — the V2 console must offer the same tunnel actions as the legacy one", needle)
		}
	}
}
