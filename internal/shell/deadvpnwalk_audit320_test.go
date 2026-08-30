package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AUDIT-320/321: the server used to carry its own SNMP VPN-walk chain —
// SNMPClient.GetAllVPNTunnels -> VendorProfile.GetAllVPNTunnels -> the
// per-vendor implementations and FortiGate's ParseVPNDialupStatus /
// ParseGRETunnels. Collectors have owned all device polling since v0.11.74, so
// the entry point had zero callers and none of it could execute.
//
// It was not harmless dead code. Because it looked live, an audit spent effort
// on its FortiGate dialup columns (AUDIT-320: they were copied from the
// site-to-site tunnel table, and the .11/.12 it read do not exist in the MIB at
// all), and its inverted Local/Remote mapping was reported as a cross-repo
// divergence against the collector (AUDIT-321) when the collector was right.
//
// This guard keeps the decision from silently reverting: any server-side VPN
// walk belongs in the collector, which is the only component that polls.
func TestNoServerSideVPNWalk_AUDIT320(t *testing.T) {
	banned := []struct{ token, why string }{
		{"GetAllVPNTunnels", "the server-side VPN walk was deleted — collectors own all device polling since v0.11.74"},
		{"ParseVPNDialupStatus", "the server's dialup parser was deleted; the collector's copy is the live one"},
		{"ParseGRETunnels", "the server's GRE parser was deleted along with the walk that called it"},
		{"12356.101.12.2.1.1", "the FortiGate dialup table OIDs were deleted; the server must not reacquire them (and the old copy was wrong — see AUDIT-320)"},
	}

	// internal/api/handlers is scanned too, and it is the root that matters:
	// it holds the server's only live *snmp.SNMPClient (handlers.go) and
	// already calls GetSystemStatus/GetInterfaceStats/GetHardwareSensors on
	// it. Restoring tunnel data on that legacy single-device path is the
	// realistic way a walk comes back, and it would sit outside internal/snmp
	// entirely. cmd/poller is included as the other historical direct-SNMP
	// site, though it holds no client today.
	roots := []string{"../../internal/snmp", "../../internal/api/handlers", "../../cmd/poller"}

	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read %s: %v", root, err)
		}
		// Counted PER ROOT: a single total would let one populated root mask
		// the other silently dropping out of the guard's stated scope.
		var scanned int
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			path := filepath.Join(root, e.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			scanned++
			src := string(b)
			for _, ban := range banned {
				if strings.Contains(src, ban.token) {
					// Report the full path: the same basename exists under
					// more than one root, so a bare name is ambiguous.
					t.Errorf("AUDIT-320 regression: %s reintroduces %q — %s",
						path, ban.token, ban.why)
				}
			}
		}
		if scanned == 0 {
			t.Fatalf("scanned no .go files under %s — this guard is not actually checking that root", root)
		}
	}
}
