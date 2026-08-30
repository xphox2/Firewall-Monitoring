package shell

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
	// it holds the server's only long-lived *snmp.SNMPClient (the field at
	// handlers.go:29, constructed in cmd/api/main.go and injected via
	// SetSNMPClient) and already calls GetSystemStatus/GetInterfaceStats/
	// GetHardwareSensors on it. Restoring tunnel data on that legacy
	// single-device path is the realistic way a walk comes back, and it would
	// sit outside internal/snmp entirely. cmd/poller is included as the other
	// historical direct-SNMP site, though it holds no client today.
	roots := []string{"../../internal/snmp", "../../internal/api/handlers", "../../cmd/poller"}

	for _, root := range roots {
		// Counted PER ROOT: a single total would let one populated root mask
		// another silently dropping out of the guard's stated scope.
		var scanned int
		// WalkDir, not ReadDir: no root has subpackages today, but a future
		// one would otherwise sit outside the guard while the sentinel below
		// still passed on the top-level files.
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
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
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
		if scanned == 0 {
			t.Fatalf("scanned no .go files under %s — this guard is not actually checking that root", root)
		}
	}
}

// TestDeadVPNWalkGuardScopeIsDocumented_AUDIT320 keeps the prose describing
// this guard in step with what it actually scans.
//
// The scope sentence in the CHANGELOG and the audit ledger has now drifted
// twice: each time the guard gained a root, the two sentences kept naming the
// old, narrower set. That matters because the ledger is the permanent record a
// future audit reads — a reader who believes a package is unguarded either
// re-does the work or treats a regression there as out of scope by design,
// which is the same class of misleading documentation AUDIT-320 existed to
// delete. Drift is cheaper to catch here than in review.
func TestDeadVPNWalkGuardScopeIsDocumented_AUDIT320(t *testing.T) {
	guard, err := os.ReadFile("deadvpnwalk_audit320_test.go")
	if err != nil {
		t.Fatalf("read guard source: %v", err)
	}
	// Pull the roots straight from this file's own declaration, so the check
	// cannot fall out of step with the list it is validating.
	decl := regexp.MustCompile(`roots := \[\]string\{([^}]*)\}`).FindSubmatch(guard)
	if decl == nil {
		t.Fatal("could not find the roots declaration in the guard source")
	}
	var roots []string
	for _, m := range regexp.MustCompile(`"\.\./\.\./([^"]+)"`).FindAllStringSubmatch(string(decl[1]), -1) {
		roots = append(roots, m[1])
	}
	if len(roots) == 0 {
		t.Fatal("parsed no roots from the declaration — this check would pass vacuously")
	}

	for _, doc := range []string{"../../CHANGELOG.md", "../../docs/audit-2026-08-27-consolidated.md"} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		// Only the v0.11.235 entry and the AUDIT-320 disposition describe this
		// guard; both contain the phrase below. Older entries are history and
		// must not be rewritten.
		text := string(b)
		idx := strings.Index(text, "guardrail test fails if")
		if idx < 0 {
			t.Errorf("%s no longer describes the AUDIT-320 guardrail — the scope sentence was removed", doc)
			continue
		}
		sentence := text[idx:]
		if end := strings.Index(sentence, "\n"); end >= 0 {
			sentence = sentence[:end]
		}
		for _, root := range roots {
			if !strings.Contains(sentence, root) {
				t.Errorf("%s describes the AUDIT-320 guard without naming %q, which it does scan — "+
					"the documented scope is narrower than the shipped guard:\n  %s", doc, root, sentence)
			}
		}
	}
}
