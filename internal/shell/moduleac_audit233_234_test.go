package shell

import (
	"regexp"
	"strings"
	"testing"
)

// AUDIT-234 (diagram-panels.js) and AUDIT-233 (admin-threatintel.js) share one
// root cause: `AC = window.AdminCommon` was declared only inside a few functions
// (api()/renderSearch(); four renderers), while OTHER functions referenced bare
// `AC.` at module scope of that reference. In diagram-panels.js
// renderVPNTunnelRows's `AC.formatTunnelUptime(...)` threw a ReferenceError for
// any 'up' tunnel, killing the rich VPN detail panel (AUDIT-234). In
// admin-threatintel.js the bare `AC.showToast` in onMasterToggle/onFeedToggle/
// onStormSave threw too — caught by the chained .catch, so (corrected scope,
// audit overstated) NOT an unhandled rejection and the button was NOT stuck,
// but no success toast fired and onFeedToggle's table did not refresh after a
// successful toggle. The fix hoists `AC = window.AdminCommon` to MODULE scope in
// both files. This class-guard pins that: a module-scope AC decl exists BEFORE
// the first function in each helper module, so no bare `AC.` reference throws.
func TestModuleScopeAC_Declared_AUDIT233_234(t *testing.T) {
	decl := regexp.MustCompile(`(?m)^\s*(?:var|const|let)\s+AC\s*=\s*window\.AdminCommon\s*;`)
	firstFn := regexp.MustCompile(`(?m)^\s*(?:function\s+\w+|window\.\w+\s*=\s*function)`)

	for _, name := range []string{"diagram-panels.js", "admin-threatintel.js"} {
		js := readJS(t, name)

		loc := decl.FindStringIndex(js)
		if loc == nil {
			t.Errorf("AUDIT-233/234 regression: %s has no module-scope `AC = window.AdminCommon` declaration; "+
				"bare AC.* references will throw ReferenceError", name)
			continue
		}
		fnLoc := firstFn.FindStringIndex(js)
		if fnLoc == nil {
			t.Errorf("%s: could not locate the first function (test needs updating)", name)
			continue
		}
		if loc[0] >= fnLoc[0] {
			t.Errorf("AUDIT-233/234 regression: in %s the AC declaration is not at module scope "+
				"(it appears at offset %d, after the first function at offset %d)", name, loc[0], fnLoc[0])
		}
	}
}

// TestModuleScopeAC_UptimeReferenceResolves_AUDIT234 pins the specific line that
// killed the rich VPN detail panel: renderVPNTunnelRows references bare
// AC.formatTunnelUptime for an 'up' tunnel. It only resolves because AC is now
// module-scoped.
func TestModuleScopeAC_UptimeReferenceResolves_AUDIT234(t *testing.T) {
	js := readPanelJS(t)
	if !strings.Contains(js, "AC.formatTunnelUptime(t.tunnel_uptime)") {
		t.Error("AUDIT-234: the tunnel-uptime reference changed; if intentional update this guardrail, " +
			"otherwise the rich VPN panel's uptime column is broken")
	}
}
