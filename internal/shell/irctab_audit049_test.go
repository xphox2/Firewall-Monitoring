package shell

import (
	"os"
	"strings"
	"testing"
)

// TestIRCTab_ActiveRuleExists_AUDIT049 is a static regression for the audit:
// no `.tab-btn.active` CSS rule existed on /admin/irc, so switchTab()'s
// classList.add('active') produced no visual change and the active-tab
// highlight was hardcoded as Tailwind utilities (text-[#58a6ff],
// border-[#58a6ff]) on the Servers button — which broke the moment another
// tab was clicked. The fix adds `.tab-btn.active { color:#58a6ff;
// border-bottom-color:#58a6ff; }` and strips the hardcoded active utilities
// from the Servers button so the rule drives the highlight uniformly.
// The IRC page was folded into the admin.html SPA: its tab markup now lives in
// admin.html and the `.tab-btn.active` rule moved to the shared design-system
// stylesheet. This regression pins both halves in their new homes.
func TestIRCTab_ActiveRuleExists_AUDIT049(t *testing.T) {
	// 1) The folded tab markup must not hardcode the active-border utility (it
	//    was the static highlight that didn't move with the active tab). Match
	//    the tab-specific `border-b-2 border-[#58a6ff]` pattern — NOT the
	//    `focus:border-[#58a6ff]` used legitimately on form inputs.
	adminPath := "../../web/admin/admin.html"
	adminData, err := os.ReadFile(adminPath)
	if err != nil {
		t.Skipf("admin.html not found at %s; err: %v", adminPath, err)
	}
	if strings.Contains(string(adminData), "border-b-2 border-[#58a6ff]") {
		t.Errorf("admin.html hardcodes the active border utility `border-b-2 border-[#58a6ff]` on a tab button (AUDIT-049): the `.tab-btn.active` CSS rule should drive the highlight instead.")
	}

	// 2) The `.tab-btn.active` rule must exist in the shared stylesheet.
	cssPath := "../../cmd/api/static/css/admin-design-system.css"
	css, err := os.ReadFile(cssPath)
	if err != nil {
		t.Skipf("admin-design-system.css not found at %s; err: %v", cssPath, err)
	}
	body := string(css)
	for _, sig := range []string{
		"AUDIT-049",         // traceability
		".tab-btn.active {", // the fix
		// The highlight color is now a Console design token (v0.10.499); the
		// rule still sets border-bottom-color, just via var(--fwmon-accent).
		"border-bottom-color: var(--fwmon-accent)",
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("admin-design-system.css missing the %q signal (AUDIT-049): a `.tab-btn.active` rule must style the active tab and reference the audit ID.", sig)
		}
	}
}
