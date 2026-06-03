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
func TestIRCTab_ActiveRuleExists_AUDIT049(t *testing.T) {
	const path = "../../web/admin/irc.html"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("irc.html not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// The hardcoded active-border utility on the tab button must be gone (it
	// was the static highlight that didn't move with the active tab). Match
	// the tab-specific `border-b-2 border-[#58a6ff]` pattern — NOT the
	// `focus:border-[#58a6ff]` used legitimately on form inputs.
	if strings.Contains(body, "border-b-2 border-[#58a6ff]") {
		t.Errorf("irc.html still hardcodes the active border utility `border-b-2 border-[#58a6ff]` on a tab button (AUDIT-049): the `.tab-btn.active` CSS rule should drive the highlight instead.")
	}
	for _, sig := range []string{
		"AUDIT-049",                    // traceability
		".tab-btn.active {",            // the fix
		"border-bottom-color: #58a6ff", // the rule actually sets the highlight
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("irc.html missing the %q signal (AUDIT-049): a `.tab-btn.active` rule must style the active tab and reference the audit ID.", sig)
		}
	}
}
