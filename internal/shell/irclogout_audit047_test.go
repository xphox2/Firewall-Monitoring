package shell

import (
	"os"
	"strings"
	"testing"
)

// TestIRCLogout_HasLogoutCase_AUDIT047 is a static regression for the audit:
// `cmd/api/static/js/admin-irc.js` delegated-click switch had no
// `case 'logout'`, so the sidebar Logout link (data-action="logout") on
// /admin/irc was dead — every other admin page handles it. The fix adds a
// logout case calling AdminCommon.doLogout(). Note: admin-irc.js uses the
// full `AdminCommon` reference (no `AC` alias is defined in this file), so
// the case must use AdminCommon.doLogout, not AC.doLogout.
func TestIRCLogout_HasLogoutCase_AUDIT047(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-irc.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-irc.js not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	for _, sig := range []string{
		"AUDIT-047",            // traceability
		"case 'logout':",       // the dead-link fix
		"AdminCommon.doLogout", // correct reference (no AC alias in this file)
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("admin-irc.js missing the %q signal (AUDIT-047): the delegated switch must handle the 'logout' data-action via AdminCommon.doLogout() and reference the audit ID.", sig)
		}
	}
}
