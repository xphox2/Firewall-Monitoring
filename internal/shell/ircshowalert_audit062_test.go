package shell

import (
	"os"
	"strings"
	"testing"
)

// TestIRCShowAlert_AUDIT062 is a static regression for the audit: admin-irc.js
// showAlert toggled inline `style.display` and scheduled a fresh 5s setTimeout
// on every call without clearing the prior one — back-to-back alerts hid each
// other early. The fix toggles the shared `.hidden` class and tracks/clears a
// module-level timer.
func TestIRCShowAlert_AUDIT062(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-irc.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-irc.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-062") {
		t.Errorf("admin-irc.js missing the AUDIT-062 marker.")
	}
	for _, sig := range []string{
		"clearTimeout(alertTimer)", // prior timer cleared
		"classList.add('hidden')",  // class-based hide
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("admin-irc.js showAlert missing %q (AUDIT-062).", sig)
		}
	}
	if strings.Contains(body, "alertDiv.style.display") {
		t.Errorf("admin-irc.js showAlert still toggles inline `alertDiv.style.display` (AUDIT-062): use the .hidden class instead.")
	}
}
