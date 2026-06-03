package shell

import (
	"os"
	"strings"
	"testing"
)

// TestConnStatusEscape_AUDIT065 is a static regression for the audit:
// admin-connection-detail.js built `statusEl.innerHTML` by concatenating the
// raw `conn.status` into both a class attribute and the text. The server
// validates the status to an enum, but the unescaped innerHTML path was a
// defense-in-depth gap. The fix wraps conn.status with AC.escapeHtml.
func TestConnStatusEscape_AUDIT065(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-connection-detail.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-connection-detail.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-065") {
		t.Errorf("admin-connection-detail.js missing the AUDIT-065 marker.")
	}
	// The raw unescaped concatenation must be gone.
	if strings.Contains(body, `'<span class="badge ' + conn.status + '">'`) {
		t.Errorf("admin-connection-detail.js still concatenates raw conn.status into innerHTML (AUDIT-065): wrap it with AC.escapeHtml.")
	}
	if !strings.Contains(body, "AC.escapeHtml(conn.status)") {
		t.Errorf("admin-connection-detail.js must escape conn.status with AC.escapeHtml (AUDIT-065).")
	}
}
