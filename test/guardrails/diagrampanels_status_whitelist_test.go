package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestDiagramPanelsStatusWhitelist pins the stored-XSS fix: a device/connection/
// tunnel status was interpolated RAW into a `class="badge ${status}"` attribute
// (and in some sites into the text too). A crafted status (e.g.
// `" onmouseover=…`) would break out of the attribute. The status→class mapping
// must go through a whitelist (statusCls) and the text through escapeHtml.
func TestDiagramPanelsStatusWhitelist(t *testing.T) {
	const path = "../../cmd/api/static/js/diagram-panels.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("diagram-panels.js not found: %v", err)
	}
	body := string(data)

	if !strings.Contains(body, "function statusCls(") {
		t.Error("diagram-panels.js is missing the statusCls whitelist helper; a raw status must never reach the class attribute.")
	}
	for _, bad := range []string{
		`class="badge ${conn.status}"`,
		`class="badge ${c.status}"`,
		`class="badge ${st}"`,
	} {
		if strings.Contains(body, bad) {
			t.Errorf("diagram-panels.js still interpolates the raw status into a class attribute (%q) — route it through statusCls().", bad)
		}
	}
}
