package shell

import (
	"os"
	"strings"
	"testing"
)

// TestConnBadgeEscape_AUDIT184 is a static regression for the audit finding:
// admin-common.js solidBadge concatenated its label into an innerHTML string
// unescaped, and typeBadgeHtml's fallback feeds the raw conn.connection_type
// through it — so a stored connection_type payload executed in every page that
// renders a type badge. The fix escapes at the sink (escapeHtml(label)), which
// covers typeBadgeHtml's raw-type fallback and every other caller at one point.
// Modeled on connstatusescape_audit065_test.go.
func TestConnBadgeEscape_AUDIT184(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-common.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-common.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-184") {
		t.Errorf("admin-common.js missing the AUDIT-184 marker.")
	}
	// The raw unescaped concatenation must be gone. (Anchored to solidBadge's
	// distinctive inline style — ipRef also concatenates a `label` variable,
	// but that one is built from escapeHtml'd parts.)
	if strings.Contains(body, `padding:1px 5px;">' + label + '</span>`) {
		t.Errorf("admin-common.js solidBadge still concatenates the raw label into innerHTML (AUDIT-184): wrap it with escapeHtml.")
	}
	if !strings.Contains(body, "+ escapeHtml(label) +") {
		t.Errorf("admin-common.js solidBadge must escape its label with escapeHtml (AUDIT-184).")
	}
}

// TestDiagramPanelsMatchMethodEscape_AUDIT184: the rich connection panel's
// method badge falls back to the raw conn.match_method for unknown methods and
// lands in panel.innerHTML — the second client-settable vector (match_method
// was bindable through the create endpoint). The fallback must go through
// window.escapeHtml.
func TestDiagramPanelsMatchMethodEscape_AUDIT184(t *testing.T) {
	const path = "../../cmd/api/static/js/diagram-panels.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("diagram-panels.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if strings.Contains(body, "${methodLabels[conn.match_method] || conn.match_method}") {
		t.Errorf("diagram-panels.js still interpolates the raw match_method fallback into innerHTML (AUDIT-184): wrap it with window.escapeHtml.")
	}
	if !strings.Contains(body, "window.escapeHtml(methodLabels[conn.match_method] || conn.match_method)") {
		t.Errorf("diagram-panels.js method badge fallback must go through window.escapeHtml (AUDIT-184).")
	}
}
