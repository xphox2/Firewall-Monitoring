package shell

import (
	"os"
	"strings"
	"testing"
)

// TestModalDedup_SingleSource_AUDIT054 is a static regression for the audit:
// the `.modal { display:none }` / `.modal.active { display:flex }` display
// rules were duplicated inline in admin.html, sites.html and probes.html,
// all redundant with admin-shared.css:506-518. The fix removes the inline
// duplicates so admin-shared.css is the single source of truth (admin.html
// keeps only its genuinely-different `.modal-content` 92vw/85vh override).
func TestModalDedup_SingleSource_AUDIT054(t *testing.T) {
	// The canonical rule must exist in admin-shared.css.
	shared, err := os.ReadFile("../../cmd/api/static/css/admin-shared.css")
	if err != nil {
		t.Skipf("admin-shared.css not found; err: %v", err)
	}
	if !strings.Contains(string(shared), ".modal.active {") {
		t.Fatalf("admin-shared.css missing the canonical `.modal.active` rule (AUDIT-054): it must be the single source of truth.")
	}

	// Each page must no longer carry the inline `.modal.active { display: flex; }`
	// duplicate, and must reference the audit for traceability. The former
	// sites.html / probes.html modals were folded into admin.html (SPA), so
	// admin.html is now the single page to check.
	for _, page := range []string{"admin.html"} {
		path := "../../web/admin/" + page
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s not found; err: %v", page, err)
		}
		body := string(data)
		if strings.Contains(body, ".modal.active { display: flex; }") {
			t.Errorf("%s still contains the inline `.modal.active { display: flex; }` duplicate (AUDIT-054): it must come solely from admin-shared.css.", page)
		}
		if !strings.Contains(body, "AUDIT-054") {
			t.Errorf("%s missing the AUDIT-054 marker (traceability): the comment noting the dedup must reference the audit ID.", page)
		}
	}
}
