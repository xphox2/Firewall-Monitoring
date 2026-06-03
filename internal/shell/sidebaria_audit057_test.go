package shell

import (
	"os"
	"strings"
	"testing"
)

// TestSidebarAria_AUDIT057 is a static regression for the audit: the
// JS-rendered sidebar nav (admin-common.js renderSidebar) marked the active
// item with a `.active` class but no `aria-current="page"`, and the nav icons
// (Unicode glyphs) had no `aria-hidden="true"` — so a screen reader couldn't
// identify the current page and read out every icon's glyph name. The fix adds
// `aria-current="page"` to the active link and `aria-hidden="true"` to every
// `<span class="nav-icon">`.
func TestSidebarAria_AUDIT057(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-common.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-common.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	for _, sig := range []string{
		"AUDIT-057",
		`aria-current="page`, // active-link marker
		`<span class="nav-icon" aria-hidden="true">`, // icons hidden from AT
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("admin-common.js missing %q (AUDIT-057): the rendered sidebar must mark the active page and hide icon glyphs from assistive tech.", sig)
		}
	}
	// No bare (unhidden) nav-icon span should remain.
	if strings.Contains(body, `<span class="nav-icon">`) {
		t.Errorf("admin-common.js still emits a bare `<span class=\"nav-icon\">` without aria-hidden (AUDIT-057).")
	}
}
