package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestModalAria_AUDIT069 is a static regression for the audit: static modal
// markup relied on admin-common.js tagStaticModals() to add role="dialog",
// aria-modal="true" and aria-labelledby at runtime — so the modals were not
// accessible until JS ran. The fix bakes those attributes into the markup of
// admin.html + device-detail.html. This test pins that every
// `<div class="modal" id="X">` carries the three attributes and that each
// aria-labelledby resolves to a real id in the same file.
func TestModalAria_AUDIT069(t *testing.T) {
	modalRe := regexp.MustCompile(`<div class="modal" id="([^"]+)"[^>]*>`)
	idRe := regexp.MustCompile(`\bid="([^"]+)"`)
	labRe := regexp.MustCompile(`aria-labelledby="([^"]+)"`)

	for _, path := range []string{"../../web/admin/admin.html", "../../web/admin/device-detail.html"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s not found; err: %v", path, err)
			continue
		}
		body := string(data)

		ids := map[string]bool{}
		for _, m := range idRe.FindAllStringSubmatch(body, -1) {
			ids[m[1]] = true
		}

		modals := modalRe.FindAllStringSubmatch(body, -1)
		if len(modals) == 0 {
			t.Errorf("%s: no `<div class=\"modal\" id=...>` found (AUDIT-069).", path)
		}
		for _, m := range modals {
			tag := m[0]
			id := m[1]
			for _, attr := range []string{`role="dialog"`, `aria-modal="true"`, "aria-labelledby="} {
				if !strings.Contains(tag, attr) {
					t.Errorf("%s: modal #%s is missing %s (AUDIT-069). Tag: %q", path, id, attr, tag)
				}
			}
			if lm := labRe.FindStringSubmatch(tag); lm != nil && !ids[lm[1]] {
				t.Errorf("%s: modal #%s aria-labelledby=%q has no matching id in the file (AUDIT-069).", path, id, lm[1])
			}
		}
	}
}
