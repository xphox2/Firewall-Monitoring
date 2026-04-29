package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDeviceDetailHTML_DiffModalUsesLegacyPattern guards the v0.10.196 fix:
// the config-diff modal must use the legacy `.modal` / `.modal-content`
// pattern from admin-shared.css, NOT the Tailwind-utility soup that fought
// with `.hidden` and made the modal render blank in v0.10.187 → v0.10.195.
//
// Failure here means the modal will not display when activated. The server
// LoadHTMLGlob's this file from disk at startup, so the assertions below run
// against exactly what the server will serve.
func TestDeviceDetailHTML_DiffModalUsesLegacyPattern(t *testing.T) {
	// Path is relative to the test binary; tests run from the package directory
	// (internal/api/handlers), so we walk up to repo root.
	candidates := []string{
		"../../../web/admin/device-detail.html",
		"web/admin/device-detail.html",
		"../../../../Firewall-Mon/web/admin/device-detail.html",
	}
	var html []byte
	var found string
	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			html = data
			found = p
			break
		}
	}
	if html == nil {
		t.Skip("device-detail.html not found in any candidate path; tests must run from repo root")
	}
	t.Logf("loaded device-detail.html from %s (%d bytes)", found, len(html))

	body := string(html)

	// 1. The modal element must exist with the expected ID.
	if !strings.Contains(body, `id="config-diff-modal"`) {
		t.Fatal(`#config-diff-modal element missing`)
	}

	// 2. The modal MUST NOT use the Tailwind `hidden` class. That class was
	//    fighting with `.modal.active` in v0.10.187 → v0.10.195 and made the
	//    modal render blank.
	modalRegex := regexp.MustCompile(`<div class="([^"]+)"[^>]*id="config-diff-modal"`)
	m := modalRegex.FindStringSubmatch(body)
	if m == nil {
		t.Fatal(`could not locate the #config-diff-modal opening tag with a class attribute`)
	}
	classList := m[1]
	t.Logf("config-diff-modal class list: %q", classList)
	classes := strings.Fields(classList)
	for _, c := range classes {
		if c == "hidden" {
			t.Errorf(`modal class list still contains "hidden" — this fights with .modal.active and the modal will render blank. class=%q`, classList)
		}
		if strings.HasPrefix(c, "fixed") || strings.HasPrefix(c, "top-") || strings.HasPrefix(c, "left-") ||
			strings.HasPrefix(c, "right-") || strings.HasPrefix(c, "bottom-") || strings.HasPrefix(c, "bg-black") ||
			strings.HasPrefix(c, "z-[") || c == "items-center" || c == "justify-center" {
			t.Errorf(`modal class list contains Tailwind positioning class %q — the legacy .modal CSS already provides this; mixing them caused the v0.10.187 → v0.10.195 blank-modal regression. class=%q`, c, classList)
		}
	}

	// 3. The modal must use `class="modal"` exactly (the legacy hook). Any
	//    extras would just be noise and would risk new collisions.
	if !contains(classes, "modal") {
		t.Errorf(`modal class list must contain "modal" (the legacy hook); got %q`, classList)
	}

	// 4. The modal content child must use `.modal-content` (the legacy hook
	//    that the .modal-content CSS rule expects).
	if !strings.Contains(body, `class="modal-content"`) {
		t.Error(`modal must contain a child with class="modal-content"`)
	}

	// 5. The body and meta IDs that the JS reads must exist.
	for _, id := range []string{`id="config-diff-meta"`, `id="config-diff-body"`} {
		if !strings.Contains(body, id) {
			t.Errorf(`required JS hook missing: %s`, id)
		}
	}

	// 6. Sanity: there must be a close button wired to the JS handler.
	if !strings.Contains(body, `data-action="close-config-diff"`) {
		t.Error(`modal close button (data-action="close-config-diff") missing`)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
