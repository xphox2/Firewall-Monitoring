package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoES5BracketWorkaround_AUDIT132 pins that the hand-written admin JS no
// longer uses the ES5/IE11 reserved-word bracket member-access workaround
// (`promise['catch'](…)`, `promise['finally'](…)`, `searchParams['delete'](…)`).
// The project's browser baseline is ES2020 (Chrome/Edge 105+, Safari 15.4+,
// Firefox 121+ — AUDIT-168/131), where `.catch`/`.finally`/`.delete` member
// access is valid, so the bracket form is dead weight. AUDIT-132 converted
// every site to dot notation; this guard fails if a future edit reintroduces
// one.
//
// Scope is *.js only. The conventions doc (cmd/api/static/js/README.md)
// intentionally quotes the literal `['catch']` syntax as the thing not to
// reintroduce, and vendored bundles (layout-base.js et al.) are excluded — they
// are third-party generated code we don't hand-edit.
func TestNoES5BracketWorkaround_AUDIT132(t *testing.T) {
	const dir = "../../cmd/api/static/js"

	// Vendored / generated bundles we do not hand-author — leave them as shipped.
	vendored := map[string]bool{
		"layout-base.js": true,
		"cose-base.js":   true,
		"fcose.js":       true,
	}

	banned := []string{"['catch']", "['finally']", "['delete']"}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s (AUDIT-132): %v", dir, err)
	}

	var scanned int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".js") || vendored[name] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("cannot read %s (AUDIT-132): %v", name, err)
		}
		body := string(data)
		for _, b := range banned {
			if strings.Contains(body, b) {
				t.Errorf("%s contains the legacy ES5 bracket workaround %q (AUDIT-132): "+
					"use dot notation (e.g. .catch / .finally / .delete) instead.", name, b)
			}
		}
		scanned++
	}

	if scanned == 0 {
		t.Fatal("scanned 0 .js files — test wiring is wrong (AUDIT-132).")
	}
}
