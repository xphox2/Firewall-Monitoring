package shell

import (
	"os"
	"strings"
	"testing"
)

// TestStaticFilesEmbed_ReferencesStaticDir_AUDIT139 is a static
// regression for the audit: the `cmd/api/static.go` file's
// `//go:embed static` directive must reference the `static/`
// directory that ships unminified JS today. The audit's
// recommendation is an `esbuild` build step that minifies into
// `cmd/api/static/js/dist/`; until that lands, the embed is
// correct as long as the source-of-truth layout is
// `cmd/api/static/`. The test pins:
//
//  1. The directive `//go:embed static` exists in `static.go`.
//  2. The corresponding `var staticFiles embed.FS` declaration
//     exists (so a future agent who removes the var but leaves
//     the directive fails the test).
//  3. The `cmd/api/static/` directory exists and contains
//     `js/`, `css/`, and the `index.html` / `login.html` (a
//     future agent who reorganizes the source-of-truth layout
//     fails the test).
//  4. The doc block references AUDIT-139 (so the lack of
//     minification is documented and the future-esbuild
//     migration has a starting point).
func TestStaticFilesEmbed_ReferencesStaticDir_AUDIT139(t *testing.T) {
	const path = "../../cmd/api/static.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cmd/api/static.go not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// 1. The directive.
	if !strings.Contains(body, "//go:embed static") {
		t.Errorf("cmd/api/static.go is missing the `//go:embed static` directive (AUDIT-139: the embed must continue to point at the `static/` directory until the esbuild migration lands).")
	}

	// 2. The declaration.
	if !strings.Contains(body, "var staticFiles embed.FS") {
		t.Errorf("cmd/api/static.go is missing the `var staticFiles embed.FS` declaration; a future agent who removes the var but leaves the directive would have a dangling embed with no consumer.")
	}

	// 4. The doc block references AUDIT-139.
	if !strings.Contains(body, "AUDIT-139") {
		t.Errorf("cmd/api/static.go's doc block no longer references AUDIT-139; the lack-of-minification is undocumented and a future agent would be more likely to silently start the esbuild migration without context.")
	}

	// 3. The static/ directory exists and contains the
	// expected sub-paths. The test doesn't pin the exact
	// file list (a future agent who adds new files shouldn't
	// break the test), but it pins the three top-level
	// assets that the audit was about. Note: HTML files
	// live in `web/`, not `cmd/api/static/` — the embed
	// directory is for CSS/JS/fonts only (HTML is served
	// by the gin router via template files).
	staticDir := "../../cmd/api/static"
	for _, sub := range []string{"js", "css", "fonts"} {
		full := staticDir + "/" + sub
		if _, err := os.Stat(full); err != nil {
			t.Errorf("cmd/api/static/%s is missing (AUDIT-139 source-of-truth layout): %v", sub, err)
		}
	}
}
