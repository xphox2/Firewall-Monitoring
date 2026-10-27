package guardrails

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The V2 console's dependency surface and its primitives.
//
// Two things happened in PR 7:
//
//   - Sixteen declared packages were imported ZERO times — ten Radix
//     packages, a form library, a validation library, a virtualiser and a
//     variant helper. They were dead weight in the lockfile and in every
//     install.
//   - Ninety-four controls were migrated onto the shared primitives, which
//     removes the duplicated class strings.
//
// The dependency test is the interesting one: a package that is declared and
// never imported is invisible in review and grows the install for everyone.

// v2PackageJSON reads ui-v2/package.json.
func v2PackageJSON(t *testing.T) map[string]any {
	t.Helper()
	root, _ := hygieneRepoFiles(t)
	data, err := os.ReadFile(filepath.Join(root, "ui-v2", "package.json"))
	if err != nil {
		t.Fatalf("read ui-v2/package.json: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse ui-v2/package.json: %v", err)
	}
	return out
}

// TestV2NoUnusedDependencies pins the dependency surface.
//
// A declared package that is never imported is dead weight: it is installed
// on every machine and every CI runner, and it is in the lockfile that
// everybody has to review. There were sixteen.
func TestV2NoUnusedDependencies(t *testing.T) {
	root, _ := hygieneRepoFiles(t)
	pkg := v2PackageJSON(t)

	deps := map[string]string{}
	for _, key := range []string{"dependencies", "devDependencies"} {
		m, ok := pkg[key].(map[string]any)
		if !ok {
			continue
		}
		for name := range m {
			deps[name] = key
		}
	}
	if len(deps) == 0 {
		t.Fatal("ui-v2/package.json declares no dependencies — the check is not reading the file")
	}

	// The source, plus the build and test configuration.
	var text strings.Builder
	_, files := hygieneRepoFiles(t)
	for _, f := range files {
		if !strings.HasPrefix(f, "ui-v2/src/") && !strings.HasPrefix(f, "ui-v2/e2e/") {
			continue
		}
		if !strings.HasSuffix(f, ".ts") && !strings.HasSuffix(f, ".tsx") &&
			!strings.HasSuffix(f, ".css") && !strings.HasSuffix(f, ".mjs") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			continue
		}
		text.Write(data)
	}
	// NOT ui-v2/package.json: it is where the packages are DECLARED, so
	// including it would make every declared package look used.
	for _, f := range []string{
		"ui-v2/vite.config.ts",
		"ui-v2/playwright.config.ts",
		"ui-v2/tailwind.config.ts",
	} {
		if data, err := os.ReadFile(filepath.Join(root, f)); err == nil {
			text.Write(data)
		}
	}
	source := text.String()

	// A package is used if its name appears in an import, a require, or a
	// CSS import. The type packages are the compiler's business.
	unused := []string{}
	for name := range deps {
		if strings.HasPrefix(name, "@types/") {
			continue
		}
		// The compiler and React itself are used through their CLIs and the
		// JSX runtime, not through an import.
		switch name {
		case "react", "react-dom", "typescript":
			continue
		}
		used := regexp.MustCompile(`['"]` + regexp.MustCompile(regexp.QuoteMeta(name)).String() + `['"/]`).MatchString(source)
		if !used {
			unused = append(unused, name)
		}
	}
	if len(unused) > 0 {
		t.Errorf("ui-v2 declares %d package(s) that are imported nowhere: %v — they are installed on every machine and every CI runner, and they are dead weight in the lockfile", len(unused), unused)
	}
}

// TestV2TheSharedPrimitivesAreUsed pins that the primitives are not
// decoration.
//
// A primitive that exists but is not used is the same problem as an unused
// dependency: it looks like the design system, and nothing uses it.
func TestV2TheSharedPrimitivesAreUsed(t *testing.T) {
	for _, comp := range []string{"Button", "Input", "Select", "Textarea", "Field"} {
		used := 0
		// The match is on the element, not the prefix: `<ButtonGroup` is
		// not a `<Button`.
		pattern := regexp.MustCompile(`<` + comp + `([\s/>])`)
		for _, rel := range v2SourceFiles(t) {
			src := readV2(t, rel)
			if pattern.MatchString(src) {
				used++
			}
		}
		// More than one file: a primitive used in a single place is not
		// yet a shared primitive, it is a component that happens to live
		// in the primitives folder.
		if used < 2 {
			t.Errorf("the %s primitive is used in %d file(s) — a primitive that nothing (or one thing) uses is not a design system", comp, used)
		}
	}
}
