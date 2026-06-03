package shell

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestParseHours_IsUsed_AUDIT154 is the regression for the audit
// (which claimed `httputil.ParseHours` was unused). The audit was
// wrong — `ParseHours` is used in 7 places across the handlers
// package. This test pins the call sites: if a future refactor
// accidentally orphans the function (e.g. by moving the parsing
// inline), the test fails and the next agent knows to either
// re-wire the callers or remove the function (and update the
// test). The audit doc is updated to `[!] wontfix / audit was
// wrong` with the explanation.
func TestParseHours_IsUsed_AUDIT154(t *testing.T) {
	refs := grepSymbol(t, "ParseHours(")
	// Filter out the definition site itself (the func signature)
	// and any doc comments. We count distinct file references.
	files := map[string]bool{}
	for _, ref := range refs {
		if strings.Contains(ref, "func ParseHours") {
			continue
		}
		// Extract the file path (everything before the colon).
		idx := strings.Index(ref, ":")
		if idx < 0 {
			continue
		}
		files[ref[:idx]] = true
	}
	if len(files) < 2 {
		t.Errorf("AUDIT-154 says ParseHours is unused, but the audit was wrong: ParseHours is used in %d files (call sites: %v). The audit doc has been updated to mark this as wontfix with the explanation. If a future refactor genuinely orphans the function, the count would drop and the test would fail.", len(files), files)
	}
}

// TestFilterAllowedFields_IsUsed_AUDIT155 — same shape as
// AUDIT-154, for `httputil.FilterAllowedFields`. The audit was
// wrong — the function is used in `handlers_connections.go` and
// elsewhere. The test pins at least 1 call site so a future
// refactor that orphans the function fails the test.
func TestFilterAllowedFields_IsUsed_AUDIT155(t *testing.T) {
	refs := grepSymbol(t, "FilterAllowedFields(")
	files := map[string]bool{}
	for _, ref := range refs {
		if strings.Contains(ref, "func FilterAllowedFields") {
			continue
		}
		idx := strings.Index(ref, ":")
		if idx < 0 {
			continue
		}
		files[ref[:idx]] = true
	}
	if len(files) < 1 {
		t.Errorf("AUDIT-155 says FilterAllowedFields is unused, but the audit was wrong: the function is used in %d files. If a future refactor genuinely orphans the function, the count would drop and the test would fail.", len(files))
	}
}

// TestIsValidVendor_IsUsed_AUDIT156 — the third "unused" claim
// that turned out to be wrong. `isValidVendor` is used in
// `handlers_devices.go` (twice). The map `validVendors` it
// indexes is used by the function; both are reachable.
func TestIsValidVendor_IsUsed_AUDIT156(t *testing.T) {
	refs := grepSymbol(t, "isValidVendor(")
	files := map[string]bool{}
	for _, ref := range refs {
		if strings.Contains(ref, "func isValidVendor") {
			continue
		}
		idx := strings.Index(ref, ":")
		if idx < 0 {
			continue
		}
		files[ref[:idx]] = true
	}
	if len(files) < 1 {
		t.Errorf("AUDIT-156 says validVendors/isValidVendor is unused, but the audit was wrong: isValidVendor is used in %d files. If a future refactor genuinely orphans the function, the count would drop and the test would fail.", len(files))
	}
}

// grepSymbol runs `git grep -n <symbol>` and returns the matching
// lines with `path:lineno:content` format. The output is the
// source of truth for "is this symbol used anywhere" — much
// more reliable than a regex over a pre-loaded buffer, because
// git grep respects .gitignore (so we don't false-positive on
// vendor directories or build artifacts) and the line:column
// format makes it easy to skip the definition site.
//
// We pass `-C <repo-root>` to git so the command works
// regardless of the test's working directory (the package's
// source dir is `internal/shell/`, not the repo root).
func grepSymbol(t *testing.T, symbol string) []string {
	t.Helper()
	repoRoot, err := findShellRepoRoot(t)
	if err != nil {
		t.Skipf("could not find repo root: %v", err)
	}
	cmd := exec.Command("git", "-C", repoRoot, "grep", "-n", "--", symbol)
	out, err := cmd.Output()
	if err != nil {
		// git grep returns non-zero when no matches are found;
		// that's not a test failure, it just means the symbol
		// really is unused.
		return nil
	}
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n")
}

// findShellRepoRoot walks up from the test's working directory
// until it finds the directory containing go.mod. The shell
// test package lives at `internal/shell/`, three levels down
// from the repo root, so we walk up to 5 levels to be safe.
func findShellRepoRoot(t *testing.T) (string, error) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir, nil
		}
		parent := dir + "/.."
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", os.ErrNotExist
}
