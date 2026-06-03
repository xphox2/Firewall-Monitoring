package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestProbe_NoFmtPrintln_AUDIT159 is a static regression for the
// audit: `cmd/probe/main.go` used to ship banner / status output
// via `fmt.Println` and `fmt.Printf` while every other log call in
// the file (and every other binary in the project) used `log.*`.
// The pre-fix output went to stdout with no timestamp or prefix,
// which made it inconsistent with the rest of the codebase's
// logs and impossible to grep with a uniform pattern.
//
// The fix: replace every `fmt.Println` / `fmt.Printf` in
// `cmd/probe/main.go` with `log.Println` / `log.Printf`. `fmt.Errorf`
// is left alone (it's a different concern — wrapping errors with
// `%w` for the caller to inspect).
//
// This test pins the contract: the file contains zero `fmt.Print`
// calls. The check is loose enough to allow `fmt.Errorf` (we
// match `fmt.Print` rather than `fmt.` because `fmt.Errorf` is
// allowed and we don't want to enumerate every allowed call).
func TestProbe_NoFmtPrintln_AUDIT159(t *testing.T) {
	const path = "../../cmd/probe/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cmd/probe/main.go not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// Find every `fmt.Print` call (catches both `Println` and
	// `Printf`). The regex is permissive on whitespace and is
	// anchored on the call name so we don't false-positive on a
	// hypothetical `fmt.Printer` type or a comment.
	re := regexp.MustCompile(`\bfmt\.Print(?:ln|f)?\b`)
	matches := re.FindAllString(body, -1)
	if len(matches) > 0 {
		t.Errorf("cmd/probe/main.go has %d fmt.Print* call(s) (AUDIT-159); use log.Print* instead so the probe's output matches the rest of the codebase. Found: %v", len(matches), matches)
	}
}

// TestProbe_HasLogImport_AUDIT159 — defensive sibling to the above.
// If a future agent removes the `log` import (because the file
// "doesn't use log"), the test fails. We check by grepping for the
// import line. (A compile error would also catch this, but a
// specific test message is friendlier.)
func TestProbe_HasLogImport_AUDIT159(t *testing.T) {
	const path = "../../cmd/probe/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cmd/probe/main.go not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, `"log"`) {
		t.Errorf("cmd/probe/main.go no longer imports \"log\" (AUDIT-159); the file's log.Print* calls require this import. Restore the import or migrate all log.Print* calls back to fmt.Print* (but the latter fails the sibling test, so the right answer is: keep the import).")
	}
}
