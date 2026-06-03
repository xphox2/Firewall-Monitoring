package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEntrypoint_NoHardcodedPostgresPassword_AUDIT093 is a static
// regression for the audit: entrypoint.sh used to ship with
// `PASSWORD 'fwmon'` and `DB_PASSWORD="fwmon"`, baking a credential
// into the public repo. The fix is to generate a random password on
// first init and persist it to /config/pg-credentials. This test
// pins the source file so a future agent who copy-pastes an example
// back into the entrypoint fails CI immediately.
//
// The user *name* `fwmon` is fine — it's the application user, not a
// credential. The audit is about the password value.
//
// The test strips bash comments before pattern matching, so a CHANGELOG-
// style explanatory comment that mentions the OLD hardcoded value (as
// part of "what was here before") doesn't false-positive. The patterns
// are precise about the SQL/export form, not just the word "fwmon".
func TestEntrypoint_NoHardcodedPostgresPassword_AUDIT093(t *testing.T) {
	const path = "../../entrypoint.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("entrypoint.sh not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := stripBashComments(string(data))

	// Look for the four patterns that would indicate a hardcoded
	// password in the script's executable form. Each gets a specific
	// failure message because the fix is different in each case.
	checks := []struct {
		pattern string
		why     string
	}{
		{"PASSWORD 'fwmon'", "Postgres CREATE USER / ALTER USER with the hardcoded literal"},
		{`PASSWORD "fwmon"`, "Postgres CREATE USER / ALTER USER with the hardcoded literal (double-quoted)"},
		{"DB_PASSWORD=fwmon", "exporting the hardcoded literal as DB_PASSWORD"},
		{`DB_PASSWORD="fwmon"`, "exporting the hardcoded literal as DB_PASSWORD (double-quoted)"},
	}
	for _, c := range checks {
		if strings.Contains(body, c.pattern) {
			t.Errorf("entrypoint.sh contains %q (%s). AUDIT-093: generate a random password on first init via /config/pg-credentials and reference $PG_PASSWORD. See CHANGELOG v0.10.265 for the migration path.", c.pattern, c.why)
		}
	}
}

// stripBashComments removes `# ...` comments from a bash script so the
// static test doesn't false-positive on a comment that explains the
// OLD behavior in a CHANGELOG-style block. The implementation handles
// the two cases that matter for this audit:
//
//   - Whole-line comments: a `#` in column 0 (after whitespace trim).
//   - Trailing comments: a `#` preceded by whitespace or a recognized
//     bash separator. We don't try to handle single-quoted strings
//     containing `#` (e.g. `# PASSWORD 'fwmon'`) because those are
//     exactly the patterns we WANT to strip from the executable text
//     (the comment is a docstring, not a real command).
//
// This is intentionally simple — the test is checking for one
// specific anti-pattern, not parsing bash. If a future agent
// constructs a more complex false-positive, refine this helper
// rather than weakening the assertion.
func stripBashComments(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		// Strip from a `#` that is preceded by whitespace, OR is
		// the first non-whitespace char (whole-line comment).
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Inline `#` — find one that looks like a comment start.
		// We deliberately do NOT strip `#` inside a quoted string;
		// in practice the entrypoint has no such pattern that
		// collides with our checks.
		if idx := indexBashCommentStart(line); idx >= 0 {
			line = line[:idx]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// indexBashCommentStart returns the byte index of the first `#` in
// `s` that is preceded by whitespace (the standard bash heuristic
// for "this `#` starts a comment"), or -1 if none. We don't try to
// handle the corner case of `#` inside a single-quoted string —
// none of the patterns we care about use that.
func indexBashCommentStart(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] != '#' {
			continue
		}
		if i == 0 {
			return -1 // not preceded by anything; not a comment
		}
		prev := s[i-1]
		if prev == ' ' || prev == '\t' {
			return i
		}
	}
	return -1
}
