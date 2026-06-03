package shell

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoTrackedAgentMemoryFiles_AUDIT115 is a static regression for
// the audit: `lessons.md`, `tasks/lessons.md`, and `tasks/todo.md`
// were AI agent session-memory files that had been accidentally
// committed to the public repo. They contained operator-private
// notes about the codebase ("Lesson: ask about the collector repo
// before changing SNMP code") that no human contributor needs to
// see and that pollute the public tree with internal process
// artifacts.
//
// The fix: `git rm` all three. The audit's alternative was to
// move them to `.claude/` (already gitignored); we picked the
// harder of the two (full removal) because the content is
// re-derivable from the codebase at any time and the AI agent
// can keep its session memory outside the repo entirely.
//
// This test pins the removal: a future agent who accidentally
// `git add` any of these files fails here immediately, with a
// message pointing at the audit and the alternative (move to
// `.claude/` if you really need the content).
func TestNoTrackedAgentMemoryFiles_AUDIT115(t *testing.T) {
	// Use `git ls-files` to enumerate the tracked files. This
	// is the source of truth — what the public clone would see
	// after a `git clone` + checkout.
	cmd := exec.Command("git", "ls-files")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("git ls-files failed (probably running outside a git work tree): %v", err)
	}
	tracked := string(out)

	forbidden := []string{
		"lessons.md",
		"tasks/lessons.md",
		"tasks/todo.md",
		// Also reject the parent dir if it's empty. `git rm` of
		// the last file in tasks/ doesn't necessarily remove the
		// directory itself, so we check both the file and the
		// directory name.
		"tasks",
	}
	for _, f := range forbidden {
		// Use a line-anchored match so `tasks/lessons.md` doesn't
		// false-positive on `tasks/foo/lessons.md`.
		if isTracked(tracked, f) {
			t.Errorf("AUDIT-115: %q is tracked in git but should not be (AI agent session memory, not for the public tree). Either `git rm` it (preferred — content is re-derivable) or move it under the gitignored .claude/ directory if you really need to keep the content.", f)
		}
	}
}

// isTracked reports whether `git ls-files` output contains the
// exact line `f`. We anchor on the line boundary (with newline)
// rather than using strings.Contains so `tasks/lessons.md` doesn't
// match `tasks/lessons.md.bak`.
func isTracked(lsFilesOutput, f string) bool {
	// git ls-files is one path per line, no quoting.
	for _, line := range strings.Split(lsFilesOutput, "\n") {
		if line == f {
			return true
		}
	}
	return false
}
