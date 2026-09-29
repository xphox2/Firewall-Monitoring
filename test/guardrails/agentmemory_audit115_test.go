package guardrails

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoTrackedInternalFiles_AUDIT115 keeps working notes, internal reports
// and one-off helper scripts out of the public tree. Task lists, lessons files,
// review reports and tool settings are useful to the people writing the code
// but carry no value for users of the project, and can carry details about the
// environments it was developed in.
//
// The paths below must never be tracked. `.gitignore` lists the same set (except
// scripts/, which is not ignored so a public script can still be added on
// purpose — it just has to be a deliberate, reviewed decision).
//
// `git ls-files --full-name` is run from the repository root: run from this
// package's directory, `git ls-files` lists only files below it and the check
// would pass without looking at anything.
func TestNoTrackedInternalFiles_AUDIT115(t *testing.T) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not inside a git work tree: %v", err)
	}
	cmd := exec.Command("git", "ls-files", "--full-name")
	cmd.Dir = strings.TrimSpace(string(root))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, path := range strings.Split(string(out), "\n") {
		if path == "" {
			continue
		}
		if why := internalPath(path); why != "" {
			t.Errorf("AUDIT-115: %q is tracked but %s — keep it out of the public tree (it is gitignored or must be removed).", path, why)
		}
	}
}

// internalPath reports why a tracked path is not allowed, or "" if it is fine.
func internalPath(p string) string {
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	switch {
	case strings.HasPrefix(p, "tasks/"):
		return "it is a working note or internal task file"
	case strings.HasPrefix(p, "scripts/"):
		return "it is an unreviewed helper script"
	case strings.HasPrefix(p, ".claude/") || strings.Contains(p, "/.claude/"):
		return "it is local tool settings"
	case p == "docs/AUDIT.md" || strings.HasPrefix(p, "docs/audit-20") || strings.HasPrefix(p, "docs/audit-archive/"):
		return "it is an internal review report"
	case base == "CLAUDE.md" || base == "AGENTS.md" || base == "lessons.md":
		return "it is a local working-notes file"
	case strings.HasPrefix(base, "session-ses_") && strings.HasSuffix(base, ".md"):
		return "it is a session transcript"
	}
	return ""
}

func TestInternalPathClassifier(t *testing.T) {
	for _, p := range []string{"tasks/todo.md", "tasks/x/y.sh", "scripts/a.py", ".claude/settings.json",
		"docs/AUDIT.md", "docs/audit-2026-01-01.md", "docs/audit-archive/README.md",
		"CLAUDE.md", "sub/AGENTS.md", "lessons.md", "session-ses_1.md"} {
		if internalPath(p) == "" {
			t.Errorf("%q should be classified as internal", p)
		}
	}
	for _, p := range []string{"docs/OPERATIONS.md", "docs/audit-log.md", "internal/audit/audit.go",
		"README.md", "cmd/api/main.go", "internal/tasks/x.go"} {
		if why := internalPath(p); why != "" {
			t.Errorf("%q wrongly classified as internal: %s", p, why)
		}
	}
}
