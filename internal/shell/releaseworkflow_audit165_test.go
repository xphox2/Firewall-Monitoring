package shell

import (
	"os"
	"strings"
	"testing"
)

// TestReleaseWorkflow_AUDIT165 pins that the GitHub release-notes automation
// exists and keeps its essential wiring. The audit flagged that there was no
// release-notes automation (AUDIT-165). The resolution is a tag-triggered,
// CHANGELOG-driven workflow (chosen over release-drafter because this repo is
// developed direct-to-master, not via labelled PRs). This guard fails if a
// future edit drops the tag trigger, the write permission, the CHANGELOG
// extraction, or the `gh release` publish step.
func TestReleaseWorkflow_AUDIT165(t *testing.T) {
	const path = "../../.github/workflows/release.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf(".github/workflows/release.yml not found at %s (AUDIT-165): %v", path, err)
	}
	body := string(data)

	// Each required element, with a reason so a future breaker sees the intent.
	required := []struct{ needle, why string }{
		{"tags:", "must be tag-triggered (AUDIT-165): release on `vX.Y.Z` tag push."},
		{`- "v*"`, "must trigger on `v*` tags (AUDIT-165)."},
		{"contents: write", "needs `contents: write` permission to create a Release (AUDIT-165)."},
		{"CHANGELOG.md", "notes must be lifted from CHANGELOG.md — the source of truth (AUDIT-165)."},
		{"[Unreleased]", "must fall back to the [Unreleased] section so a release is never note-less (AUDIT-165)."},
		{"gh release", "must publish via the gh CLI (`gh release create`/`edit`) (AUDIT-165)."},
	}
	for _, r := range required {
		if !strings.Contains(body, r.needle) {
			t.Errorf("release.yml is missing %q: %s", r.needle, r.why)
		}
	}

	// It must NOT be PR/branch-triggered on push to master (that would publish a
	// release on every commit). The only `push:` trigger is the tag one.
	if strings.Contains(body, "branches:") {
		t.Error("release.yml triggers on branches (AUDIT-165): it must trigger ONLY on tag push, not on every commit to a branch.")
	}
}
