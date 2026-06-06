package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDockerignore_CoversWorkingTreeArtifacts_AUDIT092 pins that the
// developer/working-tree files the audit named are excluded from the
// Docker build context. None are COPYed by the current Dockerfile, but a
// future PR that broadens the COPY surface (e.g. `COPY . .`) would
// otherwise drag local debris — agent working files, IRC format dumps,
// scraped CSVs — into the published image. The .dockerignore is the
// durable guard, so we assert each required entry is present.
func TestDockerignore_CoversWorkingTreeArtifacts_AUDIT092(t *testing.T) {
	const path = "../../.dockerignore"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf(".dockerignore not found at %s (tests must run from the package root); err: %v", path, err)
	}

	// Match on whole, comment-stripped lines so a substring like "tasks/"
	// inside an explanatory comment can't satisfy the check.
	present := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		present[line] = true
	}

	required := []string{
		"cookies.txt",
		"interfaces.json",
		"IRC-FORMAT.txt",
		"node_modules/",
		"tasks/",
		".claude/",
		"lessons.md",
	}
	for _, entry := range required {
		if !present[entry] {
			t.Errorf(".dockerignore is missing %q. AUDIT-092: this working-tree artifact must be excluded from the build context so a broader COPY in a future PR cannot ship it.", entry)
		}
	}
}
