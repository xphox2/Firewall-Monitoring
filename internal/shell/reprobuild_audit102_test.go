package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestReproducibleBuildFlags_AUDIT102 pins that both build paths — the
// Dockerfile `go build` lines and the Makefile `build` target — pass
// `-trimpath -buildvcs=false`, so binaries are byte-reproducible across
// build hosts. Without these, the same source produces different bytes on
// different machines (embedded GOPATH/module-cache paths + VCS stamps).
func TestReproducibleBuildFlags_AUDIT102(t *testing.T) {
	// Every `go build` invocation in the Dockerfile must carry both flags.
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Skipf("Dockerfile not found; err: %v", err)
	}
	goBuildLine := regexp.MustCompile(`(?m)^\s*RUN .*go build .*-o fwmon-`)
	lines := goBuildLine.FindAllString(string(dockerfile), -1)
	if len(lines) == 0 {
		t.Fatal("Dockerfile has no `RUN ... go build -o fwmon-*` lines — did the build stage change?")
	}
	for _, l := range lines {
		if !strings.Contains(l, "-trimpath") || !strings.Contains(l, "-buildvcs=false") {
			t.Errorf("Dockerfile build line lacks reproducible-build flags (AUDIT-102): %q must include -trimpath and -buildvcs=false", strings.TrimSpace(l))
		}
	}

	// The Makefile build target must use the same flags.
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Skipf("Makefile not found; err: %v", err)
	}
	mf := string(makefile)
	if !strings.Contains(mf, "-trimpath") || !strings.Contains(mf, "-buildvcs=false") {
		t.Error("Makefile build target lacks -trimpath/-buildvcs=false (AUDIT-102): native builds must be reproducible too.")
	}
}
