package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDockerfile_NoUnusedCToolchain_AUDIT103 pins that the builder stage no
// longer installs a C toolchain. Every binary is built with CGO_ENABLED=0,
// so `apk add ... gcc musl-dev` was dead weight that only slowed image
// builds. This fails if a future edit reintroduces the unused packages.
func TestDockerfile_NoUnusedCToolchain_AUDIT103(t *testing.T) {
	const path = "../../Dockerfile"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("Dockerfile not found at %s; err: %v", path, err)
	}

	// Strip comments so the explanatory note doesn't false-positive.
	var exec []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		exec = append(exec, line)
	}
	body := strings.Join(exec, "\n")

	for _, pkg := range []string{"gcc", "musl-dev"} {
		if strings.Contains(body, pkg) {
			t.Errorf("Dockerfile still installs %q (AUDIT-103): the builder uses CGO_ENABLED=0, so the C toolchain is never used — remove it.", pkg)
		}
	}
	// Sanity: the builds must actually be CGO-free for the above to hold.
	if !strings.Contains(body, "CGO_ENABLED=0") {
		t.Error("Dockerfile no longer sets CGO_ENABLED=0 — if CGO is now needed, AUDIT-103's removal of the C toolchain is wrong; revisit.")
	}
}
