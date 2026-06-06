package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestMakefileNativeInstall_AUDIT104 pins the non-Docker install path: the
// Makefile must expose `install` and `tarball` targets so users on
// FreeBSD/Synology/RHEL/k8s-without-Docker can deploy the native binaries.
// It also guards the subtle bug that `go build -o bin/ ./cmd/...` names
// binaries after their directories (api/poller/...), which would mismatch
// the canonical `fwmon-*` names the systemd units / install target expect —
// so the build target must emit `fwmon-*`.
func TestMakefileNativeInstall_AUDIT104(t *testing.T) {
	data, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Skipf("Makefile not found; err: %v", err)
	}
	mf := string(data)

	// Required targets (as recipe headers `name:`).
	for _, target := range []string{"install:", "tarball:"} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(target)).MatchString(mf) {
			t.Errorf("Makefile is missing a %q target (AUDIT-104): native installs need it.", strings.TrimSuffix(target, ":"))
		}
	}

	// The build target must emit the canonical fwmon-* names so install /
	// tarball / the systemd ExecStart paths line up.
	for _, name := range []string{"fwmon-api", "fwmon-poller", "fwmon-trap", "fwmon-probe"} {
		if !strings.Contains(mf, "$(BIN_DIR)/"+name) {
			t.Errorf("Makefile build target does not produce %q (AUDIT-104): native install references the canonical fwmon-* names.", name)
		}
	}

	// The install target must install into a PREFIX/DESTDIR-aware location.
	if !strings.Contains(mf, "PREFIX") || !strings.Contains(mf, "DESTDIR") {
		t.Error("Makefile install target must honor PREFIX/DESTDIR (AUDIT-104) for staged/packaged installs.")
	}
}
