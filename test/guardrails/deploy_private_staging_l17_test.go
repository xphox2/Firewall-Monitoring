package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestDeploy_PrivateStagingDir_L17 pins L-17: deploy.sh stages web/ and the
// example config in a fresh mktemp -d directory, never at fixed names in the
// shared /tmp, where another local user could pre-create them and have
// `sudo cp` install their files.
func TestDeploy_PrivateStagingDir_L17(t *testing.T) {
	data, err := os.ReadFile("../../deploy.sh")
	if err != nil {
		t.Skipf("deploy.sh not found: %v", err)
	}
	body := string(data)
	for _, bad := range []string{"${HOST}:/tmp/web", "${HOST}:/tmp/config.env", "/tmp/web /opt", "cp /tmp/config.env", "fwmon-*.service /tmp/"} {
		if strings.Contains(body, bad) {
			t.Errorf("deploy.sh still uses a fixed shared-/tmp path (%q) (L-17)", bad)
		}
	}
	for _, want := range []string{`mktemp -d /tmp/fwmon-deploy.XXXXXXXX`, `^/tmp/fwmon-deploy\.[A-Za-z0-9]{8}$`, `rm -rf "$stage"`} {
		if !strings.Contains(body, want) {
			t.Errorf("deploy.sh is missing %q: the private staging dir must be created, validated and removed (L-17)", want)
		}
	}
}
