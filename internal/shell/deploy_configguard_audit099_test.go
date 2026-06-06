package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDeploy_PreservesLiveConfig_AUDIT099 pins that deploy.sh no longer
// unconditionally overwrites the operator's live config. The pre-fix
// script ran `sudo cp /tmp/config.env.example /etc/firewall-mon/config.env`
// on every deploy, wiping the real SNMP community / JWT secret / SMTP
// credentials and reverting the service to placeholder defaults. The fix
// guards the copy behind a `[ ! -f ... ]` existence check so the example
// only seeds a first install. This test fails if the guard is removed.
func TestDeploy_PreservesLiveConfig_AUDIT099(t *testing.T) {
	const path = "../../deploy.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("deploy.sh not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// The config copy must be inside an existence guard. We assert the
	// guard line is present and references the live config path.
	if !strings.Contains(body, "if [ ! -f /etc/firewall-mon/config.env ]; then") {
		t.Error("deploy.sh does not guard the config.env copy behind `if [ ! -f /etc/firewall-mon/config.env ]` (AUDIT-099): an unguarded copy clobbers the operator's live config on every deploy.")
	}

	// Belt-and-suspenders: the example->config copy must not appear at the
	// start of a command line outside the guard. Check the comment-stripped
	// body has no bare (unindented-into-guard) cp of the example over the
	// live config. We approximate by requiring the AUDIT-099 marker so a
	// future edit that drops the guard also has to drop the marker.
	if !strings.Contains(body, "AUDIT-099") {
		t.Error("deploy.sh is missing the AUDIT-099 marker comment documenting why the config copy is guarded.")
	}
}
