package shell

import (
	"os"
	"strings"
	"testing"
)

// TestReadmePrereqs_AUDIT114 pins that the README's Quick Start lists the
// prerequisites a fresh Ubuntu box actually needs — the audit found the build
// steps assumed tools (rsync for deploy, a C toolchain for -race, systemd for
// install) and network ports (SNMP trap 162, syslog 514, sFlow 6343) that were
// never stated, so a clean-machine setup would fail or silently drop traffic.
func TestReadmePrereqs_AUDIT114(t *testing.T) {
	const path = "../../README.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("README.md not found at %s (AUDIT-114): %v", path, err)
	}
	body := string(data)

	// Tools the build/deploy/install/test paths shell out to.
	for _, kw := range []string{"apt install", "rsync", "build-essential", "systemd"} {
		if !strings.Contains(body, kw) {
			t.Errorf("README prereqs do not mention %q (AUDIT-114).", kw)
		}
	}
	// Listener ports an operator must open / be aware of.
	for _, port := range []string{"162", "514", "6343"} {
		if !strings.Contains(body, port) {
			t.Errorf("README does not document the %q network port (AUDIT-114).", port)
		}
	}
}
