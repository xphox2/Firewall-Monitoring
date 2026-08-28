package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDeploy_WebCopiedWithPrefix_AUDIT171 pins that deploy.sh installs the
// web/ tree WITH its directory prefix in both install paths. The pre-fix
// script flattened web/* into the install dir, but fwmon-api loads HTML
// templates via LoadHTMLGlob("./web/**/*.html") relative to the unit's
// WorkingDirectory — a zero-match glob panics at startup and Restart=always
// turns that into a permanent crash loop. This test fails if either copy
// loses the web/ prefix again.
func TestDeploy_WebCopiedWithPrefix_AUDIT171(t *testing.T) {
	const path = "../../deploy.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("deploy.sh not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// Local install: prefix-preserving copy.
	if !strings.Contains(body, "cp -r web ${INSTALL_DIR}/web") {
		t.Error("deploy.sh local install no longer copies web/ with its prefix (`cp -r web ${INSTALL_DIR}/web`) — LoadHTMLGlob(\"./web/**/*.html\") will panic and crash-loop (AUDIT-171).")
	}
	// Remote install: prefix-preserving copy.
	if !strings.Contains(body, "sudo cp -r /tmp/web /opt/firewall-mon/web") {
		t.Error("deploy.sh remote install no longer copies web/ with its prefix (`sudo cp -r /tmp/web /opt/firewall-mon/web`) — LoadHTMLGlob(\"./web/**/*.html\") will panic and crash-loop (AUDIT-171).")
	}
	// The flattened forms must not come back.
	for _, bad := range []string{"cp -r web/* ${INSTALL_DIR}/", "cp /tmp/web/* /opt/firewall-mon/"} {
		if strings.Contains(body, bad) {
			t.Errorf("deploy.sh contains the flattening copy %q, which strips the web/ prefix LoadHTMLGlob depends on (AUDIT-171).", bad)
		}
	}
	// Adjacent AUDIT-171 fix: scripts/ holds only *.py dev helpers, so a
	// `cp scripts/*.sh` glob never expands and, under set -e, aborted the
	// install before the systemd units were created.
	if strings.Contains(body, "cp scripts/*.sh") {
		t.Error("deploy.sh copies scripts/*.sh again — scripts/ contains no .sh files, so under `set -e` the unexpanded glob aborts install_local before create_systemd_service runs (AUDIT-171).")
	}
	if !strings.Contains(body, "AUDIT-171") {
		t.Error("deploy.sh is missing the AUDIT-171 marker comment documenting the prefix-preserving web copy.")
	}
}

// TestDeploy_SecretsDirInsideSandbox_AUDIT190 pins that the SECRETS_DIR
// seeded by config.env.example is writable under the systemd unit's
// ProtectSystem=strict sandbox, whose only write allow-list entry is
// ReadWritePaths=${DATA_DIR} (/var/lib/firewall-mon). The pre-fix example
// seeded the Docker path /data, so on first native boot every daemon
// fatal'd at the JWT-secret MkdirAll and crash-looped.
func TestDeploy_SecretsDirInsideSandbox_AUDIT190(t *testing.T) {
	example, err := os.ReadFile("../../config.env.example")
	if err != nil {
		t.Skipf("config.env.example not found: %v", err)
	}
	deploy, err := os.ReadFile("../../deploy.sh")
	if err != nil {
		t.Skipf("deploy.sh not found: %v", err)
	}

	var secretsDir string
	for _, line := range strings.Split(string(example), "\n") {
		if strings.HasPrefix(line, "SECRETS_DIR=") {
			secretsDir = strings.TrimPrefix(line, "SECRETS_DIR=")
			break
		}
	}
	if secretsDir == "" {
		t.Fatal("config.env.example no longer seeds SECRETS_DIR — the native install then falls back to the in-code default /data, which ProtectSystem=strict makes unwritable (AUDIT-190).")
	}

	// deploy.sh defines DATA_DIR (in terms of ${APP_NAME}) and allows
	// exactly ReadWritePaths=${DATA_DIR}; expand the one-level variable
	// reference so the comparison works on the literal path.
	var dataDir, appName string
	for _, line := range strings.Split(string(deploy), "\n") {
		if strings.HasPrefix(line, "APP_NAME=") {
			appName = strings.Trim(strings.TrimPrefix(line, "APP_NAME="), `"`)
		}
		if strings.HasPrefix(line, "DATA_DIR=") {
			dataDir = strings.Trim(strings.TrimPrefix(line, "DATA_DIR="), `"`)
		}
	}
	dataDir = strings.ReplaceAll(dataDir, "${APP_NAME}", appName)
	if dataDir == "" || strings.Contains(dataDir, "$") {
		t.Fatalf("deploy.sh DATA_DIR could not be resolved to a literal path (got %q) — update this guard alongside the variable change (AUDIT-190).", dataDir)
	}
	if !strings.Contains(string(deploy), "ReadWritePaths=${DATA_DIR}") {
		t.Fatal("deploy.sh unit no longer sets ReadWritePaths=${DATA_DIR} — update this guard alongside the sandbox change (AUDIT-190).")
	}
	if secretsDir != dataDir && !strings.HasPrefix(secretsDir, dataDir+"/") {
		t.Errorf("config.env.example seeds SECRETS_DIR=%s, which is outside deploy.sh's ReadWritePaths allow-list (%s): the native systemd install fatals at the JWT-secret MkdirAll on first boot (AUDIT-190).", secretsDir, dataDir)
	}
}
