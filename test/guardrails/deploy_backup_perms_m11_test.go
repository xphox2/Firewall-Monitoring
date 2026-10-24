package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestDeploy_BackupProtected_M11 pins the protection of deploy.sh's
// pre-deploy backup (M-11). The AUDIT-098 tarball is a full copy of the
// install; the pre-fix `sudo tar czf` wrote it world-readable (umask 022)
// into a world-listable directory. This test fails if the lockdown or the
// optional age encryption is removed, or if the backup step stops being
// fail-closed.
func TestDeploy_BackupProtected_M11(t *testing.T) {
	const path = "../../deploy.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("deploy.sh not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	start := strings.Index(body, "<< 'BACKUP'")
	end := strings.Index(body, "\nBACKUP\n")
	if start < 0 || end < start {
		t.Fatal("deploy.sh: the remote backup script (<< 'BACKUP' ... BACKUP heredoc) is missing (M-11)")
	}
	script := body[start:end]

	checks := []struct {
		needle string
		why    string
	}{
		{"set -euo pipefail", "a failed tar/age must fail the ssh call so `set -e` stops the deploy before the rm."},
		{"umask 077", "the archive must be created owner-only, never world-readable."},
		{`chmod 0700 "$backup_dir"`, "the backups dir must be root-only."},
		{`chmod 0600 "$backup_file"`, "the new archive must be 0600."},
		{`chown root:root "$backup_dir"`, "the backups dir must be owned by root."},
		{`-name '*.tar.gz*' -exec chmod 0600`, "archives left by older deploys (plain and .age) must be tightened too."},
		{`age -r "$recipient"`, "--backup-age-recipient must encrypt the archive."},
		{"command -v age", "a requested encryption with no age binary must abort, not silently write plaintext."},
	}
	for _, c := range checks {
		if !strings.Contains(script, c.needle) {
			t.Errorf("deploy.sh backup script is missing %q: %s", c.needle, c.why)
		}
	}

	// The recipient reaches a remote command line, so it must be validated
	// against the age public-key alphabet before use.
	if !strings.Contains(body, `^age1[02-9ac-hj-np-z]{58}$`) {
		t.Error("deploy.sh must validate --backup-age-recipient as an age1 public key before passing it to the remote (M-11).")
	}

	// The protected backup must still precede the destructive rm (AUDIT-098).
	rmIdx := strings.Index(body, "rm -rf ${REMOTE_DIR}/*")
	if rmIdx >= 0 && start > rmIdx {
		t.Error("deploy.sh runs `rm -rf ${REMOTE_DIR}/*` before the backup script (AUDIT-098/M-11).")
	}
}
