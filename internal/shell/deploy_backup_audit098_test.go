package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDeploy_BackupAndDryRun_AUDIT098 pins the two safeguards added in
// front of deploy.sh's destructive `rm -rf ${REMOTE_DIR}/*`:
//
//  1. a --dry-run flag that makes NO remote changes, and
//  2. a timestamped pre-deploy backup tarball written BEFORE the rm.
//
// The pre-fix script wiped the install dir with no backup and no rollback,
// so a typo in --host or an aborted transfer could destroy a deployment
// irrecoverably. This test fails if either safeguard is removed.
func TestDeploy_BackupAndDryRun_AUDIT098(t *testing.T) {
	const path = "../../deploy.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("deploy.sh not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	checks := []struct {
		needle string
		why    string
	}{
		{"--dry-run", "the --dry-run flag must be parsable (AUDIT-098): operators run it first to preview a deploy without touching the remote."},
		{"DRY_RUN", "the dry-run state variable must exist so the destructive path can be short-circuited (AUDIT-098)."},
		{"tar czf", "a pre-deploy backup tarball of the existing install must be taken before the rm (AUDIT-098) so a bad deploy can be rolled back."},
		{"-backups", "the backup must be written to a dedicated ${REMOTE_DIR}-backups directory (AUDIT-098)."},
		{"AUDIT-098", "the rationale comment for the backup/dry-run safeguards must remain so the intent isn't lost."},
	}
	for _, c := range checks {
		if !strings.Contains(body, c.needle) {
			t.Errorf("deploy.sh is missing %q: %s", c.needle, c.why)
		}
	}

	// The backup must precede the destructive rm. Assert ordering by byte
	// offset so a refactor can't move the rm above the backup.
	backupIdx := strings.Index(body, "tar czf")
	rmIdx := strings.Index(body, "rm -rf ${REMOTE_DIR}/*")
	if backupIdx >= 0 && rmIdx >= 0 && backupIdx > rmIdx {
		t.Error("deploy.sh runs the destructive `rm -rf ${REMOTE_DIR}/*` BEFORE the backup tarball (AUDIT-098): the backup must come first or it captures an already-wiped directory.")
	}
}
