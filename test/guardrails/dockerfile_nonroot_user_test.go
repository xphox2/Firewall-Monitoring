package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestDockerfile_NonRootUser pins that the container runs as the unprivileged
// `fwmon` user, never root. History: the Dockerfile used to carry `USER fwmon`,
// then dropped it in favor of a runtime privilege-drop (the entrypoint ran as
// root, did `chown`/`su-exec`, and started the daemons as fwmon). That left PID
// 1 running as root. This guard fails if the `USER` directive is removed again,
// or if the entrypoint regresses to running PostgreSQL via `su-exec postgres`
// (which requires root and would force the container back to root).
func TestDockerfile_NonRootUser(t *testing.T) {
	df, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Skipf("Dockerfile not found: %v", err)
	}
	// Strip comments so an explanatory note can't satisfy the check.
	var exec []string
	for _, line := range strings.Split(string(df), "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		exec = append(exec, line)
	}
	body := strings.Join(exec, "\n")

	if !strings.Contains(body, "USER fwmon") {
		t.Error("Dockerfile must end with `USER fwmon` so PID 1 runs non-root. A runtime privilege-drop via su-exec still leaves PID 1 running as root.")
	}

	// PostgreSQL must run as fwmon (single-user container), so the entrypoint
	// cannot su-exec into a separate postgres OS account.
	ep, err := os.ReadFile("../../entrypoint.sh")
	if err != nil {
		t.Skipf("entrypoint.sh not found: %v", err)
	}
	if strings.Contains(string(ep), "su-exec postgres") {
		t.Error("entrypoint.sh must not run PostgreSQL via `su-exec postgres`: that requires root. Run initdb/pg_ctl/psql as the current (fwmon) user, connecting as the postgres ROLE with -U postgres.")
	}
}
