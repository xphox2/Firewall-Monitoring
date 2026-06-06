package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEntrypoint_LoggingRationale_AUDIT095 pins that the entrypoint
// documents WHY Postgres `logging_collector` is off and demonstrates that
// crash forensics are still retained. The audit's premise ("crash
// forensics lost") is only half-true here: PG is launched with
// `pg_ctl -l "$PGDATA/postgresql.log"`, redirecting stderr to a file on
// the persistent bind-mounted volume. The fix is documentation — a future
// operator deciding whether to flip the collector on needs the rationale
// and the alternative spelled out next to the setting. This test fails if
// either the AUDIT-095 rationale or the pg_ctl log-file redirect is
// removed without revisiting the logging story.
func TestEntrypoint_LoggingRationale_AUDIT095(t *testing.T) {
	const path = "../../entrypoint.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("entrypoint.sh not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-095") {
		t.Error("entrypoint.sh is missing the AUDIT-095 rationale comment explaining the logging_collector = off choice and where PG logs are retained.")
	}
	// The rationale is only true if the log-file redirect is actually
	// present — assert both halves so they can't drift apart.
	if !strings.Contains(body, "postgresql.log") {
		t.Error("entrypoint.sh no longer references postgresql.log — the AUDIT-095 rationale claims PG stderr is redirected there for crash forensics. If logging moved to stderr/docker logs, update the comment too.")
	}
	if !strings.Contains(body, "-l \"$PGDATA/postgresql.log\"") && !strings.Contains(body, "-l \"${PGDATA}/postgresql.log\"") {
		t.Error("entrypoint.sh no longer redirects PG logs to a file via pg_ctl -l; with logging_collector = off that means crash forensics ARE lost (AUDIT-095). Re-enable the redirect or turn the collector on.")
	}
}
