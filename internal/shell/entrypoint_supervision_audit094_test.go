package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEntrypointFailFastSupervision_AUDIT094 pins the fail-fast supervision in
// entrypoint.sh: the three fwmon daemons must NOT be waited on with a bare
// `wait $API_PID $POLLER_PID $TRAP_PID` (which blocks until ALL exit, leaving a
// silently-degraded stack when one crashes). Instead the entrypoint waits for
// the FIRST to exit (`wait -n`), tears the stack down, and exits non-zero so
// Docker restarts a complete stack. The guard fails if that regresses.
func TestEntrypointFailFastSupervision_AUDIT094(t *testing.T) {
	data, err := os.ReadFile("../../entrypoint.sh")
	if err != nil {
		t.Fatalf("read entrypoint.sh: %v", err)
	}
	s := string(data)

	// Fail-fast: wait for the first daemon to exit, not all three.
	if !strings.Contains(s, "wait -n") {
		t.Error("entrypoint.sh no longer uses `wait -n` (AUDIT-094): a single daemon crash must fail the container fast, not silently degrade the stack.")
	}

	// The crash path must exit non-zero so the restart policy brings the stack back.
	if !strings.Contains(s, "teardown") || !strings.Contains(s, "exit 1") {
		t.Error("entrypoint.sh must tear the stack down and `exit 1` on a daemon crash (AUDIT-094).")
	}

	// Signals must still be trapped for a graceful `docker stop` (exit 0).
	if !strings.Contains(s, "trap shutdown INT TERM") {
		t.Error("entrypoint.sh must still trap INT/TERM for graceful shutdown (AUDIT-094).")
	}

	// The bare `wait` on all three PIDs is still legitimate INSIDE teardown to
	// reap the killed daemons, but only in its guarded form. The pre-fix bug was
	// using it UNGUARDED as the final top-level blocker; assert every occurrence
	// of the three-PID wait is the guarded reap (followed by `|| true`), so it
	// can never again be the top-level blocking wait.
	const threePidWait = "wait $API_PID $POLLER_PID $TRAP_PID"
	for _, ln := range strings.Split(s, "\n") {
		tl := strings.TrimSpace(ln)
		if strings.HasPrefix(tl, threePidWait) && !strings.HasSuffix(tl, "|| true") {
			t.Errorf("entrypoint.sh has an unguarded `%s` (AUDIT-094): the top-level blocker must be `wait -n`, and teardown's reap must end in `|| true`.", threePidWait)
		}
	}
}
