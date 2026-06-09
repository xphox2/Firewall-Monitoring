package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEntrypointSupervision_AUDIT094 pins the entrypoint's process supervision.
//
// History: the first cut tore the WHOLE stack down when ANY daemon exited
// (`wait -n` + teardown). That regressed prod — a non-essential daemon with a
// permanent startup failure (the trap-receiver declining an unset
// SNMP_TRAP_COMMUNITY) made the entire container crash-loop and the web UI never
// came online. The fix supervises the ESSENTIAL api only: `wait "$API_PID"` so a
// poller/trap death leaves the api/web UI up (degraded, visible), and only the
// api exiting tears the stack down for a clean restart. This guard fails if the
// entrypoint regresses to tearing down on a non-essential daemon's exit.
func TestEntrypointSupervision_AUDIT094(t *testing.T) {
	data, err := os.ReadFile("../../entrypoint.sh")
	if err != nil {
		t.Fatalf("read entrypoint.sh: %v", err)
	}
	s := string(data)

	// Supervise the essential api specifically — NOT all three, and not a bare
	// `wait -n` that fires on the first (possibly non-essential) daemon's exit.
	if !strings.Contains(s, `wait "$API_PID"`) {
		t.Error(`entrypoint.sh must supervise the essential api with wait "$API_PID" (AUDIT-094): a poller/trap death must not take the stack down.`)
	}

	// The api's exit must tear the stack down and exit non-zero for a clean restart.
	if !strings.Contains(s, "teardown") || !strings.Contains(s, "exit 1") {
		t.Error("entrypoint.sh must tear the stack down and `exit 1` when the api exits (AUDIT-094).")
	}

	// Signals must still be trapped for a graceful `docker stop` (exit 0).
	if !strings.Contains(s, "trap shutdown INT TERM") {
		t.Error("entrypoint.sh must still trap INT/TERM for graceful shutdown (AUDIT-094).")
	}

	// The three-PID `wait` is legitimate ONLY inside teardown to reap the killed
	// daemons, and only guarded with `|| true`. It must never be the top-level
	// blocker again (that was the pre-094 "wait for all" bug).
	const threePidWait = "wait $API_PID $POLLER_PID $TRAP_PID"
	for _, ln := range strings.Split(s, "\n") {
		tl := strings.TrimSpace(ln)
		if strings.HasPrefix(tl, threePidWait) && !strings.HasSuffix(tl, "|| true") {
			t.Errorf("entrypoint.sh has an unguarded `%s` (AUDIT-094): the top-level blocker must be the essential-api wait, and teardown's reap must end in `|| true`.", threePidWait)
		}
	}
}
