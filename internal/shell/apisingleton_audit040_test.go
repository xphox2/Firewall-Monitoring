package shell

import (
	"os"
	"strings"
	"testing"
)

// TestAPISingletonWiring_AUDIT040 pins that cmd/api wires the singleton guard:
// it acquires the lock, releases it on shutdown, refuses to start by default
// (fatal) with an ALLOW_MULTI_API follower opt-out, and gates the IRC bots
// behind being the primary. Without this, a second API instance silently
// double-runs the in-process state (IRC nick collision, 2× lockout/rate-limit,
// divergent uptime).
func TestAPISingletonWiring_AUDIT040(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s (AUDIT-040): %v", path, err)
	}
	body := string(data)

	for _, r := range []struct{ needle, why string }{
		{"db.AcquireAPISingletonLock()", "main must acquire the API singleton lock (AUDIT-040)"},
		{"defer releaseSingleton()", "the singleton lock must be released on graceful shutdown (AUDIT-040)"},
		{"cfg.Server.AllowMultiAPI", "the refuse-vs-follower branch must key off AllowMultiAPI (AUDIT-040)"},
		{"log.Fatalf", "the default must be a fatal refuse-to-start (AUDIT-040)"},
	} {
		if !strings.Contains(body, r.needle) {
			t.Errorf("main.go missing %q: %s", r.needle, r.why)
		}
	}

	// ircManager.Start() must be gated behind `if isPrimary {`, not called
	// unconditionally — a follower starting bots re-introduces the nick clash.
	startIdx := strings.Index(body, "ircManager.Start()")
	gateIdx := strings.Index(body, "if isPrimary {")
	if startIdx < 0 || gateIdx < 0 || gateIdx > startIdx {
		t.Error("ircManager.Start() must be gated behind `if isPrimary {` (AUDIT-040).")
	}
}
