package shell

import (
	"os"
	"strings"
	"testing"
)

// TestPruneGoroutineHasShutdown_AUDIT084 pins that the login-attempt prune
// goroutine in cmd/api/main.go watches a cancellable context and is stopped
// on graceful shutdown, rather than running a bare `for range ticker.C` that
// only dies with the process. Without the ctx exit, the ticker can fire
// mid-shutdown and the goroutine never participates in graceful teardown.
func TestPruneGoroutineHasShutdown_AUDIT084(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cmd/api/main.go not found at %s; err: %v", path, err)
	}
	body := string(data)

	for _, needle := range []string{"bgCtx", "bgCancel()", "<-bgCtx.Done()"} {
		if !strings.Contains(body, needle) {
			t.Errorf("cmd/api/main.go is missing %q (AUDIT-084): background workers must exit via a cancellable context on shutdown.", needle)
		}
	}
	// The pruner must no longer be an unstoppable bare ticker loop.
	if strings.Contains(body, "for range ticker.C {\n\t\t\tauthManager.PruneExpiredAttempts()") {
		t.Error("cmd/api/main.go still runs the prune loop as a bare `for range ticker.C` with no shutdown path (AUDIT-084).")
	}
}
