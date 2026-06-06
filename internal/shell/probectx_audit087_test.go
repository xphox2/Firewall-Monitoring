package shell

import (
	"os"
	"strings"
	"testing"
)

// TestProbePollDeviceContext_AUDIT087 is a cheap static guard that the
// probe's device-poll goroutines are context-aware and tracked. The pre-fix
// code launched `go p.pollDevice(dev)` with no context and no WaitGroup, so
// in-flight polls ran unbounded after Stop(). The behavioral guarantees are
// unit-tested in cmd/probe; this pins the source shape so a refactor that
// drops the context parameter or the tracking fails fast.
func TestProbePollDeviceContext_AUDIT087(t *testing.T) {
	const path = "../../cmd/probe/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cmd/probe/main.go not found at %s; err: %v", path, err)
	}
	body := string(data)

	want := []struct {
		needle string
		why    string
	}{
		{"func (p *Probe) pollDevice(ctx context.Context,", "pollDevice must take a context so it can bail on shutdown (AUDIT-087)."},
		{"p.pollWG.Add(1)", "each poll must be tracked on the WaitGroup so cleanup() can drain in-flight polls (AUDIT-087)."},
		{"p.cancel()", "cleanup() must cancel the probe context to signal in-flight polls (AUDIT-087)."},
		{"p.pollWG.Wait()", "cleanup() must wait for in-flight polls to drain (AUDIT-087)."},
	}
	for _, w := range want {
		if !strings.Contains(body, w.needle) {
			t.Errorf("cmd/probe/main.go is missing %q: %s", w.needle, w.why)
		}
	}

	// The old untracked launch form must be gone.
	if strings.Contains(body, "go p.pollDevice(dev)") {
		t.Error("cmd/probe/main.go still launches `go p.pollDevice(dev)` — the untracked, context-less form the audit flagged (AUDIT-087).")
	}
}
