package shell

import (
	"os"
	"strings"
	"testing"
)

// TestShortGatingAdopted_AUDIT142 pins that the slow / timing / concurrency
// tests are gated behind testing.Short(), so `go test -short` actually skips
// them (the audit's finding was "go test -short does nothing"). The guard fails
// if a gated file drops its testing.Short() skip.
func TestShortGatingAdopted_AUDIT142(t *testing.T) {
	mustGate := []string{
		"../database/batcher_test.go",                // time.Sleep / concurrency batcher tests
		"../snmp/trap_test.go",                       // rate-limiter refill timing + concurrency
		"../../cmd/probe/probe_ctx_audit087_test.go", // 5s bounded-drain test
	}
	for _, path := range mustGate {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s missing (AUDIT-142): %v", path, err)
			continue
		}
		if !strings.Contains(string(data), "testing.Short()") {
			t.Errorf("%s no longer gates its slow tests behind testing.Short() (AUDIT-142): -short must skip them.", path)
		}
	}
}
