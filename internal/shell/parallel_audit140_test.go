package shell

import (
	"os"
	"strings"
	"testing"
)

// TestParallelTestsAdopted_AUDIT140 pins that the test suite actually uses
// t.Parallel() — the audit's finding was "0 t.Parallel() in any test", so the
// guard fails if the pure-logic packages we parallelized lose the marker (e.g.
// a refactor that regenerates the files without it). We don't require *every*
// file to be parallel (timing/global-state tests intentionally are not); we
// require the representative pure packages to keep it.
func TestParallelTestsAdopted_AUDIT140(t *testing.T) {
	mustHaveParallel := []string{
		"../configdiff/normalize_test.go",
		"../configdiff/validate_test.go",
		"../models/models_test.go",
		"../alerts/policy_test.go",
		"../report/report_test.go",
		"../uptime/uptime_property_test.go",
		"../auth/auth_test.go",
		"../database/batcher_test.go",
		"../snmp/trap_test.go",
	}
	for _, path := range mustHaveParallel {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s missing (AUDIT-140): %v", path, err)
			continue
		}
		if !strings.Contains(string(data), "t.Parallel()") {
			t.Errorf("%s no longer calls t.Parallel() (AUDIT-140): independent tests must run in parallel.", path)
		}
	}
}
