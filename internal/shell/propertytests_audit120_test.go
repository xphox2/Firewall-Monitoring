package shell

import (
	"os"
	"strings"
	"testing"
)

// TestPropertyTestsExist_AUDIT120 pins that the counter-delta / spike-detect and
// uptime math carry property-based tests (testing/quick), not just example
// cases. The audit flagged these as textbook property-test candidates with zero
// coverage; this guard fails if the property tests are deleted or stop using
// testing/quick (e.g. quietly downgraded to a single hand-picked example).
func TestPropertyTestsExist_AUDIT120(t *testing.T) {
	checks := []struct {
		path  string
		needs []string
	}{
		{"../report/spike_property_test.go", []string{"testing/quick", "quick.Check", "meanStdDev", "detectSpikesInSeries"}},
		{"../uptime/uptime_property_test.go", []string{"testing/quick", "quick.Check", "FormatUptime", "UptimePercent"}},
	}
	for _, c := range checks {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Errorf("%s is missing (AUDIT-120): the property tests for this math must exist; err: %v", c.path, err)
			continue
		}
		body := string(data)
		for _, needle := range c.needs {
			if !strings.Contains(body, needle) {
				t.Errorf("%s no longer references %q (AUDIT-120): the property test must keep using testing/quick against the real function under test.", c.path, needle)
			}
		}
	}
}
