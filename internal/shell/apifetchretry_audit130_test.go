package shell

import (
	"os"
	"strings"
	"testing"
)

// TestApiFetchRetriesTransient_AUDIT130 pins that admin-common.js's apiFetch
// retries transient gateway errors (502/503/504) with backoff before
// surfacing a failure, so a brief proxy/DB hiccup or a rolling restart
// doesn't show the operator a hard error toast.
func TestApiFetchRetriesTransient_AUDIT130(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-common.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-common.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	// Must reference the retry mechanism and all three transient statuses.
	for _, needle := range []string{"AUDIT-130", "maxAttempts", "502", "503", "504", "setTimeout"} {
		if !strings.Contains(body, needle) {
			t.Errorf("admin-common.js apiFetch is missing %q (AUDIT-130: retry 502/503/504 with backoff).", needle)
		}
	}
	// Backoff must include jitter so many clients don't retry in lock-step.
	if !strings.Contains(body, "Math.random()") {
		t.Error("admin-common.js retry backoff has no jitter (Math.random) (AUDIT-130).")
	}
}
