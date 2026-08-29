package shell

import (
	"regexp"
	"strings"
	"testing"
)

// AUDIT-232: admin-ipsec.js startDeploy/startRollback/startRecheck opened the
// deploy modal (which immediately GET-polled the deploy record) BEFORE the POST
// that launches the operation. The immediate GET could land before the POST and
// return the PRIOR deploy record — rendering a stale failure banner during
// launch — and the later POST resolution started a SECOND concurrent poll with
// the same deployGen. The fix adds a deferPoll parameter: a fresh launch skips
// the pre-POST poll and starts the single poll only after the POST is accepted.
func TestIPSecDeploy_DefersPollUntilPost_AUDIT232(t *testing.T) {
	js := readJS(t, "admin-ipsec.js")

	if !strings.Contains(js, "function openDeployModal(id, op, deferPoll)") {
		t.Error("AUDIT-232 regression: openDeployModal no longer takes a deferPoll parameter")
	}
	// The immediate pre-POST poll must be gated by !deferPoll.
	if !regexp.MustCompile(`if\s*\(\s*!deferPoll\s*\)\s*\{`).MatchString(js) {
		t.Error("AUDIT-232 regression: openDeployModal no longer gates the immediate pollDeploy on !deferPoll — a stale prior-deploy banner can render during launch")
	}
	// Each launch caller must defer the poll (pass true).
	for _, want := range []string{
		"openDeployModal(id, 'deploy', true)",
		"openDeployModal(id, 'rollback', true)",
		"openDeployModal(id, 'recheck', true)",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("AUDIT-232 regression: launch caller %q no longer defers the poll until the POST lands", want)
		}
	}
}
