package shell

import (
	"os"
	"strings"
	"testing"
)

// TestProbesBatchStats_FrontendUsesBatch_AUDIT064 pins the JS side of the N+1
// fix: admin-probes.js must request /probes/stats?ids=... once instead of
// looping one /probes/:id/stats call per approved probe. The backend handler
// is covered by TestGetProbesStatsBatch_AUDIT064 in internal/api/handlers.
func TestProbesBatchStats_FrontendUsesBatch_AUDIT064(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-probes.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-probes.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-064") {
		t.Errorf("admin-probes.js missing the AUDIT-064 marker.")
	}
	if !strings.Contains(body, "/probes/stats?ids=") {
		t.Errorf("admin-probes.js must call the batch endpoint `/probes/stats?ids=` (AUDIT-064).")
	}
	// The old per-probe N+1 call must be gone from the summary path.
	if strings.Contains(body, "'/probes/' + probe.id + '/stats'") {
		t.Errorf("admin-probes.js still issues a per-probe `/probes/:id/stats` call in a loop (AUDIT-064): use the batch endpoint.")
	}
}
