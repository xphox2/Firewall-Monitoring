package shell

import (
	"os"
	"strings"
	"testing"
)

// TestChartTeardown_AUDIT061 is a static regression for the audit: the
// proc-ssh-chart and iface-err-chart Chart.js instances in
// admin-device-detail.js were created once and held their canvas contexts for
// the whole page session even when their tab was hidden. The fix has switchTab
// destroy each chart (and null the reference) when leaving its tab, and
// recreate it from the current control values on re-entry.
func TestChartTeardown_AUDIT061(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-device-detail.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-device-detail.js not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-061") {
		t.Errorf("admin-device-detail.js missing the AUDIT-061 marker.")
	}
	for _, sig := range []string{
		"procSshChart.destroy(); procSshChart = null",
		"ifaceErrChart.destroy(); ifaceErrChart = null",
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("admin-device-detail.js switchTab must tear down the chart on leave: missing %q (AUDIT-061).", sig)
		}
	}
}
