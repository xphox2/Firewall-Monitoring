package shell

import (
	"strings"
	"testing"
)

// AUDIT-230: admin-connection-detail.js renderTunnelCharts rebuilds each tunnel
// chart host via host.innerHTML = html on every unconditional 30s auto-refresh.
// The rebuilt markup has no .fwmon-bw-toggle, so FwmonBwChart.mount could not
// recover the operator's selected bw mode (Combined/Transfer) from the sibling
// and snapped back to 'rate' every poll. The fix snapshots each group's mode
// BEFORE the wipe (keyed by group, like groupRanges) and passes it to mount as
// initialView on the fresh mount.
func TestTunnelBwMode_PreservedAcrossRefresh_AUDIT230(t *testing.T) {
	js := readConnDetailJS(t)

	if !strings.Contains(js, "var groupBwViews") {
		t.Error("AUDIT-230 regression: groupBwViews map removed — the bw-chart mode is no longer remembered across the 30s rebuild")
	}
	// The snapshot must read the active toggle button BEFORE the innerHTML wipe.
	if !strings.Contains(js, ".fwmon-bw-toggle-btn.active") {
		t.Error("AUDIT-230 regression: renderTunnelCharts no longer snapshots the active .fwmon-bw-toggle-btn before the innerHTML rebuild")
	}
	if !strings.Contains(js, "groupBwViews[groupKey(hostId,") {
		t.Error("AUDIT-230 regression: the bw mode is no longer stored keyed by group")
	}
	// mount must be handed the preserved mode as initialView.
	if !strings.Contains(js, "initialView: bwView") {
		t.Error("AUDIT-230 regression: FwmonBwChart.mount is no longer passed the remembered initialView — the mode resets to 'rate' on refresh")
	}
}
