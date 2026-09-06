package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDiagramOffnetEdgeOnlyWhileConnected pins that the connection map draws
// an Off-Net edge (device → Internet cloud) only while a remote user or
// unmonitored peer is actually connected, and never paints one DOWN.
//
// An unmatched tunnel that is not up is an idle remote-access / dialup phase1
// — a config row with no SA — not a failure. The earlier build set the edge's
// status to 'down' whenever no unmatched tunnel was up, which crossed out every
// remote-access endpoint that simply had nobody dialled in (DC2-FW1 and
// NUDAY-FW on prod, 2026-09-05). Reverting to a status-driven edge, or building
// it from a raw "unmatched" count, would bring that false warning back.
func TestDiagramOffnetEdgeOnlyWhileConnected(t *testing.T) {
	data, err := os.ReadFile("../../cmd/api/static/js/diagram-cytoscape.js")
	if err != nil {
		t.Fatalf("read diagram-cytoscape.js: %v", err)
	}
	js := string(data)

	for _, pin := range []string{
		"function offnetConnected(",
		"t.status === 'up'",
		"function offnetEdgeData(",
		"status: 'up'",
		"label: count + ' connected'",
		"function reconcileOffnetEdges(",
	} {
		if !strings.Contains(js, pin) {
			t.Errorf("diagram-cytoscape.js must contain %q", pin)
		}
	}

	// The label must actually be painted: only a stylesheet rule that reads
	// data(label) on the off-net selector makes "N connected" visible. Before
	// this rule existed the edge carried a label no rule ever drew.
	sel := strings.Index(js, `selector: 'edge[edgeType="offnet"]'`)
	if sel < 0 {
		t.Fatal("off-net edge style selector not found")
	}
	rule := js[sel:]
	if end := strings.Index(rule, "}},"); end > 0 {
		rule = rule[:end]
	}
	if !strings.Contains(rule, "'label': 'data(label)'") {
		t.Error("the off-net edge style must paint data(label)")
	}

	// The live refresh must reconcile the edges, not only the node badges,
	// so a user dialling in (or hanging up) changes the map without a reload.
	badges := strings.Index(js, "function updateVPNBadges(")
	if badges < 0 {
		t.Fatal("updateVPNBadges not found")
	}
	body := js[badges:]
	if end := strings.Index(body, "\n    }\n"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "reconcileOffnetEdges(vpnMap);") {
		t.Error("updateVPNBadges must call reconcileOffnetEdges(vpnMap)")
	}

	for _, banned := range []string{
		"info.anyUp ? 'up' : 'down'",
		"' unmatched'",
	} {
		if strings.Contains(js, banned) {
			t.Errorf("diagram-cytoscape.js must not contain %q: an off-net edge is never DOWN and never counts idle tunnels", banned)
		}
	}
}
