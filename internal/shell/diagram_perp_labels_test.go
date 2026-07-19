package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDiagramLabelsPerpendicular pins that the connection-map edge labels read
// ACROSS the wire (perpendicular): vertical on horizontal links, horizontal on
// vertical links. This is driven by a per-edge data(labelAngle) numeric
// rotation (see perpLabelAngle / refreshLabelAngles in diagram-cytoscape.js) —
// NOT 'none' (always screen-horizontal, which runs parallel to E/W links) and
// NOT 'autorotate' (always along the line). Reverting any word label to 'none'
// or 'autorotate' would silently regress the orientation, so guard the exact
// style strings.
func TestDiagramLabelsPerpendicular(t *testing.T) {
	data, err := os.ReadFile("../../cmd/api/static/js/diagram-cytoscape.js")
	if err != nil {
		t.Fatalf("read diagram-cytoscape.js: %v", err)
	}
	js := string(data)

	// The center type label and both endpoint port labels must use the
	// data-driven perpendicular angle.
	for _, pin := range []string{
		"'text-rotation': 'data(labelAngle)'",
		"'source-text-rotation': 'data(labelAngle)'",
		"'target-text-rotation': 'data(labelAngle)'",
	} {
		if !strings.Contains(js, pin) {
			t.Errorf("missing %q — link labels must read perpendicular to the wire", pin)
		}
	}

	// The angle wiring must be present: helper + batched refresh.
	for _, pin := range []string{
		"function perpLabelAngle(",
		"function refreshLabelAngles(",
	} {
		if !strings.Contains(js, pin) {
			t.Errorf("missing %q — perpendicular-angle wiring dropped", pin)
		}
	}

	// No word label may fall back to 'none' (screen-horizontal) — that runs
	// parallel to horizontal links instead of across them.
	for _, bad := range []string{
		"'text-rotation': 'none'",
		"'source-text-rotation': 'none'",
		"'target-text-rotation': 'none'",
	} {
		if strings.Contains(js, bad) {
			t.Errorf("found %q — word labels must be perpendicular (data(labelAngle)), not screen-horizontal", bad)
		}
	}

	// No labelled EDGE selector may use autorotate. The only permitted
	// 'text-rotation': 'autorotate' is on the single-glyph down-marker (✖),
	// whose orientation is visually irrelevant; every other occurrence would be
	// a text label rotating along the line.
	const bad = "'text-rotation': 'autorotate'"
	count := strings.Count(js, bad)
	glyph := strings.Count(js, "'label': '\\u2716', 'text-rotation': 'autorotate'")
	if count-glyph > 0 {
		t.Errorf("found %d text-label autorotate uses beyond the ✖ down-marker — labels must be perpendicular", count-glyph)
	}
}
