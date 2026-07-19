package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDiagramLabelsHorizontal pins that the connection-map edge labels render
// horizontal (v0.11.123) — port endpoint labels and the center type label must
// NOT rotate along the line (autorotate forced nodes apart and hurt
// readability). A revert to 'autorotate' on a labelled edge selector would
// silently reintroduce it, so guard the exact style strings.
func TestDiagramLabelsHorizontal(t *testing.T) {
	data, err := os.ReadFile("../../cmd/api/static/js/diagram-cytoscape.js")
	if err != nil {
		t.Fatalf("read diagram-cytoscape.js: %v", err)
	}
	js := string(data)

	// The endpoint port labels must opt out of rotation.
	for _, pin := range []string{
		"'source-text-rotation': 'none'",
		"'target-text-rotation': 'none'",
	} {
		if !strings.Contains(js, pin) {
			t.Errorf("missing %q — port labels must stay horizontal", pin)
		}
	}

	// No labelled EDGE selector may use autorotate. The only permitted
	// 'text-rotation': 'autorotate' is on the single-glyph down-marker (✖),
	// whose orientation is visually irrelevant; every other occurrence would
	// be a text label rotating along the line.
	const bad = "'text-rotation': 'autorotate'"
	count := strings.Count(js, bad)
	glyph := strings.Count(js, "'label': '\\u2716', 'text-rotation': 'autorotate'")
	if count-glyph > 0 {
		t.Errorf("found %d text-label autorotate uses beyond the ✖ down-marker — labels must be horizontal", count-glyph)
	}
}
