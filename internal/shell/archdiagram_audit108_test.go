package shell

import (
	"os"
	"strings"
	"testing"
)

// TestArchitectureDiagram_AUDIT108 pins that docs/architecture.md exists with
// real Mermaid diagrams (a component flowchart + the three sequence diagrams
// the audit named: probe registration, poll cycle, alert firing) and is
// linked from the README. The pre-fix README had only an ASCII directory
// tree, not a data-flow diagram.
func TestArchitectureDiagram_AUDIT108(t *testing.T) {
	const path = "../../docs/architecture.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("docs/architecture.md not found (AUDIT-108): %v", err)
	}
	body := string(data)

	// At least one flowchart + sequence diagrams.
	if !strings.Contains(body, "```mermaid") {
		t.Error("docs/architecture.md has no Mermaid diagram (AUDIT-108).")
	}
	if strings.Count(body, "sequenceDiagram") < 3 {
		t.Errorf("docs/architecture.md has %d sequence diagrams, want >= 3 (probe registration, poll cycle, alert firing) (AUDIT-108).", strings.Count(body, "sequenceDiagram"))
	}
	lower := strings.ToLower(body)
	for _, topic := range []string{"registration", "poll cycle", "alert"} {
		if !strings.Contains(lower, topic) {
			t.Errorf("docs/architecture.md does not cover %q (AUDIT-108).", topic)
		}
	}

	readme, err := os.ReadFile("../../README.md")
	if err == nil && !strings.Contains(string(readme), "docs/architecture.md") {
		t.Error("README.md does not link docs/architecture.md (AUDIT-108).")
	}
}
