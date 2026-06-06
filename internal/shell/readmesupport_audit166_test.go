package shell

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeSupportChannel_AUDIT166 pins that the README points users at a
// support channel. The audit noted the project ships an IRC bot feature but
// never told its own users where to get help. The resolution is a Support
// section pointing at GitHub Issues (bugs) + Discussions (Q&A), and clarifying
// that the IRC bot is a monitoring feature, not a support channel.
func TestReadmeSupportChannel_AUDIT166(t *testing.T) {
	const path = "../../README.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("README.md not found at %s (AUDIT-166): %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "## Support") {
		t.Error("README has no Support section (AUDIT-166).")
	}
	for _, kw := range []string{"GitHub Issue", "GitHub Discussions"} {
		if !strings.Contains(body, kw) {
			t.Errorf("README Support section does not name %q (AUDIT-166).", kw)
		}
	}
	// It should disambiguate the IRC bot from a support channel.
	if !strings.Contains(body, "IRC bot") || !strings.Contains(body, "not a support channel") {
		t.Error("README should clarify the IRC bot is a monitoring feature, not a support channel (AUDIT-166).")
	}
}
