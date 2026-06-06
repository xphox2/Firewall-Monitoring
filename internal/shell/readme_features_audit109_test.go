package shell

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeFeatureListCurrent_AUDIT109 pins that the README Features list
// reflects the shipped feature set. The audit flagged it as stale — it
// omitted reports, sites, alert policies, maintenance windows, the IRC bot,
// the connection map, sFlow/syslog/ICMP collection, and the multi-tenant
// probe architecture. This guards against the list silently rotting again
// by requiring a keyword for each major subsystem.
func TestReadmeFeatureListCurrent_AUDIT109(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Skipf("README.md not found; err: %v", err)
	}
	// Only inspect the Features section so an incidental mention elsewhere
	// doesn't satisfy the check.
	body := string(data)
	start := strings.Index(body, "## Features")
	if start < 0 {
		t.Fatal("README.md has no `## Features` section (AUDIT-109).")
	}
	rest := body[start+len("## Features"):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	features := strings.ToLower(rest)

	for _, kw := range []string{"report", "site", "alert polic", "maintenance window", "irc", "probe", "sflow", "syslog"} {
		if !strings.Contains(features, kw) {
			t.Errorf("README Features section does not mention %q (AUDIT-109): the list must reflect the shipped feature set.", kw)
		}
	}
}
