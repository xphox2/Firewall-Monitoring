package shell

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeDocumentsEndpoints_AUDIT106 pins that the README no longer documents
// only ~12 of the ~170 registered routes. The audit found the README silently
// omitted whole route families (sites, probes, syslog, flows, maintenance,
// alert-policies, reports, network, and all probe-ingestion POSTs) and lacked
// the audience/positioning sections a public project needs. This guard fails if
// a future edit drops those families or the positioning sections.
func TestReadmeDocumentsEndpoints_AUDIT106(t *testing.T) {
	const path = "../../README.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("README.md not found at %s (AUDIT-106): %v", path, err)
	}
	body := string(data)

	// Route families the audit said were missing.
	families := []string{
		"/admin/api", "/sites", "/probes", "/syslog", "/flows",
		"/maintenance-windows", "/alert-policies", "/reports/send",
		"/api/probes", "config-revision",
	}
	for _, f := range families {
		if !strings.Contains(body, f) {
			t.Errorf("README no longer documents the %q route family (AUDIT-106).", f)
		}
	}

	// Positioning sections the audit asked for.
	sections := []string{
		"## Who is this for",
		"## When NOT to use this",
		"## How it compares",
	}
	for _, s := range sections {
		if !strings.Contains(body, s) {
			t.Errorf("README is missing the %q section (AUDIT-106).", s)
		}
	}

	// The comparison should actually name the alternatives the audit listed.
	for _, tool := range []string{"PRTG", "Nagios", "Zabbix", "LibreNMS", "Checkmk", "Uptime Kuma", "StatusCake"} {
		if !strings.Contains(body, tool) {
			t.Errorf("README comparison does not mention %q (AUDIT-106).", tool)
		}
	}
}
