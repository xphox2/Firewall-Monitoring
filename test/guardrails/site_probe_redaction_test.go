package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestGetSiteRedactsProbes pins that GET /admin/api/sites/:id redacts the
// preloaded Site.Probes before responding. db.GetSite preloads Probes
// (registration-key hash, TLS cert/key paths + material), and the route is
// reachable by the viewer role, so the redaction must live in the handler — not
// only in an admin-only caller. Regression here leaks probe secrets to viewers.
func TestGetSiteRedactsProbes(t *testing.T) {
	data, err := os.ReadFile("../../internal/api/handlers/handlers_sites.go")
	if err != nil {
		t.Skipf("handlers_sites.go not found: %v", err)
	}
	if !strings.Contains(string(data), "httputil.RedactProbes(site.Probes)") {
		t.Error("GetSite must call httputil.RedactProbes(site.Probes) before returning — the route is viewer-reachable and GetSite preloads Probes with registration-key + TLS material.")
	}
}
