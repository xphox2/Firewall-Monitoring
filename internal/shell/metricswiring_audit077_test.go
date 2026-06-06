package shell

import (
	"os"
	"strings"
	"testing"
)

// TestMetricsWiring_AUDIT077 pins that cmd/api/main.go actually wires the
// Prometheus surface — the metrics package can exist but do nothing unless the
// middleware is registered, the /metrics route is served, and the DB pool is
// hooked up. This guard fails if a future edit drops any of the three.
func TestMetricsWiring_AUDIT077(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s (AUDIT-077): %v", path, err)
	}
	body := string(data)

	required := []struct{ needle, why string }{
		{`"firewall-mon/internal/metrics"`, "main must import the metrics package (AUDIT-077)"},
		{"metrics.Middleware()", "the request-latency middleware must be registered (AUDIT-077)"},
		{`"/metrics"`, "the /metrics route must be served (AUDIT-077)"},
		{"metrics.Handler()", "/metrics must be served by the Prometheus handler (AUDIT-077)"},
		{"metrics.RegisterDBPool(", "the DB connection-pool collector must be wired (AUDIT-077)"},
	}
	for _, r := range required {
		if !strings.Contains(body, r.needle) {
			t.Errorf("main.go missing %q: %s", r.needle, r.why)
		}
	}
}
