package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestMetricsMiddlewareAndHandler_AUDIT077 drives a request through the
// middleware and then scrapes the exposition, proving (1) the HTTP histogram is
// recorded under the matched route template, (2) an unmatched path collapses to
// a single `unmatched` series instead of leaking the raw path, and (3) the
// default Go runtime collectors ride along on /metrics.
func TestMetricsMiddlewareAndHandler_AUDIT077(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Middleware())
	r.GET("/ping", func(c *gin.Context) { c.String(200, "ok") })

	// A matched route and a 404 (no route).
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/ping", nil))
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/no-such-path-7731", nil))

	// Scrape the exposition.
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatalf("/metrics returned %d, want 200", w.Code)
	}
	body := w.Body.String()

	checks := []struct{ needle, why string }{
		{"fwmon_http_request_duration_seconds", "the HTTP latency histogram must be exposed (AUDIT-077)"},
		{`route="/ping"`, "a matched request must be labelled by its route template (AUDIT-077)"},
		{`route="unmatched"`, "a 404 must collapse to route=\"unmatched\", not leak the raw path (AUDIT-077)"},
		{"go_goroutines", "the default Go runtime collectors must ride along on /metrics (AUDIT-077)"},
	}
	for _, c := range checks {
		if !strings.Contains(body, c.needle) {
			t.Errorf("/metrics output missing %q: %s", c.needle, c.why)
		}
	}

	// The raw probe path must NOT appear as a label (cardinality guard).
	if strings.Contains(body, "no-such-path-7731") {
		t.Error("/metrics leaked a raw unmatched path into a label (AUDIT-077): cardinality blows up under scanning.")
	}
}

// TestRegisterDBPoolNilSafe_AUDIT077 pins that wiring the pool collector is a
// no-op (not a panic) when the *sql.DB handle is unavailable — main.go only
// registers it when db.Gorm().DB() succeeds, but the helper must be safe either
// way.
func TestRegisterDBPoolNilSafe_AUDIT077(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RegisterDBPool(nil) panicked (AUDIT-077): %v", r)
		}
	}()
	RegisterDBPool(nil, "test")
}
