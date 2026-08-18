package handlers

import (
	"os"
	"strings"
	"testing"
)

// TestRequestContextBoundary_AUDIT032 freezes the cancel-vs-durable boundary for
// request-context propagation (AUDIT-032/079). Browser-facing handlers run DB
// queries on the request context via `db := h.reqDB(c)` so a client disconnect
// cancels the query (the dashboard-polling pool-exhaustion fix). The probe
// ingestion path (handlers_data.go) deliberately stays on the durable
// background context (h.db) so a probe's in-flight write over a flaky WAN is
// never cancelled. This guard fails if either side of that boundary drifts.
func TestRequestContextBoundary_AUDIT032(t *testing.T) {
	read := func(name string) string {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(data)
	}

	// The helper itself must bind the request context. reqDB returns the
	// repository interface (database.Store); WithContextStore wraps the concrete
	// WithContext(ctx), so the request-context binding is preserved.
	core := read("handlers.go")
	if !strings.Contains(core, "func (h *Handler) reqDB(c *gin.Context)") ||
		!strings.Contains(core, "h.db.WithContextStore(c.Request.Context())") {
		t.Error("handlers.go must define reqDB(c) returning h.db.WithContextStore(c.Request.Context()) (AUDIT-032).")
	}

	// POSITIVE: every browser-facing handler file routes DB work through reqDB.
	inScope := []string{
		"handlers_dashboard.go", "handlers_devices.go", "handlers_analytics.go",
		"handlers_connections.go", "handlers_alert_policies.go", "handlers_sites.go",
		"handlers_maintenance.go", "handlers_irc.go", "handlers_auth.go",
		"handlers_audit.go", "handlers_probes.go", "handlers_reports.go",
	}
	for _, f := range inScope {
		if !strings.Contains(read(f), "h.reqDB(c)") {
			t.Errorf("%s no longer routes DB calls through h.reqDB(c) (AUDIT-032): browser-facing handlers must use the request-scoped DB.", f)
		}
	}

	// NEGATIVE: probe ingestion must NOT be request-cancellable.
	if strings.Contains(read("handlers_data.go"), "h.reqDB(") {
		t.Error("handlers_data.go uses h.reqDB — probe-ingestion writes must stay on the durable background context (h.db), not the request context (AUDIT-032).")
	}

	// BACKGROUND-STORE ALLOWED: browser-facing, but deliberately NOT on the
	// request context.
	//
	// handlers_health_dashboard.go was simply missing from inScope above, which
	// left the single heaviest browser-facing handler unguarded. It cannot be
	// added there: the positive check requires the file to CONTAIN h.reqDB(c),
	// and this one legitimately never will. Its computation is a global
	// aggregate shared by every client through a background refresher / the
	// singleflight cache, so binding it to one requester's context would let that
	// client's disconnect cancel the work every other client is waiting on — and
	// since ttlCache does not cache errors, the cache would never warm.
	//
	// So the exemption is asserted rather than assumed: these files must use the
	// background store and must NOT reach for reqDB.
	backgroundStoreAllowed := []string{"handlers_health_dashboard.go"}
	for _, f := range backgroundStoreAllowed {
		src := read(f)
		if strings.Contains(src, "h.reqDB(") {
			t.Errorf("%s uses h.reqDB — this file computes shared global aggregates on the background store (h.db) so one client's disconnect cannot cancel work every other client is waiting on (AUDIT-032).", f)
		}
		if !strings.Contains(src, "db := h.db") {
			t.Errorf("%s must compute on the background store (db := h.db); if that changed, revisit whether it belongs in inScope instead (AUDIT-032).", f)
		}
	}
}
