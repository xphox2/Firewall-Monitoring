package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDevicePurgeRoutesAdminOnly pins the v0.11.243 permanent-purge wiring in
// cmd/api/main.go: all five routes are registered under the admin group, every
// one of their templates is listed in adminOnlyRoutes (RequireRole keys on
// c.FullPath(); an unlisted GET would fall to viewer and an unlisted POST to
// operator), and the login rate limiter sits on the POST purge ONLY — it is
// the one route that re-verifies a password; cancel/status/estimate/list
// carry no credential and must not share a bucket with login attempts.
// Same wiring-guard pattern as TestRevealSecretRouteAdminOnly.
func TestDevicePurgeRoutesAdminOnly(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s: %v", path, err)
	}
	body := string(data)

	// Registrations, with the rate limiter exactly where it belongs.
	registrations := map[string]bool{ // line fragment → must carry LoginRateLimiter
		`admin.POST("/api/devices/:id/purge", middleware.LoginRateLimiter(), handler.PurgeDevice)`: true,
		`admin.POST("/api/devices/:id/purge/cancel", handler.CancelDevicePurge)`:                   false,
		`admin.GET("/api/devices/:id/purge", handler.GetDevicePurge)`:                              false,
		`admin.GET("/api/devices/:id/purge/estimate", handler.EstimateDevicePurge)`:                false,
		`admin.GET("/api/purge-jobs", handler.ListPurgeJobs)`:                                      false,
	}
	for line := range registrations {
		if !strings.Contains(body, line) {
			t.Errorf("main.go missing route registration %s", line)
		}
	}
	limited := 0
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, "purge") && strings.Contains(l, "middleware.LoginRateLimiter()") {
			limited++
			if !strings.Contains(l, `"/api/devices/:id/purge"`) || !strings.Contains(l, "handler.PurgeDevice") {
				t.Errorf("LoginRateLimiter on a purge route other than POST purge: %s", strings.TrimSpace(l))
			}
		}
	}
	if limited != 1 {
		t.Errorf("LoginRateLimiter appears on %d purge route lines, want exactly 1 (the POST purge)", limited)
	}

	// adminOnlyRoutes lists every template (scoped to the literal so a
	// registration line elsewhere can't satisfy the assertion).
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatalf("adminOnlyRoutes map comment marker not found in main.go")
	}
	end := strings.Index(body[start:], "))")
	if end < 0 {
		t.Fatalf("end of RequireRole registration not found in main.go")
	}
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")
	for _, route := range []string{
		"/admin/api/devices/:id/purge",
		"/admin/api/devices/:id/purge/cancel",
		"/admin/api/devices/:id/purge/estimate",
		"/admin/api/purge-jobs",
	} {
		if !strings.Contains(adminOnly, `"`+route+`":true`) {
			t.Errorf("adminOnlyRoutes in main.go missing %s — every purge route must stay admin-only", route)
		}
	}

	// The worker only runs on the singleton primary.
	if !strings.Contains(body, `logging.SafeGo("device-purge"`) {
		t.Error("main.go does not start the device-purge worker goroutine")
	}
	if !strings.Contains(body, "database.NewDevicePurgeWorker(db)") {
		t.Error("main.go does not construct the DevicePurgeWorker on the background *Database")
	}
	workerAt := strings.Index(body, `logging.SafeGo("device-purge"`)
	guardAt := strings.LastIndex(body[:workerAt], "if isPrimary {")
	if workerAt < 0 || guardAt < 0 || workerAt-guardAt > 400 {
		t.Error("device-purge worker start is not guarded by `if isPrimary {` — a follower must never run purges")
	}
}
