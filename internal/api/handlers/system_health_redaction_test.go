package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// platformFixture mirrors buildSystemHealth's platform shape: the fields the
// dashboard tiles need (version, runtime, generic host stats) plus the DB
// internals M-13 gates behind admin (pool stats, size, data_directory and the
// derived data_disk_* host block).
func platformFixture() gin.H {
	return gin.H{
		"version":        "test",
		"uptime_seconds": int64(5),
		"runtime":        gin.H{"goroutines": 10},
		"db": gin.H{
			"reachable":      true,
			"pool":           gin.H{"open": 3},
			"size_bytes":     int64(123),
			"data_directory": "/var/lib/postgresql",
		},
		"host": gin.H{
			"cpu_percent":       1.0,
			"data_disk_path":    "/var/lib/postgresql",
			"data_disk_percent": 50.0,
		},
	}
}

// hasDBInternals reports whether a rendered platform block still carries any
// admin-only DB internal. Nested blocks arrive as gin.H (live Go fixtures)
// or plain map[string]interface{} (decoded JSON) — both must work.
func hasDBInternals(plat map[string]interface{}) bool {
	var dbm map[string]interface{}
	switch v := plat["db"].(type) {
	case map[string]interface{}:
		dbm = v
	case gin.H:
		dbm = v
	}
	for _, k := range []string{"pool", "size_bytes", "data_directory"} {
		if _, ok := dbm[k]; ok {
			return true
		}
	}
	var host map[string]interface{}
	switch v := plat["host"].(type) {
	case map[string]interface{}:
		host = v
	case gin.H:
		host = v
	}
	for k := range host {
		if len(k) >= 10 && k[:10] == "data_disk_" {
			return true
		}
	}
	return false
}

// TestRedactPlatformForRole_DropsDBInternals: a non-admin view keeps the
// DB-reachability flag (the dashboard's Database service tile reads it) and
// the generic host stats, but drops the pool stats, the size, the
// data_directory path, and the derived data_disk_* host block. The shared
// snapshot must come through UNTOUCHED — the hub serves it to every role, so
// mutating it would leak the internals back to the next admin request.
func TestRedactPlatformForRole_DropsDBInternals(t *testing.T) {
	snap := platformFixture()

	red := redactPlatformForRole(snap)

	dbm, ok := red["db"].(gin.H)
	if !ok {
		t.Fatalf("redacted platform lost its db block")
	}
	if r, ok := dbm["reachable"].(bool); !ok || !r {
		t.Fatalf("redacted db must keep reachable=true, got %v", dbm)
	}
	for _, forbidden := range []string{"pool", "size_bytes", "data_directory"} {
		if _, has := dbm[forbidden]; has {
			t.Fatalf("redacted db must drop %s, got %v", forbidden, dbm)
		}
	}
	host, ok := red["host"].(gin.H)
	if !ok {
		t.Fatalf("redacted platform lost its host block")
	}
	for k := range host {
		if len(k) >= 10 && k[:10] == "data_disk_" {
			t.Fatalf("redacted host must drop %s, got %v", k, host)
		}
	}
	if host["cpu_percent"] == nil {
		t.Fatalf("generic host stats must survive redaction, got %v", host)
	}
	if red["version"] == nil || red["runtime"] == nil {
		t.Fatalf("version/runtime must survive redaction, got %v", red)
	}

	// The shared snapshot must be untouched — the hub serves it to every role.
	if _, has := snap["db"].(gin.H)["pool"]; !has {
		t.Fatal("redaction mutated the shared snapshot db block")
	}
	if _, has := snap["host"].(gin.H)["data_disk_path"]; !has {
		t.Fatal("redaction mutated the shared snapshot host block")
	}
}

// TestGetDashboardHealth_RedactsDBInternalsByRole drives the real handler
// against an injected hub snapshot (the same technique as the hub tests
// above): viewer and operator requests must not receive the DB internals,
// admin requests must. The typed-nil store means the handler would panic if
// it ever touched the database on this path.
func TestGetDashboardHealth_RedactsDBInternalsByRole(t *testing.T) {
	for role, expectInternals := range map[string]bool{
		"viewer":   false,
		"operator": false,
		"admin":    true,
	} {
		platform := platformFixture()
		h := newHubTestHandler(t)
		h.dashHub.mu.Lock()
		h.dashHub.snap = gin.H{"platform": platform}
		h.dashHub.generatedAt = time.Now()
		h.dashHub.mu.Unlock()

		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/dashboard/health", nil)
		c.Set("role", role)
		h.GetDashboardHealth(c)

		if w.Code != http.StatusOK {
			t.Fatalf("role %s: status = %d, want 200", role, w.Code)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("role %s: decode response: %v (body %q)", role, err, w.Body.String())
		}
		data, _ := body["data"].(map[string]interface{})
		plat, _ := data["platform"].(map[string]interface{})
		if plat == nil {
			t.Fatalf("role %s: no platform block in response: %#v", role, data)
		}
		if got := hasDBInternals(plat); got != expectInternals {
			t.Fatalf("role %s: DB internals present=%v, want %v (platform %#v)", role, got, expectInternals, plat)
		}
		// Redaction must never mutate what the hub still holds: after a
		// viewer request, the snapshot's own platform block keeps everything.
		if !hasDBInternals(platform) {
			t.Fatalf("role %s: the handler mutated the shared snapshot", role)
		}
	}
}
