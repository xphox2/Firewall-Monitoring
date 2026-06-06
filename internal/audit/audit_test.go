package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/database"

	"github.com/gin-gonic/gin"
)

// TestAuditMiddleware_AUDIT078 drives requests through the middleware against a
// real (in-memory) DB and asserts: mutations are recorded with actor / route
// template / concrete target / final status, GETs are NOT recorded, and the
// status captured is the one the handler actually returned (incl. failures).
func TestAuditMiddleware_AUDIT078(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := database.NewDatabaseForTesting(t)

	r := gin.New()
	// Stand in for AdminAuth: put the actor on the context, as the real auth
	// middleware does, before the audit middleware runs.
	r.Use(func(c *gin.Context) {
		c.Set("username", "alice")
		c.Set("user_id", uint(7))
		c.Next()
	})
	r.Use(Middleware(db))

	r.GET("/admin/api/devices", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/admin/api/devices", func(c *gin.Context) { c.Status(http.StatusCreated) })
	r.DELETE("/admin/api/devices/:id", func(c *gin.Context) { c.Status(http.StatusInternalServerError) })

	do := func(method, path string) {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
	}
	do(http.MethodGet, "/admin/api/devices")      // not audited
	do(http.MethodPost, "/admin/api/devices")     // audited, 201
	do(http.MethodDelete, "/admin/api/devices/5") // audited, 500 (still recorded)

	logs, total, err := db.GetAuditLogs("", "", time.Time{}, 100, 0)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if total != 2 {
		t.Fatalf("recorded %d audit rows, want 2 (GET must be skipped) — %+v", total, logs)
	}

	// Newest-first: the DELETE was last.
	del := logs[0]
	if del.Method != http.MethodDelete {
		t.Errorf("logs[0].Method = %q, want DELETE", del.Method)
	}
	if del.Action != "/admin/api/devices/:id" {
		t.Errorf("Action = %q, want the route template /admin/api/devices/:id (not the raw path)", del.Action)
	}
	if del.Target != "id=5" {
		t.Errorf("Target = %q, want id=5", del.Target)
	}
	if del.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 — failed mutations must still be recorded", del.Status)
	}
	if del.Actor != "alice" || del.ActorID != 7 {
		t.Errorf("actor = %q/%d, want alice/7", del.Actor, del.ActorID)
	}

	post := logs[1]
	if post.Method != http.MethodPost || post.Status != http.StatusCreated {
		t.Errorf("logs[1] = %s %d, want POST 201", post.Method, post.Status)
	}
}

// TestAuditFilters_AUDIT078 pins the actor / action / since filters used by the
// read endpoint.
func TestAuditFilters_AUDIT078(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := database.NewDatabaseForTesting(t)

	r := gin.New()
	actor := "bob"
	r.Use(func(c *gin.Context) { c.Set("username", actor); c.Set("user_id", uint(1)); c.Next() })
	r.Use(Middleware(db))
	r.POST("/admin/api/sites", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.PUT("/admin/api/devices/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/admin/api/sites", nil))
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/admin/api/devices/9", nil))

	// Filter by action route template.
	logs, total, err := db.GetAuditLogs("", "/admin/api/sites", time.Time{}, 100, 0)
	if err != nil {
		t.Fatalf("GetAuditLogs(action): %v", err)
	}
	if total != 1 || len(logs) != 1 || logs[0].Action != "/admin/api/sites" {
		t.Errorf("action filter returned %d rows, want exactly the /admin/api/sites row", total)
	}

	// Filter by actor returns both.
	_, total, err = db.GetAuditLogs(actor, "", time.Time{}, 100, 0)
	if err != nil {
		t.Fatalf("GetAuditLogs(actor): %v", err)
	}
	if total != 2 {
		t.Errorf("actor filter returned %d rows, want 2", total)
	}

	// A future cutoff returns nothing.
	_, total, err = db.GetAuditLogs("", "", time.Now().Add(time.Hour), 100, 0)
	if err != nil {
		t.Fatalf("GetAuditLogs(since): %v", err)
	}
	if total != 0 {
		t.Errorf("since=+1h returned %d rows, want 0", total)
	}
}
