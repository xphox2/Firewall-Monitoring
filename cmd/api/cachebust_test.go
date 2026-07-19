package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestStaticCacheBustMiddleware pins the v0.11.124 asset cache-busting: /static
// responses carry Cache-Control:no-cache + a build-version ETag, a matching
// If-None-Match short-circuits to 304, a stale/absent one falls through, a
// version bump changes the ETag, and non-/static paths are untouched.
func TestStaticCacheBustMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouter := func(version string) *gin.Engine {
		r := gin.New()
		r.Use(staticCacheBustMiddleware(version))
		r.GET("/static/js/diagram-cytoscape.js", func(c *gin.Context) { c.String(http.StatusOK, "// js") })
		r.GET("/api/version", func(c *gin.Context) { c.String(http.StatusOK, "v") })
		return r
	}
	r := newRouter("0.11.124")
	wantETag := `"fwmon-0.11.124"`

	// Fresh GET: 200 + headers.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/static/js/diagram-cytoscape.js", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("fresh GET: code %d, want 200", w.Code)
	}
	if got := w.Header().Get("ETag"); got != wantETag {
		t.Errorf("ETag = %q, want %q", got, wantETag)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}

	// Conditional GET with the matching ETag → 304, no body.
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/js/diagram-cytoscape.js", nil)
	req.Header.Set("If-None-Match", wantETag)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotModified {
		t.Errorf("matching If-None-Match: code %d, want 304", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("304 must have empty body, got %q", w.Body.String())
	}

	// Stale ETag (old version) → 200 fresh.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/static/js/diagram-cytoscape.js", nil)
	req.Header.Set("If-None-Match", `"fwmon-0.11.123"`)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("stale If-None-Match must refetch: code %d, want 200", w.Code)
	}

	// A deploy (version bump) changes the ETag → the old conditional misses.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/static/js/diagram-cytoscape.js", nil)
	req.Header.Set("If-None-Match", wantETag) // browser's cached 0.11.124 etag
	newRouter("0.11.125").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("version bump must bust the cache: code %d, want 200", w.Code)
	}
	if got := w.Header().Get("ETag"); got != `"fwmon-0.11.125"` {
		t.Errorf("bumped ETag = %q, want fwmon-0.11.125", got)
	}

	// Non-/static path: no cache headers, no interference.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if w.Header().Get("ETag") != "" || w.Header().Get("Cache-Control") != "" {
		t.Error("non-/static response must not carry the static cache headers")
	}
}
