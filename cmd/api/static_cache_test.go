package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"firewall-mon/internal/api/middleware"

	"github.com/gin-gonic/gin"
)

// /static used to inherit SecureHeaders' no-store with no validator at all, so
// every admin page load re-downloaded every asset. These run the production
// wiring (SecureHeaders first, then registerStatic) and check that assets
// revalidate — never go stale — while every other response keeps no-store.

func staticRouter(t *testing.T, diskDir string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.SecureHeaders())
	registerStatic(r, diskDir)
	r.GET("/page", func(c *gin.Context) { c.String(http.StatusOK, "html") })
	return r
}

func do(r *gin.Engine, method, url, inm string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, nil)
	if inm != "" {
		req.Header.Set("If-None-Match", inm)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestStaticAssets_ETagAndRevalidate_Embedded(t *testing.T) {
	r := staticRouter(t, filepath.Join(t.TempDir(), "absent")) // forces the embedded tree

	w := do(r, http.MethodGet, "/static/js/admin-main.js", "")
	etag := w.Header().Get("ETag")
	if w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatalf("GET asset = %d (%d bytes)", w.Code, w.Body.Len())
	}
	if len(etag) < 3 || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Fatalf("ETag = %q, want a quoted strong tag (an unquoted one never matches)", etag)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache (revalidate every load)", cc)
	}
	if p := w.Header().Get("Pragma"); p != "" {
		t.Fatalf("Pragma = %q, want none on assets", p)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("the other security headers must still apply to assets")
	}

	for _, m := range []string{http.MethodGet, http.MethodHead} {
		w := do(r, m, "/static/js/admin-main.js", etag)
		if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
			t.Fatalf("%s with If-None-Match = %d (%d bytes), want 304 with no body", m, w.Code, w.Body.Len())
		}
	}
	if w := do(r, http.MethodGet, "/static/js/admin-main.js", `"stale"`); w.Code != http.StatusOK {
		t.Fatalf("a non-matching tag = %d, want the full 200", w.Code)
	}

	for _, u := range []string{"/static/js/no-such-file.js", "/static/js/"} {
		w := do(r, http.MethodGet, u, "")
		if w.Header().Get("ETag") != "" {
			t.Fatalf("%s carries ETag %q; only a regular file may", u, w.Header().Get("ETag"))
		}
	}

	if cc := do(r, http.MethodGet, "/page", "").Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("non-static Cache-Control = %q, must stay no-store", cc)
	}
}

// The on-disk tree exists for hot fixes without a rebuild, so an edited file
// must get a new tag at once — never a 304 for the old content.
func TestStaticAssets_DiskEditChangesETag(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.js")
	if err := os.WriteFile(f, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := staticRouter(t, dir)
	first := do(r, http.MethodGet, "/static/a.js", "").Header().Get("ETag")
	if first == "" {
		t.Fatal("no ETag on a disk asset")
	}
	if err := os.WriteFile(f, []byte("two, longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := do(r, http.MethodGet, "/static/a.js", first)
	if w.Code != http.StatusOK || w.Body.String() != "two, longer" || w.Header().Get("ETag") == first {
		t.Fatalf("after an edit: %d %q etag %q, want 200 with the new body and a new tag", w.Code, w.Body.String(), w.Header().Get("ETag"))
	}
}
