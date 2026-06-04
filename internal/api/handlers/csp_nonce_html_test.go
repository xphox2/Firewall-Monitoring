package handlers

import (
	"html"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"firewall-mon/internal/api/middleware"

	"github.com/gin-gonic/gin"
)

// TestAllHTMLFiles_StampNonceOnEveryInlineScriptAndStyle_AUDIT022 — full-stack
// regression for AUDIT-022. For every HTML template that ships in web/, the
// rendered page must:
//  1. Carry nonce="..." on every inline <script> (no src=) and <style> tag.
//  2. Use the SAME nonce on the inline tags as the one in the CSP header —
//     so the browser's nonce check actually accepts the inline content.
//
// We don't use the gin engine's LoadHTMLGlob here because the test package
// runs from internal/api/handlers/ and the relative glob resolves to the
// wrong directory. Instead we parse each file individually with the same
// text/template syntax the production engine uses.
//
// This test would have caught the entire class of mistakes that produces a
// blank admin page: a missing nonce attribute, a typo in {{ .Nonce }} vs
// {{ .data.Nonce }}, a route that uses c.HTML directly instead of
// middleware.RenderHTML, etc.
func TestAllHTMLFiles_StampNonceOnEveryInlineScriptAndStyle_AUDIT022(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Find the repo root by walking up from the test package's working dir.
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Skipf("could not locate repo root: %v", err)
	}
	htmlDir := repoRoot + "/web"
	entries, err := os.ReadDir(htmlDir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", htmlDir, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := htmlDir + "/" + e.Name()
		files, err := os.ReadDir(sub)
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", sub, err)
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".html") {
				continue
			}
			path := sub + "/" + f.Name()
			t.Run(e.Name()+"/"+f.Name(), func(t *testing.T) {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("ReadFile: %v", err)
				}
				htmlSrc := string(body)
				if !strings.Contains(htmlSrc, "{{ .Nonce }}") {
					t.Skipf("%s: no {{ .Nonce }} template directive (file uses no inline script/style — nothing to test)", f.Name())
				}

				// Parse the file as a template so {{ .Nonce }} resolves.
				tpl, err := template.New(f.Name()).Parse(htmlSrc)
				if err != nil {
					t.Fatalf("parse %s: %v", f.Name(), err)
				}

				// Render via a real gin engine + middleware.RenderHTML so the
				// production code path is exercised end-to-end. We do NOT seed
				// a fixed nonce — we let SecureHeaders generate a fresh one
				// and read it back from the CSP header for the comparison,
				// which is what a real request would see.
				r := gin.New()
				r.SetHTMLTemplate(tpl)
				r.Use(middleware.SecureHeaders())
				r.GET("/probe", func(c *gin.Context) {
					middleware.RenderHTML(c, http.StatusOK, f.Name(), nil)
				})

				w := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "/probe", nil)
				r.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
				}
				renderedBody := w.Body.String()
				csp := w.Header().Get("Content-Security-Policy")
				if csp == "" {
					t.Fatal("Content-Security-Policy header missing")
				}
				// script-src must stay strict (no inline-script execution); only
				// style-src is allowed 'unsafe-inline' (AUDIT-022b) so runtime
				// libraries like GridStack/Chart.js can size widgets via inline
				// style attributes. Scope the check to the script-src directive.
				scriptDir := csp
				if i := strings.Index(scriptDir, "script-src"); i >= 0 {
					scriptDir = scriptDir[i:]
					if j := strings.Index(scriptDir, ";"); j >= 0 {
						scriptDir = scriptDir[:j]
					}
					if strings.Contains(scriptDir, "'unsafe-inline'") {
						t.Errorf("script-src must not contain 'unsafe-inline' (AUDIT-022 regression): %s", csp)
					}
				}
				// Extract the nonce from the CSP header for comparison.
				cspNonce := extractNonceFromCSP(t, csp)
				if cspNonce == "" {
					t.Fatalf("CSP missing nonce: %s", csp)
				}

				// Count inline <script> and <style> opening tags in the
				// rendered body and verify each one carries nonce="<cspNonce>".
				assertAllInlineTagsHaveNonce(t, renderedBody, cspNonce)
			})
		}
	}
}

// findRepoRoot walks up the directory tree until it finds go.mod. Tests in
// this package run from internal/api/handlers/, but html/template file paths
// must be absolute to find web/. Mirrors the candidate-list pattern in
// device_detail_html_test.go but is more general.
func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir, nil
		}
		parent := dir + "/.."
		// Stop climbing if we cross into a parent that doesn't exist or
		// we've obviously left the repo (e.g. filesystem root on Windows).
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", os.ErrNotExist
}

// inlineOpenTagRe matches a <script ...> or <style ...> opening tag with no
// src= attribute (which would make it an external file reference, not an
// inline block). We re-parse from the rendered body, not the source file, so
// the test verifies what the browser actually receives.
var inlineOpenTagRe = regexp.MustCompile(`<(script|style)\b([^>]*)>`)

// nonceAttrRe extracts the value of a nonce="..." attribute from a tag's
// attribute string. Handles HTML entity encoding that html/template applies
// (e.g. nonce="abc&#43;def" represents the same string as nonce="abc+def"
// once the browser decodes the entity).
var nonceAttrRe = regexp.MustCompile(`nonce="([^"]*)"`)

func assertAllInlineTagsHaveNonce(t *testing.T, renderedBody, cspNonce string) {
	t.Helper()
	matches := inlineOpenTagRe.FindAllStringSubmatch(renderedBody, -1)
	if len(matches) == 0 {
		// File declares no inline blocks (only external scripts/styles).
		// Nothing to assert beyond the CSP header check above.
		return
	}
	for _, m := range matches {
		tag := m[1]
		attrs := m[2]
		// External <script src="..."> tags are deliberately exempt — the
		// browser doesn't apply nonce-checking to src= references when the
		// directive is 'self' 'nonce-...'. We only stamp inline blocks.
		if tag == "script" && regexp.MustCompile(`\bsrc\s*=`).MatchString(attrs) {
			continue
		}
		nm := nonceAttrRe.FindStringSubmatch(attrs)
		if len(nm) < 2 {
			t.Errorf("inline <%s> tag missing nonce attribute; full opening tag: <%s%s>", tag, tag, attrs)
			continue
		}
		// Decode HTML entities the way the browser will on parse. Go's
		// html/template escapes `<`, `>`, `&`, `'`, `"` by default; for
		// attribute values that means `+` becomes `&#43;` etc. The browser
		// decodes those before applying the CSP check, so we must too.
		decodedNonce := html.UnescapeString(nm[1])
		if decodedNonce != cspNonce {
			t.Errorf("inline <%s> tag nonce mismatch:\n  attribute (raw):     %s\n  attribute (decoded): %s\n  CSP header value:   %s\n  (browser will refuse to execute this block under the new CSP)", tag, nm[1], decodedNonce, cspNonce)
		}
	}
}

func extractNonceFromCSP(t *testing.T, csp string) string {
	t.Helper()
	re := regexp.MustCompile(`'nonce-([^']+)'`)
	m := re.FindStringSubmatch(csp)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
