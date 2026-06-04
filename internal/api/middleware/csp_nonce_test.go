package middleware

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestSecureHeaders_CSPNoLongerAllowsUnsafeInline_AUDIT022 is the headline
// regression: the AUDIT-022 finding noted that the previous CSP used
// `'unsafe-inline'` for script-src and style-src, which provides no XSS
// defense-in-depth. The fix replaces it with per-request nonces. This test
// guards the *header shape* — independent of the route layer — so a future
// refactor can't quietly re-add the wildcard without breaking a test.
func TestSecureHeaders_CSPNoLongerAllowsUnsafeInline_AUDIT022(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecureHeaders())
	r.GET("/probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	r.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}
	// script-src is the XSS-critical directive: it MUST carry a per-request
	// nonce and MUST NOT allow 'unsafe-inline' — no inline <script> may run.
	scriptSrc := extractDirective(t, csp, "script-src")
	if !strings.Contains(scriptSrc, "'nonce-") {
		t.Errorf("script-src must carry a nonce; got: %s", scriptSrc)
	}
	if strings.Contains(scriptSrc, "'unsafe-inline'") {
		t.Errorf("script-src must NOT contain 'unsafe-inline' (AUDIT-022); got: %s", scriptSrc)
	}
	if extractNonce(scriptSrc) == "" {
		t.Errorf("could not extract a nonce from script-src=%q", scriptSrc)
	}
	// style-src allows 'unsafe-inline' (AUDIT-022b): GridStack and Chart.js
	// size their widgets/canvases by setting inline style ATTRIBUTES at runtime
	// (which can't carry a nonce) — nonce-locking style-src collapsed every
	// dashboard widget to height 0. A nonce on style-src would make
	// 'unsafe-inline' be ignored, so style-src must NOT carry one. CSS injection
	// (the only thing this re-opens) cannot execute JS, so the XSS posture is
	// unchanged — script-src above is what matters.
	styleSrc := extractDirective(t, csp, "style-src")
	if !strings.Contains(styleSrc, "'unsafe-inline'") {
		t.Errorf("style-src must allow 'unsafe-inline' so runtime libraries (GridStack/Chart.js) can size widgets (AUDIT-022b); got: %s", styleSrc)
	}
	if strings.Contains(styleSrc, "'nonce-") {
		t.Errorf("style-src must NOT carry a nonce — it silently disables the 'unsafe-inline' allowance (AUDIT-022b); got: %s", styleSrc)
	}
}

// TestSecureHeaders_NonceIsFreshPerRequest — the nonce must rotate every
// request, otherwise an attacker who can predict or replay one nonce (e.g. via
// a cached response) can use it to authorize injected inline content in a
// later request. Two sequential requests must produce different nonces.
func TestSecureHeaders_NonceIsFreshPerRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecureHeaders())
	r.GET("/probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	const N = 5
	seen := make(map[string]bool, N)
	for i := 0; i < N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/probe", nil)
		r.ServeHTTP(w, req)
		csp := w.Header().Get("Content-Security-Policy")
		nonce := extractNonce(extractDirective(t, csp, "script-src"))
		if nonce == "" {
			t.Fatalf("iter %d: empty nonce in CSP %q", i, csp)
		}
		if seen[nonce] {
			t.Errorf("iter %d: nonce %q was reused (collision in %d requests)", i, nonce, N)
		}
		seen[nonce] = true
	}
}

// TestSecureHeaders_OtherHeadersPreserved_AUDIT022 — AUDIT-022 was scoped to
// dropping 'unsafe-inline'. The other security headers (X-Content-Type-Options,
// X-Frame-Options, Permissions-Policy) were already in place from AUDIT-025 and
// must not be disturbed by this change.
func TestSecureHeaders_OtherHeadersPreserved_AUDIT022(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecureHeaders())
	r.GET("/probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	r.ServeHTTP(w, req)

	expectations := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Permissions-Policy":      "camera=()",
		"X-XSS-Protection":        "1; mode=block",
		"Content-Security-Policy": "default-src 'self'",
	}
	for h, want := range expectations {
		got := w.Header().Get(h)
		if !strings.Contains(got, want) {
			t.Errorf("header %q missing expected fragment %q; got: %q", h, want, got)
		}
	}
}

// TestGetCSPNonce_ReturnsStoredValue — the helper that the route layer uses
// to retrieve the per-request nonce for template data injection.
func TestGetCSPNonce_ReturnsStoredValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	const want = "test-nonce-abc123"
	r.Use(func(c *gin.Context) {
		c.Set(cspNonceKey, want)
		c.Next()
	})
	r.GET("/probe", func(c *gin.Context) {
		got := GetCSPNonce(c)
		if got != want {
			t.Errorf("GetCSPNonce returned %q, want %q", got, want)
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestGetCSPNonce_MissingReturnsEmpty — if the middleware that stores the
// nonce didn't run (e.g. a test handler, or a route attached to a router that
// doesn't use SecureHeaders), GetCSPNonce must return "" rather than panic.
func TestGetCSPNonce_MissingReturnsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := GetCSPNonce(c); got != "" {
		t.Errorf("GetCSPNonce on empty context returned %q, want \"\"", got)
	}
}

// TestRenderHTML_InjectsNonceIntoTemplateData — the wrapper around c.HTML
// that route handlers use. It must surface `{{ .Nonce }}` correctly so
// templates can stamp the nonce onto inline <script> / <style> tags.
func TestRenderHTML_InjectsNonceIntoTemplateData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tpl := template.Must(template.New("test").Parse(
		`script-src-NONCE-{{ .Nonce}}-END
style-src-NONCE-{{ .Nonce}}-END
data-{{ .Data.Foo}}-END`))

	r := gin.New()
	// SetHTMLTemplate is the same plumbing LoadHTMLGlob uses, just bypassing
	// the filesystem so this test is hermetic.
	r.SetHTMLTemplate(tpl)
	r.Use(func(c *gin.Context) {
		c.Set(cspNonceKey, "FIXED-NONCE-XYZ")
		c.Next()
	})
	r.GET("/probe", func(c *gin.Context) {
		RenderHTML(c, http.StatusOK, "test", struct{ Foo string }{Foo: "bar"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	r.ServeHTTP(w, req)

	body := w.Body.String()
	for _, want := range []string{
		"script-src-NONCE-FIXED-NONCE-XYZ-END",
		"style-src-NONCE-FIXED-NONCE-XYZ-END",
		"data-bar-END",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; got: %s", want, body)
		}
	}
}

// TestRenderHTML_NilDataStillExposesNonce — the existing route handlers all
// pass nil as the template data (none of the HTML files reference any data
// fields). RenderHTML must still emit `{{ .Nonce }}` correctly when data is
// nil — otherwise every existing route would start rendering empty nonces
// and the browser would block all inline scripts.
func TestRenderHTML_NilDataStillExposesNonce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tpl := template.Must(template.New("test").Parse(`NONCE-{{ .Nonce}}-END`))

	r := gin.New()
	r.SetHTMLTemplate(tpl)
	r.Use(func(c *gin.Context) {
		c.Set(cspNonceKey, "NIL-DATA-OK")
		c.Next()
	})
	r.GET("/probe", func(c *gin.Context) {
		RenderHTML(c, http.StatusOK, "test", nil)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "NONCE-NIL-DATA-OK-END") {
		t.Errorf("nil-data render did not surface .Nonce; got: %s", body)
	}
}

// TestNewCSPNonce_FormatAndEntropy — the nonce generator must:
//  1. Return a non-empty string.
//  2. Be a valid base64 string (round-trips through the decoder).
//  3. Decode to 16 bytes (128 bits of entropy).
//  4. Use the standard base64 alphabet (with padding), so it can be embedded
//     in a CSP header and an HTML attribute without escaping.
func TestNewCSPNonce_FormatAndEntropy(t *testing.T) {
	for i := 0; i < 100; i++ {
		nonce := newCSPNonce()
		if nonce == "" {
			t.Fatalf("iter %d: newCSPNonce returned empty string", i)
		}
		decoded, err := base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			t.Fatalf("iter %d: nonce %q is not valid base64: %v", i, nonce, err)
		}
		if got, want := len(decoded), 16; got != want {
			t.Errorf("iter %d: decoded nonce length = %d, want %d (128 bits)", i, got, want)
		}
	}
}

// TestNewCSPNonce_ConcurrentSafe — the nonce generator pulls from
// crypto/rand, which is goroutine-safe, but we exercise the property
// explicitly. Any future change that adds a shared mutable state (e.g. a
// counter) would surface as a race / duplicate here.
func TestNewCSPNonce_ConcurrentSafe(t *testing.T) {
	const N = 200
	var wg sync.WaitGroup
	out := make(chan string, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out <- newCSPNonce()
		}()
	}
	wg.Wait()
	close(out)
	seen := make(map[string]bool, N)
	for s := range out {
		if seen[s] {
			t.Errorf("concurrent run produced duplicate nonce %q", s)
		}
		seen[s] = true
	}
	if len(seen) != N {
		t.Errorf("len(seen) = %d, want %d (one unique nonce per goroutine)", len(seen), N)
	}
}

// TestSecureHeaders_CSPHasAllExpectedDirectives — the CSP must still list
// the other directives that were there before AUDIT-022 (default-src,
// connect-src, img-src, object-src 'none', base-uri 'self', form-action
// 'self', frame-ancestors 'none'). The audit was scoped to dropping
// 'unsafe-inline' from script-src + style-src, nothing else.
func TestSecureHeaders_CSPHasAllExpectedDirectives(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecureHeaders())
	r.GET("/probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	r.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	mustContain := []string{
		"default-src 'self'",
		"connect-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}
	for _, fragment := range mustContain {
		if !strings.Contains(csp, fragment) {
			t.Errorf("CSP missing expected fragment %q; full CSP: %s", fragment, csp)
		}
	}
}

// TestSecureHeaders_HSTSOnlyOnTLS — pre-existing behavior. AUDIT-022 didn't
// touch it, but the regression suite should confirm we didn't accidentally
// start sending HSTS over plain HTTP.
func TestSecureHeaders_HSTSOnlyOnTLS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecureHeaders())
	r.GET("/probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	// httptest.NewRequest does not set req.TLS.
	r.ServeHTTP(w, req)
	if h := w.Header().Get("Strict-Transport-Security"); h != "" {
		t.Errorf("HSTS sent over plain HTTP: %q", h)
	}
}

// --- helpers ---

// nonceRe matches the `'nonce-<value>'` form inside a CSP directive value.
var nonceRe = regexp.MustCompile(`'nonce-([^']+)'`)

func extractNonce(directiveValue string) string {
	m := nonceRe.FindStringSubmatch(directiveValue)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// extractDirective finds a directive in a CSP header by name and returns the
// trailing list of source expressions. Fails the test if the directive is
// missing (which would mask the actual assertion failures downstream).
func extractDirective(t *testing.T, csp, name string) string {
	t.Helper()
	for _, raw := range strings.Split(csp, ";") {
		raw = strings.TrimSpace(raw)
		// Each directive is "<name> <value list>".
		idx := strings.IndexByte(raw, ' ')
		if idx < 0 {
			continue
		}
		if raw[:idx] == name {
			return raw[idx+1:]
		}
	}
	t.Fatalf("CSP missing directive %q; full CSP: %s", name, csp)
	return ""
}
