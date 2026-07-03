package middleware

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// cspNonceKey is the gin.Context key under which SecureHeaders stores the
// per-request CSP nonce. Exported indirectly via GetCSPNonce / RenderHTML so
// the route handlers and tests don't need to know the literal string.
const cspNonceKey = "csp-nonce"

// maxRateLimiterEntries caps the per-IP table size. AUDIT-083: without a
// cap, an attacker spraying unique source IPs (trivially done from an EC2
// metadata-style address pool or via X-Forwarded-For spoofing when behind
// an untrusted proxy) grows the table to millions of entries and OOMs the
// process. 50,000 entries × ~150 bytes = 7.5 MiB, comfortable headroom for
// any reasonable fleet.
const maxRateLimiterEntries = 50000

type ipRateLimiter struct {
	limiters   map[string]*rateLimiterEntry
	lru        *list.List // doubly-linked LRU: front = most recent, back = oldest
	mu         sync.Mutex
	rate       rate.Limit
	burst      int
	maxEntries int
	quit       chan struct{}
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	ip       string
	elem     *list.Element // pointer to this entry's node in rl.lru
}

func newIPRateLimiter(r rate.Limit, burst int) *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters:   make(map[string]*rateLimiterEntry),
		lru:        list.New(),
		rate:       r,
		burst:      burst,
		maxEntries: maxRateLimiterEntries,
		quit:       make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

func (rl *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if entry, exists := rl.limiters[ip]; exists {
		entry.lastSeen = time.Now()
		rl.lru.MoveToFront(entry.elem)
		return entry.limiter
	}

	// AUDIT-083: cap the map. When full, evict the least-recently-used
	// entry (back of the LRU list) before adding the new one. Single-eviction
	// per insert keeps amortized O(1); the next call from the evicted IP
	// will simply get a fresh limiter (with full burst), which is the
	// "fail-open for an unknown IP" semantics this middleware already had.
	if len(rl.limiters) >= rl.maxEntries {
		if oldest := rl.lru.Back(); oldest != nil {
			oldEntry := oldest.Value.(*rateLimiterEntry)
			delete(rl.limiters, oldEntry.ip)
			rl.lru.Remove(oldest)
		}
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	entry := &rateLimiterEntry{
		limiter:  limiter,
		lastSeen: time.Now(),
		ip:       ip,
	}
	entry.elem = rl.lru.PushFront(entry)
	rl.limiters[ip] = entry
	return limiter
}

func (rl *ipRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			// Walk from back (oldest). Stop on first entry newer than
			// cutoff — LRU order guarantees no older entries remain after it.
			for elem := rl.lru.Back(); elem != nil; {
				entry := elem.Value.(*rateLimiterEntry)
				if entry.lastSeen.After(cutoff) {
					break
				}
				prev := elem.Prev()
				delete(rl.limiters, entry.ip)
				rl.lru.Remove(elem)
				elem = prev
			}
			rl.mu.Unlock()
		case <-rl.quit:
			return
		}
	}
}

// Stop terminates the background cleanup goroutine. AUDIT-083: pre-fix this
// goroutine ran for the lifetime of the process with no shutdown hook. Now
// it respects quit so tests don't leak goroutines and production can release
// the limiter resources at graceful shutdown.
//
// Safe to call once. A second call panics on close-of-closed-channel — by
// design (matches container/list's idiom of "Stop is final").
func (rl *ipRateLimiter) Stop() {
	close(rl.quit)
}

func RateLimiter(cfg *config.Config) gin.HandlerFunc {
	limiter := newIPRateLimiter(rate.Limit(30), 60)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.getLimiter(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func PublicRateLimiter() gin.HandlerFunc {
	limiter := newIPRateLimiter(rate.Limit(60), 120)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.getLimiter(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func LoginRateLimiter() gin.HandlerFunc {
	limiter := newIPRateLimiter(rate.Limit(1), 5) // 1 req/s, burst of 5
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.getLimiter(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many login attempts, please try again later",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func ProbeRateLimiter() gin.HandlerFunc {
	limiter := newIPRateLimiter(rate.Limit(30), 60) // 30 req/s, burst of 60
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.getLimiter(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// TokenAuthStore is the narrow token-resolution dependency of AdminAuth
// (P0-2); *database.Database satisfies it. Mirrors how auth.Database keeps the
// auth package decoupled from the concrete store.
type TokenAuthStore interface {
	LookupAPIToken(plaintext string) (*models.ApiToken, error)
	TouchAPITokenLastUsed(id uint, t time.Time) error
}

// apiTokenScopeRoles maps token scopes onto the RBAC ladder so RequireRole is
// the single enforcement path for sessions AND tokens. An unknown scope maps
// to "" (level 0) and is denied everything — fail closed.
var apiTokenScopeRoles = map[string]string{
	"read":  auth.RoleViewer,
	"write": auth.RoleOperator,
	"admin": auth.RoleAdmin,
}

// APITokenScopeRole resolves a token scope to its effective role ("" for
// unknown). Exported for the token-management handlers to validate scopes.
func APITokenScopeRole(scope string) string { return apiTokenScopeRoles[scope] }

// lastUsedTouches throttles api_tokens.last_used_at writes to at most one per
// token per minute — observability metadata must not write-amplify every
// programmatic API call.
var (
	lastUsedMu      sync.Mutex
	lastUsedTouches = map[uint]time.Time{}
)

func touchTokenLastUsed(tokens TokenAuthStore, id uint) {
	now := time.Now()
	lastUsedMu.Lock()
	if last, ok := lastUsedTouches[id]; ok && now.Sub(last) < time.Minute {
		lastUsedMu.Unlock()
		return
	}
	lastUsedTouches[id] = now
	lastUsedMu.Unlock()
	if err := tokens.TouchAPITokenLastUsed(id, now); err != nil {
		log.Printf("api token %d: failed to record last_used_at: %v", id, err)
	}
}

// AdminAuth authenticates /admin requests by EITHER a scoped API token
// (Authorization: Bearer fwm_…) or the session cookie (JWT). The bearer path
// only intercepts fwm_-prefixed values, so probe keys and any other bearer
// scheme are unaffected. Token failures fail CLOSED (same philosophy as the
// JWT token-version check): a DB error rejects rather than admits.
// auth_method on the context ("token"|"session") lets CSRF and the forced
// password-change gate skip token calls — CSRF defends cookies, and tokens
// have no password to rotate.
func AdminAuth(authManager *auth.AuthManager, tokens TokenAuthStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ah := c.GetHeader("Authorization"); tokens != nil && strings.HasPrefix(ah, "Bearer "+database.APITokenPlaintextPrefix) {
			plaintext := strings.TrimPrefix(ah, "Bearer ")
			tok, err := tokens.LookupAPIToken(plaintext)
			if err != nil || tok == nil ||
				tok.RevokedAt != nil ||
				(tok.ExpiresAt != nil && time.Now().After(*tok.ExpiresAt)) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API token"})
				c.Abort()
				return
			}
			c.Set("username", "token:"+tok.Name)
			c.Set("user_id", tok.CreatedByID)
			c.Set("is_admin", true)
			c.Set("role", APITokenScopeRole(tok.Scope))
			c.Set("auth_method", "token")
			c.Set("token_id", tok.ID)
			touchTokenLastUsed(tokens, tok.ID)
			c.Next()
			return
		}

		token, err := c.Cookie("auth_token")
		if err != nil {
			handleAuthFailure(c)
			return
		}

		claims, err := authManager.ValidateToken(token)
		if err != nil {
			handleAuthFailure(c)
			return
		}

		c.Set("username", claims.Username)
		c.Set("user_id", claims.UserID)
		c.Set("is_admin", true)
		c.Set("role", claims.EffectiveRole())
		c.Set("auth_method", "session")
		c.Next()
	}
}

// CheckAdminAuth checks if user is admin but doesn't require authentication
func CheckAdminAuth(authManager *auth.AuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("auth_token")
		if err != nil {
			c.Set("is_admin", false)
			c.Next()
			return
		}

		claims, err := authManager.ValidateToken(token)
		if err != nil {
			c.Set("is_admin", false)
			c.Next()
			return
		}

		c.Set("username", claims.Username)
		c.Set("user_id", claims.UserID)
		c.Set("is_admin", true)
		c.Set("role", claims.EffectiveRole())
		c.Next()
	}
}

// RequireRole enforces the RBAC ladder on the /admin group (P0-1). It runs
// after AdminAuth (which stores the session's role in context) and mirrors the
// RequirePasswordChanged route-template style: method defaults plus explicit
// route maps, so the ~150 flat route registrations in main.go stay untouched.
//
// Rules, evaluated in order:
//  1. selfServiceRoutes — any authenticated role (password change, logout,
//     CSRF, session/self-info endpoints).
//  2. adminOnlyRoutes — matched on route template regardless of method
//     (settings incl. GET — it exposes credential metadata; user, token, and
//     probe-key management).
//  3. GET/HEAD (and SPA page loads) — viewer and above.
//  4. Any other mutation — operator and above.
//
// Fail-closed: a session with a missing/unknown role gets level 0 and is
// denied everything the maps don't explicitly allow.
func RequireRole(selfServiceRoutes, adminOnlyRoutes map[string]bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		route := c.FullPath()
		if selfServiceRoutes[route] {
			c.Next()
			return
		}
		roleVal, _ := c.Get("role")
		role, _ := roleVal.(string)

		required := auth.RoleOperator
		switch {
		case adminOnlyRoutes[route]:
			required = auth.RoleAdmin
		case c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead:
			required = auth.RoleViewer
		}

		if !auth.RoleAtLeast(role, required) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient role for this action",
				"code":  "insufficient_role",
			})
			return
		}
		c.Next()
	}
}

func handleAuthFailure(c *gin.Context) {
	// API routes get 401 JSON; page routes get redirected
	if strings.HasPrefix(c.Request.URL.Path, "/admin/api/") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
	} else {
		c.Redirect(http.StatusFound, "/admin/login")
	}
	c.Abort()
}

// GenerateCSRFToken creates an HMAC-signed CSRF token tied to the auth token
func GenerateCSRFToken(authToken, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(authToken))
	return hex.EncodeToString(mac.Sum(nil))
}

func CSRFProtection(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// API-token requests carry no cookies, so there is no ambient
		// authority for a cross-site request to ride — CSRF is a cookie-session
		// defense. auth_method is set by AdminAuth earlier in the chain.
		if c.GetString("auth_method") == "token" {
			c.Next()
			return
		}
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" || c.Request.Method == "PATCH" {
			csrfToken := c.GetHeader("X-CSRF-Token")
			if csrfToken == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token missing"})
				c.Abort()
				return
			}

			authToken, err := c.Cookie("auth_token")
			if err != nil || authToken == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Not authenticated"})
				c.Abort()
				return
			}

			secret := ""
			if cfg != nil {
				secret = cfg.Server.JWTSecretKey
			}
			if secret == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Server misconfiguration: JWT_SECRET_KEY not set"})
				c.Abort()
				return
			}

			expected := GenerateCSRFToken(authToken, secret)
			if !hmac.Equal([]byte(csrfToken), []byte(expected)) {
				log.Printf("[CSRF] Token mismatch: got_len=%d expected_len=%d authToken_len=%d",
					len(csrfToken), len(expected), len(authToken))
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token invalid"})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// BodySizeLimit rejects request bodies larger than maxBytes.
func BodySizeLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}

// newCSPNonce returns a fresh base64-encoded 128-bit random nonce. AUDIT-022:
// emitted on every request so the CSP header can list 'nonce-<x>' in place of
// 'unsafe-inline'. 128 bits of entropy is the same strength Cloudflare/AWS use
// for per-request nonces — collision risk is negligible (birthday bound ≈ 2^64
// requests before a 50% chance of a repeat).
//
// base64 (not hex, not raw) keeps the header value short and the inline-attribute
// serialization compatible with Go's html/template attribute escaping.
func newCSPNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail on a healthy OS. If it does, the
		// process is in such a bad state that falling back to a fixed
		// nonce is the least of the operator's problems — and falling
		// back would silently weaken CSP. Log loudly and return an empty
		// string; the route will render with no nonce and the browser
		// will block the inline script (loud failure, not silent).
		log.Printf("[SECURITY] crypto/rand failed in CSP nonce generation: %v", err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// GetCSPNonce returns the per-request CSP nonce that SecureHeaders generated
// for this request, or "" if the middleware didn't run (e.g. the route was
// attached to a router that doesn't use SecureHeaders, or the request is
// being rendered by a code path that bypassed middleware). Exported for
// tests and for any handler that builds HTML by hand.
func GetCSPNonce(c *gin.Context) string {
	if v, ok := c.Get(cspNonceKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// HTMLRenderData is the wrapper that RenderHTML passes to gin.HTML. It carries
// the per-request CSP nonce alongside the caller's payload so templates can
// reference `{{ .Nonce }}` on inline `<script>` and `<style>` tags. The
// embedded `Data` is the user-supplied struct/map (kept under the field name
// `Data` so callers who want to opt in to nonce injection can do so
// explicitly: `RenderHTML(c, code, name, myStruct)`.
type HTMLRenderData struct {
	Data  interface{}
	Nonce string
}

func SecureHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
		c.Header("Pragma", "no-cache")
		// AUDIT-025: deny browser APIs we don't use; admin panel has no
		// reason to access camera, microphone, geolocation, USB, etc.
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=(), accelerometer=(), gyroscope=(), magnetometer=(), midi=(), sync-xhr=()")
		// Only send HSTS over TLS to avoid issues with plain HTTP setups
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// AUDIT-022: per-request nonce replaces 'unsafe-inline' in script-src
		// (the XSS-critical directive). The nonce is generated above, stored on
		// the gin context, and exposed to templates via RenderHTML — every
		// inline <script> tag in web/**/*.html must carry nonce="{{ .Nonce }}",
		// or the browser will refuse to execute it. style-src is NOT nonce-locked
		// (see AUDIT-022b below) because runtime libraries set inline styles.
		nonce := newCSPNonce()
		if nonce != "" {
			c.Set(cspNonceKey, nonce)
		}
		c.Header("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'nonce-"+nonce+"'; "+
				// AUDIT-022b: style-src allows 'unsafe-inline'. The original
				// AUDIT-022 also nonce-locked style-src, but that BROKE the
				// public GridStack dashboard (and any inline-style rendering):
				// GridStack and Chart.js size their widgets/canvases by setting
				// inline `style=""` ATTRIBUTES at runtime, which can't carry a
				// nonce — so every cell collapsed to height 0 and charts fell
				// back to the 300x150 default ("tiny graphs"). Note a nonce on
				// style-src would have made 'unsafe-inline' be IGNORED, so the
				// nonce is dropped here. The XSS-critical directive is script-src,
				// which stays strict (nonce, no unsafe-inline) — inline <script>
				// is still refused. CSS injection (the only thing this re-opens)
				// can't execute JS.
				"style-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"object-src 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")
		c.Next()
	}
}

// RenderHTML is the wrapper around c.HTML that injects the per-request CSP
// nonce (from SecureHeaders) into the template data. Use this from route
// handlers instead of c.HTML directly — the templates assume `{{ .Nonce }}` is
// available.
//
// `data` may be nil; the wrapper still emits a payload that exposes
// `{{ .Nonce }}` correctly. (Go's html/template treats a nil interface in a
// struct field as the zero value, which for a string is "".)
func RenderHTML(c *gin.Context, code int, name string, data interface{}) {
	c.HTML(code, name, HTMLRenderData{Data: data, Nonce: GetCSPNonce(c)})
}

// parseCORSAllowedOrigins parses the comma-separated CORS_ALLOWED_ORIGINS
// env value into a lookup set. AUDIT-015: returns an error if the wildcard
// "*" is present, because this server always sends
// `Access-Control-Allow-Credentials: true` and the combination is forbidden
// by the CORS spec (browsers drop the response) and unsafe (reflecting an
// arbitrary origin while allowing credentials lets any third-party site
// issue authenticated cross-origin requests against the cookie-based
// admin session). Exported for unit-test access.
func parseCORSAllowedOrigins(raw string) (map[string]bool, error) {
	origins := make(map[string]bool)
	if raw == "" {
		return origins, nil
	}
	for _, o := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(o)
		if origin == "" {
			continue
		}
		if origin == "*" {
			return nil, fmt.Errorf("CORS_ALLOWED_ORIGINS contains '*' but this server always sends Access-Control-Allow-Credentials: true; the combination is forbidden by the CORS spec and would let any third-party site issue authenticated cross-origin requests. Set CORS_ALLOWED_ORIGINS to an explicit comma-separated allow-list of scheme+host[:port] origins, or unset it to disable cross-origin entirely")
		}
		origins[origin] = true
	}
	return origins, nil
}

// CORS restricts cross-origin requests. By default only same-origin is allowed.
// Set CORS_ALLOWED_ORIGINS env var to a comma-separated list to allow specific origins.
//
// AUDIT-015: a wildcard "*" entry is REJECTED at startup because this handler
// always sends `Access-Control-Allow-Credentials: true`. See parseCORSAllowedOrigins.
func CORS(cfg *config.Config) gin.HandlerFunc {
	origins, err := parseCORSAllowedOrigins(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}

		// If no specific origins configured, reject all cross-origin requests
		if len(origins) == 0 {
			c.Header("Vary", "Origin")
			c.Next()
			return
		}

		if origins[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Max-Age", "86400")
			c.Header("Vary", "Origin")

			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
		} else {
			// Origin not allowed — don't set CORS headers
			c.Header("Vary", "Origin")
		}

		c.Next()
	}
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		if status >= 400 {
			// AUDIT-076: structured access log for failed requests (was a flat
			// log.Printf). The status splits the level — client 4xx → warn,
			// server 5xx → error — and method/path/status/latency become
			// queryable attributes. AUDIT-135: req carries the per-request
			// X-Request-ID so a logged failure correlates with the
			// X-Request-ID the client/proxy saw. slog stamps its own time, so
			// the manual timestamp is gone.
			reqID, _ := c.Get(RequestIDKey)
			level := slog.LevelWarn
			if status >= 500 {
				level = slog.LevelError
			}
			slog.LogAttrs(c.Request.Context(), level, "http request",
				slog.Any("req", reqID),
				slog.String("method", method),
				slog.String("path", path),
				slog.Int("status", status),
				slog.Duration("latency", latency),
			)
		}
	}
}

// RequestIDKey is the gin context key under which the per-request ID is stored.
const RequestIDKey = "request_id"

// requestIDPattern bounds a trusted inbound X-Request-ID to a safe charset and
// length, so a hostile client can't inject newlines / huge values into the
// logs via the header (log forging).
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// RequestID assigns a stable ID to every request (AUDIT-135). It reuses a
// safe-looking inbound X-Request-ID (so a fronting proxy's trace ID is kept)
// or mints a fresh 128-bit hex one, stores it on the context for downstream
// handlers/loggers, and echoes it in the X-Request-ID response header so a
// single click can be traced end-to-end through the logs.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if !requestIDPattern.MatchString(id) {
			id = newRequestID()
		}
		c.Set(RequestIDKey, id)
		c.Writer.Header().Set("X-Request-ID", id)
		c.Next()
	}
}

// newRequestID returns a random 128-bit hex request ID.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is effectively impossible; fall back to a
		// constant so logging still has something to group on.
		return "req-unknown"
	}
	return hex.EncodeToString(b[:])
}
