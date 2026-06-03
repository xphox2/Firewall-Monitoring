package middleware

import (
	"container/list"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

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

func AdminAuth(authManager *auth.AuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
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
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		c.Next()
	}
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
			log.Printf("[%s] %s %s %d %v",
				time.Now().Format("2006-01-02 15:04:05"),
				method,
				path,
				status,
				latency,
			)
		}
	}
}
