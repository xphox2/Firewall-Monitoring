package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"fortiGate-Mon/internal/auth"
	"fortiGate-Mon/internal/config"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
	limiters map[string]*rateLimiterEntry
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	stop     chan struct{}
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(r rate.Limit, burst int) *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		rate:     r,
		burst:    burst,
		stop:     make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

func (rl *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[ip] = &rateLimiterEntry{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

func (rl *ipRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			for ip, entry := range rl.limiters {
				if time.Since(entry.lastSeen) > 10*time.Minute {
					delete(rl.limiters, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stop:
			return
		}
	}
}

func RateLimiter(cfg *config.Config) gin.HandlerFunc {
	limiter := newIPRateLimiter(rate.Limit(10), 20)

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
				log.Printf("[CSRF] Token mismatch: got=%q (len=%d) expected=%q (len=%d) authToken_len=%d",
					csrfToken, len(csrfToken), expected, len(expected), len(authToken))
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
		// Only send HSTS over TLS to avoid issues with plain HTTP setups
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
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
