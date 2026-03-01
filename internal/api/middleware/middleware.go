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
	for {
		time.Sleep(5 * time.Minute)
		rl.mu.Lock()
		for ip, entry := range rl.limiters {
			if time.Since(entry.lastSeen) > 10*time.Minute {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
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
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF validation failed"})
				c.Abort()
				return
			}

			authToken, err := c.Cookie("auth_token")
			if err != nil || authToken == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF validation failed"})
				c.Abort()
				return
			}

			secret := ""
			if cfg != nil {
				secret = cfg.Server.JWTSecretKey
			}
			if secret == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF validation failed"})
				c.Abort()
				return
			}

			expected := GenerateCSRFToken(authToken, secret)
			if !hmac.Equal([]byte(csrfToken), []byte(expected)) {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF validation failed"})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

func SecureHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
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

func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if origin != "" {
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin {
					allowed = true
					break
				}
			}

			if allowed {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func GetRealIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		realIP := c.Request.Header.Get("X-Real-IP")
		if realIP == "" {
			forwarded := c.Request.Header.Get("X-Forwarded-For")
			if forwarded != "" {
				ips := strings.Split(forwarded, ",")
				realIP = strings.TrimSpace(ips[0])
			}
		}
		if realIP == "" {
			realIP = c.ClientIP()
		}
		c.Set("real_ip", realIP)
		c.Next()
	}
}
