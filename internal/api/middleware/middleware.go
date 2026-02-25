package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"fortiGate-Mon/internal/auth"
	"fortiGate-Mon/internal/config"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func RateLimiter(cfg *config.Config) gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Limit(10), 20)

	return func(c *gin.Context) {
		if !limiter.Allow() {
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
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		claims, err := authManager.ValidateToken(token)
		if err != nil {
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" {
			csrfToken := c.GetHeader("X-CSRF-Token")
			cookieToken, err := c.Cookie("csrf_token")
			if err != nil || csrfToken == "" || csrfToken != cookieToken {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "CSRF validation failed",
				})
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
				if origin == allowedOrigin || allowedOrigin == "*" {
					allowed = true
					break
				}
			}

			if allowed {
				if allowedOrigins[0] == "*" {
					c.Header("Access-Control-Allow-Origin", "*")
				} else {
					c.Header("Access-Control-Allow-Origin", origin)
				}
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
