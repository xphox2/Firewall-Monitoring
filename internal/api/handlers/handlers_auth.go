package handlers

import (
	"log"
	"net/http"
	"strings"
	"time"

	"firewall-mon/internal/api/middleware"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// parseSameSite converts a config string to an http.SameSite constant.
func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func (h *Handler) Login(c *gin.Context) {
	db := h.reqDB(c)
	if h.authManager == nil {
		httputil.InternalError(c, "Authentication not configured", nil)
		return
	}

	var creds struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	// Reject oversized passwords to prevent bcrypt CPU exhaustion DoS
	if len(creds.Password) > 1024 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid credentials"))
		return
	}

	// Reject oversized usernames to prevent map/DB bloat
	if len(creds.Username) > 255 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid credentials"))
		return
	}

	ip := c.ClientIP()
	userAgent := c.Request.UserAgent()
	// Truncate user agent to prevent stored XSS and DB bloat
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}

	if err := h.authManager.ValidateCredentials(creds.Username, creds.Password, ip); err != nil {
		if db != nil {
			if dbErr := db.SaveLoginAttempt(&models.LoginAttempt{
				Timestamp: time.Now(),
				Username:  creds.Username,
				IPAddress: ip,
				Success:   false,
				UserAgent: userAgent,
			}); dbErr != nil {
				log.Printf("Failed to save login attempt: %v", dbErr)
			}
		}
		if err == auth.ErrAccountLocked {
			c.JSON(http.StatusTooManyRequests, models.ErrorResponse("Account temporarily locked due to too many failed attempts"))
			return
		}
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Invalid credentials"))
		return
	}

	if db != nil {
		if dbErr := db.SaveLoginAttempt(&models.LoginAttempt{
			Timestamp: time.Now(),
			Username:  creds.Username,
			IPAddress: ip,
			Success:   true,
			UserAgent: userAgent,
		}); dbErr != nil {
			log.Printf("Failed to save login attempt: %v", dbErr)
		}
	}

	// Get admin record to use real ID and token version in JWT
	var adminID uint = 1
	var tokenVersion uint
	if db != nil {
		adminRecord, adminErr := db.GetAdminByUsername(creds.Username)
		if adminErr == nil && adminRecord != nil {
			adminID = adminRecord.ID
			tokenVersion = adminRecord.TokenVersion
		}
	}

	token, err := h.authManager.GenerateToken(creds.Username, adminID, tokenVersion)
	if err != nil {
		httputil.InternalError(c, "Failed to generate token", err)
		return
	}

	// Generate HMAC-signed CSRF token tied to the auth token
	csrfToken := middleware.GenerateCSRFToken(token, h.config.Server.JWTSecretKey)

	cookieSecure := h.config != nil && h.config.Server.CookieSecure
	cookieSameSite := http.SameSiteStrictMode
	if h.config != nil && h.config.Server.CookieSameSite != "" {
		cookieSameSite = parseSameSite(h.config.Server.CookieSameSite)
	}
	cookieMaxAge := 86400
	if h.config != nil && h.config.Auth.TokenExpiry > 0 {
		cookieMaxAge = int(h.config.Auth.TokenExpiry.Seconds())
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		MaxAge:   cookieMaxAge,
		Path:     "/",
		Secure:   cookieSecure,
		HttpOnly: true,
		SameSite: cookieSameSite,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		MaxAge:   cookieMaxAge,
		Path:     "/",
		Secure:   cookieSecure,
		HttpOnly: false,
		SameSite: cookieSameSite,
	})

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message":    "Login successful",
		"csrf_token": csrfToken,
	}))
}

func (h *Handler) Logout(c *gin.Context) {
	db := h.reqDB(c)
	// Only clear cookies if an auth token is present (prevents cross-origin logout)
	if _, err := c.Cookie("auth_token"); err != nil {
		c.JSON(http.StatusOK, models.MessageResponse("Already logged out"))
		return
	}

	// Invalidate all tokens for this user by incrementing token version
	if db != nil {
		if userID, exists := c.Get("user_id"); exists {
			if uid, ok := userID.(uint); ok {
				if err := db.IncrementAdminTokenVersion(uid); err != nil {
					log.Printf("Failed to increment token version on logout: %v", err)
				}
			}
		}
	}

	cookieSecure := h.config != nil && h.config.Server.CookieSecure
	cookieSameSite := http.SameSiteStrictMode
	if h.config != nil && h.config.Server.CookieSameSite != "" {
		cookieSameSite = parseSameSite(h.config.Server.CookieSameSite)
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   cookieSecure,
		HttpOnly: true,
		SameSite: cookieSameSite,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   cookieSecure,
		HttpOnly: true,
		SameSite: cookieSameSite,
	})

	c.JSON(http.StatusOK, models.MessageResponse("Logged out successfully"))
}

// GetCSRFToken returns a fresh CSRF token derived from the current auth cookie.
func (h *Handler) GetCSRFToken(c *gin.Context) {
	authToken, err := c.Cookie("auth_token")
	if err != nil || authToken == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authenticated"})
		return
	}
	secret := ""
	if h.config != nil {
		secret = h.config.Server.JWTSecretKey
	}
	if secret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server misconfiguration"})
		return
	}
	token := middleware.GenerateCSRFToken(authToken, secret)
	c.JSON(http.StatusOK, gin.H{"csrf_token": token})
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

func (h *Handler) ChangePassword(c *gin.Context) {
	db := h.reqDB(c)
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Auth not available"))
		return
	}

	// Reject oversized current password
	if len(req.CurrentPassword) > 1024 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	// Enforce password length constraints
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("New password must be at least 8 characters"))
		return
	}
	if len(req.NewPassword) > 72 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("New password must be at most 72 characters"))
		return
	}

	// Get username and user ID from JWT claims
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Not authenticated"))
		return
	}
	userID, uidExists := c.Get("user_id")
	if !uidExists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Not authenticated"))
		return
	}

	usernameStr, ok := username.(string)
	if !ok {
		httputil.InternalError(c, "Invalid session data", nil)
		return
	}
	userIDUint, ok := userID.(uint)
	if !ok {
		httputil.InternalError(c, "Invalid session data", nil)
		return
	}

	// Verify current password directly (bypass rate limiter — user is already authenticated)
	admin, adminErr := db.GetAdminByUsername(usernameStr)
	if adminErr != nil || admin == nil {
		c.JSON(http.StatusForbidden, models.ErrorResponse("Current password is incorrect"))
		return
	}
	if !h.authManager.CheckPassword(req.CurrentPassword, admin.Password) {
		c.JSON(http.StatusForbidden, models.ErrorResponse("Current password is incorrect"))
		return
	}

	hashedPassword, err := h.authManager.HashPassword(req.NewPassword)
	if err != nil {
		httputil.InternalError(c, "Failed to process password", err)
		return
	}

	err = db.UpdateAdminPassword(userIDUint, hashedPassword)
	if err != nil {
		httputil.InternalError(c, "Failed to update password", err)
		return
	}

	// Invalidate all existing tokens by incrementing token version
	if err := db.IncrementAdminTokenVersion(userIDUint); err != nil {
		log.Printf("Failed to increment token version after password change: %v", err)
	}

	c.JSON(http.StatusOK, models.MessageResponse("Password changed successfully. Please log in again."))
}
