package handlers

import (
	"log"
	"net/http"
	"strings"
	"time"

	"firewall-mon/internal/api/middleware"
	"firewall-mon/internal/api/response"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
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
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// Reject oversized passwords to prevent bcrypt CPU exhaustion DoS
	if len(creds.Password) > 1024 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid credentials"))
		return
	}

	// Reject oversized usernames to prevent map/DB bloat
	if len(creds.Username) > 255 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid credentials"))
		return
	}

	ip := c.ClientIP()
	userAgent := c.Request.UserAgent()
	// Truncate user agent to prevent stored XSS and DB bloat
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}

	// recordAttempt writes the login_attempts row. A success row means a
	// session was issued; a refusal after the password check is recorded as a
	// failure. For a 2FA account the password step alone issues nothing, so it
	// writes no row: TOTPLogin records that login's outcome under method
	// "totp". Lockout counting is unaffected.
	recordAttempt := func(success bool) {
		if db == nil {
			return
		}
		if dbErr := db.SaveLoginAttempt(&models.LoginAttempt{
			Timestamp: time.Now(),
			Username:  creds.Username,
			IPAddress: ip,
			Success:   success,
			UserAgent: userAgent,
			Method:    strPtr(loginMethodPassword),
		}); dbErr != nil {
			log.Printf("Failed to save login attempt: %v", dbErr)
		}
	}

	if err := h.authManager.ValidateCredentials(creds.Username, creds.Password, ip); err != nil {
		recordAttempt(false)
		if err == auth.ErrAccountLocked {
			c.JSON(http.StatusTooManyRequests, response.Error("Account temporarily locked due to too many failed attempts"))
			return
		}
		c.JSON(http.StatusUnauthorized, response.Error("Invalid credentials"))
		return
	}

	// D1: the session belongs to exactly the row whose password was just
	// verified — never a fallback identity. If that row cannot be loaded the
	// login fails with a 500 and no cookies (fail closed); it must not mint a
	// session for another account or skip the TOTP stage.
	if db == nil {
		httputil.InternalError(c, "Failed to load account", nil)
		return
	}
	adminRecord, adminErr := db.GetAdminByUsername(creds.Username)
	if adminErr != nil || adminRecord == nil {
		recordAttempt(false)
		httputil.InternalError(c, "Failed to load account", adminErr)
		return
	}

	// 2FA-enabled accounts don't get a session yet: they get a short-lived
	// pending token that only unlocks POST /api/auth/totp (P0-3).
	if adminRecord.TOTPEnabled {
		pending, perr := h.authManager.GeneratePendingToken(creds.Username, adminRecord.ID, adminRecord.TokenVersion)
		if perr != nil {
			recordAttempt(false)
			httputil.InternalError(c, "Failed to generate token", perr)
			return
		}
		// No row here: the password step of a 2FA login is an intermediate
		// stage, not a login. TOTPLogin writes the "totp" success or failure
		// row once the second factor has been decided.
		cookieSecure, cookieSameSite, _ := h.sessionCookieParams(c)
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "pending_2fa",
			Value:    pending,
			MaxAge:   int(auth.PendingTokenExpiry.Seconds()),
			Path:     "/",
			Secure:   cookieSecure,
			HttpOnly: true,
			SameSite: cookieSameSite,
		})
		c.JSON(http.StatusOK, response.Success(gin.H{
			"totp_required": true,
		}))
		return
	}

	recordAttempt(h.completeLogin(c, db, adminRecord.ID, loginMethodPassword))
}

// Login methods accepted by completeLogin. Each maps to the generic failure
// message its entry point has always returned, so the refactor changes no
// response body. loginMethodPasskey (handlers_passkeys.go) is the third.
const (
	loginMethodPassword = "password"
	loginMethodTOTP     = "totp"
)

// loginFailureMessage returns the generic failure text of a login method's
// entry point, and false for an unknown method.
func loginFailureMessage(method string) (string, bool) {
	switch method {
	case loginMethodPassword:
		return "Invalid credentials", true
	case loginMethodTOTP:
		return "Pending login invalid — start over", true
	case loginMethodPasskey:
		return passkeyLoginFailedMsg, true
	}
	return "", false
}

// completeLogin is the single tail of every fully-authenticated login
// (password-only and the TOTP second step). It re-reads the account BY ID so
// the session reflects the row's CURRENT disabled flag, role and token
// version — never values captured earlier in the request — and fails closed:
//   - DB error → 500, no cookies;
//   - account gone, disabled, or holding an empty/unknown role (D5) → 401 with
//     the entry point's usual generic message, no cookies;
//   - method "password" on an account that now has 2FA enabled → the same
//     generic 401 (the second factor is owed; Login routes such accounts to
//     the pending_2fa stage before ever getting here).
//
// Method "passkey" issues a full session with NO TOTP stage: the assertion
// was user-verified (checked by the caller), which is itself multi-factor.
//
// On success it clears pending_2fa (TOTP and passkey methods; the password
// method is unchanged) and mints the JWT + CSRF cookies via issueSession.
// When passkeys are enabled and the account has new-passkey notices pending,
// the success payload also carries passkey_notices (absent otherwise, so the
// password response is unchanged for accounts without them). It reports
// whether a session was issued (the response has been written either way).
func (h *Handler) completeLogin(c *gin.Context, db database.Store, adminID uint, method string) bool {
	failMsg, known := loginFailureMessage(method)
	if !known {
		httputil.InternalError(c, "Unknown login method", nil)
		return false
	}
	admin, err := db.GetAdminByID(adminID)
	if err != nil {
		httputil.InternalError(c, "Failed to load account", err)
		return false
	}
	if admin == nil || admin.Disabled || (method == loginMethodPassword && admin.TOTPEnabled) {
		c.JSON(http.StatusUnauthorized, response.Error(failMsg))
		return false
	}
	if !auth.ValidRole(admin.Role) {
		log.Printf("login refused for admin id %d: role %q is not a valid role", admin.ID, admin.Role)
		c.JSON(http.StatusUnauthorized, response.Error(failMsg))
		return false
	}

	if method == loginMethodTOTP || method == loginMethodPasskey {
		cookieSecure, cookieSameSite, _ := h.sessionCookieParams(c)
		http.SetCookie(c.Writer, &http.Cookie{
			Name: "pending_2fa", Value: "", MaxAge: -1, Path: "/",
			Secure: cookieSecure, HttpOnly: true, SameSite: cookieSameSite,
		})
	}

	extra := gin.H{
		"message":              "Login successful",
		"must_change_password": admin.MustChangePassword,
	}
	if notices := h.passkeyNotices(db, admin.ID); len(notices) > 0 {
		extra["passkey_notices"] = notices
	}
	return h.issueSession(c, admin.Username, admin.ID, admin.TokenVersion, admin.Role, extra)
}

// sessionCookieParams derives the cookie attributes every auth cookie shares.
//
// Secure: an explicit COOKIE_SECURE always wins. Otherwise the flag follows
// how THIS request arrived (middleware.RequestOverHTTPS): in-process TLS, or
// a trusted proxy (TRUSTED_PROXIES) saying X-Forwarded-Proto: https. So a
// deployment behind a TLS-terminating proxy gets Secure cookies without any
// setting, while a plain-HTTP direct login still works — a Secure cookie
// there would be dropped by the browser and the login would silently fail
// (AUDIT-024).
func (h *Handler) sessionCookieParams(c *gin.Context) (secure bool, sameSite http.SameSite, maxAge int) {
	if h.config != nil && h.config.Server.CookieSecureExplicit {
		secure = h.config.Server.CookieSecure
	} else {
		secure = middleware.RequestOverHTTPS(c)
	}
	sameSite = http.SameSiteStrictMode
	if h.config != nil && h.config.Server.CookieSameSite != "" {
		sameSite = parseSameSite(h.config.Server.CookieSameSite)
	}
	maxAge = 86400
	if h.config != nil && h.config.Auth.TokenExpiry > 0 {
		maxAge = int(h.config.Auth.TokenExpiry.Seconds())
	}
	return
}

// issueSession mints the JWT + CSRF pair and sets both cookies — the tail of
// a fully-completed authentication, shared by password-only logins and the
// TOTP second step. extra is merged into the success payload (csrf_token is
// always set/overwritten here). Reports whether the session was issued.
func (h *Handler) issueSession(c *gin.Context, username string, adminID uint, tokenVersion uint, role string, extra gin.H) bool {
	token, err := h.authManager.GenerateToken(username, adminID, tokenVersion, role)
	if err != nil {
		httputil.InternalError(c, "Failed to generate token", err)
		return false
	}

	// Generate HMAC-signed CSRF token tied to the auth token
	csrfToken := middleware.GenerateCSRFToken(token, h.config.Server.JWTSecretKey)
	cookieSecure, cookieSameSite, cookieMaxAge := h.sessionCookieParams(c)

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

	payload := gin.H{}
	for k, v := range extra {
		payload[k] = v
	}
	payload["csrf_token"] = csrfToken

	c.JSON(http.StatusOK, response.Success(payload))
	return true
}

func (h *Handler) Logout(c *gin.Context) {
	db := h.reqDB(c)
	// Only clear cookies if an auth token is present (prevents cross-origin logout)
	if _, err := c.Cookie("auth_token"); err != nil {
		c.JSON(http.StatusOK, response.Message("Already logged out"))
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

	cookieSecure, cookieSameSite, _ := h.sessionCookieParams(c)

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

	c.JSON(http.StatusOK, response.Message("Logged out successfully"))
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
	// RemovePasskeys (D-RESET): also delete every passkey of the account.
	// ABSENT means TRUE — a password change removes passkeys unless the
	// caller explicitly sends false.
	RemovePasskeys *bool `json:"remove_passkeys"`
}

func (h *Handler) ChangePassword(c *gin.Context) {
	db := h.reqDB(c)
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}

	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Auth not available"))
		return
	}

	// Reject oversized current password
	if len(req.CurrentPassword) > 1024 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// Enforce password length constraints
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, response.Error("New password must be at least 8 characters"))
		return
	}
	if len(req.NewPassword) > 72 {
		c.JSON(http.StatusBadRequest, response.Error("New password must be at most 72 characters"))
		return
	}

	// Get username and user ID from JWT claims
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, response.Error("Not authenticated"))
		return
	}
	userID, uidExists := c.Get("user_id")
	if !uidExists {
		c.JSON(http.StatusUnauthorized, response.Error("Not authenticated"))
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
		c.JSON(http.StatusForbidden, response.Error("Current password is incorrect"))
		return
	}
	if !h.authManager.CheckPassword(req.CurrentPassword, admin.Password) {
		c.JSON(http.StatusForbidden, response.Error("Current password is incorrect"))
		return
	}

	hashedPassword, err := h.authManager.HashPassword(req.NewPassword)
	if err != nil {
		httputil.InternalError(c, "Failed to process password", err)
		return
	}

	// One transaction (D-RESET): new password, clear the forced-change flag,
	// delete every passkey (unless remove_passkeys is explicitly false) and
	// bump token_version to invalidate all existing sessions. Either all of
	// it happens or none of it does.
	removePasskeys := req.RemovePasskeys == nil || *req.RemovePasskeys
	mustChange := false
	removed, err := db.ResetAdminCredentials(userIDUint, database.AdminReset{
		PasswordHash:       hashedPassword,
		MustChangePassword: &mustChange,
		KeepPasskeys:       !removePasskeys,
	})
	if err != nil {
		httputil.InternalError(c, "Failed to update password", err)
		return
	}
	if removePasskeys {
		h.discardRegistration(userIDUint)
	}
	if removed > 0 {
		log.Printf("password change for admin %d removed %d passkey(s)", userIDUint, removed)
	}

	c.JSON(http.StatusOK, response.Message("Password changed successfully. Please log in again."))
}

// RequirePasswordChanged blocks admin API routes for an account still flagged
// must_change_password, so the forced first-login rotation cannot be skipped by
// calling the API directly (the SPA modal is only the UX half). The change-
// password, logout, CSRF, and session endpoints stay reachable so the operator
// can actually complete the change. Returns 403 with a machine-readable code the
// SPA uses to pop the change-password modal.
// passwordChangeAllowlist is the set of admin routes reachable while an account
// is still flagged must_change_password: exactly what the operator needs to load
// the SPA and complete the change. Everything else under /admin/api is blocked.
var passwordChangeAllowlist = map[string]bool{
	"/admin/api/csrf-token":        true,
	"/admin/api/logout":            true,
	"/admin/api/settings/password": true,
}

func (h *Handler) RequirePasswordChanged() gin.HandlerFunc {
	return func(c *gin.Context) {
		// API-token principals (P0-2) have no password to rotate — the gate
		// only makes sense for cookie sessions.
		if c.GetString("auth_method") == "token" {
			c.Next()
			return
		}
		route := c.FullPath()
		// HTML SPA pages (no /api/ segment) must load so the change-password
		// modal can render; the completion endpoints are explicitly allowed.
		if !strings.Contains(route, "/api/") || passwordChangeAllowlist[route] {
			c.Next()
			return
		}
		db := h.reqDB(c)
		if db == nil {
			c.Next()
			return
		}
		userID, ok := c.Get("user_id")
		if !ok {
			c.Next()
			return
		}
		uid, ok := userID.(uint)
		if !ok {
			c.Next()
			return
		}
		must, err := db.GetAdminMustChangePassword(uid)
		if err != nil {
			// Fail closed: if we can't confirm the account is clear, block the
			// action rather than let a forced-change account through on a DB blip.
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Password change required",
				"code":  "password_change_required",
			})
			return
		}
		if must {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "You must change your password before continuing",
				"code":  "password_change_required",
			})
			return
		}
		c.Next()
	}
}
