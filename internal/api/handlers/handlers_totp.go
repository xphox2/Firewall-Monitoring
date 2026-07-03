package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP 2FA (P0-3). Enrollment endpoints are self-service (any role, own
// account only — selfServiceRoutes map); the per-user reset is admin-only.
// The login second step (TOTPLogin) is pre-session and lives on the public
// /api/auth group behind the login rate limiter.

const recoveryCodeCount = 10

// validateTOTPCode checks a 6-digit code against the shared secret with ±1
// period of clock skew (RFC 6238 recommendation).
func validateTOTPCode(code, secret string) bool {
	if secret == "" || code == "" {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

// newRecoveryCodes mints N human-typable single-use codes (10 hex chars).
func newRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		var b [5]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		codes[i] = hex.EncodeToString(b[:])
	}
	return codes, nil
}

type totpLoginRequest struct {
	Code string `json:"code" binding:"required,min=6,max=32"`
}

// TOTPLogin is the second authentication step (POST /api/auth/totp): it
// exchanges a pending_2fa token plus a valid TOTP or recovery code for a real
// session. Failures count toward the SAME lockout bucket as password failures,
// so the second factor can't be brute-forced on a fresh budget.
func (h *Handler) TOTPLogin(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req totpLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("code is required"))
		return
	}

	pending, err := c.Cookie("pending_2fa")
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.Error("No pending login — start over"))
		return
	}
	claims, err := h.authManager.ValidateToken(pending)
	if err != nil || claims.Stage != auth.StageTOTP {
		c.JSON(http.StatusUnauthorized, response.Error("Pending login expired — start over"))
		return
	}

	ip := c.ClientIP()
	if h.authManager.IsLocked(claims.Username, ip) {
		c.JSON(http.StatusTooManyRequests, response.Error("Account temporarily locked due to too many failed attempts"))
		return
	}

	admin, err := db.GetAdminByUsername(claims.Username)
	if err != nil || admin == nil || admin.Disabled || !admin.TOTPEnabled {
		c.JSON(http.StatusUnauthorized, response.Error("Pending login invalid — start over"))
		return
	}

	// TOTP code first (with single-use-per-slot replay guard); recovery code
	// as the fallback path.
	authenticated := false
	if validateTOTPCode(req.Code, admin.TOTPSecret) {
		authenticated = h.authManager.MarkTOTPSlotUsed(admin.ID)
	}
	if !authenticated {
		used, cerr := db.ConsumeRecoveryCode(admin.ID, database.HashAPIToken(req.Code))
		if cerr != nil {
			httputil.InternalError(c, "Failed to verify recovery code", cerr)
			return
		}
		authenticated = used
	}
	if !authenticated {
		h.authManager.RecordFailure(claims.Username, ip)
		c.JSON(http.StatusUnauthorized, response.Error("Invalid code"))
		return
	}

	h.authManager.ClearFailures(claims.Username, ip)
	cookieSecure, cookieSameSite, _ := h.sessionCookieParams()
	http.SetCookie(c.Writer, &http.Cookie{
		Name: "pending_2fa", Value: "", MaxAge: -1, Path: "/",
		Secure: cookieSecure, HttpOnly: true, SameSite: cookieSameSite,
	})

	role := admin.Role
	if role == "" {
		role = auth.RoleAdmin
	}
	h.issueSession(c, admin.Username, admin.ID, admin.TokenVersion, role, gin.H{
		"message":              "Login successful",
		"must_change_password": admin.MustChangePassword,
	})
}

type totpSetupRequest struct {
	Password string `json:"password" binding:"required"`
}

// Setup2FA starts enrollment for the calling account: re-authenticates the
// password (a hijacked session must not be able to swap the second factor),
// generates the shared secret, stores it encrypted with enabled=false, and
// returns the otpauth URI + base32 secret for the authenticator app.
func (h *Handler) Setup2FA(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req totpSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("password is required"))
		return
	}
	username := c.GetString("username")
	admin, err := db.GetAdminByUsername(username)
	if err != nil || admin == nil {
		httputil.InternalError(c, "Failed to load account", err)
		return
	}
	if !h.authManager.CheckPassword(req.Password, admin.Password) {
		c.JSON(http.StatusForbidden, response.Error("Password is incorrect"))
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Firewall-Mon",
		AccountName: username,
	})
	if err != nil {
		httputil.InternalError(c, "Failed to generate TOTP secret", err)
		return
	}
	if err := db.SetAdminTOTP(admin.ID, db.EncryptField(key.Secret()), false); err != nil {
		httputil.InternalError(c, "Failed to store TOTP secret", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"secret":      key.Secret(),
		"otpauth_url": key.URL(),
	}))
}

type totpCodeRequest struct {
	Code string `json:"code" binding:"required,min=6,max=32"`
}

// Verify2FA completes enrollment: the first valid code proves the
// authenticator holds the secret, so 2FA flips on, recovery codes are minted
// (shown once), and every existing session is revoked — the next login
// exercises the new flow.
func (h *Handler) Verify2FA(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req totpCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("code is required"))
		return
	}
	username := c.GetString("username")
	admin, err := db.GetAdminByUsername(username)
	if err != nil || admin == nil {
		httputil.InternalError(c, "Failed to load account", err)
		return
	}
	if admin.TOTPSecret == "" {
		c.JSON(http.StatusBadRequest, response.Error("No pending 2FA setup — run setup first"))
		return
	}
	if !validateTOTPCode(req.Code, admin.TOTPSecret) {
		c.JSON(http.StatusBadRequest, response.Error("Invalid code — check your authenticator app"))
		return
	}

	codes, err := newRecoveryCodes(recoveryCodeCount)
	if err != nil {
		httputil.InternalError(c, "Failed to generate recovery codes", err)
		return
	}
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hashes[i] = database.HashAPIToken(code)
	}
	if err := db.ReplaceRecoveryCodes(admin.ID, hashes); err != nil {
		httputil.InternalError(c, "Failed to store recovery codes", err)
		return
	}
	if err := db.SetAdminTOTP(admin.ID, db.EncryptField(admin.TOTPSecret), true); err != nil {
		httputil.InternalError(c, "Failed to enable 2FA", err)
		return
	}
	// Revoke existing sessions — the user re-authenticates with the new flow.
	if err := db.IncrementAdminTokenVersion(admin.ID); err != nil {
		log.Printf("Failed to bump token version after 2FA enable: %v", err)
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"enabled": true,
		// Shown once; only hashes are stored.
		"recovery_codes": codes,
		"message":        "Two-factor authentication enabled. You will be asked to log in again.",
	}))
}

type totpDisableRequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required,min=6,max=32"`
}

// Disable2FA turns 2FA off for the calling account. Requires BOTH the
// password and a current code (or recovery code) — possession of a session
// alone is not enough to strip the second factor.
func (h *Handler) Disable2FA(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req totpDisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("password and code are required"))
		return
	}
	username := c.GetString("username")
	admin, err := db.GetAdminByUsername(username)
	if err != nil || admin == nil {
		httputil.InternalError(c, "Failed to load account", err)
		return
	}
	if !h.authManager.CheckPassword(req.Password, admin.Password) {
		c.JSON(http.StatusForbidden, response.Error("Password is incorrect"))
		return
	}
	codeOK := validateTOTPCode(req.Code, admin.TOTPSecret)
	if !codeOK {
		used, cerr := db.ConsumeRecoveryCode(admin.ID, database.HashAPIToken(req.Code))
		if cerr != nil {
			httputil.InternalError(c, "Failed to verify code", cerr)
			return
		}
		codeOK = used
	}
	if !codeOK {
		c.JSON(http.StatusForbidden, response.Error("Invalid code"))
		return
	}
	if err := db.ClearAdminTOTP(admin.ID); err != nil {
		httputil.InternalError(c, "Failed to disable 2FA", err)
		return
	}
	if err := db.IncrementAdminTokenVersion(admin.ID); err != nil {
		log.Printf("Failed to bump token version after 2FA disable: %v", err)
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"enabled": false}))
}

// ResetUser2FA (admin-only) clears another account's 2FA — the recovery path
// when an operator loses both the authenticator and the recovery codes.
func (h *Handler) ResetUser2FA(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, _, ok := h.loadUserParam(c)
	if !ok {
		return
	}
	if err := db.ClearAdminTOTP(id); err != nil {
		httputil.InternalError(c, "Failed to reset 2FA", err)
		return
	}
	if err := db.IncrementAdminTokenVersion(id); err != nil {
		log.Printf("Failed to bump token version after 2FA reset: %v", err)
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"reset": id}))
}
