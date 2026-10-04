package handlers

import (
	"net/http"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// Self-service account actions: identity and re-authentication (D4, D8).
//
// Every endpoint that acts on "the calling account" resolves it from the
// session's user_id, never from its username claim: the id is what the
// session was minted for (and what the token-version check revokes), while a
// username is a mutable label that another row could carry later. API-token
// principals are refused on all of them — a token carries user_id = its
// CREATOR's id (so a by-id lookup would make the token act on that account)
// and has no password of its own to re-verify — which is what passkey
// management and token minting already enforce.

// sessionOnlyMsg is the refusal for an API-token principal on a self-service
// account action.
const sessionOnlyMsg = "This action can only be done from a signed-in browser session"

// reauthLimitedMsg is the 429 body when the per-account re-authentication
// budget (auth.ReauthLimiter) is spent.
const reauthLimitedMsg = "Too many attempts — wait a minute and try again"

// sessionUserID returns the calling browser session's own account id. It
// refuses an API-token principal (403), a request that did not come through
// AdminAuth at all (no auth_method — 401) and a context without a usable
// user_id (401); the response has been written when ok is false.
func sessionUserID(c *gin.Context) (uint, bool) {
	switch c.GetString("auth_method") {
	case "session":
	case "token":
		c.JSON(http.StatusForbidden, response.Error(sessionOnlyMsg))
		return 0, false
	default:
		c.JSON(http.StatusUnauthorized, response.Error("Not authenticated"))
		return 0, false
	}
	v, _ := c.Get("user_id")
	id, ok := v.(uint)
	if !ok || id == 0 {
		c.JSON(http.StatusUnauthorized, response.Error("Not authenticated"))
		return 0, false
	}
	return id, true
}

// loadSessionAccount resolves the calling session (sessionUserID) to its
// admins row, loaded by id. Returns nil after writing the response: 403/401
// from sessionUserID, 500 on a store error, and 500 when the row is gone
// (the session's token-version check normally catches that first).
func (h *Handler) loadSessionAccount(c *gin.Context, db database.Store) *models.Admin {
	id, ok := sessionUserID(c)
	if !ok {
		return nil
	}
	admin, err := db.GetAdminByID(id)
	if err != nil || admin == nil {
		httputil.InternalError(c, "Failed to load account", err)
		return nil
	}
	return admin
}

// reauthPassword re-verifies the calling session's OWN password for a
// step-up action and returns the account row (loaded by id), or nil after
// writing the response. In order: session-only (403), the per-account
// re-authentication limiter (429 — every attempt counts, so a hijacked
// session gets 5 guesses and then one a minute), the row by the session's
// user_id (500 on error), then the password via CheckPassword — never
// ValidateCredentials, so a wrong password here does not touch the login
// lockout (a stolen session must not be able to lock the real operator out,
// and the login budget must stay the login's). A missing row, a disabled
// account, an empty / oversized or wrong password all answer 403 with
// wrongMsg (no account-state oracle).
func (h *Handler) reauthPassword(c *gin.Context, db database.Store, password, wrongMsg string) *models.Admin {
	id, ok := sessionUserID(c)
	if !ok {
		return nil
	}
	if !h.reauth.Allow(id) {
		c.JSON(http.StatusTooManyRequests, response.Error(reauthLimitedMsg))
		return nil
	}
	admin, err := db.GetAdminByID(id)
	if err != nil {
		httputil.InternalError(c, "Failed to load account", err)
		return nil
	}
	if admin == nil || admin.Disabled || password == "" || len(password) > 1024 ||
		h.authManager == nil || !h.authManager.CheckPassword(password, admin.Password) {
		c.JSON(http.StatusForbidden, response.Error(wrongMsg))
		return nil
	}
	return admin
}

// reauthTOTP is the second half of a step-up: when the account has 2FA
// enrolled it demands a valid, not-yet-used authenticator code (the replay
// guard is shared with every other TOTP consumer, so a code spent on a login
// cannot be replayed here and vice versa). A phished password plus a stolen
// session — which alone could not pass a fresh 2FA login — must not be
// enough for a credential reveal, a purge or a passkey change. Returns false
// after writing the 403.
func (h *Handler) reauthTOTP(c *gin.Context, db database.Store, admin *models.Admin, code string) bool {
	if !admin.TOTPEnabled {
		return true
	}
	if code == "" {
		c.JSON(http.StatusForbidden, response.Error("Authenticator code required"))
		return false
	}
	if !validateTOTPCode(code, db.DecryptField(admin.TOTPSecret)) {
		c.JSON(http.StatusForbidden, response.Error("Authenticator code is incorrect"))
		return false
	}
	if !h.authManager.MarkTOTPSlotUsed(admin.ID, code) {
		c.JSON(http.StatusForbidden, response.Error(totpCodeAlreadyUsedMsg))
		return false
	}
	return true
}
