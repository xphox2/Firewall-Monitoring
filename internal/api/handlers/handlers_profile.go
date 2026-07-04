package handlers

import (
	"net/http"
	"net/mail"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// Self-service profile endpoints (v28). Both routes live in the
// selfServiceRoutes map (main.go) so every role — including viewer — can
// manage its OWN account; the request body carries no id/username/role
// fields, so this path can never touch another account or escalate.

// loadOwnAccount resolves the calling session to its full admins row. Returns
// nil after writing the error response.
func (h *Handler) loadOwnAccount(c *gin.Context) *models.Admin {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return nil
	}
	authRow, err := db.GetAdminByUsername(c.GetString("username"))
	if err != nil || authRow == nil {
		httputil.InternalError(c, "Failed to load account", err)
		return nil
	}
	admin, err := db.GetAdminByID(authRow.ID)
	if err != nil || admin == nil {
		httputil.InternalError(c, "Failed to load account", err)
		return nil
	}
	return admin
}

type updateProfileRequest struct {
	Email    string `json:"email"`
	FullName string `json:"full_name"`
}

// UpdateProfile — PUT /admin/api/me. Writes exactly email + full_name for the
// calling account. Both fields are optional (empty clears); a non-empty email
// must parse as a bare RFC 5322 address.
func (h *Handler) UpdateProfile(c *gin.Context) {
	admin := h.loadOwnAccount(c)
	if admin == nil {
		return
	}
	var req updateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	email := strings.TrimSpace(req.Email)
	fullName := strings.TrimSpace(req.FullName)
	if len(email) > 254 {
		c.JSON(http.StatusBadRequest, response.Error("Email must be at most 254 characters"))
		return
	}
	if len(fullName) > 128 {
		c.JSON(http.StatusBadRequest, response.Error("Display name must be at most 128 characters"))
		return
	}
	if email != "" {
		addr, err := mail.ParseAddress(email)
		// Reject "Name <a@b>" forms: the field stores a bare address.
		if err != nil || addr.Address != email {
			c.JSON(http.StatusBadRequest, response.Error("Email address is not valid"))
			return
		}
	}
	if err := h.reqDB(c).UpdateAdminProfile(admin.ID, email, fullName); err != nil {
		httputil.InternalError(c, "Failed to update profile", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"email":     email,
		"full_name": fullName,
		"message":   "Profile updated",
	}))
}

type mfaDeclineRequest struct {
	// The explicit acknowledgment is required so the decline is a deliberate,
	// audit-visible act — the wizard's checkbox maps to this field.
	AcknowledgeRisk bool `json:"acknowledge_risk" binding:"required"`
}

// DeclineMFAPrompt — POST /admin/api/me/mfa-decline. Permanently silences the
// login-time MFA onboarding wizard for this account (the profile page keeps a
// banner + relaunch button, so declining is never final). Idempotent; a no-op
// with 200 when 2FA is already enabled.
func (h *Handler) DeclineMFAPrompt(c *gin.Context) {
	admin := h.loadOwnAccount(c)
	if admin == nil {
		return
	}
	var req mfaDeclineRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("acknowledge_risk is required"))
		return
	}
	if !admin.TOTPEnabled {
		if err := h.reqDB(c).SetAdminMFAPromptDismissed(admin.ID); err != nil {
			httputil.InternalError(c, "Failed to record decline", err)
			return
		}
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"message": "You won't be prompted about two-factor authentication again. You can enable it any time from your profile.",
	}))
}
