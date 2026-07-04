package handlers

import (
	"net/http"
	"strconv"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// User management (RBAC, P0-1). Rows live in the historical `admins` table;
// the API presents them as "users". All mutation endpoints here are in the
// adminOnlyRoutes map (middleware.RequireRole), so only role=admin reaches
// them; guards below additionally protect the last enabled admin and the
// caller's own account.

// userDTO is the wire shape — never the raw model (Password stays server-side).
type userDTO struct {
	ID                 uint      `json:"id"`
	Username           string    `json:"username"`
	Role               string    `json:"role"`
	Disabled           bool      `json:"disabled"`
	MustChangePassword bool      `json:"must_change_password"`
	TOTPEnabled        bool      `json:"totp_enabled"`
	Email              string    `json:"email"`
	FullName           string    `json:"full_name"`
	CreatedAt          time.Time `json:"created_at"`
}

func toUserDTO(a *models.Admin) userDTO {
	return userDTO{
		ID:                 a.ID,
		Username:           a.Username,
		Role:               a.Role,
		Disabled:           a.Disabled,
		MustChangePassword: a.MustChangePassword,
		TOTPEnabled:        a.TOTPEnabled,
		Email:              a.Email,
		FullName:           a.FullName,
		CreatedAt:          a.CreatedAt,
	}
}

// GetMe returns the calling session's identity so the SPA can gate admin-only
// UI client-side (the server enforces regardless). Reachable by any role
// (selfServiceRoutes).
func (h *Handler) GetMe(c *gin.Context) {
	username, _ := c.Get("username")
	role, _ := c.Get("role")
	userID, _ := c.Get("user_id")
	// Profile fields (v28). The dismissed timestamp is reported only as a
	// boolean — the client needs "should I offer the MFA wizard", not when
	// the risk was accepted (that stays server-side for the audit story).
	var (
		totpEnabled        bool
		email, fullName    string
		createdAt          *time.Time
		mustChange         bool
		mfaPromptDismissed bool
	)
	if db := h.reqDB(c); db != nil {
		if name, ok := username.(string); ok {
			if authRow, err := db.GetAdminByUsername(name); err == nil && authRow != nil {
				if admin, err := db.GetAdminByID(authRow.ID); err == nil && admin != nil {
					totpEnabled = admin.TOTPEnabled
					email = admin.Email
					fullName = admin.FullName
					createdAt = &admin.CreatedAt
					mustChange = admin.MustChangePassword
					mfaPromptDismissed = admin.MFAPromptDismissedAt != nil
				}
			}
		}
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"id":                   userID,
		"username":             username,
		"role":                 role,
		"totp_enabled":         totpEnabled,
		"email":                email,
		"full_name":            fullName,
		"created_at":           createdAt,
		"must_change_password": mustChange,
		"mfa_prompt_dismissed": mfaPromptDismissed,
	}))
}

func (h *Handler) ListUsers(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	admins, err := db.ListAdmins()
	if err != nil {
		httputil.InternalError(c, "Failed to list users", err)
		return
	}
	out := make([]userDTO, len(admins))
	for i := range admins {
		out[i] = toUserDTO(&admins[i])
	}
	c.JSON(http.StatusOK, response.Success(out))
}

type createUserRequest struct {
	Username string `json:"username" binding:"required,min=3,max=64"`
	Role     string `json:"role" binding:"required"`
}

// CreateUser provisions an account with a generated temporary password that is
// returned exactly once and flagged must_change_password — the same forced
// first-login rotation as the bootstrap admin (v0.10.555), so a temp credential
// can never quietly become a permanent one.
func (h *Handler) CreateUser(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("username (3-64 chars) and role are required"))
		return
	}
	if !auth.ValidRole(req.Role) {
		c.JSON(http.StatusBadRequest, response.Error("role must be admin, operator, or viewer"))
		return
	}

	tempPassword, err := auth.GenerateSecureToken(20)
	if err != nil {
		httputil.InternalError(c, "Failed to generate temporary password", err)
		return
	}
	hashed, err := h.authManager.HashPassword(tempPassword)
	if err != nil {
		httputil.InternalError(c, "Failed to hash password", err)
		return
	}

	admin := models.Admin{
		Username:           req.Username,
		Password:           hashed,
		Role:               req.Role,
		MustChangePassword: true,
	}
	if err := db.CreateAdmin(&admin); err != nil {
		// Unique-index violation on username is the overwhelmingly likely
		// cause; don't leak driver detail.
		c.JSON(http.StatusConflict, response.Error("Could not create user (username may already exist)"))
		return
	}
	c.JSON(http.StatusCreated, response.Success(gin.H{
		"user": toUserDTO(&admin),
		// Shown once; only the bcrypt hash is stored.
		"temp_password": tempPassword,
	}))
}

type updateUserRequest struct {
	Role     *string `json:"role"`
	Disabled *bool   `json:"disabled"`
}

// UpdateUser changes role and/or disabled state. Both paths bump the target's
// token version (in the store methods) so live sessions pick up the change
// immediately. Guards: no self-demotion/disable (prevents accidental lockout
// mid-session), and the last enabled admin can be neither demoted nor disabled.
func (h *Handler) UpdateUser(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, target, ok := h.loadUserParam(c)
	if !ok {
		return
	}
	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil || (req.Role == nil && req.Disabled == nil) {
		c.JSON(http.StatusBadRequest, response.Error("provide role and/or disabled"))
		return
	}

	callerID, _ := c.Get("user_id")
	isSelf := callerID == id

	if req.Role != nil && *req.Role != target.Role {
		if !auth.ValidRole(*req.Role) {
			c.JSON(http.StatusBadRequest, response.Error("role must be admin, operator, or viewer"))
			return
		}
		if isSelf {
			c.JSON(http.StatusBadRequest, response.Error("You cannot change your own role"))
			return
		}
		if target.Role == auth.RoleAdmin && *req.Role != auth.RoleAdmin {
			if !h.otherAdminsExist(c, id) {
				return
			}
		}
		if err := db.UpdateAdminRole(id, *req.Role); err != nil {
			httputil.InternalError(c, "Failed to update role", err)
			return
		}
	}

	if req.Disabled != nil && *req.Disabled != target.Disabled {
		if isSelf {
			c.JSON(http.StatusBadRequest, response.Error("You cannot disable your own account"))
			return
		}
		if *req.Disabled && target.Role == auth.RoleAdmin {
			if !h.otherAdminsExist(c, id) {
				return
			}
		}
		if err := db.SetAdminDisabled(id, *req.Disabled); err != nil {
			httputil.InternalError(c, "Failed to update user", err)
			return
		}
	}

	updated, err := db.GetAdminByID(id)
	if err != nil || updated == nil {
		httputil.InternalError(c, "Failed to reload user", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(toUserDTO(updated)))
}

func (h *Handler) DeleteUser(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, target, ok := h.loadUserParam(c)
	if !ok {
		return
	}
	callerID, _ := c.Get("user_id")
	if callerID == id {
		c.JSON(http.StatusBadRequest, response.Error("You cannot delete your own account"))
		return
	}
	if target.Role == auth.RoleAdmin && !target.Disabled {
		if !h.otherAdminsExist(c, id) {
			return
		}
	}
	if err := db.DeleteAdmin(id); err != nil {
		httputil.InternalError(c, "Failed to delete user", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"deleted": id}))
}

// ResetUserPassword issues a fresh temporary password (returned once), flags
// the account for forced change, and revokes its live sessions.
func (h *Handler) ResetUserPassword(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, _, ok := h.loadUserParam(c)
	if !ok {
		return
	}
	tempPassword, err := auth.GenerateSecureToken(20)
	if err != nil {
		httputil.InternalError(c, "Failed to generate temporary password", err)
		return
	}
	hashed, err := h.authManager.HashPassword(tempPassword)
	if err != nil {
		httputil.InternalError(c, "Failed to hash password", err)
		return
	}
	if err := db.UpdateAdminPassword(id, hashed); err != nil {
		httputil.InternalError(c, "Failed to reset password", err)
		return
	}
	if err := db.SetAdminMustChangePassword(id, true); err != nil {
		httputil.InternalError(c, "Failed to flag password change", err)
		return
	}
	if err := db.IncrementAdminTokenVersion(id); err != nil {
		httputil.InternalError(c, "Failed to revoke sessions", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"temp_password": tempPassword}))
}

// loadUserParam parses :id and loads the row, writing the error response on
// failure.
func (h *Handler) loadUserParam(c *gin.Context) (uint, *models.Admin, bool) {
	db := h.reqDB(c)
	id64, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("invalid user id"))
		return 0, nil, false
	}
	id := uint(id64)
	target, err := db.GetAdminByID(id)
	if err != nil {
		httputil.InternalError(c, "Failed to load user", err)
		return 0, nil, false
	}
	if target == nil {
		c.JSON(http.StatusNotFound, response.Error("user not found"))
		return 0, nil, false
	}
	return id, target, true
}

// otherAdminsExist enforces the last-admin guard, writing the error response
// when the target is the only enabled admin (or the check fails — fail closed).
func (h *Handler) otherAdminsExist(c *gin.Context, excludeID uint) bool {
	db := h.reqDB(c)
	n, err := db.CountOtherEnabledAdmins(excludeID)
	if err != nil {
		httputil.InternalError(c, "Failed to verify remaining admins", err)
		return false
	}
	if n == 0 {
		c.JSON(http.StatusBadRequest, response.Error("Cannot remove the last enabled admin"))
		return false
	}
	return true
}
