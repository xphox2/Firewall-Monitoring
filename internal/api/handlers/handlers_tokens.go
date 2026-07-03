package handlers

import (
	"net/http"
	"strconv"
	"time"

	"firewall-mon/internal/api/middleware"
	"firewall-mon/internal/api/response"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// Scoped API tokens (P0-2). All routes are admin-only (adminOnlyRoutes map);
// creation additionally requires a cookie SESSION — a token must never mint
// another token, or a leaked admin-scope token could launder itself into
// fresh, unexpiring credentials.

type createTokenRequest struct {
	Name          string `json:"name" binding:"required,min=3,max=64"`
	Scope         string `json:"scope" binding:"required"`
	ExpiresInDays int    `json:"expires_in_days"`
}

func (h *Handler) CreateAPIToken(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	if c.GetString("auth_method") != "session" {
		c.JSON(http.StatusForbidden, response.Error("API tokens can only be created from a logged-in session"))
		return
	}
	var req createTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("name (3-64 chars) and scope are required"))
		return
	}
	if middleware.APITokenScopeRole(req.Scope) == "" {
		c.JSON(http.StatusBadRequest, response.Error("scope must be read, write, or admin"))
		return
	}
	if req.ExpiresInDays < 0 || req.ExpiresInDays > 3650 {
		c.JSON(http.StatusBadRequest, response.Error("expires_in_days must be 0 (never) to 3650"))
		return
	}

	random, err := auth.GenerateSecureToken(43) // ~256 bits of URL-safe base64
	if err != nil {
		httputil.InternalError(c, "Failed to generate token", err)
		return
	}
	plaintext := database.APITokenPlaintextPrefix + random

	var expires *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expires = &t
	}
	userID, _ := c.Get("user_id")
	creatorID, _ := userID.(uint)

	tok := models.ApiToken{
		Name:        req.Name,
		TokenHash:   database.HashAPIToken(plaintext),
		Prefix:      plaintext[:12],
		Scope:       req.Scope,
		CreatedBy:   c.GetString("username"),
		CreatedByID: creatorID,
		ExpiresAt:   expires,
	}
	if err := db.CreateAPIToken(&tok); err != nil {
		c.JSON(http.StatusConflict, response.Error("Could not create token (name may already exist)"))
		return
	}
	c.JSON(http.StatusCreated, response.Success(gin.H{
		"token_meta": tok,
		// Shown once; only the hash is stored.
		"token": plaintext,
	}))
}

func (h *Handler) ListAPITokens(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	toks, err := db.ListAPITokens()
	if err != nil {
		httputil.InternalError(c, "Failed to list tokens", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(toks))
}

// RevokeAPIToken soft-revokes; the row stays for the audit trail and the list.
func (h *Handler) RevokeAPIToken(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id64, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("invalid token id"))
		return
	}
	if err := db.RevokeAPIToken(uint(id64)); err != nil {
		httputil.InternalError(c, "Failed to revoke token", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"revoked": id64}))
}
