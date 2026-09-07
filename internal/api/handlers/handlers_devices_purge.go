package handlers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Permanent device purge (v0.11.243). All five routes are admin-only
// (adminOnlyRoutes in cmd/api/main.go); the POST additionally re-verifies the
// caller's password (+ TOTP when enrolled) and is login-rate-limited. The work
// itself is a background job run by the API primary's DevicePurgeWorker —
// these handlers only queue, cancel and report it.

// reauthCaller re-verifies the caller's OWN credentials for a step-up action:
// the admin is resolved by the JWT username (never a request-supplied
// identity), the password is re-checked, and — when the account has 2FA
// enrolled — a valid, not-yet-used TOTP code is required as well, with the
// replay guard namespaced by purpose so a code spent on one action can't be
// replayed on another. On success it returns the caller's username and id; on
// failure it has already written the response (401 when not authenticated at
// all, 403 otherwise — the RevealDeviceSecret precedent) and returns ok=false.
func (h *Handler) reauthCaller(c *gin.Context, db database.Store, password, totpCode, purpose string) (username string, userID uint, ok bool) {
	usernameVal, _ := c.Get("username")
	userIDVal, _ := c.Get("user_id")
	username, _ = usernameVal.(string)
	userID, _ = userIDVal.(uint)
	if username == "" {
		c.JSON(http.StatusUnauthorized, response.Error("Not authenticated"))
		return "", 0, false
	}
	if password == "" {
		c.JSON(http.StatusForbidden, response.Error("Password is required"))
		return "", 0, false
	}
	admin, err := db.GetAdminByUsername(username)
	if err != nil || admin == nil || !h.authManager.CheckPassword(password, admin.Password) {
		c.JSON(http.StatusForbidden, response.Error("Password is incorrect"))
		return "", 0, false
	}
	// Step-up: a phished password + stolen session (which alone couldn't pass a
	// fresh 2FA login) must not be enough for a credential reveal or a purge.
	if admin.TOTPEnabled {
		if totpCode == "" {
			c.JSON(http.StatusForbidden, response.Error("Authenticator code required"))
			return "", 0, false
		}
		if !validateTOTPCode(totpCode, admin.TOTPSecret) {
			c.JSON(http.StatusForbidden, response.Error("Authenticator code is incorrect"))
			return "", 0, false
		}
		// AUDIT L3: single-use-per-slot replay guard, same as the 2FA login path
		// (handlers_totp.go). Without it a valid code could be replayed within
		// its ~30–90s validity window to repeat the action.
		if !h.authManager.MarkTOTPSlotUsed(admin.ID, purpose, totpCode) {
			c.JSON(http.StatusForbidden, response.Error("Authenticator code already used — wait for the next code"))
			return "", 0, false
		}
	}
	return username, userID, true
}

// ipsecPurgeBlockingStatuses are the tunnel states in which a purge is refused:
// the plan's ipsec_tunnels entry is a cross-device deletion that would
// otherwise bypass DeleteIPSecTunnel's active-deployment guard while a saga is
// writing the peer's config.
//
// "verifying" is listed for contract completeness: no handler persists it
// today (the SA-liveness check runs under `deploying`), so it costs nothing
// and future-proofs the guard if a verifying state is ever stored.
var ipsecPurgeBlockingStatuses = map[string]bool{
	ipsecStatusDeploying:   true,
	"verifying":            true,
	ipsecStatusRollingBack: true,
}

// purgeAuditLog writes the explicit forensic record for a purge action. Best
// effort: a log failure never blocks the operator.
func purgeAuditLog(c *gin.Context, db database.Store, username string, userID uint, action, target string, status int) {
	if err := db.SaveAuditLog(&models.AuditLog{
		CreatedAt: time.Now(),
		Actor:     username,
		ActorID:   userID,
		Method:    http.MethodPost,
		Action:    action,
		Target:    target,
		Status:    status,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	}); err != nil {
		log.Printf("%s: audit log write failed for %s by %s: %v", action, target, username, err)
	}
}

// PurgeDevice queues the permanent deletion of a RETIRED device's data.
// POST /admin/api/devices/:id/purge, body {confirm_name, password, totp_code}.
// Checks, in order: device exists (404) and is retired (409); confirm_name
// matches (400); no IPSec tunnel on either end is deploying/verifying/
// rolling_back (409, naming them); no pending/running/cancelling job exists
// for the device (409 with job_id, checked before re-auth so a duplicate
// request never burns a TOTP slot); the caller re-authenticates (403). Then
// the job is created, audit-logged as purge_device, and returned with 202.
func (h *Handler) PurgeDevice(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var req struct {
		ConfirmName string `json:"confirm_name"`
		Password    string `json:"password"`
		TOTPCode    string `json:"totp_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	device, err := db.GetDevice(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Device not found"))
		return
	}
	if device.RetiredAt == nil {
		c.JSON(http.StatusConflict, response.Error("device must be retired first"))
		return
	}
	if strings.TrimSpace(req.ConfirmName) != device.Name {
		c.JSON(http.StatusBadRequest, response.Error("confirm_name does not match the device name"))
		return
	}
	tunnels, err := db.ListIPSecTunnelsForDevice(id)
	if err != nil {
		httputil.InternalError(c, "Failed to check IPSec tunnels", err)
		return
	}
	var blocking []string
	for _, t := range tunnels {
		if ipsecPurgeBlockingStatuses[t.Status] {
			blocking = append(blocking, fmt.Sprintf("%s (%s)", t.Name, t.Status))
		}
	}
	if len(blocking) > 0 {
		c.JSON(http.StatusConflict, response.Error(
			"IPSec tunnel deployment in progress on this device — wait for it to finish or roll it back first: "+strings.Join(blocking, ", ")))
		return
	}
	// Before the step-up: a 409 for an already-queued job must never consume
	// the caller's single-use TOTP code.
	if active, err := db.GetActiveDevicePurgeJob(id); err != nil {
		httputil.InternalError(c, "Failed to check purge jobs", err)
		return
	} else if active != nil {
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"error":   fmt.Sprintf("a purge job is already %s for this device", active.Status),
			"job_id":  active.ID,
		})
		return
	}
	username, userID, ok := h.reauthCaller(c, db, req.Password, req.TOTPCode, "purge")
	if !ok {
		return
	}
	job := &models.DevicePurgeJob{
		DeviceID:    device.ID,
		DeviceUUID:  device.UUID,
		DeviceName:  device.Name,
		RequestedBy: username,
	}
	if err := db.CreateDevicePurgeJob(job); err != nil {
		httputil.InternalError(c, "Failed to queue purge", err)
		return
	}
	purgeAuditLog(c, db, username, userID, "purge_device",
		fmt.Sprintf("device_id=%d uuid=%s name=%s job_id=%d", device.ID, device.UUID, device.Name, job.ID), http.StatusAccepted)
	c.JSON(http.StatusAccepted, response.Success(job))
}

// CancelDevicePurge cancels the device's latest job: pending → cancelled at
// once, running → cancelling (the worker finishes it as cancelled between
// batches); anything else is 409. POST /admin/api/devices/:id/purge/cancel.
func (h *Handler) CancelDevicePurge(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	job, err := db.GetLatestDevicePurgeJob(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("No purge job for this device"))
			return
		}
		httputil.InternalError(c, "Failed to load purge job", err)
		return
	}
	status, applied, err := db.CancelDevicePurgeJob(job.ID)
	if err != nil {
		httputil.InternalError(c, "Failed to cancel purge", err)
		return
	}
	if !applied {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("purge job is %s and cannot be cancelled", job.Status)))
		return
	}
	usernameVal, _ := c.Get("username")
	userIDVal, _ := c.Get("user_id")
	username, _ := usernameVal.(string)
	userID, _ := userIDVal.(uint)
	purgeAuditLog(c, db, username, userID, "purge_device_cancel",
		fmt.Sprintf("device_id=%d job_id=%d status=%s", id, job.ID, status), http.StatusOK)
	if fresh, err := db.GetDevicePurgeJob(job.ID); err == nil {
		job = fresh
	} else {
		job.Status = status
	}
	c.JSON(http.StatusOK, response.Success(job))
}

// GetDevicePurge returns the device's latest purge job in any state (404 when
// the device was never queued). GET /admin/api/devices/:id/purge.
func (h *Handler) GetDevicePurge(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	job, err := db.GetLatestDevicePurgeJob(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("No purge job for this device"))
			return
		}
		httputil.InternalError(c, "Failed to load purge job", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(job))
}

// ListPurgeJobs returns every active (pending/running/cancelling) job plus the
// 20 most recent terminal ones. GET /admin/api/purge-jobs.
func (h *Handler) ListPurgeJobs(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	jobs, err := db.ListDevicePurgeJobs(20)
	if err != nil {
		httputil.InternalError(c, "Failed to list purge jobs", err)
		return
	}
	if jobs == nil {
		jobs = []models.DevicePurgeJob{}
	}
	c.JSON(http.StatusOK, response.Success(jobs))
}

// EstimateDevicePurge returns the capped per-table row counts the purge would
// remove plus the IPSec tunnel intents it would delete (with the peer device
// name), for the confirm dialog. The device must be retired (409).
// GET /admin/api/devices/:id/purge/estimate.
func (h *Handler) EstimateDevicePurge(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	device, err := db.GetDevice(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Device not found"))
		return
	}
	if device.RetiredAt == nil {
		c.JSON(http.StatusConflict, response.Error("device must be retired first"))
		return
	}
	est, err := db.EstimateDevicePurge(id)
	if err != nil {
		httputil.InternalError(c, "Failed to estimate purge", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(est))
}
