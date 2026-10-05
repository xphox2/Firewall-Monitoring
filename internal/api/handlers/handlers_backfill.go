package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// One-time normalized-event backfill (Phase 1, S-5; v0.11.297). All four
// routes are admin-only (adminOnlyRoutes in cmd/api/main.go); start and
// resume additionally re-verify the caller's password (+ TOTP when enrolled),
// the purge's step-up, and are login-rate-limited. The work itself is a job
// the poller's NormalizeBackfillWorker runs (database.RunNormalizeBackfill);
// these handlers queue, cancel, resume and report it.

// backfillRequest is the body of POST /admin/api/normalize/backfill.
type backfillRequest struct {
	// SinceDays is how far back from now to backfill (default and max 30).
	SinceDays int `json:"since_days"`
	// DeviceID restricts the job to one device (optional).
	DeviceID *uint `json:"device_id"`
	// RateRowsPerSec is the raw-row scan rate (default 2000, 100..100000).
	RateRowsPerSec int `json:"rate_rows_per_sec"`
	// Window is the optional local-time run window "HH:MM-HH:MM"; when empty
	// the normalize_backfill_window setting applies, if set.
	Window   string `json:"window"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// StartNormalizeBackfill queues the backfill. Checks, in order: normalization
// enabled (409), body valid (400: since_days 1..30, rate in range, window
// parseable), device exists when given (404), the ingest watermark exists
// (409) and the window is non-empty (409), no active job (409 with job_id —
// before the step-up, so a duplicate request never burns a TOTP slot), disk
// headroom (409 with the estimate), then re-authentication (403). The job is
// created, audit-logged as normalize_backfill, and returned with 202 together
// with the estimate.
func (h *Handler) StartNormalizeBackfill(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	if h.config != nil && h.config.Normalize.Disabled {
		c.JSON(http.StatusConflict, response.Error("normalization is disabled (NORMALIZE_ENABLED=false); enable it and let the ingest record its start before backfilling"))
		return
	}
	var req backfillRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if req.SinceDays == 0 {
		req.SinceDays = database.NormalizeBackfillMaxDays
	}
	if req.SinceDays < 1 || req.SinceDays > database.NormalizeBackfillMaxDays {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("since_days must be 1..%d", database.NormalizeBackfillMaxDays)))
		return
	}
	if req.RateRowsPerSec == 0 {
		req.RateRowsPerSec = database.NormalizeBackfillDefaultRate
	}
	if req.RateRowsPerSec < database.NormalizeBackfillMinRate || req.RateRowsPerSec > database.NormalizeBackfillMaxRate {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("rate_rows_per_sec must be %d..%d", database.NormalizeBackfillMinRate, database.NormalizeBackfillMaxRate)))
		return
	}
	if req.Window == "" {
		req.Window, _ = db.GetSettingValue(database.NormalizeBackfillWindowSetting)
	}
	if err := database.ValidateRunWindow(req.Window); err != nil {
		c.JSON(http.StatusBadRequest, response.Error(err.Error()))
		return
	}
	if req.DeviceID != nil {
		if _, err := db.GetDevice(*req.DeviceID); err != nil {
			c.JSON(http.StatusNotFound, response.Error("Device not found"))
			return
		}
	}
	since, until, err := db.NormalizeBackfillBounds(req.SinceDays, time.Now())
	if err != nil {
		if errors.Is(err, database.ErrNormalizeNotStarted) || errors.Is(err, database.ErrNormalizeBackfillEmpty) {
			c.JSON(http.StatusConflict, response.Error(err.Error()))
			return
		}
		httputil.InternalError(c, "Failed to resolve the backfill window", err)
		return
	}
	// Before the step-up: a 409 for an already-queued job must never consume
	// the caller's single-use TOTP code.
	if active, err := db.GetActiveNormalizeBackfillJob(); err != nil {
		httputil.InternalError(c, "Failed to check backfill jobs", err)
		return
	} else if active != nil {
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"error":   fmt.Sprintf("a backfill job is already %s", active.Status),
			"job_id":  active.ID,
		})
		return
	}
	est, err := db.EstimateNormalizeBackfill(since, until)
	if err != nil {
		httputil.InternalError(c, "Failed to estimate the backfill", err)
		return
	}
	if !est.Enough {
		c.JSON(http.StatusConflict, gin.H{
			"success":  false,
			"error":    fmt.Sprintf("insufficient disk headroom: the backfill may write ~%d MB and the data volume has %d MB free (twice the estimate is required)", est.Bytes>>20, est.FreeBytes>>20),
			"estimate": est,
		})
		return
	}
	username, userID, ok := h.reauthCaller(c, db, req.Password, req.TOTPCode)
	if !ok {
		return
	}
	job := &models.NormalizeBackfillJob{
		RequestedBy:    username,
		Since:          since,
		Until:          until,
		DeviceID:       req.DeviceID,
		Window:         req.Window,
		RateRowsPerSec: req.RateRowsPerSec,
	}
	if err := db.CreateNormalizeBackfillJob(job); err != nil {
		if errors.Is(err, database.ErrNormalizeBackfillActive) || errors.Is(err, database.ErrNormalizeBackfillEmpty) {
			c.JSON(http.StatusConflict, response.Error(err.Error()))
			return
		}
		httputil.InternalError(c, "Failed to queue the backfill", err)
		return
	}
	purgeAuditLog(c, db, username, userID, "normalize_backfill",
		fmt.Sprintf("job_id=%d since=%s until=%s device_id=%s rate=%d window=%q", job.ID,
			since.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339), optUint(req.DeviceID), req.RateRowsPerSec, req.Window),
		http.StatusAccepted)
	c.JSON(http.StatusAccepted, gin.H{"success": true, "data": job, "estimate": est})
}

func optUint(v *uint) string {
	if v == nil {
		return "all"
	}
	return fmt.Sprint(*v)
}

// GetNormalizeBackfill reports the latest job in any state (404 when none was
// ever queued) and the 10 before it, with `resumable` and a `hint` naming the
// next step for a failed / cancelled job. GET /admin/api/normalize/backfill/status.
func (h *Handler) GetNormalizeBackfill(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	job, err := db.GetLatestNormalizeBackfillJob()
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("No backfill job has been queued"))
			return
		}
		httputil.InternalError(c, "Failed to load backfill job", err)
		return
	}
	history, err := db.ListNormalizeBackfillJobs(11)
	if err != nil {
		httputil.InternalError(c, "Failed to list backfill jobs", err)
		return
	}
	if len(history) > 0 {
		history = history[1:] // the latest is `job`
	}
	resumable, hint := database.NormalizeBackfillResumable(job)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": job, "history": history, "resumable": resumable, "hint": hint})
}

// CancelNormalizeBackfill cancels the active job: pending → cancelled at once,
// running / paused → cancelling (the worker finishes it as cancelled between
// batches, cursor kept); 404 with no active job. The cancelled job can be
// resumed. POST /admin/api/normalize/backfill/cancel.
func (h *Handler) CancelNormalizeBackfill(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	job, err := db.GetActiveNormalizeBackfillJob()
	if err != nil {
		httputil.InternalError(c, "Failed to load backfill job", err)
		return
	}
	if job == nil {
		c.JSON(http.StatusNotFound, response.Error("No active backfill job"))
		return
	}
	status, applied, err := db.CancelNormalizeBackfillJob(job.ID)
	if err != nil {
		httputil.InternalError(c, "Failed to cancel backfill", err)
		return
	}
	if !applied {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("backfill job is %s and cannot be cancelled", job.Status)))
		return
	}
	usernameVal, _ := c.Get("username")
	userIDVal, _ := c.Get("user_id")
	username, _ := usernameVal.(string)
	userID, _ := userIDVal.(uint)
	purgeAuditLog(c, db, username, userID, "normalize_backfill_cancel",
		fmt.Sprintf("job_id=%d status=%s", job.ID, status), http.StatusOK)
	if fresh, err := db.GetNormalizeBackfillJob(job.ID); err == nil {
		job = fresh
	} else {
		job.Status = status
	}
	c.JSON(http.StatusOK, response.Success(job))
}

// ResumeNormalizeBackfill puts the latest job back to pending when it is
// cancelled or failed, keeping its cursor — the worker continues where it
// stopped. Re-authenticated and disk-prechecked (over the remaining window)
// like a start (it is one). 404 with no job, 409 when the latest job is not
// resumable, another is active, or the headroom is short.
// POST /admin/api/normalize/backfill/resume, body {password, totp_code}.
func (h *Handler) ResumeNormalizeBackfill(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req struct {
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	job, err := db.GetLatestNormalizeBackfillJob()
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("No backfill job has been queued"))
			return
		}
		httputil.InternalError(c, "Failed to load backfill job", err)
		return
	}
	if job.Status != database.NormalizeBackfillStatusCancelled && job.Status != database.NormalizeBackfillStatusFailed {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("backfill job %d is %s and cannot be resumed", job.ID, job.Status)))
		return
	}
	// The disk precheck again, over what is left: the volume may have filled
	// since the job was queued. Before the step-up, like the start's.
	from, until := database.NormalizeBackfillRemaining(job)
	est, err := db.EstimateNormalizeBackfill(from, until)
	if err != nil {
		httputil.InternalError(c, "Failed to estimate the backfill", err)
		return
	}
	if !est.Enough {
		c.JSON(http.StatusConflict, gin.H{
			"success":  false,
			"error":    fmt.Sprintf("insufficient disk headroom: the rest of the backfill may write ~%d MB and the data volume has %d MB free (twice the estimate is required)", est.Bytes>>20, est.FreeBytes>>20),
			"estimate": est,
		})
		return
	}
	username, userID, ok := h.reauthCaller(c, db, req.Password, req.TOTPCode)
	if !ok {
		return
	}
	applied, err := db.ResumeNormalizeBackfillJob(job.ID)
	if err != nil {
		if errors.Is(err, database.ErrNormalizeBackfillActive) {
			c.JSON(http.StatusConflict, response.Error(err.Error()))
			return
		}
		httputil.InternalError(c, "Failed to resume backfill", err)
		return
	}
	if !applied {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("backfill job %d is no longer resumable", job.ID)))
		return
	}
	purgeAuditLog(c, db, username, userID, "normalize_backfill_resume",
		fmt.Sprintf("job_id=%d cursor=%s/%d", job.ID, job.CurrentPartition, job.CursorID), http.StatusAccepted)
	if fresh, err := db.GetNormalizeBackfillJob(job.ID); err == nil {
		job = fresh
	}
	c.JSON(http.StatusAccepted, response.Success(job))
}
