package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Archive restore to staging (archive plan PR 9; database/archive_restore.go).
// All routes are admin-only (adminOnlyRoutes); queueing, resuming and
// dropping a restore re-verify the caller's password (+ TOTP when enrolled)
// and are login-rate-limited and audit-logged — a restore downloads archived
// raw logs into the database and a drop deletes the staged copy. The poller's
// restore worker does the work; these handlers queue, cancel, resume, drop
// and report it. The CLI twin is `fwmon-api archive --restore ...`
// (cmd/api/archive.go).

// archiveRestoreRequest is the body of POST /admin/api/archive/restores.
type archiveRestoreRequest struct {
	// Stream: syslog, sflow, netflow or sflow-counters.
	Stream string `json:"stream"`
	// From / To: message-time UTC days, YYYY-MM-DD, inclusive.
	From     string `json:"from"`
	To       string `json:"to"`
	DeviceID *uint  `json:"device_id"`
	// Renormalize (syslog only) queues a normalized-event backfill over the
	// staging table; Replace makes it rewrite existing normalized rows.
	Renormalize bool `json:"renormalize"`
	Replace     bool `json:"replace"`
	// FromBucket selects from the bucket's sealed months instead of the
	// database manifest.
	FromBucket bool `json:"from_bucket"`
	// Force queues past a refused disk precheck (an unknown free space, or
	// too little): re-authenticated like every queue, and audited.
	Force          bool   `json:"force"`
	RateRowsPerSec int    `json:"rate_rows_per_sec"`
	TTLDays        int    `json:"ttl_days"`
	Password       string `json:"password"`
	TOTPCode       string `json:"totp_code"`
}

// archiveRestoreView is a job as the API lists it.
type archiveRestoreView struct {
	models.ArchiveRestoreJob
	// StagingBytes: the staging table's size with its indexes (-1 when it
	// does not exist).
	StagingBytes int64 `json:"staging_bytes"`
}

// archiveRestoreReady reports why this API's configuration cannot restore
// ("" when it can): the poller runs the restore with the same ARCHIVE_* keys.
func (h *Handler) archiveRestoreReady() string {
	if h.config == nil {
		return "no configuration"
	}
	if err := h.config.Archive.ValidateS3(); err != nil {
		return "the archive bucket is not configured: " + err.Error()
	}
	if !filepath.IsAbs(h.config.Archive.StagingDir) {
		return "ARCHIVE_STAGING_DIR is not set (an absolute directory for the downloads)"
	}
	return ""
}

// ListArchiveRestores lists the newest restore jobs with their staging
// tables' sizes. GET /admin/api/archive/restores.
func (h *Handler) ListArchiveRestores(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	jobs, err := db.ListArchiveRestoreJobs(50)
	if err != nil {
		httputil.InternalError(c, "Failed to list archive restores", err)
		return
	}
	out := make([]archiveRestoreView, len(jobs))
	for i, j := range jobs {
		out[i] = archiveRestoreView{ArchiveRestoreJob: j, StagingBytes: -1}
		if j.Status != models.ArchiveRestoreDropped {
			out[i].StagingBytes = db.ArchiveRestoreTableBytes(c.Request.Context(), j.StagingTable)
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": out})
}

// StartArchiveRestore queues a restore. Checks, in order: the bucket is
// configured (409), body and days (400), device exists (404), the plan —
// request rules (400), no archived object for the days (404), disk headroom
// (409 with the estimate, also when the free space is unknown; force queues
// past it) — then re-authentication (403), so a request that
// cannot run never spends a TOTP code. 202 with the job and the estimate;
// audit-logged as archive_restore.
func (h *Handler) StartArchiveRestore(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	if why := h.archiveRestoreReady(); why != "" {
		c.JSON(http.StatusConflict, response.Error(why))
		return
	}
	var body archiveRestoreRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	from, err := database.ParseArchiveRestoreDay(body.From)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("from: "+err.Error()))
		return
	}
	to, err := database.ParseArchiveRestoreDay(body.To)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("to: "+err.Error()))
		return
	}
	if body.DeviceID != nil {
		if _, err := db.GetDevice(*body.DeviceID); err != nil {
			c.JSON(http.StatusNotFound, response.Error("Device not found"))
			return
		}
	}
	req := database.ArchiveRestoreRequest{Stream: body.Stream, From: from, To: to, DeviceID: body.DeviceID, FromBucket: body.FromBucket,
		Renormalize: body.Renormalize, Replace: body.Replace, Rate: body.RateRowsPerSec, TTLDays: body.TTLDays, Force: body.Force}
	plan, err := db.PlanArchiveRestore(c.Request.Context(), req)
	switch {
	case errors.Is(err, database.ErrArchiveRestoreInvalid):
		c.JSON(http.StatusBadRequest, response.Error(err.Error()))
		return
	case errors.Is(err, database.ErrArchiveRestoreNothing):
		c.JSON(http.StatusNotFound, response.Error(err.Error()))
		return
	case errors.Is(err, database.ErrArchiveRestoreDisk):
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": err.Error(), "estimate": plan.Estimate})
		return
	case err != nil:
		httputil.InternalError(c, "Failed to plan the archive restore", err)
		return
	}
	username, userID, ok := h.reauthCaller(c, db, body.Password, body.TOTPCode)
	if !ok {
		return
	}
	plan.Request.RequestedBy = username
	job, err := db.CreateArchiveRestoreJob(c.Request.Context(), plan, time.Now())
	if err != nil {
		httputil.InternalError(c, "Failed to queue the archive restore", err)
		return
	}
	purgeAuditLog(c, db, username, userID, "archive_restore", archiveRestoreTarget(job), http.StatusAccepted)
	c.JSON(http.StatusAccepted, gin.H{"success": true, "data": job, "estimate": plan.Estimate})
}

// archiveRestoreTarget is a job's audit-log target.
func archiveRestoreTarget(j *models.ArchiveRestoreJob) string {
	dev := "all"
	if j.DeviceID != nil {
		dev = strconv.FormatUint(uint64(*j.DeviceID), 10)
	}
	return fmt.Sprintf("restore_id=%d stream=%s days=%s..%s device=%s staging=%s renormalize=%t replace=%t from_bucket=%t force=%t",
		j.ID, j.Stream, j.FromDay, j.ToDay, dev, j.StagingTable, j.Renormalize, j.Replace, j.FromBucket, j.Force)
}

// archiveRestoreJob loads the :id job, writing 400 / 404 / 500 itself.
func archiveRestoreJob(c *gin.Context, db database.Store) (*models.ArchiveRestoreJob, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid restore id"))
		return nil, false
	}
	job, err := db.GetArchiveRestoreJob(uint(id))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("Archive restore not found"))
			return nil, false
		}
		httputil.InternalError(c, "Failed to load the archive restore", err)
		return nil, false
	}
	return job, true
}

// CancelArchiveRestore asks a pending / running / loaded restore to stop (a
// running one stops between batches, its cursors kept). 409 in any other
// state. POST /admin/api/archive/restores/:id/cancel.
func (h *Handler) CancelArchiveRestore(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	job, ok := archiveRestoreJob(c, db)
	if !ok {
		return
	}
	status, applied, err := db.CancelArchiveRestoreJob(job.ID)
	if err != nil {
		httputil.InternalError(c, "Failed to cancel the archive restore", err)
		return
	}
	if !applied {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("restore %d is %s and cannot be cancelled", job.ID, job.Status)))
		return
	}
	if id, ok := sessionUserID(c); ok {
		purgeAuditLog(c, db, c.GetString("username"), id, "archive_restore_cancel", fmt.Sprintf("restore_id=%d", job.ID), http.StatusOK)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": job.ID, "status": status}})
}

// archiveRestoreAuth is the body of the resume and drop routes.
type archiveRestoreAuth struct {
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// ResumeArchiveRestore puts a failed or cancelled restore back in the queue
// (it continues from its objects' cursors). 409 in another state (before the
// step-up), then re-authentication (403).
// POST /admin/api/archive/restores/:id/resume.
func (h *Handler) ResumeArchiveRestore(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	job, ok := archiveRestoreJob(c, db)
	if !ok {
		return
	}
	var body archiveRestoreAuth
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if job.Status != models.ArchiveRestoreFailed && job.Status != models.ArchiveRestoreCancelled {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("restore %d is %s; only a failed or cancelled restore resumes", job.ID, job.Status)))
		return
	}
	username, userID, ok := h.reauthCaller(c, db, body.Password, body.TOTPCode)
	if !ok {
		return
	}
	applied, err := db.ResumeArchiveRestoreJob(job.ID)
	if err != nil {
		httputil.InternalError(c, "Failed to resume the archive restore", err)
		return
	}
	if !applied {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("restore %d changed state meanwhile", job.ID)))
		return
	}
	purgeAuditLog(c, db, username, userID, "archive_restore_resume", fmt.Sprintf("restore_id=%d", job.ID), http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": job.ID, "status": models.ArchiveRestorePending}})
}

// DropArchiveRestore drops a finished restore's staging table. 409 while the
// job is not finished or already dropped (before the step-up), then
// re-authentication (403), then 409 while a normalized-event backfill over
// the table is active. DELETE /admin/api/archive/restores/:id.
func (h *Handler) DropArchiveRestore(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	job, ok := archiveRestoreJob(c, db)
	if !ok {
		return
	}
	var body archiveRestoreAuth
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	switch job.Status {
	case models.ArchiveRestoreDone, models.ArchiveRestoreFailed, models.ArchiveRestoreCancelled, models.ArchiveRestoreLoaded:
	default:
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("restore %d is %s: %v", job.ID, job.Status, database.ErrArchiveRestoreBusy)))
		return
	}
	username, userID, ok := h.reauthCaller(c, db, body.Password, body.TOTPCode)
	if !ok {
		return
	}
	dropped, err := db.DropArchiveRestore(c.Request.Context(), job.ID, time.Now())
	if err != nil {
		if errors.Is(err, database.ErrArchiveRestoreBusy) || errors.Is(err, database.ErrArchiveRestoreInUse) {
			c.JSON(http.StatusConflict, response.Error(err.Error()))
			return
		}
		httputil.InternalError(c, "Failed to drop the archive restore", err)
		return
	}
	purgeAuditLog(c, db, username, userID, "archive_restore_drop", fmt.Sprintf("restore_id=%d staging=%s", job.ID, job.StagingTable), http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": dropped})
}
