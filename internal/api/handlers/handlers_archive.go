package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Operator escapes of the raw archive's retention gate (archive plan PR 5;
// internal/database/archive_gate.go). While a stream's archiving is enabled
// its raw rows are deleted only once the archive has verified them; these
// admin-only routes are the two ways an operator can intervene:
//
//   - POST /admin/api/archive/override releases one stream's gate (or both)
//     for at most database.ArchiveGateOverrideMaxHours, re-authenticated
//     (password + TOTP when enrolled) and audit-logged. Rows deleted under it
//     may never reach the archive. hours = 0 re-engages the gate at once: that
//     only restores the safe state, so it needs no step-up (still audited).
//   - POST /admin/api/archive/chunks/:id/reset puts a chunk parked in
//     needs_attention back to pending for a fresh export (re-authenticated,
//     audited); such a chunk stops the verified-through id, so without it the
//     gate would hold its table's deletes forever.
//
// GET /admin/api/archive/override reports each stream's state and the parked
// chunks. The CLI twin is `fwmon-api archive` (cmd/api/archive.go).

// archiveReasonMax bounds the operator's free-text reason.
const archiveReasonMax = 500

// archiveOverrideRequest is the body of POST /admin/api/archive/override.
type archiveOverrideRequest struct {
	// Stream is syslog, flows or all.
	Stream string `json:"stream"`
	// Hours the gate stays released: 1..24, or 0 to re-engage it now.
	Hours    *int   `json:"hours"`
	Reason   string `json:"reason"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// archiveGateStatus is one stream's gate as the API reports it.
type archiveGateStatus struct {
	Stream string `json:"stream"`
	// Enabled: the stream's archiving is on, so its deletes are gated
	// (as configured for this API process; the poller reads the same env).
	Enabled        bool       `json:"enabled"`
	OverrideActive bool       `json:"override_active"`
	OverrideUntil  *time.Time `json:"override_until,omitempty"`
}

func (h *Handler) archiveGateStatuses(db database.Store, now time.Time) []archiveGateStatus {
	out := make([]archiveGateStatus, 0, len(database.ArchiveGateStreams))
	for _, s := range database.ArchiveGateStreams {
		st := archiveGateStatus{Stream: s}
		if h.config != nil {
			st.Enabled = (s == database.ArchiveGateSyslog && h.config.Archive.SyslogEnabled) ||
				(s == database.ArchiveGateFlows && h.config.Archive.FlowsEnabled)
		}
		if until, active := db.ArchiveGateOverride(s, now); active {
			u := until.UTC()
			st.OverrideActive, st.OverrideUntil = true, &u
		}
		out = append(out, st)
	}
	return out
}

// GetArchiveGate reports the gate of every stream and the chunks parked in
// needs_attention. GET /admin/api/archive/override.
func (h *Handler) GetArchiveGate(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	parked, err := db.ListArchiveChunksNeedingAttention(100)
	if err != nil {
		httputil.InternalError(c, "Failed to list archive chunks", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"streams":         h.archiveGateStatuses(db, time.Now()),
		"needs_attention": parked,
		"max_hours":       database.ArchiveGateOverrideMaxHours,
	}})
}

// SetArchiveGateOverride releases (hours 1..24) or re-engages (hours 0) the
// gate of a stream. Checks, in order: body (400: stream, hours present and in
// range, a reason when releasing), then — releasing only — re-authentication
// (403). Each stream changed gets an archive_gate_override audit row with the
// stream, the end instant and the reason.
func (h *Handler) SetArchiveGateOverride(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req archiveOverrideRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	streams, err := database.ParseArchiveGateStreams(req.Stream)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error(err.Error()))
		return
	}
	if req.Hours == nil || *req.Hours < 0 || *req.Hours > database.ArchiveGateOverrideMaxHours {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("hours must be 0..%d (0 re-engages the gate)", database.ArchiveGateOverrideMaxHours)))
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > archiveReasonMax {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("reason must be at most %d characters", archiveReasonMax)))
		return
	}
	var until time.Time
	var username string
	var userID uint
	if *req.Hours > 0 {
		if reason == "" {
			c.JSON(http.StatusBadRequest, response.Error("reason is required to release the gate"))
			return
		}
		var ok bool
		if username, userID, ok = h.reauthCaller(c, db, req.Password, req.TOTPCode); !ok {
			return
		}
		until = time.Now().UTC().Add(time.Duration(*req.Hours) * time.Hour).Truncate(time.Second)
	} else {
		id, ok := sessionUserID(c)
		if !ok {
			return
		}
		userID, username = id, c.GetString("username")
	}
	for _, s := range streams {
		if err := db.SetArchiveGateOverride(s, until); err != nil {
			httputil.InternalError(c, "Failed to set the archive gate override", err)
			return
		}
		target := fmt.Sprintf("stream=%s until=%s reason=%q", s, until.Format(time.RFC3339), reason)
		if until.IsZero() {
			target = fmt.Sprintf("stream=%s re-engaged reason=%q", s, reason)
		}
		purgeAuditLog(c, db, username, userID, "archive_gate_override", target, http.StatusOK)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": h.archiveGateStatuses(db, time.Now())})
}

// archiveChunkResetRequest is the body of POST /admin/api/archive/chunks/:id/reset.
type archiveChunkResetRequest struct {
	Reason   string `json:"reason"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// ResetArchiveChunk puts a chunk parked in needs_attention back to pending.
// Checks, in order: id (400), body and reason (400), the chunk exists (404)
// and is parked (409) — both before the step-up, so a wrong target never
// spends a TOTP code — then re-authentication (403). Audit-logged as
// archive_chunk_reset. POST /admin/api/archive/chunks/:id/reset.
func (h *Handler) ResetArchiveChunk(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid chunk id"))
		return
	}
	var req archiveChunkResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > archiveReasonMax {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("reason is required (at most %d characters)", archiveReasonMax)))
		return
	}
	chunk, err := db.GetArchiveChunk(uint(id))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("Archive chunk not found"))
			return
		}
		httputil.InternalError(c, "Failed to load the archive chunk", err)
		return
	}
	if chunk.Status != models.ArchiveChunkNeedsAttention {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("chunk %d is %s, not %s", chunk.ID, chunk.Status, models.ArchiveChunkNeedsAttention)))
		return
	}
	username, userID, ok := h.reauthCaller(c, db, req.Password, req.TOTPCode)
	if !ok {
		return
	}
	reset, err := db.ResetArchiveChunk(c.Request.Context(), chunk.ID, "reset for re-export by "+username+": "+reason, time.Now())
	if err != nil {
		if errors.Is(err, database.ErrArchiveChunkNotParked) || errors.Is(err, database.ErrArchiveChunkSealed) {
			c.JSON(http.StatusConflict, response.Error(err.Error()))
			return
		}
		httputil.InternalError(c, "Failed to reset the archive chunk", err)
		return
	}
	purgeAuditLog(c, db, username, userID, "archive_chunk_reset",
		fmt.Sprintf("chunk_id=%d table=%s seq=%d mismatches=%d reason=%q", chunk.ID, chunk.SourceTable, chunk.Seq, chunk.Mismatches, reason),
		http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": reset})
}
