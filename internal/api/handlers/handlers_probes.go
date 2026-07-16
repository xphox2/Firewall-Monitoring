package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/relay"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (h *Handler) GetProbes(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success([]models.Probe{}))
		return
	}

	probes, err := db.GetAllProbes()
	if err != nil {
		httputil.InternalError(c, "Failed to fetch probes", err)
		return
	}

	httputil.RedactProbes(probes)

	c.JSON(http.StatusOK, response.Success(probes))
}

func (h *Handler) GetProbe(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusNotFound, response.Error("Probe not found"))
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	probe, err := db.GetProbe(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Probe not found"))
		return
	}

	// LC-16: reads after create are always redacted (the list endpoint already
	// was; this one leaked the at-rest key hash + TLS paths).
	httputil.RedactProbe(probe)
	c.JSON(http.StatusOK, response.Success(probe))
}

func (h *Handler) CreateProbe(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var probe models.Probe
	if err := c.ShouldBindJSON(&probe); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if strings.TrimSpace(probe.Name) == "" {
		c.JSON(http.StatusBadRequest, response.Error("Name is required"))
		return
	}

	existing, err := db.GetProbeByName(probe.Name)
	if err == nil && existing != nil {
		c.JSON(http.StatusBadRequest, response.Error("Probe with this name already exists"))
		return
	}

	if probe.SiteID > 0 {
		_, err := db.GetSite(probe.SiteID)
		if err != nil {
			c.JSON(http.StatusBadRequest, response.Error("Site not found"))
			return
		}
	}

	if probe.ListenPort == 0 {
		probe.ListenPort = 8089
	}
	if probe.ListenPort < 1 || probe.ListenPort > 65535 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid listen port"))
		return
	}

	probe.ID = 0
	probe.Status = "offline"
	probe.ApprovalStatus = "pending"
	probe.ApprovedAt = nil
	probe.ApprovedBy = nil
	probe.RejectedAt = nil
	probe.RejectedReason = ""
	probe.LastSeen = time.Time{}
	probe.RegistrationKey = ""

	// AUDIT-017: store the key HASHED at rest. The plaintext is never persisted,
	// so a DB compromise yields no usable probe tokens. LC-16: the plaintext IS
	// returned once, in this create response — the creator (operator-level)
	// needs it to deploy the collector, and the only other reveal path
	// (RegenerateProbeKey) is admin-only. Every subsequent read stays redacted.
	plainKey := ""
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		log.Printf("Failed to generate registration key: %v", err)
	} else {
		plainKey = hex.EncodeToString(keyBytes)
		probe.RegistrationKey = database.HashProbeKey(plainKey)
	}

	if err := db.CreateProbe(&probe); err != nil {
		httputil.InternalError(c, "Failed to create probe", err)
		return
	}

	// Create SystemSetting so RegisterProbe can look up this probe by key.
	// The setting key embeds the HASHED key (RegisterProbe hashes the presented
	// token before looking it up), so no plaintext lands in the settings table.
	if probe.RegistrationKey != "" {
		setting := models.SystemSetting{
			Key:      "probe_registration_" + probe.RegistrationKey,
			Value:    probe.Name,
			Type:     "string",
			Label:    "Probe Registration Key for " + probe.Name,
			Category: "probes",
		}
		if err := db.Gorm().Create(&setting).Error; err != nil {
			log.Printf("Warning: Failed to create registration setting for probe %s: %v", probe.Name, err)
		}
	}

	httputil.RedactProbe(&probe)
	// LC-16 show-once reveal: after redacting everything else, put the
	// plaintext key (never the hash, never the mask) on the create response
	// only. Empty when key generation failed — the UI then points at the
	// admin-only Regenerate Key path instead of rendering a fake key.
	probe.RegistrationKey = plainKey
	c.JSON(http.StatusCreated, response.Success(probe))
}

func (h *Handler) UpdateProbe(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	probe, err := db.GetProbe(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Probe not found"))
		return
	}

	allowedFields := map[string]bool{
		"name":           true,
		"site_id":        true,
		"listen_address": true,
		"listen_port":    true,
		"enabled":        true,
		"server_url":     true,
		"description":    true,
		"tftp_server_ip": true,
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	filteredUpdates := httputil.FilterAllowedFields(updates, allowedFields)

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("No valid fields to update"))
		return
	}

	if portVal, ok := filteredUpdates["listen_port"]; ok {
		port, isNum := portVal.(float64)
		if !isNum || port < 1 || port > 65535 || port != float64(int(port)) {
			c.JSON(http.StatusBadRequest, response.Error("Invalid listen port"))
			return
		}
	}

	if siteIDVal, ok := filteredUpdates["site_id"]; ok {
		siteID, isNum := siteIDVal.(float64)
		if !isNum || siteID < 0 {
			c.JSON(http.StatusBadRequest, response.Error("Invalid site ID"))
			return
		}
		if siteID > 0 {
			_, err := db.GetSite(uint(siteID))
			if err != nil {
				c.JSON(http.StatusBadRequest, response.Error("Site not found"))
				return
			}
		}
	}

	if enabledVal, ok := filteredUpdates["enabled"]; ok {
		if _, isBool := enabledVal.(bool); !isBool {
			c.JSON(http.StatusBadRequest, response.Error("Invalid value for enabled"))
			return
		}
	}

	// Use Model(&Probe{}).Where(id) instead of Model(probe): `probe` was loaded
	// by GetProbe with Preload("Site"), so passing it to Updates makes gorm
	// re-derive site_id from the loaded Site association and clobber the map's
	// site_id (the same belongs-to write-back bug fixed for devices). A bare
	// model + WHERE honors the map values verbatim.
	if err := db.Gorm().Model(&models.Probe{}).Where("id = ?", id).Updates(filteredUpdates).Error; err != nil {
		httputil.InternalError(c, "Failed to update probe", err)
		return
	}

	updated, err := db.GetProbe(id)
	if err != nil {
		httputil.RedactProbe(probe)
		c.JSON(http.StatusOK, response.Success(probe))
		return
	}
	httputil.RedactProbe(updated)
	c.JSON(http.StatusOK, response.Success(updated))
}

func (h *Handler) DeleteProbe(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := db.DeleteProbe(id); err != nil {
		if errors.Is(err, database.ErrProbeHasDevices) {
			c.JSON(http.StatusConflict, response.Error(
				"Cannot delete probe: it still has devices assigned. Reassign or remove those devices first."))
			return
		}
		httputil.InternalError(c, "Failed to delete probe", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Probe deleted"))
}

// DecommissionProbe retires a replaced/decommissioned probe without deleting any
// data (the row and all its telemetry are kept, so running totals are preserved;
// it's just hidden from active lists). This is the primary "remove a probe" UI
// action — use DeleteProbe only for probes that never collected data.
func (h *Handler) DecommissionProbe(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if err := db.DecommissionProbe(id); err != nil {
		if errors.Is(err, database.ErrProbeHasDevices) {
			c.JSON(http.StatusConflict, response.Error(
				"Cannot decommission probe: it still has devices assigned. Reassign those devices to the replacement probe first."))
			return
		}
		httputil.InternalError(c, "Failed to decommission probe", err)
		return
	}
	c.JSON(http.StatusOK, response.Message("Probe decommissioned"))
}

// RecommissionProbe reverses a decommission (restores the probe to active).
func (h *Handler) RecommissionProbe(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if err := db.RecommissionProbe(id); err != nil {
		httputil.InternalError(c, "Failed to restore probe", err)
		return
	}
	c.JSON(http.StatusOK, response.Message("Probe restored"))
}

// GetTelemetryTotals returns orphan-safe, probe-independent running totals of
// all ingested telemetry. Used by the "Data Totals (All Probes)" card so the
// numbers never drop when a probe is decommissioned or deleted.
func (h *Handler) GetTelemetryTotals(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	totals, err := db.GetTelemetryTotals()
	if err != nil {
		httputil.InternalError(c, "Failed to get telemetry totals", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(totals))
}

type ApproveProbeRequest struct {
	Notes string `json:"notes"`
}

func (h *Handler) ApproveProbe(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var req ApproveProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, response.Error("Not authenticated"))
		return
	}
	adminID, ok := userID.(uint)
	if !ok {
		httputil.InternalError(c, "Invalid session data", nil)
		return
	}

	if err := db.ApproveProbe(id, adminID); err != nil {
		httputil.InternalError(c, "Failed to approve probe", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Probe approved successfully"))
}

type RejectProbeRequest struct {
	Reason string `json:"reason" binding:"required"`
}

func (h *Handler) RejectProbe(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var req RejectProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Reason is required"))
		return
	}

	if _, exists := c.Get("user_id"); !exists {
		c.JSON(http.StatusUnauthorized, response.Error("Not authenticated"))
		return
	}

	if err := db.RejectProbe(id, req.Reason); err != nil {
		httputil.InternalError(c, "Failed to reject probe", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Probe rejected successfully"))
}

type TestProbeRequest struct {
	ListenAddress string `json:"listen_address" binding:"required"`
	ListenPort    int    `json:"listen_port"`
	ServerURL     string `json:"server_url"`
	TLSCertPath   string `json:"tls_cert_path"`
	TLSKeyPath    string `json:"tls_key_path"`
}

func (h *Handler) TestProbeConnection(c *gin.Context) {
	var req TestProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if req.ListenPort == 0 {
		req.ListenPort = 8089
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid listen port"))
		return
	}

	// Validate address to prevent SSRF / internal port scanning
	if !isValidExternalIP(req.ListenAddress) {
		c.JSON(http.StatusBadRequest, response.Error("Invalid or disallowed listen address"))
		return
	}

	// v0.10.219 (bundle H3): use net.JoinHostPort so IPv6 listen addresses
	// get bracketed correctly. `fmt.Sprintf("%s:%d", host, port)` produces
	// `2001:db8::1:9876` instead of `[2001:db8::1]:9876` for IPv6 hosts,
	// which net.DialTimeout would parse incorrectly (treating `9876` as
	// part of the address). JoinHostPort handles both v4 and v6.
	address := net.JoinHostPort(req.ListenAddress, strconv.Itoa(req.ListenPort))

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"success": false,
			"message": "Failed to connect to probe",
			"online":  false,
		}))
		return
	}
	defer conn.Close()

	c.JSON(http.StatusOK, response.Success(gin.H{
		"success": true,
		"message": "Connected successfully",
		"online":  true,
	}))
}

// probeErr emits a consistent error payload for the probe-facing endpoints
// (v0.10.217, bundle D4). Historically RegisterProbe / TestProbeConnection
// used a top-level `message` field while ProbeHeartbeat used `error` —
// any client that wanted to display the reason had to read both. This
// helper emits BOTH on every error so older collector binaries keep
// working unchanged while new clients can read just `error`.
func probeErr(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"success": false, "error": msg, "message": msg})
}

func (h *Handler) RegisterProbe(c *gin.Context) {
	if h.db == nil {
		probeErr(c, http.StatusServiceUnavailable, "Database not available")
		return
	}

	var req struct {
		RegistrationKey string `json:"registration_key"`
		// Wire-format version the probe speaks. *int (not int) so we can
		// distinguish "field absent" (a pre-handshake collector) from
		// "field present and set to 0" (a probe explicitly claiming a
		// too-old version). Absent defaults to v1 for backward compat; any
		// other value outside [SchemaVersionMin, SchemaVersionMax] is
		// rejected with HTTP 426 (Upgrade Required) and the supported range
		// in the X-Probe-Schema-Version-Supported response header.
		SchemaVersion *int `json:"schema_version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		probeErr(c, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.RegistrationKey == "" {
		probeErr(c, http.StatusBadRequest, "Registration key required")
		return
	}

	// Resolve the effective schema version. A nil pointer means the field
	// was absent → default to v1. Any other value is validated against the
	// supported range before any auth or DB lookup runs (cheap, no probe-
	// state side effects). The selected version is echoed back so the probe
	// can self-report what the server chose.
	selectedVersion := 1
	if req.SchemaVersion != nil {
		if *req.SchemaVersion < relay.SchemaVersionMin || *req.SchemaVersion > relay.SchemaVersionMax {
			c.Header("X-Probe-Schema-Version-Supported",
				fmt.Sprintf("%d-%d", relay.SchemaVersionMin, relay.SchemaVersionMax))
			probeErr(c, http.StatusUpgradeRequired,
				fmt.Sprintf("Probe schema_version %d not supported (server supports %d-%d); see MIGRATING.md",
					*req.SchemaVersion, relay.SchemaVersionMin, relay.SchemaVersionMax))
			return
		}
		selectedVersion = *req.SchemaVersion
	}

	// AUDIT-017: keys are stored hashed; hash the presented key to look it up.
	keyHash := database.HashProbeKey(req.RegistrationKey)

	// Primary lookup: find the probe directly by its stored (hashed)
	// registration_key — the same column heartbeat auth uses
	// (authenticateProbeByBearer). This is robust to a renamed probe: the legacy
	// path below keyed off a `probe_registration_<hash>` setting whose Value is
	// the probe NAME captured at create time, so renaming a probe (UpdateProbe
	// allows it) left the setting stale and made registration 404 with "Probe
	// not found" even though the probe still existed.
	existingProbe := &models.Probe{}
	err := h.db.Gorm().Where("registration_key = ?", keyHash).First(existingProbe).Error
	if err != nil || existingProbe.ID == 0 {
		// Legacy fallback: the settings indirection, for any probe whose
		// registration_key column predates being stored on the row.
		var setting models.SystemSetting
		if e := h.db.Gorm().Where("key = ?", "probe_registration_"+keyHash).First(&setting).Error; e != nil || setting.Value == "" {
			probeErr(c, http.StatusUnauthorized, "Invalid registration key")
			return
		}
		existingProbe = &models.Probe{}
		if e := h.db.Gorm().Where("name = ?", setting.Value).First(existingProbe).Error; e != nil || existingProbe.ID == 0 {
			probeErr(c, http.StatusNotFound, "Probe not found — it may have been deleted")
			return
		}
	}

	// M7 of the 2026-07-01 audit: an admin's rejection or decommission must
	// not be reversible by the key-holder. Pre-fix, any probe that wasn't
	// already approved+online was unconditionally flipped back to
	// approved+online below — so a REJECTED probe (RejectProbe leaves the
	// registration key valid) silently re-approved itself by re-POSTing this
	// unauthenticated endpoint, and a decommissioned one resurrected. Both are
	// admin decisions: reactivation goes through the admin UI
	// (approve / RecommissionProbe), never through the wire.
	if existingProbe.ApprovalStatus == "rejected" {
		probeErr(c, http.StatusForbidden, "Probe registration was rejected by an administrator")
		return
	}
	if existingProbe.DecommissionedAt != nil || !existingProbe.Enabled {
		probeErr(c, http.StatusGone, "Probe is decommissioned or disabled — re-commission it in the admin UI first")
		return
	}

	// If already approved and online, just return success. Still PERSIST the
	// negotiated schema_version when it changed — this path is exactly what a
	// freshly-upgraded collector hits (its probe row is already
	// approved+online), and the heartbeat handler gates schema-v4 command
	// delivery on the stored value, so skipping the write here would leave an
	// upgraded collector stuck without commands until a lifecycle bounce.
	if existingProbe.ApprovalStatus == "approved" && existingProbe.Status == "online" {
		if existingProbe.SchemaVersion != selectedVersion {
			if err := h.db.Gorm().Model(&models.Probe{}).Where("id = ?", existingProbe.ID).
				Update("schema_version", selectedVersion).Error; err != nil {
				httputil.InternalError(c, "Failed to update probe schema version", err)
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"success":        true,
			"probe_id":       existingProbe.ID,
			"probe_name":     existingProbe.Name,
			"approved":       true,
			"schema_version": selectedVersion,
		})
		return
	}

	// Link the remote probe: set online, auto-approve (admin created it
	// explicitly). schema_version persists the NEGOTIATED wire version — the
	// heartbeat handler reads it to decide whether this probe may receive
	// schema-v4 pending_commands.
	now := time.Now()
	if err := h.db.Gorm().Model(existingProbe).Updates(map[string]interface{}{
		"status":          "online",
		"approval_status": "approved",
		"approved_at":     now,
		"last_seen":       now,
		"schema_version":  selectedVersion,
	}).Error; err != nil {
		httputil.InternalError(c, "Failed to update probe status", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":        true,
		"probe_id":       existingProbe.ID,
		"probe_name":     existingProbe.Name,
		"approved":       true,
		"schema_version": selectedVersion,
	})
}

func (h *Handler) RegenerateProbeKey(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	probe, err := db.GetProbe(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Probe not found"))
		return
	}

	// AUDIT-085: generate the new key BEFORE any DB write, then do every
	// write (update probe → delete old setting → create new setting) in a
	// single transaction. The pre-fix code deleted the old key's
	// SystemSetting first and only *logged a warning* if the new setting
	// failed to write — so a mid-sequence failure could leave the probe with
	// a rotated key but no usable registration setting, locking it out
	// permanently. Generating first + transacting means any failure rolls the
	// whole thing back and the probe keeps its existing, working key.
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		httputil.InternalError(c, "Failed to generate key", err)
		return
	}
	newKey := hex.EncodeToString(keyBytes) // plaintext — returned once below
	// AUDIT-017: store the HASH at rest; the stored old key is already hashed,
	// so the old setting's key (probe_registration_<hash>) matches for deletion.
	hashedNew := database.HashProbeKey(newKey)
	oldKey := probe.RegistrationKey

	if err := db.Gorm().Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(probe).Update("registration_key", hashedNew).Error; err != nil {
			return err
		}
		if oldKey != "" {
			if err := tx.Where("key = ?", "probe_registration_"+oldKey).Delete(&models.SystemSetting{}).Error; err != nil {
				return err
			}
		}
		return tx.Create(&models.SystemSetting{
			Key:      "probe_registration_" + hashedNew,
			Value:    probe.Name,
			Type:     "string",
			Label:    "Probe Registration Key for " + probe.Name,
			Category: "probes",
		}).Error
	}); err != nil {
		log.Printf("RegenerateProbeKey: rollback for probe %s (key unchanged): %v", probe.Name, err)
		httputil.InternalError(c, "Failed to regenerate key", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"registration_key": newKey,
	}))
}

func (h *Handler) ProbeHeartbeat(c *gin.Context) {
	if h.db == nil {
		probeErr(c, http.StatusServiceUnavailable, "Database not available")
		return
	}

	// Authenticate probe by Bearer token
	probe, ok := h.authenticateProbeByBearer(c)
	if !ok {
		return
	}

	var req struct {
		ProbeID uint   `json:"probe_id"`
		Status  string `json:"status"`
		// ObservedHostKeys maps device ID -> the SSH host-key fingerprint the
		// probe last saw for it (SSH host-key change detection). Optional;
		// absent for probes that don't report it.
		ObservedHostKeys map[uint]string `json:"observed_host_keys"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		probeErr(c, http.StatusBadRequest, "Invalid request")
		return
	}

	// Validate that the probe_id in the body matches the authenticated probe
	if req.ProbeID != 0 && req.ProbeID != probe.ID {
		probeErr(c, http.StatusForbidden, "Probe ID mismatch")
		return
	}

	// M7 of the 2026-07-01 audit: a still-running collector must not resurrect
	// a rejected/decommissioned/disabled probe. Pre-fix, this handler wrote
	// status='online' + fresh last_seen unconditionally, so within 30s of an
	// admin decommission the probe flipped back to 'online' — permanently,
	// since the fresh last_seen also kept it immune to the
	// MarkStaleProbesOffline sweep. 410 tells the collector the probe is gone
	// on purpose (non-retryable), not that its auth is transiently broken.
	if probe.ApprovalStatus == "rejected" || probe.DecommissionedAt != nil || !probe.Enabled {
		probeErr(c, http.StatusGone, "Probe is rejected or decommissioned — heartbeat refused")
		return
	}

	// Validate status against allowed values
	validStatuses := map[string]bool{"online": true, "offline": true, "degraded": true}
	if req.Status != "" && !validStatuses[req.Status] {
		probeErr(c, http.StatusBadRequest, "Invalid status value")
		return
	}

	status := req.Status
	if status == "" {
		status = "online"
	}

	h.db.Gorm().Model(probe).Updates(map[string]interface{}{
		"last_seen": time.Now(),
		"status":    status,
	})

	if len(req.ObservedHostKeys) > 0 {
		h.processObservedHostKeys(probe.ID, req.ObservedHostKeys)
	}

	resp := gin.H{"success": true}

	// Relay schema v4: deliver queued commands on the heartbeat response —
	// ONLY for a probe whose NEGOTIATED schema version (persisted at register)
	// is ≥ 4. A v3 collector ignores unknown JSON fields, but gating here
	// keeps undelivered commands in `pending` (visible as such in the admin
	// UI) instead of burning delivery attempts against a collector that can't
	// execute them. Claiming flips pending→dispatched and increments Attempts;
	// an unacknowledged dispatched command is re-delivered on a later
	// heartbeat; anything past expires_at is terminally expired inside
	// ClaimProbeCommands. SECURITY: payloads may carry credentials — never log
	// them (log command_id/type only), and rely on the bearer-authed HTTPS
	// channel for transport.
	if probe.SchemaVersion >= 4 {
		cmds, err := h.db.ClaimProbeCommands(probe.ID)
		if err != nil {
			log.Printf("ProbeHeartbeat: claim commands for probe %d: %v", probe.ID, err)
		} else if len(cmds) > 0 {
			out := make([]relay.PendingCommand, 0, len(cmds))
			for i := range cmds {
				out = append(out, relay.PendingCommand{
					CommandID: cmds[i].CommandID,
					DeviceID:  cmds[i].DeviceID,
					Type:      cmds[i].Type,
					Payload:   cmds[i].Payload,
					ExpiresAt: cmds[i].ExpiresAt,
				})
			}
			resp["pending_commands"] = out
		}
	}

	c.JSON(http.StatusOK, resp)
}

// ReceiveCommandResult is POST /api/probes/:id/command-result (relay schema
// v4): the collector's outcome report for one delivered command. Probe-authed
// (validateProbe: bearer token + lifecycle gates) and idempotent by
// command_id — CompleteProbeCommand keeps the FIRST terminal result and
// no-ops replays, so collector retries and heartbeat-redelivery races are
// safe. A result for another probe's command is a 404 (the lookup is scoped
// to the authenticated probe). SECURITY: never log req.Result — command
// output may echo device configuration.
func (h *Handler) ReceiveCommandResult(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var req relay.CommandResultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if req.CommandID == "" {
		c.JSON(http.StatusBadRequest, response.Error("command_id required"))
		return
	}
	if req.Status != database.ProbeCommandStatusSucceeded && req.Status != database.ProbeCommandStatusFailed {
		c.JSON(http.StatusBadRequest, response.Error("status must be succeeded or failed"))
		return
	}

	cmd, applied, err := h.db.CompleteProbeCommand(probe.ID, req.CommandID, req.Status, req.Result)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, response.Error("Unknown command_id for this probe"))
			return
		}
		log.Printf("ReceiveCommandResult: probe %d command %s: %v", probe.ID, req.CommandID, err)
		httputil.InternalError(c, "Failed to record command result", err)
		return
	}
	// A first-time SUCCEEDED result for a command whose execution contacts the
	// device (SSH/API) is reachability evidence, exactly like a successful
	// poll. noop never qualifies (it completes inside the collector), and a
	// failure never bumps — it may mean the device was unreachable. `now` is
	// correct here (not a row timestamp): commands are never spooled and the
	// TTL bounds staleness to minutes.
	if applied && req.Status == database.ProbeCommandStatusSucceeded &&
		cmd.DeviceID > 0 && database.ProbeCommandTouchesDevice(cmd.Type) {
		h.bumpDevicesOnline(map[uint]time.Time{cmd.DeviceID: time.Now()}, time.Now())
	}
	log.Printf("ReceiveCommandResult: probe %d command %s -> %s (applied=%v)", probe.ID, req.CommandID, req.Status, applied)
	c.JSON(http.StatusOK, response.Success(gin.H{"applied": applied}))
}

// CreateProbeCommand is the minimal admin enqueue endpoint
// (POST /admin/api/probes/:id/commands) that proves the schema-v4 command
// channel end-to-end. PR-1 deliberately supports ONLY the `noop` type — the
// collector executes it as an immediate success — so the round-trip
// (enqueue → heartbeat delivery → execution → result ingest) can be verified
// before any command type that writes device configuration exists. Payload is
// encrypted at rest by EnqueueProbeCommand and never logged or echoed back.
func (h *Handler) CreateProbeCommand(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	probe, err := db.GetProbe(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Probe not found"))
		return
	}

	var req struct {
		Type       string `json:"type"`
		DeviceID   uint   `json:"device_id"`
		Payload    string `json:"payload"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	// Allow-list of enqueueable command types. Grows in later PRs
	// (apply_ipsec/remove_ipsec/status_ipsec); rejecting everything else here
	// keeps an unknown/mistyped command from sitting pending until expiry.
	if req.Type != database.ProbeCommandTypeNoop {
		c.JSON(http.StatusBadRequest, response.Error("Unsupported command type (PR-1 supports: noop)"))
		return
	}

	// A device-targeted command must target a device THIS probe manages —
	// defense before any write-type command exists.
	if req.DeviceID > 0 {
		dev, derr := db.GetDevice(req.DeviceID)
		if derr != nil || dev.ProbeID == nil || *dev.ProbeID != probe.ID {
			c.JSON(http.StatusBadRequest, response.Error("device_id is not managed by this probe"))
			return
		}
	}
	// Cap TTL: default 15m, hard max 1h, so a wedged command can't outlive its
	// usefulness and fire stale.
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 900
	}
	if ttl > 3600 {
		ttl = 3600
	}

	cmd := &models.ProbeCommand{
		ProbeID:   probe.ID,
		DeviceID:  req.DeviceID,
		Type:      req.Type,
		Payload:   req.Payload,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	if err := db.EnqueueProbeCommand(cmd); err != nil {
		httputil.InternalError(c, "Failed to enqueue command", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"command_id": cmd.CommandID,
		"status":     cmd.Status,
		"expires_at": cmd.ExpiresAt,
	}))
}

// GetProbeCommands lists a probe's recent commands for the admin UI
// (GET /admin/api/probes/:id/commands). Payload is json:"-" on the model AND
// left encrypted by the query layer, so it cannot leak through this response.
func (h *Handler) GetProbeCommands(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	limit := 50
	if l, err := strconv.Atoi(c.DefaultQuery("limit", "50")); err == nil {
		limit = l
	}
	cmds, err := db.GetProbeCommands(id, limit)
	if err != nil {
		httputil.InternalError(c, "Failed to list probe commands", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(cmds))
}

// CancelProbeCommand force-expires a still-live command — the admin cleanup for
// a command wedged against an offline probe (DELETE
// /admin/api/probes/:id/commands/:cmdid). No-op if already terminal.
func (h *Handler) CancelProbeCommand(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	cmdID := c.Param("cmdid")
	if cmdID == "" {
		c.JSON(http.StatusBadRequest, response.Error("Missing command id"))
		return
	}
	applied, err := db.CancelProbeCommand(id, cmdID)
	if err != nil {
		httputil.InternalError(c, "Failed to cancel command", err)
		return
	}
	if !applied {
		c.JSON(http.StatusNotFound, response.Error("Command not found or already terminal"))
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"cancelled": true}))
}

// processObservedHostKeys applies the SSH host-key change-detection rule for the
// fingerprints a probe reported on its heartbeat. For each device assigned to
// this probe: a blank stored key is pinned (trust-on-first-use); an unchanged
// key is a no-op; a changed key fires one CRITICAL SSH_HOST_KEY_CHANGED alert
// and then re-pins to the new fingerprint. Devices not assigned to this probe
// are ignored, so a probe can only report for its own devices.
func (h *Handler) processObservedHostKeys(probeID uint, observed map[uint]string) {
	for deviceID, fp := range observed {
		if fp == "" {
			continue
		}
		var device models.Device
		if err := h.db.Gorm().Where("id = ? AND probe_id = ?", deviceID, probeID).First(&device).Error; err != nil {
			continue // not this probe's device, or it no longer exists
		}

		known := splitHostKeys(device.SSHHostKeys)
		if slices.Contains(known, fp) {
			continue // already a known-good key for this device — no-op
		}

		firstContact := len(known) == 0
		known = append(known, fp)
		h.db.Gorm().Model(&models.Device{}).Where("id = ?", device.ID).Update("ssh_host_key", strings.Join(known, "\n"))

		if firstContact || h.alertManager == nil {
			continue // trust-on-first-use: learn the first key silently
		}

		// A new key that correlates with a recent HA failover is expected
		// (cluster members present distinct host keys) → WARNING; an unexplained
		// new key → CRITICAL "possible MITM". RecentHAFailover returns false for
		// non-HA devices, so they default to CRITICAL.
		haFailover := h.db.RecentHAFailover(device.ID, time.Hour)
		if err := h.alertManager.CheckSSHHostKeyChanged(&device, fp, haFailover); err != nil {
			log.Printf("ProbeHeartbeat: SSH host-key alert for device %d: %v", device.ID, err)
		}
	}
}

// splitHostKeys parses the newline-joined known-host-key set, dropping blanks.
func splitHostKeys(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// authenticateProbeByBearer extracts the Bearer token from the Authorization header
// and looks up the probe by its registration key. Returns the probe if authenticated.
func (h *Handler) authenticateProbeByBearer(c *gin.Context) (*models.Probe, bool) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, response.Error("Authorization required"))
		return nil, false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		c.JSON(http.StatusUnauthorized, response.Error("Authorization required"))
		return nil, false
	}

	// Look up probe by registration key (AUDIT-017: stored hashed).
	var probe models.Probe
	if err := h.db.Gorm().Where("registration_key = ?", database.HashProbeKey(token)).First(&probe).Error; err != nil {
		c.JSON(http.StatusUnauthorized, response.Error("Invalid authorization"))
		return nil, false
	}
	return &probe, true
}

// validateProbe parses probe ID from URL param and checks it exists, is approved,
// and the caller provides a valid Bearer token matching the probe's registration key.
//
// Status-code contract (must stay consistent with RegisterProbe/ProbeHeartbeat —
// the collector's retry taxonomy keys off these):
//   - 404: probe ID unknown
//   - 403: probe exists but is not approved (admin decision pending/rejected)
//   - 401: missing or invalid Bearer token
//   - 410: probe is decommissioned or disabled — deliberate admin retirement,
//     non-retryable; the collector must quiesce, NOT re-register
func (h *Handler) validateProbe(c *gin.Context) (*models.Probe, bool) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return nil, false
	}
	id := c.Param("id")
	idUint, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid probe ID"))
		return nil, false
	}
	probe, err := h.db.GetProbe(uint(idUint))
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Probe not found"))
		return nil, false
	}
	if probe.ApprovalStatus != "approved" {
		c.JSON(http.StatusForbidden, response.Error("Probe not approved"))
		return nil, false
	}
	// Verify Bearer token matches this probe's registration key
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, response.Error("Authorization required"))
		return nil, false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	// AUDIT-016: constant-time compare against the stored registration key
	// after the indexed PK lookup above. A naive `token != probe.Registration
	// Key` is a byte-by-byte compare that an attacker on the LAN can use as
	// a single-character oracle (Go strings short-circuit on first mismatch).
	// subtle.ConstantTimeCompare returns 1 only if both lengths and all bytes
	// match; it does not short-circuit on content.
	// AUDIT-017: stored key is hashed; hash the presented token and compare the
	// digests in constant time (preserves the AUDIT-016 timing-safety property).
	if token == "" || subtle.ConstantTimeCompare([]byte(database.HashProbeKey(token)), []byte(probe.RegistrationKey)) != 1 {
		c.JSON(http.StatusUnauthorized, response.Error("Invalid authorization"))
		return nil, false
	}

	// M7 of the 2026-07-01 audit: enforce the lifecycle flags on the data
	// plane. DecommissionProbe deliberately leaves approval_status='approved'
	// (to preserve telemetry attribution), so the approval check alone let a
	// decommissioned or admin-disabled probe keep ingesting — and each POST
	// refreshed last_seen/last_data_received, making the retired probe look
	// live again.
	//
	// LC-01 of the 2026-07-04 audit: this must be 410 Gone, matching
	// RegisterProbe and ProbeHeartbeat for the SAME lifecycle state. The
	// pre-fix 403 here fed the collector's "auth broken → re-register" branch,
	// so a decommission produced a permanent re-register/requeue loop (403 on
	// ingest → deapprove + Register → 410 → requeue batch as transient →
	// repeat forever) instead of the documented non-retryable quiesce. 403
	// stays reserved for not-approved above; 401 for bad/missing key. The
	// check sits AFTER bearer verification (like ProbeHeartbeat) so lifecycle
	// state is only disclosed to the key-holder and never reached pre-auth.
	if probe.DecommissionedAt != nil || !probe.Enabled {
		c.JSON(http.StatusGone, response.Error("Probe is decommissioned or disabled — re-commission it in the admin UI first"))
		return nil, false
	}

	// Update last_seen and last_data_received on any data submission
	now := time.Now()
	h.db.Gorm().Model(probe).Updates(map[string]interface{}{
		"last_seen":          now,
		"last_data_received": now,
	})
	return probe, true
}

// probeDeviceIDs returns the set of device IDs assigned to the given probe.
// Used by data ingestion handlers to reject data for unassigned devices.
//
// On a lookup error it returns a NON-NIL EMPTY map (deny-all), never nil. The
// ingestion guards enforce only when the map is non-nil, so returning nil on
// error made the allow-list fail OPEN — during a transient DB error window an
// authenticated probe could push telemetry (including forged config revisions)
// attributed to devices assigned to a different probe. A security allow-list
// must fail closed: on error, deny everything and let the collector retry.
func (h *Handler) probeDeviceIDs(probeID uint) map[uint]bool {
	deviceIDs, err := h.db.GetDeviceIDsByProbe(probeID)
	if err != nil {
		log.Printf("probeDeviceIDs: device lookup failed for probe %d, denying all device-attributed telemetry this batch: %v", probeID, err)
		return map[uint]bool{}
	}
	ids := make(map[uint]bool, len(deviceIDs))
	for _, id := range deviceIDs {
		ids[id] = true
	}
	return ids
}

func (h *Handler) GetProbeStats(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	now := time.Now().UTC()
	hourAgo := now.Add(-1 * time.Hour)

	// Total counts
	var syslogCount, trapCount, flowCount, pingCount int64
	if err := db.Gorm().Model(&models.SyslogMessage{}).Where("probe_id = ?", id).Count(&syslogCount).Error; err != nil {
		httputil.InternalError(c, "Failed to count syslog messages", err)
		return
	}
	if err := db.Gorm().Model(&models.TrapEvent{}).Where("probe_id = ?", id).Count(&trapCount).Error; err != nil {
		httputil.InternalError(c, "Failed to count trap events", err)
		return
	}
	if err := db.Gorm().Model(&models.FlowSample{}).Where("probe_id = ?", id).Count(&flowCount).Error; err != nil {
		httputil.InternalError(c, "Failed to count flow samples", err)
		return
	}
	if err := db.Gorm().Model(&models.PingResult{}).Where("probe_id = ?", id).Count(&pingCount).Error; err != nil {
		httputil.InternalError(c, "Failed to count ping results", err)
		return
	}

	// Last hour counts
	var syslogLastHour, trapLastHour, flowLastHour, pingLastHour int64
	if err := db.Gorm().Model(&models.SyslogMessage{}).Where("probe_id = ? AND timestamp > ?", id, hourAgo).Count(&syslogLastHour).Error; err != nil {
		syslogLastHour = 0
	}
	if err := db.Gorm().Model(&models.TrapEvent{}).Where("probe_id = ? AND timestamp > ?", id, hourAgo).Count(&trapLastHour).Error; err != nil {
		trapLastHour = 0
	}
	if err := db.Gorm().Model(&models.FlowSample{}).Where("probe_id = ? AND timestamp > ?", id, hourAgo).Count(&flowLastHour).Error; err != nil {
		flowLastHour = 0
	}
	if err := db.Gorm().Model(&models.PingResult{}).Where("probe_id = ? AND timestamp > ?", id, hourAgo).Count(&pingLastHour).Error; err != nil {
		pingLastHour = 0
	}

	// Hourly breakdown for last 24 hours
	hourlyBreakdown := make([]gin.H, 0, 24)
	for i := 23; i >= 0; i-- {
		hourStart := now.Add(-time.Duration(i) * time.Hour)
		hourStart = time.Date(hourStart.Year(), hourStart.Month(), hourStart.Day(), hourStart.Hour(), 0, 0, 0, time.UTC)
		hourEnd := hourStart.Add(time.Hour)

		var hSyslog, hTrap, hFlow, hPing int64
		if err := db.Gorm().Model(&models.SyslogMessage{}).Where("probe_id = ? AND timestamp >= ? AND timestamp < ?", id, hourStart, hourEnd).Count(&hSyslog).Error; err != nil {
			log.Printf("GetProbeStats: failed to count syslog for hour %s: %v", hourStart.Format("15:04"), err)
			hSyslog = 0
		}
		if err := db.Gorm().Model(&models.TrapEvent{}).Where("probe_id = ? AND timestamp >= ? AND timestamp < ?", id, hourStart, hourEnd).Count(&hTrap).Error; err != nil {
			log.Printf("GetProbeStats: failed to count traps for hour %s: %v", hourStart.Format("15:04"), err)
			hTrap = 0
		}
		if err := db.Gorm().Model(&models.FlowSample{}).Where("probe_id = ? AND timestamp >= ? AND timestamp < ?", id, hourStart, hourEnd).Count(&hFlow).Error; err != nil {
			log.Printf("GetProbeStats: failed to count flows for hour %s: %v", hourStart.Format("15:04"), err)
			hFlow = 0
		}
		if err := db.Gorm().Model(&models.PingResult{}).Where("probe_id = ? AND timestamp >= ? AND timestamp < ?", id, hourStart, hourEnd).Count(&hPing).Error; err != nil {
			log.Printf("GetProbeStats: failed to count pings for hour %s: %v", hourStart.Format("15:04"), err)
			hPing = 0
		}

		hourlyBreakdown = append(hourlyBreakdown, gin.H{
			"timestamp": hourStart.Format("2006-01-02T15:04:05Z"),
			"syslog":    hSyslog,
			"traps":     hTrap,
			"flows":     hFlow,
			"pings":     hPing,
			"total":     hSyslog + hTrap + hFlow + hPing,
		})
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"probe_id": id,
		"syslog":   syslogCount,
		"traps":    trapCount,
		"flows":    flowCount,
		"pings":    pingCount,
		"last_hour": gin.H{
			"syslog": syslogLastHour,
			"traps":  trapLastHour,
			"flows":  flowLastHour,
			"pings":  pingLastHour,
		},
		"hourly_breakdown": hourlyBreakdown,
	}))
}

// GetProbesStatsBatch returns total + last-hour counts for many probes in a
// fixed number of queries (8: four totals + four last-hour, each grouped by
// probe_id), eliminating the N+1 the probes summary page used to make — one
// GET /probes/:id/stats per approved probe. It intentionally omits the 24h
// hourly_breakdown that GetProbeStats computes: the summary never uses it and
// computing it per probe is 96 extra queries each. AUDIT-064.
func (h *Handler) GetProbesStatsBatch(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	idsParam := strings.TrimSpace(c.Query("ids"))
	if idsParam == "" {
		c.JSON(http.StatusOK, response.Success([]gin.H{}))
		return
	}

	const maxBatchIDs = 500
	ids := make([]uint, 0)
	seen := make(map[uint]bool)
	for _, p := range strings.Split(idsParam, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil || n == 0 || seen[uint(n)] {
			continue
		}
		seen[uint(n)] = true
		ids = append(ids, uint(n))
		if len(ids) >= maxBatchIDs {
			break
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusOK, response.Success([]gin.H{}))
		return
	}

	hourAgo := time.Now().UTC().Add(-1 * time.Hour)

	// countByProbe runs one grouped query:
	//   SELECT probe_id, count(*) FROM <table>
	//   WHERE probe_id IN (ids) [AND timestamp > hourAgo] GROUP BY probe_id
	// returning probe_id -> count. Eight calls cover four tables × {total,
	// last-hour} regardless of how many probe ids are requested.
	countByProbe := func(model interface{}, sinceHour bool) map[uint]int64 {
		type row struct {
			ProbeID uint
			Cnt     int64
		}
		var rows []row
		q := db.Gorm().Model(model).
			Select("probe_id, count(*) as cnt").
			Where("probe_id IN ?", ids)
		if sinceHour {
			q = q.Where("timestamp > ?", hourAgo)
		}
		if err := q.Group("probe_id").Scan(&rows).Error; err != nil {
			log.Printf("GetProbesStatsBatch: grouped count failed: %v", err)
			return map[uint]int64{}
		}
		m := make(map[uint]int64, len(rows))
		for _, r := range rows {
			m[r.ProbeID] = r.Cnt
		}
		return m
	}

	syslogTotal := countByProbe(&models.SyslogMessage{}, false)
	trapTotal := countByProbe(&models.TrapEvent{}, false)
	flowTotal := countByProbe(&models.FlowSample{}, false)
	pingTotal := countByProbe(&models.PingResult{}, false)
	syslogHour := countByProbe(&models.SyslogMessage{}, true)
	trapHour := countByProbe(&models.TrapEvent{}, true)
	flowHour := countByProbe(&models.FlowSample{}, true)
	pingHour := countByProbe(&models.PingResult{}, true)

	out := make([]gin.H, 0, len(ids))
	for _, id := range ids {
		out = append(out, gin.H{
			"probe_id": id,
			"syslog":   syslogTotal[id],
			"traps":    trapTotal[id],
			"flows":    flowTotal[id],
			"pings":    pingTotal[id],
			"last_hour": gin.H{
				"syslog": syslogHour[id],
				"traps":  trapHour[id],
				"flows":  flowHour[id],
				"pings":  pingHour[id],
			},
		})
	}
	c.JSON(http.StatusOK, response.Success(out))
}

func (h *Handler) GetProbeDevices(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	devices, err := h.db.GetDevicesByProbe(probe.ID)
	if err != nil {
		httputil.InternalError(c, "Failed to get devices", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success":        true,
		"data":           devices,
		"tftp_server_ip": probe.TFTPServerIP,
	})
}
