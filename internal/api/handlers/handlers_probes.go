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

	// AUDIT-017: store the key HASHED at rest. The plaintext is never persisted
	// (and these endpoints always redact it — RegenerateProbeKey is the
	// show-once reveal path, unchanged), so a DB compromise yields no usable
	// probe tokens.
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		log.Printf("Failed to generate registration key: %v", err)
	} else {
		probe.RegistrationKey = database.HashProbeKey(hex.EncodeToString(keyBytes))
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

	var setting models.SystemSetting
	// AUDIT-017: keys are stored hashed; hash the presented key to look it up.
	err := h.db.Gorm().Where("key = ?", "probe_registration_"+database.HashProbeKey(req.RegistrationKey)).First(&setting).Error
	if err != nil || setting.Value == "" {
		probeErr(c, http.StatusUnauthorized, "Invalid registration key")
		return
	}

	existingProbe := &models.Probe{}
	err = h.db.Gorm().Where("name = ?", setting.Value).First(existingProbe).Error
	if err != nil || existingProbe.ID == 0 {
		probeErr(c, http.StatusNotFound, "Probe not found — it may have been deleted")
		return
	}

	// If already approved and online, just return success
	if existingProbe.ApprovalStatus == "approved" && existingProbe.Status == "online" {
		c.JSON(http.StatusOK, gin.H{
			"success":        true,
			"probe_id":       existingProbe.ID,
			"probe_name":     existingProbe.Name,
			"approved":       true,
			"schema_version": selectedVersion,
		})
		return
	}

	// Link the remote probe: set online, auto-approve (admin created it explicitly)
	now := time.Now()
	if err := h.db.Gorm().Model(existingProbe).Updates(map[string]interface{}{
		"status":          "online",
		"approval_status": "approved",
		"approved_at":     now,
		"last_seen":       now,
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

	c.JSON(http.StatusOK, gin.H{"success": true})
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
func (h *Handler) probeDeviceIDs(probeID uint) map[uint]bool {
	devices, err := h.db.GetDevicesByProbe(probeID)
	if err != nil {
		return nil
	}
	ids := make(map[uint]bool, len(devices))
	for _, d := range devices {
		ids[d.ID] = true
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
