package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (h *Handler) GetProbes(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.Probe{}))
		return
	}

	probes, err := h.db.GetAllProbes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to fetch probes"))
		return
	}

	httputil.RedactProbes(probes)

	c.JSON(http.StatusOK, models.SuccessResponse(probes))
}

func (h *Handler) GetProbe(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Probe not found"))
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	probe, err := h.db.GetProbe(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Probe not found"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(probe))
}

func (h *Handler) CreateProbe(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	var probe models.Probe
	if err := c.ShouldBindJSON(&probe); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if strings.TrimSpace(probe.Name) == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Name is required"))
		return
	}

	existing, err := h.db.GetProbeByName(probe.Name)
	if err == nil && existing != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Probe with this name already exists"))
		return
	}

	if probe.SiteID > 0 {
		_, err := h.db.GetSite(probe.SiteID)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Site not found"))
			return
		}
	}

	if probe.ListenPort == 0 {
		probe.ListenPort = 8089
	}
	if probe.ListenPort < 1 || probe.ListenPort > 65535 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid listen port"))
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

	if err := h.db.CreateProbe(&probe); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create probe"))
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
		if err := h.db.Gorm().Create(&setting).Error; err != nil {
			log.Printf("Warning: Failed to create registration setting for probe %s: %v", probe.Name, err)
		}
	}

	httputil.RedactProbe(&probe)
	c.JSON(http.StatusCreated, models.SuccessResponse(probe))
}

func (h *Handler) UpdateProbe(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	probe, err := h.db.GetProbe(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Probe not found"))
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	filteredUpdates := httputil.FilterAllowedFields(updates, allowedFields)

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("No valid fields to update"))
		return
	}

	if portVal, ok := filteredUpdates["listen_port"]; ok {
		port, isNum := portVal.(float64)
		if !isNum || port < 1 || port > 65535 || port != float64(int(port)) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid listen port"))
			return
		}
	}

	if siteIDVal, ok := filteredUpdates["site_id"]; ok {
		siteID, isNum := siteIDVal.(float64)
		if !isNum || siteID < 0 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid site ID"))
			return
		}
		if siteID > 0 {
			_, err := h.db.GetSite(uint(siteID))
			if err != nil {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Site not found"))
				return
			}
		}
	}

	if enabledVal, ok := filteredUpdates["enabled"]; ok {
		if _, isBool := enabledVal.(bool); !isBool {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid value for enabled"))
			return
		}
	}

	if err := h.db.Gorm().Model(probe).Updates(filteredUpdates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update probe"))
		return
	}

	updated, err := h.db.GetProbe(id)
	if err != nil {
		httputil.RedactProbe(probe)
		c.JSON(http.StatusOK, models.SuccessResponse(probe))
		return
	}
	httputil.RedactProbe(updated)
	c.JSON(http.StatusOK, models.SuccessResponse(updated))
}

func (h *Handler) DeleteProbe(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := h.db.DeleteProbe(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete probe"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Probe deleted"))
}

func (h *Handler) GetPendingProbes(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.Probe{}))
		return
	}

	probes, err := h.db.GetPendingProbes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to fetch pending probes"))
		return
	}

	httputil.RedactProbes(probes)

	c.JSON(http.StatusOK, models.SuccessResponse(probes))
}

type ApproveProbeRequest struct {
	Notes string `json:"notes"`
}

func (h *Handler) ApproveProbe(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var req ApproveProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Not authenticated"))
		return
	}
	adminID, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Invalid session data"))
		return
	}

	if err := h.db.ApproveProbe(id, adminID); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to approve probe"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Probe approved successfully"))
}

type RejectProbeRequest struct {
	Reason string `json:"reason" binding:"required"`
}

func (h *Handler) RejectProbe(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var req RejectProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Reason is required"))
		return
	}

	if _, exists := c.Get("user_id"); !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Not authenticated"))
		return
	}

	if err := h.db.RejectProbe(id, req.Reason); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to reject probe"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Probe rejected successfully"))
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if req.ListenPort == 0 {
		req.ListenPort = 8089
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid listen port"))
		return
	}

	// Validate address to prevent SSRF / internal port scanning
	if !isValidExternalIP(req.ListenAddress) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid or disallowed listen address"))
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
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": "Failed to connect to probe",
			"online":  false,
		}))
		return
	}
	defer conn.Close()

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
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
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		probeErr(c, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.RegistrationKey == "" {
		probeErr(c, http.StatusBadRequest, "Registration key required")
		return
	}

	var setting models.SystemSetting
	// AUDIT-017: keys are stored hashed; hash the presented key to look it up.
	err := h.db.Gorm().Where("key = ?", "probe_registration_"+database.HashProbeKey(req.RegistrationKey)).First(&setting).Error
	if err != nil || setting.Value == "" {
		// AUDIT-067: failed registration attempts are still audit-logged, but
		// without a resolved probe (the auth is by the key, which may be a
		// brand-new one we haven't seen). probeID=0/tenantID="" is the
		// documented "anonymous" audit shape.
		h.writeProbeTokenAudit(c, 0, "", http.StatusUnauthorized)
		probeErr(c, http.StatusUnauthorized, "Invalid registration key")
		return
	}

	existingProbe := &models.Probe{}
	err = h.db.Gorm().Where("name = ?", setting.Value).First(existingProbe).Error
	if err != nil || existingProbe.ID == 0 {
		h.writeProbeTokenAudit(c, 0, "", http.StatusNotFound)
		probeErr(c, http.StatusNotFound, "Probe not found — it may have been deleted")
		return
	}

	// If already approved and online, just return success
	if existingProbe.ApprovalStatus == "approved" && existingProbe.Status == "online" {
		// AUDIT-067: registration is itself a token-usage event — record the
		// resolved probe/tenant so an operator can see "probe X first
		// registered at Y" in the audit timeline.
		h.writeProbeTokenAudit(c, existingProbe.ID, existingProbe.TenantID, http.StatusOK)
		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"probe_id":   existingProbe.ID,
			"probe_name": existingProbe.Name,
			"approved":   true,
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update probe status"))
		return
	}

	// AUDIT-067: same audit row as the already-approved branch — the probe
	// identity is known at this point regardless of approval state.
	h.writeProbeTokenAudit(c, existingProbe.ID, existingProbe.TenantID, http.StatusOK)
	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"probe_id":   existingProbe.ID,
		"probe_name": existingProbe.Name,
		"approved":   true,
	})
}

func (h *Handler) RegenerateProbeKey(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	probe, err := h.db.GetProbe(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Probe not found"))
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to generate key"))
		return
	}
	newKey := hex.EncodeToString(keyBytes) // plaintext — returned once below
	// AUDIT-017: store the HASH at rest; the stored old key is already hashed,
	// so the old setting's key (probe_registration_<hash>) matches for deletion.
	hashedNew := database.HashProbeKey(newKey)
	oldKey := probe.RegistrationKey

	if err := h.db.Gorm().Transaction(func(tx *gorm.DB) error {
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to regenerate key"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
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

// probeAuthError is a small helper used by both authenticateProbeByBearer and
// validateProbe to (a) emit a uniform error response and (b) record a
// ProbeTokenAudit row. AUDIT-067: every authentication outcome is audit-logged
// so a stolen token's usage is reconstructable. The endpoint/method/remote IP
// come from the gin.Context, and probeID is the resolved authenticated probe
// (or 0 when auth failed before resolution). The audit write is best-effort:
// a transient DB failure logs to stderr but does NOT change the auth
// outcome — the request still fails with the original error.
func (h *Handler) probeAuthError(c *gin.Context, status int, msg string, probe *models.Probe) {
	probeID := uint(0)
	tenantID := ""
	if probe != nil {
		probeID = probe.ID
		tenantID = probe.TenantID
	}
	h.writeProbeTokenAudit(c, probeID, tenantID, status)
	c.JSON(status, models.ErrorResponse(msg))
}

// writeProbeTokenAudit persists a single audit row. Intentionally tolerant of
// a nil DB / nil gorm handle (test fixtures sometimes wire the handler without
// a database) — those calls are no-ops, not panics, so the auth path doesn't
// fail-open in the absence of a backing store. The remote IP comes from
// gin's ClientIP() so the recorded value is consistent with the rest of the
// request log (which already passes through the same helper). A nil context
// is also tolerated, since some tests construct a recorder without a request.
func (h *Handler) writeProbeTokenAudit(c *gin.Context, probeID uint, tenantID string, status int) {
	if h == nil || h.db == nil {
		return
	}
	endpoint := ""
	method := ""
	remoteIP := ""
	if c != nil && c.Request != nil {
		endpoint = c.Request.URL.Path
		method = c.Request.Method
		remoteIP = c.ClientIP()
	}
	entry := &models.ProbeTokenAudit{
		TenantID:   tenantID,
		ProbeID:    probeID,
		Endpoint:   endpoint,
		Method:     method,
		RemoteIP:   remoteIP,
		StatusCode: status,
		Timestamp:  time.Now(),
	}
	// Use a fresh GORM session so a request that has already begun writing a
	// response (e.g. one that was aborted by an earlier handler) still gets the
	// audit row committed. Best-effort: a failure here is logged, never fatal.
	if err := h.db.Gorm().Create(entry).Error; err != nil {
		log.Printf("writeProbeTokenAudit: probe=%d endpoint=%s: %v", probeID, endpoint, err)
	}
}

// authenticateProbeByBearer extracts the Bearer token from the Authorization header
// and looks up the probe by its registration key. Returns the probe if authenticated.
//
// AUDIT-067: every authentication outcome is recorded to probe_token_audits
// (token, IP, endpoint, status). A failed auth logs with probe_id=0 and
// tenant_id="" because we have no resolved identity — the audit row is still
// useful because it captures the (anonymous) request fingerprint.
func (h *Handler) authenticateProbeByBearer(c *gin.Context) (*models.Probe, bool) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		h.probeAuthError(c, http.StatusUnauthorized, "Authorization required", nil)
		return nil, false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		h.probeAuthError(c, http.StatusUnauthorized, "Authorization required", nil)
		return nil, false
	}

	// Look up probe by registration key (AUDIT-017: stored hashed).
	var probe models.Probe
	if err := h.db.Gorm().Where("registration_key = ?", database.HashProbeKey(token)).First(&probe).Error; err != nil {
		h.probeAuthError(c, http.StatusUnauthorized, "Invalid authorization", nil)
		return nil, false
	}
	// Successful auth — record the audit row with the resolved probe/tenant.
	h.writeProbeTokenAudit(c, probe.ID, probe.TenantID, http.StatusOK)
	return &probe, true
}

// validateProbe parses probe ID from URL param and checks it exists, is approved,
// and the caller provides a valid Bearer token matching the probe's registration key.
//
// AUDIT-067: in addition to the AUDIT-016/AUDIT-017 token checks, the resolved
// (token-bound) probe's tenant must match the URL :id probe's tenant. A
// mismatch is rejected with 403 — semantically distinct from 401 (which still
// means "your token doesn't authenticate this probe at all"). The two probes
// in the check below are the same object for a correctly-authenticated request;
// they only differ when an attacker presents probe-A's token at probe-B's URL,
// which is exactly the cross-tenant attack AUDIT-067 calls out.
func (h *Handler) validateProbe(c *gin.Context) (*models.Probe, bool) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return nil, false
	}
	id := c.Param("id")
	idUint, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid probe ID"))
		return nil, false
	}
	probe, err := h.db.GetProbe(uint(idUint))
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Probe not found"))
		return nil, false
	}
	if probe.ApprovalStatus != "approved" {
		// AUDIT-067: audit the unauthenticated/unauthorized probe-state access
		// attempt with the target probe's ID (the auth-less 403 still has
		// signal value for incident review).
		h.writeProbeTokenAudit(c, probe.ID, probe.TenantID, http.StatusForbidden)
		c.JSON(http.StatusForbidden, models.ErrorResponse("Probe not approved"))
		return nil, false
	}

	// Verify Bearer token matches this probe's registration key
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		h.probeAuthError(c, http.StatusUnauthorized, "Authorization required", probe)
		return nil, false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	// AUDIT-016: constant-time compare against the stored registration key
	// after the indexed PK lookup above. A naive `token != probe.Registration
	// Key` is a byte-by-byte compare that an attacker on the LAN can use as a
	// single-character oracle (Go strings short-circuit on first mismatch).
	// subtle.ConstantTimeCompare returns 1 only if both lengths and all bytes
	// match; it does not short-circuit on content.
	// AUDIT-017: stored key is hashed; hash the presented token and compare the
	// digests in constant time (preserves the AUDIT-016 timing-safety property).
	if token == "" || subtle.ConstantTimeCompare([]byte(database.HashProbeKey(token)), []byte(probe.RegistrationKey)) != 1 {
		// AUDIT-067: a token-mismatch on this probe's URL is potentially a
		// cross-tenant attack (probe-A's token presented at probe-B). Resolve
		// the token to its actual owning probe to get a definitive 401-vs-403
		// answer — same tenant → 401 (wrong key, no privilege leak), different
		// tenant → 403 (cross-tenant attempt, auditable escalation).
		var tokenProbe models.Probe
		if err := h.db.Gorm().Where("registration_key = ?", database.HashProbeKey(token)).First(&tokenProbe).Error; err == nil {
			if tokenProbe.TenantID != probe.TenantID {
				h.writeProbeTokenAudit(c, probe.ID, probe.TenantID, http.StatusForbidden)
				c.JSON(http.StatusForbidden, models.ErrorResponse("Cross-tenant access denied"))
				return nil, false
			}
		}
		// Same tenant (or token doesn't resolve to any probe — treat as 401
		// since we can't make a tenant claim).
		h.probeAuthError(c, http.StatusUnauthorized, "Invalid authorization", probe)
		return nil, false
	}

	// Update last_seen and last_data_received on any data submission
	now := time.Now()
	h.db.Gorm().Model(probe).Updates(map[string]interface{}{
		"last_seen":          now,
		"last_data_received": now,
	})
	// AUDIT-067: successful auth — record the audit row with the resolved
	// probe/tenant. Status 200 is set later by the handler; we record 200 here
	// because the auth itself succeeded (handler-side errors that yield a
	// non-2xx are out of scope for the token-usage audit).
	h.writeProbeTokenAudit(c, probe.ID, probe.TenantID, http.StatusOK)
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
	if !httputil.RequireDB(c, h.db) {
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
	if err := h.db.Gorm().Model(&models.SyslogMessage{}).Where("probe_id = ?", id).Count(&syslogCount).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to count syslog messages"))
		return
	}
	if err := h.db.Gorm().Model(&models.TrapEvent{}).Where("probe_id = ?", id).Count(&trapCount).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to count trap events"))
		return
	}
	if err := h.db.Gorm().Model(&models.FlowSample{}).Where("probe_id = ?", id).Count(&flowCount).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to count flow samples"))
		return
	}
	if err := h.db.Gorm().Model(&models.PingResult{}).Where("probe_id = ?", id).Count(&pingCount).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to count ping results"))
		return
	}

	// Last hour counts
	var syslogLastHour, trapLastHour, flowLastHour, pingLastHour int64
	if err := h.db.Gorm().Model(&models.SyslogMessage{}).Where("probe_id = ? AND timestamp > ?", id, hourAgo).Count(&syslogLastHour).Error; err != nil {
		syslogLastHour = 0
	}
	if err := h.db.Gorm().Model(&models.TrapEvent{}).Where("probe_id = ? AND timestamp > ?", id, hourAgo).Count(&trapLastHour).Error; err != nil {
		trapLastHour = 0
	}
	if err := h.db.Gorm().Model(&models.FlowSample{}).Where("probe_id = ? AND timestamp > ?", id, hourAgo).Count(&flowLastHour).Error; err != nil {
		flowLastHour = 0
	}
	if err := h.db.Gorm().Model(&models.PingResult{}).Where("probe_id = ? AND timestamp > ?", id, hourAgo).Count(&pingLastHour).Error; err != nil {
		pingLastHour = 0
	}

	// Hourly breakdown for last 24 hours
	hourlyBreakdown := make([]gin.H, 0, 24)
	for i := 23; i >= 0; i-- {
		hourStart := now.Add(-time.Duration(i) * time.Hour)
		hourStart = time.Date(hourStart.Year(), hourStart.Month(), hourStart.Day(), hourStart.Hour(), 0, 0, 0, time.UTC)
		hourEnd := hourStart.Add(time.Hour)

		var hSyslog, hTrap, hFlow, hPing int64
		if err := h.db.Gorm().Model(&models.SyslogMessage{}).Where("probe_id = ? AND timestamp >= ? AND timestamp < ?", id, hourStart, hourEnd).Count(&hSyslog).Error; err != nil {
			log.Printf("GetProbeStats: failed to count syslog for hour %s: %v", hourStart.Format("15:04"), err)
			hSyslog = 0
		}
		if err := h.db.Gorm().Model(&models.TrapEvent{}).Where("probe_id = ? AND timestamp >= ? AND timestamp < ?", id, hourStart, hourEnd).Count(&hTrap).Error; err != nil {
			log.Printf("GetProbeStats: failed to count traps for hour %s: %v", hourStart.Format("15:04"), err)
			hTrap = 0
		}
		if err := h.db.Gorm().Model(&models.FlowSample{}).Where("probe_id = ? AND timestamp >= ? AND timestamp < ?", id, hourStart, hourEnd).Count(&hFlow).Error; err != nil {
			log.Printf("GetProbeStats: failed to count flows for hour %s: %v", hourStart.Format("15:04"), err)
			hFlow = 0
		}
		if err := h.db.Gorm().Model(&models.PingResult{}).Where("probe_id = ? AND timestamp >= ? AND timestamp < ?", id, hourStart, hourEnd).Count(&hPing).Error; err != nil {
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

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
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
	if !httputil.RequireDB(c, h.db) {
		return
	}

	idsParam := strings.TrimSpace(c.Query("ids"))
	if idsParam == "" {
		c.JSON(http.StatusOK, models.SuccessResponse([]gin.H{}))
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
		c.JSON(http.StatusOK, models.SuccessResponse([]gin.H{}))
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
		q := h.db.Gorm().Model(model).
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
	c.JSON(http.StatusOK, models.SuccessResponse(out))
}

func (h *Handler) GetProbeDevices(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	devices, err := h.db.GetDevicesByProbe(probe.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get devices"))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success":        true,
		"data":           devices,
		"tftp_server_ip": probe.TFTPServerIP,
	})
}
