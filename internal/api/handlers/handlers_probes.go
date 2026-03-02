package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
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

	httputil.RedactProbe(probe)

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

	existing, _ := h.db.GetProbeByName(probe.Name)
	if existing != nil {
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

	probe.Status = "offline"

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		log.Printf("Failed to generate registration key: %v", err)
	} else {
		probe.RegistrationKey = hex.EncodeToString(keyBytes)
	}

	if err := h.db.CreateProbe(&probe); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create probe"))
		return
	}

	// Create SystemSetting so RegisterProbe can look up this probe by key
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

	address := fmt.Sprintf("%s:%d", req.ListenAddress, req.ListenPort)

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

func (h *Handler) RegisterProbe(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "message": "Database not available"})
		return
	}

	var req struct {
		RegistrationKey string `json:"registration_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
		return
	}

	if req.RegistrationKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Registration key required"})
		return
	}

	var setting models.SystemSetting
	err := h.db.Gorm().Where("key = ?", "probe_registration_"+req.RegistrationKey).First(&setting).Error
	if err != nil || setting.Value == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Invalid registration key"})
		return
	}

	existingProbe := &models.Probe{}
	err = h.db.Gorm().Where("name = ?", setting.Value).First(existingProbe).Error
	if err != nil || existingProbe.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Probe not found — it may have been deleted"})
		return
	}

	// If already approved and online, just return success
	if existingProbe.ApprovalStatus == "approved" && existingProbe.Status == "online" {
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
	h.db.Gorm().Model(existingProbe).Updates(map[string]interface{}{
		"status":          "online",
		"approval_status": "approved",
		"approved_at":     now,
		"last_seen":       now,
	})

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

	// Delete old SystemSetting for the previous key
	if probe.RegistrationKey != "" {
		h.db.Gorm().Where("key = ?", "probe_registration_"+probe.RegistrationKey).Delete(&models.SystemSetting{})
	}

	// Generate new key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to generate key"))
		return
	}
	newKey := hex.EncodeToString(keyBytes)

	// Update probe record
	h.db.Gorm().Model(probe).Update("registration_key", newKey)

	// Create new SystemSetting
	setting := models.SystemSetting{
		Key:      "probe_registration_" + newKey,
		Value:    probe.Name,
		Type:     "string",
		Label:    "Probe Registration Key for " + probe.Name,
		Category: "probes",
	}
	if err := h.db.Gorm().Create(&setting).Error; err != nil {
		log.Printf("Warning: Failed to create registration setting for probe %s: %v", probe.Name, err)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"registration_key": newKey,
	}))
}

func (h *Handler) ProbeHeartbeat(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}

	var req struct {
		ProbeID uint   `json:"probe_id"`
		Status  string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if req.ProbeID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Probe ID required"})
		return
	}

	var probe models.Probe
	if err := h.db.Gorm().First(&probe, req.ProbeID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Probe not found"})
		return
	}

	h.db.Gorm().Model(&probe).Updates(map[string]interface{}{
		"last_seen": time.Now(),
		"status":    req.Status,
	})

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// validateProbe parses probe ID from URL param and checks it exists and is approved.
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
		c.JSON(http.StatusForbidden, models.ErrorResponse("Probe not approved"))
		return nil, false
	}
	// Update last_seen on any data submission
	h.db.Gorm().Model(probe).Update("last_seen", time.Now())
	return probe, true
}

func (h *Handler) GetProbeStats(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

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

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"probe_id": id,
		"syslog":   syslogCount,
		"traps":    trapCount,
		"flows":    flowCount,
		"pings":    pingCount,
	}))
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
	c.JSON(http.StatusOK, models.SuccessResponse(devices))
}
