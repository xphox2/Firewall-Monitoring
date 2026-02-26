package handlers

import (
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"fortiGate-Mon/internal/auth"
	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/database"
	"fortiGate-Mon/internal/models"
	"fortiGate-Mon/internal/snmp"
	"fortiGate-Mon/internal/uptime"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	config      *config.Config
	authManager *auth.AuthManager
	snmpClient  *snmp.SNMPClient
	uptimeTrack *uptime.UptimeTracker
	db          *database.Database
	mu          sync.RWMutex
}

func NewHandler(cfg *config.Config, authManager *auth.AuthManager, db *database.Database) *Handler {
	return &Handler{
		config:      cfg,
		authManager: authManager,
		uptimeTrack: uptime.NewUptimeTracker(cfg),
		db:          db,
	}
}

func (h *Handler) SetSNMPClient(client *snmp.SNMPClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.snmpClient = client
}

func (h *Handler) GetPublicDashboard(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.snmpClient == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("SNMP client not initialized"))
		return
	}

	status, err := h.snmpClient.GetSystemStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get system status"))
		return
	}

	uptimeStats := h.uptimeTrack.GetStats()

	publicData := gin.H{
		"hostname":     status.Hostname,
		"version":      status.Version,
		"uptime":       uptime.FormatUptime(status.Uptime),
		"uptime_raw":   status.Uptime,
		"cpu":          status.CPUUsage,
		"memory":       status.MemoryUsage,
		"sessions":     status.SessionCount,
		"uptime_stats": uptimeStats,
	}

	c.JSON(http.StatusOK, models.SuccessResponse(publicData))
}

func (h *Handler) GetPublicInterfaces(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.snmpClient == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("SNMP client not initialized"))
		return
	}

	interfaces, err := h.snmpClient.GetInterfaceStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get interface stats"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(interfaces))
}

func (h *Handler) Login(c *gin.Context) {
	log.Printf("[DEBUG] Login request received from %s", c.ClientIP())
	log.Printf("[DEBUG] authManager = %v, config = %v", h.authManager, h.config)

	if h.authManager == nil {
		log.Printf("[DEBUG] FAILURE: authManager is NIL")
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Authentication not configured"))
		return
	}

	var creds struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	ip := c.ClientIP()
	userAgent := c.Request.UserAgent()

	if err := h.authManager.ValidateCredentials(creds.Username, creds.Password); err != nil {
		if h.db != nil {
			if err := h.db.SaveLoginAttempt(&models.LoginAttempt{
				Timestamp: time.Now(),
				Username:  creds.Username,
				IPAddress: ip,
				Success:   false,
				UserAgent: userAgent,
			}); err != nil {
				log.Printf("Failed to save login attempt: %v", err)
			}
		}
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Invalid credentials"))
		return
	}

	if h.db != nil {
		if err := h.db.SaveLoginAttempt(&models.LoginAttempt{
			Timestamp: time.Now(),
			Username:  creds.Username,
			IPAddress: ip,
			Success:   true,
			UserAgent: userAgent,
		}); err != nil {
			log.Printf("Failed to save login attempt: %v", err)
		}
	}

	token, err := h.authManager.GenerateToken(creds.Username, 1)
	if err != nil {
		log.Printf("ERROR: Failed to generate token for user %s: %v", creds.Username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to generate token"))
		return
	}

	csrfToken, _ := auth.GenerateSecureToken(32)
	if csrfToken == "" {
		csrfToken = "fallback-csrf-token"
	}

	cookieSecure := true
	if h.config != nil {
		cookieSecure = h.config.Server.CookieSecure
	}

	c.SetCookie("auth_token", token, 86400, "/", "", cookieSecure, true)
	c.SetCookie("csrf_token", csrfToken, 86400, "/", "", cookieSecure, false)

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message":    "Login successful",
		"csrf_token": csrfToken,
	}))
}

func (h *Handler) Logout(c *gin.Context) {
	cookieSecure := true
	if h.config != nil {
		cookieSecure = h.config.Server.CookieSecure
	}
	c.SetCookie("auth_token", "", -1, "/", "", cookieSecure, true)
	c.SetCookie("csrf_token", "", -1, "/", "", cookieSecure, true)

	c.JSON(http.StatusOK, models.MessageResponse("Logged out successfully"))
}

func (h *Handler) GetAdminDashboard(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.snmpClient == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("SNMP client not initialized"))
		return
	}

	status, err := h.snmpClient.GetSystemStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get system status"))
		return
	}

	interfaces, err := h.snmpClient.GetInterfaceStats()
	if err != nil {
		log.Printf("Failed to get interface stats: %v", err)
	}
	sensors, err := h.snmpClient.GetHardwareSensors()
	if err != nil {
		log.Printf("Failed to get hardware sensors: %v", err)
	}

	var recentAlerts []models.Alert
	if h.db != nil {
		alerts, _ := h.db.GetAlerts(10, nil)
		recentAlerts = alerts
	}

	dashboard := models.DashboardData{
		SystemStatus:    *status,
		Interfaces:      interfaces,
		HardwareSensors: sensors,
		RecentAlerts:    recentAlerts,
		UptimeData:      h.uptimeTrack.GetUptimeRecord(),
	}

	c.JSON(http.StatusOK, models.SuccessResponse(dashboard))
}

func (h *Handler) GetAlerts(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.Alert{}))
		return
	}

	alerts, err := h.db.GetAlerts(100, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get alerts"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(alerts))
}

func (h *Handler) GetTraps(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.TrapEvent{}))
		return
	}

	traps, err := h.db.GetTrapEvents(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get traps"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(traps))
}

func (h *Handler) GetUptime(c *gin.Context) {
	stats := h.uptimeTrack.GetStats()
	fiveNines := h.uptimeTrack.CalculateFiveNines()

	var records []models.UptimeRecord
	if h.db != nil {
		records, _ = h.db.GetUptimeRecords(100)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"stats":      stats,
		"five_nines": fiveNines,
		"history":    records,
	}))
}

func (h *Handler) ResetUptime(c *gin.Context) {
	if err := h.uptimeTrack.Reset(); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to reset uptime"))
		return
	}
	c.JSON(http.StatusOK, models.MessageResponse("Uptime tracking reset successfully"))
}

func (h *Handler) GetHealth(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	health := gin.H{
		"status":         "healthy",
		"snmp_connected": h.snmpClient != nil,
		"database":       h.db != nil,
	}

	c.JSON(http.StatusOK, models.SuccessResponse(health))
}

func (h *Handler) GetFortiGates(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.FortiGate{}))
		return
	}

	fortigates, err := h.db.GetAllFortiGates()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get FortiGates"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(fortigates))
}

func (h *Handler) CreateFortiGate(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	var fg models.FortiGate
	if err := c.ShouldBindJSON(&fg); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	fg.Status = "unknown"
	if err := h.db.CreateFortiGate(&fg); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create FortiGate"))
		return
	}

	c.JSON(http.StatusCreated, models.SuccessResponse(fg))
}

func (h *Handler) UpdateFortiGate(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	id := c.Param("id")
	idUint, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid ID format"))
		return
	}

	fg, err := h.db.GetFortiGate(uint(idUint))
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("FortiGate not found"))
		return
	}

	allowedFields := map[string]bool{
		"name":           true,
		"hostname":       true,
		"ip_address":     true,
		"snmp_port":      true,
		"snmp_community": true,
		"location":       true,
		"description":    true,
		"enabled":        true,
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	filteredUpdates := make(map[string]interface{})
	for key, value := range updates {
		if allowedFields[key] {
			filteredUpdates[key] = value
		}
	}

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("No valid fields to update"))
		return
	}

	if err := h.db.Gorm().Model(fg).Updates(filteredUpdates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update FortiGate"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(fg))
}

func (h *Handler) DeleteFortiGate(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	id := c.Param("id")
	idUint, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid ID format"))
		return
	}

	if err := h.db.DeleteFortiGate(uint(idUint)); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete FortiGate"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("FortiGate deleted"))
}

func (h *Handler) GetFortiGateConnections(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.FortiGateConnection{}))
		return
	}

	connections, err := h.db.GetAllConnections()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get connections"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(connections))
}

func (h *Handler) CreateFortiGateConnection(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	var conn models.FortiGateConnection
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	conn.Status = "unknown"
	if err := h.db.CreateConnection(&conn); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create connection"))
		return
	}

	c.JSON(http.StatusCreated, models.SuccessResponse(conn))
}

func (h *Handler) UpdateFortiGateConnection(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	id := c.Param("id")
	idUint, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid ID format"))
		return
	}

	var conn models.FortiGateConnection
	if err := h.db.Gorm().First(&conn, idUint).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Connection not found"))
		return
	}

	allowedFields := map[string]bool{
		"name":         true,
		"source_fg_id": true,
		"dest_fg_id":   true,
		"description":  true,
		"enabled":      true,
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	filteredUpdates := make(map[string]interface{})
	for key, value := range updates {
		if allowedFields[key] {
			filteredUpdates[key] = value
		}
	}

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("No valid fields to update"))
		return
	}

	if err := h.db.Gorm().Model(&conn).Updates(filteredUpdates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update connection"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(conn))
}

func (h *Handler) DeleteFortiGateConnection(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	id := c.Param("id")
	idUint, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid ID format"))
		return
	}

	if err := h.db.Gorm().Delete(&models.FortiGateConnection{}, idUint).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete connection"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Connection deleted"))
}

func (h *Handler) GetSettings(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.SystemSetting{}))
		return
	}

	var settings []models.SystemSetting
	if err := h.db.Gorm().Find(&settings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get settings"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(settings))
}

func (h *Handler) UpdateSettings(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	var settings []models.SystemSetting
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	allowedKeys := map[string]bool{
		"cpu_threshold":     true,
		"memory_threshold":  true,
		"disk_threshold":    true,
		"session_threshold": true,
		"email_enabled":     true,
		"slack_webhook":     true,
		"discord_webhook":   true,
		"webhook_url":       true,
	}

	var validSettings []models.SystemSetting
	for _, s := range settings {
		if allowedKeys[s.Key] {
			validSettings = append(validSettings, s)
		}
	}

	for _, s := range validSettings {
		existing := models.SystemSetting{Key: s.Key}
		if err := h.db.Gorm().FirstOrCreate(&existing, models.SystemSetting{Key: s.Key}).Error; err != nil {
			continue
		}
		if !s.IsSecret || s.Value != "" {
			existing.Value = s.Value
			existing.Label = s.Label
			existing.Category = s.Category
			if err := h.db.Gorm().Save(&existing).Error; err != nil {
				log.Printf("Failed to save setting %s: %v", s.Key, err)
				continue
			}
		}
	}

	c.JSON(http.StatusOK, models.MessageResponse("Settings updated"))
}

func (h *Handler) GetDashboardAll(c *gin.Context) {
	fortigates := []models.FortiGate{}
	connections := []models.FortiGateConnection{}
	recentAlerts := []models.Alert{}

	if h.db != nil {
		if err := h.db.Gorm().Find(&fortigates).Error; err != nil {
			log.Printf("Failed to get fortigates: %v", err)
		}

		if err := h.db.Gorm().Preload("SourceFG").Preload("DestFG").Find(&connections).Error; err != nil {
			log.Printf("Failed to get connections: %v", err)
		}

		if err := h.db.Gorm().Order("timestamp DESC").Limit(20).Find(&recentAlerts).Error; err != nil {
			log.Printf("Failed to get recent alerts: %v", err)
		}
	}

	dashboard := models.DashboardData{
		FortiGates:   fortigates,
		RecentAlerts: recentAlerts,
		Connections:  connections,
	}

	c.JSON(http.StatusOK, models.SuccessResponse(dashboard))
}

type TestDeviceRequest struct {
	IPAddress     string `json:"ip_address" binding:"required"`
	SNMPPort      int    `json:"snmp_port"`
	SNMPCommunity string `json:"snmp_community"`
	SNMPVersion   string `json:"snmp_version"`
}

func (h *Handler) TestDeviceConnection(c *gin.Context) {
	var req TestDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if req.SNMPPort == 0 {
		req.SNMPPort = 161
	}
	if req.SNMPCommunity == "" {
		req.SNMPCommunity = "public"
	}
	if req.SNMPVersion == "" {
		req.SNMPVersion = "2c"
	}

	cfg := &config.Config{
		SNMP: config.SNMPConfig{
			FortiGateHost: req.IPAddress,
			FortiGatePort: req.SNMPPort,
			Community:     req.SNMPCommunity,
			Version:       req.SNMPVersion,
			Timeout:       10 * time.Second,
			Retries:       1,
		},
	}

	client, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": "Failed to connect: " + err.Error(),
			"online":  false,
		}))
		return
	}
	defer client.Close()

	status, err := client.GetSystemStatus()
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": "Failed to poll: " + err.Error(),
			"online":  false,
		}))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"success":  true,
		"message":  "Connected successfully",
		"online":   true,
		"hostname": status.Hostname,
		"version":  status.Version,
		"cpu":      status.CPUUsage,
		"memory":   status.MemoryUsage,
		"sessions": status.SessionCount,
		"uptime":   status.Uptime,
	}))
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

func (h *Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if err := h.authManager.ValidateCredentials(h.config.Auth.AdminUsername, req.CurrentPassword); err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Current password is incorrect"))
		return
	}

	if err := h.authManager.UpdatePassword(h.config.Auth.AdminUsername, req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update password"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Password changed successfully"))
}
