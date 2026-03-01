package handlers

import (
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"fortiGate-Mon/internal/api/middleware"
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

	// Try SNMP first
	if h.snmpClient != nil {
		status, err := h.snmpClient.GetSystemStatus()
		if err == nil {
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
			return
		}
	}

	// Fall back to database
	if h.db != nil {
		status, err := h.db.GetLatestSystemStatus()
		if err == nil && status != nil {
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
				"cached":       true,
				"cached_at":    status.Timestamp,
			}
			c.JSON(http.StatusOK, models.SuccessResponse(publicData))
			return
		}
	}

	c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("No monitoring data available"))
}

func (h *Handler) GetPublicInterfaces(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Try SNMP first
	if h.snmpClient != nil {
		interfaces, err := h.snmpClient.GetInterfaceStats()
		if err == nil {
			c.JSON(http.StatusOK, models.SuccessResponse(interfaces))
			return
		}
	}

	// Fall back to database
	if h.db != nil {
		interfaces, err := h.db.GetLatestInterfaceStats()
		if err == nil && len(interfaces) > 0 {
			c.JSON(http.StatusOK, models.SuccessResponse(interfaces))
			return
		}
	}

	c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("No interface data available"))
}

func (h *Handler) Login(c *gin.Context) {
	if h.authManager == nil {
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
			if dbErr := h.db.SaveLoginAttempt(&models.LoginAttempt{
				Timestamp: time.Now(),
				Username:  creds.Username,
				IPAddress: ip,
				Success:   false,
				UserAgent: userAgent,
			}); dbErr != nil {
				log.Printf("Failed to save login attempt: %v", dbErr)
			}
		}
		if err == auth.ErrAccountLocked {
			c.JSON(http.StatusTooManyRequests, models.ErrorResponse("Account temporarily locked due to too many failed attempts"))
			return
		}
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Invalid credentials"))
		return
	}

	if h.db != nil {
		if dbErr := h.db.SaveLoginAttempt(&models.LoginAttempt{
			Timestamp: time.Now(),
			Username:  creds.Username,
			IPAddress: ip,
			Success:   true,
			UserAgent: userAgent,
		}); dbErr != nil {
			log.Printf("Failed to save login attempt: %v", dbErr)
		}
	}

	// Get admin record to use real ID in token
	adminRecord, adminErr := h.db.GetAdminByUsername(creds.Username)
	var adminID uint = 1
	if adminErr == nil && adminRecord != nil {
		adminID = adminRecord.ID
	}

	token, err := h.authManager.GenerateToken(creds.Username, adminID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to generate token"))
		return
	}

	// Generate HMAC-signed CSRF token tied to the auth token
	csrfToken := middleware.GenerateCSRFToken(token, h.config.Server.JWTSecretKey)

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

	var status *models.SystemStatus
	var interfaces []models.InterfaceStats
	var sensors []models.HardwareSensor

	// Try SNMP first
	if h.snmpClient != nil {
		s, err := h.snmpClient.GetSystemStatus()
		if err == nil {
			status = s
		}
		ifaces, err := h.snmpClient.GetInterfaceStats()
		if err == nil {
			interfaces = ifaces
		}
		hw, err := h.snmpClient.GetHardwareSensors()
		if err == nil {
			sensors = hw
		}
	}

	// Fall back to DB if SNMP unavailable
	if status == nil && h.db != nil {
		s, err := h.db.GetLatestSystemStatus()
		if err == nil && s != nil {
			status = s
		}
	}
	if len(interfaces) == 0 && h.db != nil {
		ifaces, err := h.db.GetLatestInterfaceStats()
		if err == nil {
			interfaces = ifaces
		}
	}

	if status == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("No monitoring data available"))
		return
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
		"snmp_version":   true,
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

	// Re-fetch to return fresh data
	updated, err := h.db.GetFortiGate(uint(idUint))
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(fg))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(updated))
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
		"name":            true,
		"source_fg_id":    true,
		"dest_fg_id":      true,
		"description":     true,
		"enabled":         true,
		"connection_type": true,
		"notes":           true,
		"status":          true,
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

	// Re-fetch to return fresh data with preloaded relations
	var updated models.FortiGateConnection
	if err := h.db.Gorm().Preload("SourceFG").Preload("DestFG").First(&updated, idUint).Error; err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(conn))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(updated))
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
		"cpu_threshold":            true,
		"memory_threshold":         true,
		"disk_threshold":           true,
		"session_threshold":        true,
		"email_enabled":            true,
		"slack_webhook":            true,
		"discord_webhook":          true,
		"webhook_url":              true,
		"public_show_hostname":     true,
		"public_show_uptime":       true,
		"public_show_cpu":          true,
		"public_show_memory":       true,
		"public_show_sessions":     true,
		"public_show_interfaces":   true,
		"public_refresh_interval":  true,
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

func (h *Handler) GetPublicDisplaySettings(c *gin.Context) {
	defaults := map[string]string{
		"public_show_hostname":    "true",
		"public_show_uptime":      "true",
		"public_show_cpu":         "true",
		"public_show_memory":      "true",
		"public_show_sessions":    "true",
		"public_show_interfaces":  "true",
		"public_refresh_interval": "30",
	}

	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(defaults))
		return
	}

	var settings []models.SystemSetting
	h.db.Gorm().Where("`key` LIKE ?", "public_%").Find(&settings)

	result := make(map[string]string)
	for k, v := range defaults {
		result[k] = v
	}
	for _, s := range settings {
		result[s.Key] = s.Value
	}

	c.JSON(http.StatusOK, models.SuccessResponse(result))
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
	if req.SNMPPort < 1 || req.SNMPPort > 65535 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid SNMP port"))
		return
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
		log.Printf("TestDevice connect error for %s: %v", req.IPAddress, err)
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": "Failed to connect to device",
			"online":  false,
		}))
		return
	}
	defer client.Close()

	status, err := client.GetSystemStatus()
	if err != nil {
		log.Printf("TestDevice poll error for %s: %v", req.IPAddress, err)
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": "Failed to poll device",
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

	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Auth not available"))
		return
	}

	// Enforce minimum password length
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("New password must be at least 8 characters"))
		return
	}

	// Get username and user ID from JWT claims
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Not authenticated"))
		return
	}
	userID, uidExists := c.Get("user_id")
	if !uidExists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Not authenticated"))
		return
	}

	// Validate current password
	if err := h.authManager.ValidateCredentials(username.(string), req.CurrentPassword); err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Current password is incorrect"))
		return
	}

	hashedPassword, err := h.authManager.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to process password"))
		return
	}

	err = h.db.UpdateAdminPassword(userID.(uint), hashedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update password"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Password changed successfully"))
}
