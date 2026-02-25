package handlers

import (
	"fmt"
	"net/http"
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
			h.db.SaveLoginAttempt(&models.LoginAttempt{
				Timestamp: time.Now(),
				Username:  creds.Username,
				IPAddress: ip,
				Success:   false,
				UserAgent: userAgent,
			})
		}
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Invalid credentials"))
		return
	}

	if h.db != nil {
		h.db.SaveLoginAttempt(&models.LoginAttempt{
			Timestamp: time.Now(),
			Username:  creds.Username,
			IPAddress: ip,
			Success:   true,
			UserAgent: userAgent,
		})
	}

	token, err := h.authManager.GenerateToken(creds.Username, 1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to generate token"))
		return
	}

	csrfToken, _ := auth.GenerateSecureToken(32)

	c.SetCookie("auth_token", token, 86400, "/", "", h.config.Server.CookieSecure, true)
	c.SetCookie("csrf_token", csrfToken, 86400, "/", "", h.config.Server.CookieSecure, true)

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message":    "Login successful",
		"csrf_token": csrfToken,
	}))
}

func (h *Handler) Logout(c *gin.Context) {
	c.SetCookie("auth_token", "", -1, "/", "", h.config.Server.CookieSecure, true)
	c.SetCookie("csrf_token", "", -1, "/", "", h.config.Server.CookieSecure, true)

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

	interfaces, _ := h.snmpClient.GetInterfaceStats()
	sensors, _ := h.snmpClient.GetHardwareSensors()

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
	var idUint uint
	fmt.Sscanf(id, "%d", &idUint)

	fg, err := h.db.GetFortiGate(idUint)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("FortiGate not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if err := h.db.Gorm().Model(fg).Updates(updates).Error; err != nil {
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
	var idUint uint
	fmt.Sscanf(id, "%d", &idUint)

	if err := h.db.DeleteFortiGate(idUint); err != nil {
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
	var conn models.FortiGateConnection
	if err := h.db.Gorm().First(&conn, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Connection not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if err := h.db.Gorm().Model(&conn).Updates(updates).Error; err != nil {
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
	if err := h.db.Gorm().Delete(&models.FortiGateConnection{}, id).Error; err != nil {
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

	for _, s := range settings {
		existing := models.SystemSetting{Key: s.Key}
		if err := h.db.Gorm().FirstOrCreate(&existing, models.SystemSetting{Key: s.Key}).Error; err != nil {
			continue
		}
		if !s.IsSecret || s.Value != "" {
			existing.Value = s.Value
			existing.Label = s.Label
			existing.Category = s.Category
			h.db.Gorm().Save(&existing)
		}
	}

	c.JSON(http.StatusOK, models.MessageResponse("Settings updated"))
}

func (h *Handler) GetDashboardAll(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	var fortigates []models.FortiGate
	h.db.Gorm().Find(&fortigates)

	var connections []models.FortiGateConnection
	h.db.Gorm().Preload("SourceFG").Preload("DestFG").Find(&connections)

	var recentAlerts []models.Alert
	h.db.Gorm().Order("timestamp DESC").Limit(20).Find(&recentAlerts)

	dashboard := models.DashboardData{
		FortiGates:   fortigates,
		RecentAlerts: recentAlerts,
		Connections:  connections,
	}

	c.JSON(http.StatusOK, models.SuccessResponse(dashboard))
}
