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

	// Reject oversized passwords to prevent bcrypt CPU exhaustion DoS
	if len(creds.Password) > 1024 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid credentials"))
		return
	}

	// Reject oversized usernames to prevent map/DB bloat
	if len(creds.Username) > 255 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid credentials"))
		return
	}

	ip := c.ClientIP()
	userAgent := c.Request.UserAgent()
	// Truncate user agent to prevent stored XSS and DB bloat
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}

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
	var adminID uint = 1
	if h.db != nil {
		adminRecord, adminErr := h.db.GetAdminByUsername(creds.Username)
		if adminErr == nil && adminRecord != nil {
			adminID = adminRecord.ID
		}
	}

	token, err := h.authManager.GenerateToken(creds.Username, adminID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to generate token"))
		return
	}

	// Generate HMAC-signed CSRF token tied to the auth token
	csrfToken := middleware.GenerateCSRFToken(token, h.config.Server.JWTSecretKey)

	cookieSecure := h.config != nil && h.config.Server.CookieSecure
	cookieMaxAge := 86400
	if h.config != nil && h.config.Auth.TokenExpiry > 0 {
		cookieMaxAge = int(h.config.Auth.TokenExpiry.Seconds())
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		MaxAge:   cookieMaxAge,
		Path:     "/",
		Secure:   cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		MaxAge:   cookieMaxAge,
		Path:     "/",
		Secure:   cookieSecure,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message":    "Login successful",
		"csrf_token": csrfToken,
	}))
}

func (h *Handler) Logout(c *gin.Context) {
	// Only clear cookies if an auth token is present (prevents cross-origin logout)
	if _, err := c.Cookie("auth_token"); err != nil {
		c.JSON(http.StatusOK, models.MessageResponse("Already logged out"))
		return
	}

	cookieSecure := h.config != nil && h.config.Server.CookieSecure

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

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

	// Redact SNMP community strings from response
	for i := range fortigates {
		if fortigates[i].SNMPCommunity != "" {
			fortigates[i].SNMPCommunity = "********"
		}
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

	// Validate required fields
	if strings.TrimSpace(fg.Name) == "" || strings.TrimSpace(fg.IPAddress) == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Name and IP address are required"))
		return
	}

	// Validate IP to prevent SSRF
	if !isValidExternalIP(fg.IPAddress) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid or disallowed IP address"))
		return
	}

	// Default and validate SNMP port
	if fg.SNMPPort == 0 {
		fg.SNMPPort = 161
	}
	if fg.SNMPPort < 1 || fg.SNMPPort > 65535 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid SNMP port"))
		return
	}

	fg.Status = "unknown"
	if err := h.db.CreateFortiGate(&fg); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create FortiGate"))
		return
	}

	fg.SNMPCommunity = "********"
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

	// Validate snmp_port is a valid number if present
	if portVal, ok := filteredUpdates["snmp_port"]; ok {
		port, isNum := portVal.(float64) // JSON numbers decode as float64
		if !isNum || port < 1 || port > 65535 || port != float64(int(port)) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid SNMP port"))
			return
		}
	}

	// Validate ip_address if present
	if ipVal, ok := filteredUpdates["ip_address"]; ok {
		ipStr, isStr := ipVal.(string)
		if !isStr || !isValidExternalIP(ipStr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid or disallowed IP address"))
			return
		}
	}

	// Validate enabled is boolean if present
	if enabledVal, ok := filteredUpdates["enabled"]; ok {
		if _, isBool := enabledVal.(bool); !isBool {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid value for enabled"))
			return
		}
	}

	if err := h.db.Gorm().Model(fg).Updates(filteredUpdates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update FortiGate"))
		return
	}

	// Re-fetch to return fresh data
	updated, err := h.db.GetFortiGate(uint(idUint))
	if err != nil {
		fg.SNMPCommunity = "********"
		c.JSON(http.StatusOK, models.SuccessResponse(fg))
		return
	}
	updated.SNMPCommunity = "********"
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

func (h *Handler) GetSites(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.Site{}))
		return
	}

	sites, err := h.db.GetAllSites()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to fetch sites"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(sites))
}

func (h *Handler) GetSite(c *gin.Context) {
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

	site, err := h.db.GetSite(uint(idUint))
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Site not found"))
		return
	}

	var children []models.Site
	h.db.Gorm().Where("parent_site_id = ?", idUint).Find(&children)

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"data":     site,
		"children": children,
	})
}

func (h *Handler) CreateSite(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	var site models.Site
	if err := c.ShouldBindJSON(&site); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if strings.TrimSpace(site.Name) == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Name is required"))
		return
	}

	existing, err := h.db.GetSiteByName(site.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to check existing site"))
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, models.ErrorResponse("Site with this name already exists"))
		return
	}

	if site.ParentSiteID != nil && *site.ParentSiteID > 0 {
		parent, err := h.db.GetSite(*site.ParentSiteID)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Parent site not found"))
			return
		}
		if parent == nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Parent site not found"))
			return
		}
	}

	if err := h.db.CreateSite(&site); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create site"))
		return
	}

	c.JSON(http.StatusCreated, models.SuccessResponse(site))
}

func (h *Handler) UpdateSite(c *gin.Context) {
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

	site, err := h.db.GetSite(uint(idUint))
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Site not found"))
		return
	}

	allowedFields := map[string]bool{
		"name":           true,
		"region":         true,
		"country":        true,
		"address":        true,
		"timezone":       true,
		"parent_site_id": true,
		"description":    true,
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if parentIDVal, ok := updates["parent_site_id"]; ok {
		if parentIDVal == nil {
			updates["parent_site_id"] = nil
		} else if pid, isNum := parentIDVal.(float64); isNum && pid > 0 {
			parent, err := h.db.GetSite(uint(pid))
			if err != nil || parent == nil {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Parent site not found"))
				return
			}
			if uint(pid) == uint(idUint) {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Site cannot be its own parent"))
				return
			}
		}
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

	if nameVal, ok := filteredUpdates["name"]; ok {
		if nameStr, isStr := nameVal.(string); isStr {
			existing, err := h.db.GetSiteByName(nameStr)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to check existing site"))
				return
			}
			if existing != nil && existing.ID != uint(idUint) {
				c.JSON(http.StatusConflict, models.ErrorResponse("Site with this name already exists"))
				return
			}
		}
	}

	if err := h.db.Gorm().Model(site).Updates(filteredUpdates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update site"))
		return
	}

	updated, err := h.db.GetSite(uint(idUint))
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(site))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(updated))
}

func (h *Handler) DeleteSite(c *gin.Context) {
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

	var children []models.Site
	if err := h.db.Gorm().Where("parent_site_id = ?", idUint).Find(&children).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to check child sites"))
		return
	}
	if len(children) > 0 {
		c.JSON(http.StatusConflict, models.ErrorResponse("Cannot delete site with child sites"))
		return
	}

	if err := h.db.DeleteSite(uint(idUint)); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete site"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Site deleted"))
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

	// Validate required FK references
	if conn.SourceFGID == 0 || conn.DestFGID == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source and destination FortiGate IDs are required"))
		return
	}
	if conn.SourceFGID == conn.DestFGID {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source and destination cannot be the same device"))
		return
	}
	if _, err := h.db.GetFortiGate(conn.SourceFGID); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source FortiGate not found"))
		return
	}
	if _, err := h.db.GetFortiGate(conn.DestFGID); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Destination FortiGate not found"))
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
		"connection_type": true,
		"notes":           true,
		"status":          true,
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	// Validate status enum if provided
	if statusVal, ok := updates["status"]; ok {
		validStatuses := map[string]bool{"unknown": true, "up": true, "down": true}
		if s, isStr := statusVal.(string); !isStr || !validStatuses[s] {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid status value"))
			return
		}
	}

	// Validate FK references if being updated
	if srcVal, ok := updates["source_fg_id"]; ok {
		srcID, isNum := srcVal.(float64)
		if !isNum || srcID < 1 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid source FortiGate ID"))
			return
		}
		if _, err := h.db.GetFortiGate(uint(srcID)); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Source FortiGate not found"))
			return
		}
	}
	if dstVal, ok := updates["dest_fg_id"]; ok {
		dstID, isNum := dstVal.(float64)
		if !isNum || dstID < 1 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid destination FortiGate ID"))
			return
		}
		if _, err := h.db.GetFortiGate(uint(dstID)); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Destination FortiGate not found"))
			return
		}
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

	// Validate source and dest won't be the same after update
	effectiveSrc := conn.SourceFGID
	effectiveDst := conn.DestFGID
	if srcVal, ok := filteredUpdates["source_fg_id"]; ok {
		if srcID, isNum := srcVal.(float64); isNum {
			effectiveSrc = uint(srcID)
		}
	}
	if dstVal, ok := filteredUpdates["dest_fg_id"]; ok {
		if dstID, isNum := dstVal.(float64); isNum {
			effectiveDst = uint(dstID)
		}
	}
	if effectiveSrc == effectiveDst {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source and destination cannot be the same device"))
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

	result := h.db.Gorm().Delete(&models.FortiGateConnection{}, idUint)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete connection"))
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Connection not found"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Connection deleted"))
}

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

	for i := range probes {
		probes[i].TLSCertPath = "********"
		probes[i].TLSKeyPath = "********"
		probes[i].ServerTLSCert = "********"
	}

	c.JSON(http.StatusOK, models.SuccessResponse(probes))
}

func (h *Handler) GetProbe(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Probe not found"))
		return
	}

	id := c.Param("id")
	idUint, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid ID format"))
		return
	}

	probe, err := h.db.GetProbe(uint(idUint))
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Probe not found"))
		return
	}

	probe.TLSCertPath = "********"
	probe.TLSKeyPath = "********"
	probe.ServerTLSCert = "********"

	c.JSON(http.StatusOK, models.SuccessResponse(probe))
}

func (h *Handler) CreateProbe(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
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

	probe.TLSCertPath = "********"
	probe.TLSKeyPath = "********"
	probe.ServerTLSCert = "********"
	c.JSON(http.StatusCreated, models.SuccessResponse(probe))
}

func (h *Handler) UpdateProbe(c *gin.Context) {
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

	probe, err := h.db.GetProbe(uint(idUint))
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

	updated, err := h.db.GetProbe(uint(idUint))
	if err != nil {
		probe.TLSCertPath = "********"
		probe.TLSKeyPath = "********"
		probe.ServerTLSCert = "********"
		c.JSON(http.StatusOK, models.SuccessResponse(probe))
		return
	}
	updated.TLSCertPath = "********"
	updated.TLSKeyPath = "********"
	updated.ServerTLSCert = "********"
	c.JSON(http.StatusOK, models.SuccessResponse(updated))
}

func (h *Handler) DeleteProbe(c *gin.Context) {
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

	if err := h.db.DeleteProbe(uint(idUint)); err != nil {
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

	for i := range probes {
		probes[i].TLSCertPath = "********"
		probes[i].TLSKeyPath = "********"
		probes[i].ServerTLSCert = "********"
	}

	c.JSON(http.StatusOK, models.SuccessResponse(probes))
}

type ApproveProbeRequest struct {
	Notes string `json:"notes"`
}

func (h *Handler) ApproveProbe(c *gin.Context) {
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

	if err := h.db.ApproveProbe(uint(idUint), adminID); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to approve probe"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Probe approved successfully"))
}

type RejectProbeRequest struct {
	Reason string `json:"reason" binding:"required"`
}

func (h *Handler) RejectProbe(c *gin.Context) {
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

	var req RejectProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Reason is required"))
		return
	}

	if _, exists := c.Get("user_id"); !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Not authenticated"))
		return
	}

	if err := h.db.RejectProbe(uint(idUint), req.Reason); err != nil {
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

	// Mask secret values
	for i := range settings {
		if settings[i].IsSecret {
			settings[i].Value = "********"
		}
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
		"cpu_threshold":           true,
		"memory_threshold":        true,
		"disk_threshold":          true,
		"session_threshold":       true,
		"email_enabled":           true,
		"slack_webhook":           true,
		"discord_webhook":         true,
		"webhook_url":             true,
		"public_show_hostname":    true,
		"public_show_uptime":      true,
		"public_show_cpu":         true,
		"public_show_memory":      true,
		"public_show_sessions":    true,
		"public_show_interfaces":  true,
		"public_refresh_interval": true,
	}

	var validSettings []models.SystemSetting
	for _, s := range settings {
		if !allowedKeys[s.Key] {
			continue
		}
		// Validate values by key type
		switch s.Key {
		case "cpu_threshold", "memory_threshold", "disk_threshold":
			v, err := strconv.ParseFloat(s.Value, 64)
			if err != nil || v < 0 || v > 100 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("Invalid value for %s: must be 0-100", s.Key)))
				return
			}
		case "session_threshold":
			v, err := strconv.Atoi(s.Value)
			if err != nil || v < 1 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid value for session_threshold: must be a positive integer"))
				return
			}
		case "public_refresh_interval":
			v, err := strconv.Atoi(s.Value)
			if err != nil || v < 5 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid value for public_refresh_interval: must be at least 5"))
				return
			}
		case "email_enabled", "public_show_hostname", "public_show_uptime",
			"public_show_cpu", "public_show_memory", "public_show_sessions", "public_show_interfaces":
			if s.Value != "true" && s.Value != "false" {
				c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("Invalid value for %s: must be true or false", s.Key)))
				return
			}
		}
		validSettings = append(validSettings, s)
	}

	var failedKeys []string
	for _, s := range validSettings {
		existing := models.SystemSetting{Key: s.Key}
		if err := h.db.Gorm().FirstOrCreate(&existing, models.SystemSetting{Key: s.Key}).Error; err != nil {
			log.Printf("Failed to find/create setting %s: %v", s.Key, err)
			failedKeys = append(failedKeys, s.Key)
			continue
		}
		if !s.IsSecret || s.Value != "" {
			existing.Value = s.Value
			existing.Label = s.Label
			existing.Category = s.Category
			if err := h.db.Gorm().Save(&existing).Error; err != nil {
				log.Printf("Failed to save setting %s: %v", s.Key, err)
				failedKeys = append(failedKeys, s.Key)
				continue
			}
		}
	}

	if len(failedKeys) > 0 {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(fmt.Sprintf("Failed to save %d setting(s)", len(failedKeys))))
		return
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

	// Redact SNMP community strings
	for i := range fortigates {
		if fortigates[i].SNMPCommunity != "" {
			fortigates[i].SNMPCommunity = "********"
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

	// Validate IP to prevent SSRF against internal services
	if !isValidExternalIP(req.IPAddress) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid or disallowed IP address"))
		return
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

	// Reject oversized current password
	if len(req.CurrentPassword) > 1024 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	// Enforce password length constraints
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("New password must be at least 8 characters"))
		return
	}
	if len(req.NewPassword) > 72 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("New password must be at most 72 characters"))
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

	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Invalid session data"))
		return
	}
	userIDUint, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Invalid session data"))
		return
	}

	// Verify current password directly (bypass rate limiter — user is already authenticated)
	admin, adminErr := h.db.GetAdminByUsername(usernameStr)
	if adminErr != nil || admin == nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Current password is incorrect"))
		return
	}
	if !h.authManager.CheckPassword(req.CurrentPassword, admin.Password) {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("Current password is incorrect"))
		return
	}

	hashedPassword, err := h.authManager.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to process password"))
		return
	}

	err = h.db.UpdateAdminPassword(userIDUint, hashedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update password"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Password changed successfully"))
}

// isBlockedIP checks if an IP address is loopback, unspecified, or link-local.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}

// isValidExternalIP validates that the IP/hostname does not resolve to a blocked address
// to prevent SSRF attacks against internal services.
func isValidExternalIP(ipStr string) bool {
	// Try parsing as IP first
	ip := net.ParseIP(ipStr)
	if ip != nil {
		return !isBlockedIP(ip)
	}

	// It's a hostname - resolve it and validate all resolved IPs
	addrs, err := net.LookupHost(ipStr)
	if err != nil {
		// Cannot resolve - reject to be safe
		return false
	}
	for _, addr := range addrs {
		resolved := net.ParseIP(addr)
		if resolved != nil && isBlockedIP(resolved) {
			return false
		}
	}
	return len(addrs) > 0
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
	if err == nil && existingProbe.ID > 0 {
		if existingProbe.ApprovalStatus == "approved" {
			c.JSON(http.StatusOK, gin.H{
				"success":    true,
				"probe_id":   existingProbe.ID,
				"probe_name": existingProbe.Name,
				"approved":   true,
			})
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "Probe pending approval"})
		return
	}

	probeName := "probe-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	probe := &models.Probe{
		Name:            probeName,
		RegistrationKey: req.RegistrationKey,
		Status:          "online",
		ApprovalStatus:  "approved",
		ApprovedAt:      func() *time.Time { t := time.Now(); return &t }(),
	}

	if err := h.db.Gorm().Create(probe).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to register probe"})
		return
	}

	h.db.Gorm().Model(&models.SystemSetting{}).Where("key = ?", "probe_registration_"+req.RegistrationKey).Update("used", "true")

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"probe_id":   probe.ID,
		"probe_name": probe.Name,
		"approved":   true,
	})
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

	h.db.Gorm().Model(&models.Probe{}).Where("id = ?", req.ProbeID).Updates(map[string]interface{}{
		"last_seen": time.Now(),
		"status":    req.Status,
	})

	c.JSON(http.StatusOK, gin.H{"success": true})
}
