package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/snmp"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetDevices(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.Device{}))
		return
	}

	devices, err := h.db.GetAllDevices()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get devices"))
		return
	}

	httputil.RedactDevices(devices)

	c.JSON(http.StatusOK, models.SuccessResponse(devices))
}

func (h *Handler) CreateDevice(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	var device models.Device
	if err := c.ShouldBindJSON(&device); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	// Validate required fields
	if strings.TrimSpace(device.Name) == "" || strings.TrimSpace(device.IPAddress) == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Name and IP address are required"))
		return
	}

	// Length validation
	if len(device.Name) > 255 || len(device.Hostname) > 255 || len(device.IPAddress) > 255 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Name, hostname, and IP address must be 255 characters or less"))
		return
	}
	if len(device.Location) > 500 || len(device.Description) > 1000 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Location (max 500) or description (max 1000) too long"))
		return
	}

	// Default and validate vendor
	if device.Vendor == "" {
		device.Vendor = "fortigate"
	}
	if !isValidVendor(device.Vendor) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid vendor: must be fortigate, paloalto, cisco_asa, or generic"))
		return
	}

	// Validate IP to prevent SSRF
	if !isValidExternalIP(device.IPAddress) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid or disallowed IP address"))
		return
	}

	// Default and validate SNMP port
	if device.SNMPPort == 0 {
		device.SNMPPort = 161
	}
	if device.SNMPPort < 1 || device.SNMPPort > 65535 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid SNMP port"))
		return
	}

	device.ID = 0
	device.Status = "unknown"
	device.CreatedAt = time.Time{}
	device.UpdatedAt = time.Time{}
	device.LastPolled = time.Time{}
	if err := h.db.CreateDevice(&device); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create device"))
		return
	}

	httputil.RedactDevice(&device)
	c.JSON(http.StatusCreated, models.SuccessResponse(device))
}

func (h *Handler) UpdateDevice(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	device, err := h.db.GetDevice(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Device not found"))
		return
	}

	allowedFields := map[string]bool{
		"name":             true,
		"hostname":         true,
		"ip_address":       true,
		"snmp_port":        true,
		"snmp_community":   true,
		"snmp_version":     true,
		"snmpv3_username":  true,
		"snmpv3_auth_type": true,
		"snmpv3_auth_pass": true,
		"snmpv3_priv_type": true,
		"snmpv3_priv_pass": true,
		"location":         true,
		"description":      true,
		"enabled":          true,
		"site_id":          true,
		"probe_id":         true,
		"vendor":           true,
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

	// Validate string field lengths
	stringLimits := map[string]int{
		"name": 255, "hostname": 255, "ip_address": 255,
		"location": 500, "description": 1000,
		"snmp_community": 255, "snmpv3_username": 255,
	}
	for field, maxLen := range stringLimits {
		if val, ok := filteredUpdates[field]; ok {
			if str, isStr := val.(string); isStr && len(str) > maxLen {
				c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("Field %s exceeds max length of %d", field, maxLen)))
				return
			}
		}
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

	// Validate vendor if present
	if vendorVal, ok := filteredUpdates["vendor"]; ok {
		vendorStr, isStr := vendorVal.(string)
		if !isStr || !isValidVendor(vendorStr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid vendor: must be fortigate, paloalto, cisco_asa, or generic"))
			return
		}
	}

	if err := h.db.Gorm().Model(device).Updates(filteredUpdates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update device"))
		return
	}

	// Re-fetch to return fresh data
	updated, err := h.db.GetDevice(id)
	if err != nil {
		httputil.RedactDevice(device)
		c.JSON(http.StatusOK, models.SuccessResponse(device))
		return
	}
	httputil.RedactDevice(updated)
	c.JSON(http.StatusOK, models.SuccessResponse(updated))
}

func (h *Handler) DeleteDevice(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := h.db.DeleteDevice(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete device"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Device deleted"))
}

func (h *Handler) GetDeviceDetail(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	device, err := h.db.GetDevice(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Device not found"))
		return
	}

	// Redact secrets
	httputil.RedactDevice(device)

	// Latest system status
	var systemStatus *models.SystemStatus
	var ss models.SystemStatus
	if err := h.db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").First(&ss).Error; err == nil {
		systemStatus = &ss
	}

	// Latest interface stats (most recent timestamp)
	var latestIface models.InterfaceStats
	var interfaces []models.InterfaceStats
	if err := h.db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").First(&latestIface).Error; err == nil {
		h.db.Gorm().Where("device_id = ? AND timestamp = ?", id, latestIface.Timestamp).Find(&interfaces)
	}

	// Latest VPN statuses
	vpnStatuses, _ := h.db.GetLatestVPNStatuses(id)

	// Latest hardware sensors
	var latestSensor models.HardwareSensor
	var sensors []models.HardwareSensor
	if err := h.db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").First(&latestSensor).Error; err == nil {
		h.db.Gorm().Where("device_id = ? AND timestamp = ?", id, latestSensor.Timestamp).Find(&sensors)
	}

	// Latest processor stats
	processorStats, _ := h.db.GetLatestProcessorStats(id)

	// Recent alerts
	var recentAlerts []models.Alert
	h.db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").Limit(20).Find(&recentAlerts)

	// Ping stats
	var pingStats []models.PingStats
	h.db.Gorm().Where("device_id = ?", id).Order("updated_at DESC").Limit(100).Find(&pingStats)

	// Latest HA status
	var latestHA models.HAStatus
	var haStatus []models.HAStatus
	if err := h.db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").First(&latestHA).Error; err == nil {
		h.db.Gorm().Where("device_id = ? AND timestamp = ?", id, latestHA.Timestamp).Find(&haStatus)
	}

	// Latest security stats
	var securityStats *models.SecurityStats
	var secStats models.SecurityStats
	if err := h.db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").First(&secStats).Error; err == nil {
		securityStats = &secStats
	}

	// Latest SD-WAN health
	var latestSDWAN models.SDWANHealth
	var sdwanHealth []models.SDWANHealth
	if err := h.db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").First(&latestSDWAN).Error; err == nil {
		h.db.Gorm().Where("device_id = ? AND timestamp = ?", id, latestSDWAN.Timestamp).Find(&sdwanHealth)
	}

	// Latest license info
	var latestLicense models.LicenseInfo
	var licenseInfo []models.LicenseInfo
	if err := h.db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").First(&latestLicense).Error; err == nil {
		h.db.Gorm().Where("device_id = ? AND timestamp = ?", id, latestLicense.Timestamp).Find(&licenseInfo)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"device":           device,
		"system_status":    systemStatus,
		"interfaces":       interfaces,
		"vpn_status":       vpnStatuses,
		"hardware_sensors": sensors,
		"processor_stats":  processorStats,
		"recent_alerts":    recentAlerts,
		"ping_stats":       pingStats,
		"ha_status":        haStatus,
		"security_stats":   securityStats,
		"sdwan_health":     sdwanHealth,
		"license_info":     licenseInfo,
	}))
}

func (h *Handler) GetDeviceStatusHistory(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	hours := httputil.ParseHours(c)

	statuses, err := h.db.GetSystemStatusHistory(id, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get status history"))
		return
	}

	pingHistory, err := h.db.GetPingResultHistory(id, hours)
	if err != nil {
		// Non-fatal: return system status without ping data
		pingHistory = nil
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"system_status": statuses,
		"ping_history":  pingHistory,
	}))
}

func (h *Handler) GetInterfaceHistory(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	deviceID := c.Param("id")
	ifIndex := c.Param("ifIndex")

	deviceIDUint, err := strconv.ParseUint(deviceID, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid device ID"))
		return
	}

	ifIndexInt, err := strconv.Atoi(ifIndex)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid interface index"))
		return
	}

	hours := httputil.ParseHours(c)

	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	var stats []models.InterfaceStats
	err = h.db.Gorm().Where("device_id = ? AND `index` = ? AND timestamp > ?", deviceIDUint, ifIndexInt, since).
		Order("timestamp ASC").Limit(500).Find(&stats).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get interface history"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(stats))
}

func (h *Handler) GetInterfaceChart(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	deviceID := c.Param("id")
	ifIndex := c.Param("ifIndex")

	deviceIDUint, err := strconv.ParseUint(deviceID, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid device ID"))
		return
	}

	ifIndexInt, err := strconv.Atoi(ifIndex)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid interface index"))
		return
	}

	rangeStr := c.DefaultQuery("range", "24h")
	validRanges := map[string]bool{"24h": true, "7d": true, "30d": true, "90d": true}
	if !validRanges[rangeStr] {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid range: must be 24h, 7d, 30d, or 90d"))
		return
	}

	buckets, err := h.db.GetInterfaceChartData(uint(deviceIDUint), ifIndexInt, rangeStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get chart data"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(buckets))
}

func (h *Handler) GetAllInterfaces(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	// Get all enabled devices
	var devices []models.Device
	if err := h.db.Gorm().Where("enabled = ?", true).Find(&devices).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get devices"))
		return
	}

	// Optional filters
	filterDeviceID := c.Query("device_id")
	filterStatus := c.Query("status")
	filterType := c.Query("type")

	type EnrichedInterface struct {
		models.InterfaceStats
		DeviceName string `json:"device_name"`
	}

	var result []EnrichedInterface

	for _, dev := range devices {
		if filterDeviceID != "" {
			if fmt.Sprintf("%d", dev.ID) != filterDeviceID {
				continue
			}
		}

		// Get latest interface snapshot for this device
		var latestIface models.InterfaceStats
		if err := h.db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&latestIface).Error; err != nil {
			continue
		}

		var ifaces []models.InterfaceStats
		h.db.Gorm().Where("device_id = ? AND timestamp = ?", dev.ID, latestIface.Timestamp).Find(&ifaces)

		for _, iface := range ifaces {
			if filterStatus != "" && iface.Status != filterStatus {
				continue
			}
			if filterType != "" && iface.TypeName != filterType {
				continue
			}
			result = append(result, EnrichedInterface{
				InterfaceStats: iface,
				DeviceName:     dev.Name,
			})
		}
	}

	limit, offset := httputil.ParsePagination(c)
	total := len(result)

	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"interfaces": result[start:end],
		"total":      total,
		"limit":      limit,
		"offset":     offset,
	}))
}

type TestDeviceRequest struct {
	IPAddress      string `json:"ip_address" binding:"required"`
	SNMPPort       int    `json:"snmp_port"`
	SNMPCommunity  string `json:"snmp_community"`
	SNMPVersion    string `json:"snmp_version"`
	SNMPV3Username string `json:"snmpv3_username"`
	SNMPV3AuthType string `json:"snmpv3_auth_type"`
	SNMPV3AuthPass string `json:"snmpv3_auth_pass"`
	SNMPV3PrivType string `json:"snmpv3_priv_type"`
	SNMPV3PrivPass string `json:"snmpv3_priv_pass"`
	ProbeID        *uint  `json:"probe_id"`
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

	// Probe-managed devices cannot be tested from the API server
	if req.ProbeID != nil && *req.ProbeID > 0 {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success":       false,
			"probe_managed": true,
			"message":       "Device is managed by a remote probe. Direct test not available — the probe polls this device automatically.",
		}))
		return
	}

	cfg := &config.Config{
		SNMP: config.SNMPConfig{
			SNMPHost:   req.IPAddress,
			SNMPPort:   req.SNMPPort,
			Community:  req.SNMPCommunity,
			Version:    req.SNMPVersion,
			V3Username: req.SNMPV3Username,
			V3AuthType: req.SNMPV3AuthType,
			V3AuthPass: req.SNMPV3AuthPass,
			V3PrivType: req.SNMPV3PrivType,
			V3PrivPass: req.SNMPV3PrivPass,
			Timeout:    10 * time.Second,
			Retries:    1,
		},
	}

	client, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		log.Printf("TestDevice connect error for %s: %v", req.IPAddress, err)
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": fmt.Sprintf("Failed to connect to device: %v", err),
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
			"message": fmt.Sprintf("Failed to poll device: %v", err),
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
