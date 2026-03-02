package handlers

import (
	"log"
	"net/http"
	"strconv"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/uptime"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetPublicDevices(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]gin.H{}))
		return
	}

	var devices []models.Device
	if err := h.db.Gorm().Where("enabled = ?", true).Find(&devices).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get devices"))
		return
	}

	// Return only safe public fields
	result := make([]gin.H, 0, len(devices))
	for _, d := range devices {
		result = append(result, gin.H{
			"id":     d.ID,
			"name":   d.Name,
			"status": d.Status,
		})
	}
	c.JSON(http.StatusOK, models.SuccessResponse(result))
}

// resolvePublicDeviceID returns the device ID from ?device_id query param,
// or falls back to the first enabled device.
func (h *Handler) resolvePublicDeviceID(c *gin.Context) (uint, bool) {
	if idStr := c.Query("device_id"); idStr != "" {
		id, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			return 0, false
		}
		return uint(id), true
	}
	// Default to first enabled device
	if h.db != nil {
		var dev models.Device
		if err := h.db.Gorm().Where("enabled = ?", true).Order("id ASC").First(&dev).Error; err == nil {
			return dev.ID, true
		}
	}
	return 0, false
}

func (h *Handler) GetPublicDashboard(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	deviceID, hasDevice := h.resolvePublicDeviceID(c)

	// Try SNMP first (only for legacy single-device mode without device_id param)
	if !hasDevice && h.snmpClient != nil {
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
	if h.db != nil && hasDevice {
		var status models.SystemStatus
		if err := h.db.Gorm().Where("device_id = ?", deviceID).Order("timestamp DESC").First(&status).Error; err == nil {
			// Get device name
			var dev models.Device
			h.db.Gorm().Select("name").Where("id = ?", deviceID).First(&dev)
			uptimeStats := h.uptimeTrack.GetStats()
			publicData := gin.H{
				"hostname":     status.Hostname,
				"device_name":  dev.Name,
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
	} else if h.db != nil {
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

	deviceID, hasDevice := h.resolvePublicDeviceID(c)

	// Try SNMP first (only for legacy single-device mode)
	if !hasDevice && h.snmpClient != nil {
		interfaces, err := h.snmpClient.GetInterfaceStats()
		if err == nil {
			c.JSON(http.StatusOK, models.SuccessResponse(interfaces))
			return
		}
	}

	// Fall back to database
	if h.db != nil && hasDevice {
		var latestIface models.InterfaceStats
		if err := h.db.Gorm().Where("device_id = ?", deviceID).Order("timestamp DESC").First(&latestIface).Error; err == nil {
			var ifaces []models.InterfaceStats
			h.db.Gorm().Where("device_id = ? AND timestamp = ?", deviceID, latestIface.Timestamp).Find(&ifaces)
			c.JSON(http.StatusOK, models.SuccessResponse(ifaces))
			return
		}
	} else if h.db != nil {
		interfaces, err := h.db.GetLatestInterfaceStats()
		if err == nil && len(interfaces) > 0 {
			c.JSON(http.StatusOK, models.SuccessResponse(interfaces))
			return
		}
	}

	c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("No interface data available"))
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

func (h *Handler) GetDashboardAll(c *gin.Context) {
	devices := []models.Device{}
	connections := []models.DeviceConnection{}
	recentAlerts := []models.Alert{}

	if h.db != nil {
		if err := h.db.Gorm().Preload("Site").Preload("Probe").Find(&devices).Error; err != nil {
			log.Printf("Failed to get devices: %v", err)
		}

		if err := h.db.Gorm().Preload("SourceDevice").Preload("DestDevice").Find(&connections).Error; err != nil {
			log.Printf("Failed to get connections: %v", err)
		}

		if err := h.db.Gorm().Order("timestamp DESC").Limit(20).Find(&recentAlerts).Error; err != nil {
			log.Printf("Failed to get recent alerts: %v", err)
		}
	}

	// Redact SNMP secrets
	httputil.RedactDevices(devices)

	// Per-device enrichment: latest system status, interface summary, VPN summary
	type DeviceEnrichment struct {
		DeviceID     uint    `json:"device_id"`
		CPUUsage     float64 `json:"cpu_usage"`
		MemoryUsage  float64 `json:"memory_usage"`
		SessionCount int     `json:"session_count"`
		IfaceTotal   int     `json:"iface_total"`
		IfaceUp      int     `json:"iface_up"`
		IfaceDown    int     `json:"iface_down"`
		VPNTotal     int     `json:"vpn_total"`
		VPNUp        int     `json:"vpn_up"`
	}

	enrichments := make(map[uint]*DeviceEnrichment)
	if h.db != nil {
		for _, dev := range devices {
			e := &DeviceEnrichment{DeviceID: dev.ID}
			// Latest system status
			var ss models.SystemStatus
			if err := h.db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&ss).Error; err == nil {
				e.CPUUsage = ss.CPUUsage
				e.MemoryUsage = ss.MemoryUsage
				e.SessionCount = ss.SessionCount
			}
			// Interface summary
			var latestIface models.InterfaceStats
			if err := h.db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&latestIface).Error; err == nil {
				var total, up int64
				h.db.Gorm().Model(&models.InterfaceStats{}).Where("device_id = ? AND timestamp = ?", dev.ID, latestIface.Timestamp).Count(&total)
				h.db.Gorm().Model(&models.InterfaceStats{}).Where("device_id = ? AND timestamp = ? AND status = 'up'", dev.ID, latestIface.Timestamp).Count(&up)
				e.IfaceTotal = int(total)
				e.IfaceUp = int(up)
				e.IfaceDown = int(total - up)
			}
			// VPN summary
			var latestVPN models.VPNStatus
			if err := h.db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&latestVPN).Error; err == nil {
				var vpnTotal, vpnUp int64
				h.db.Gorm().Model(&models.VPNStatus{}).Where("device_id = ? AND timestamp = ?", dev.ID, latestVPN.Timestamp).Count(&vpnTotal)
				h.db.Gorm().Model(&models.VPNStatus{}).Where("device_id = ? AND timestamp = ? AND status = 'up'", dev.ID, latestVPN.Timestamp).Count(&vpnUp)
				e.VPNTotal = int(vpnTotal)
				e.VPNUp = int(vpnUp)
			}
			enrichments[dev.ID] = e
		}
	}

	dashboard := models.DashboardData{
		Devices:      devices,
		RecentAlerts: recentAlerts,
		Connections:  connections,
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"dashboard":   dashboard,
		"enrichments": enrichments,
	}))
}

func (h *Handler) GetDashboardStats(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(nil))
		return
	}

	hours := httputil.ParseHours(c)

	stats, err := h.db.GetDashboardTimeSeries(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get dashboard stats"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(stats))
}
