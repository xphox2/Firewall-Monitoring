package handlers

import (
	"log"
	"net/http"
	"strconv"
	"time"

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
			var uptimeStats *uptime.UptimeStats
			if h.uptimeTrack != nil {
				stats := h.uptimeTrack.GetStats()
				uptimeStats = &stats
			}
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

func (h *Handler) GetPublicInterfaceChart(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	deviceID, hasDevice := h.resolvePublicDeviceID(c)
	if !hasDevice {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Device ID required"))
		return
	}

	ifIndexStr := c.Query("index")
	ifIndex, err := strconv.Atoi(ifIndexStr)
	if err != nil || ifIndex < 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid interface index"))
		return
	}

	viewType := c.DefaultQuery("view", "rate")
	if viewType != "total" && viewType != "rate" && viewType != "mix" {
		viewType = "rate"
	}

	rangeStr := c.DefaultQuery("range", "1h")
	validRanges := map[string]int{"1m": 1, "5m": 5, "15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080, "90d": 129600}
	hours, ok := validRanges[rangeStr]
	if !ok {
		hours = 60
	}

	since := time.Now().Add(-time.Duration(hours) * time.Minute)

	var stats []models.InterfaceStats
	err = h.db.Gorm().Where("device_id = ? AND `index` = ? AND timestamp > ?", deviceID, ifIndex, since).
		Order("timestamp ASC").Limit(2000).Find(&stats).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get interface data"))
		return
	}

	if len(stats) < 2 {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"labels":   []string{},
			"rx_total": []float64{},
			"tx_total": []float64{},
			"rx_rate":  []float64{},
			"tx_rate":  []float64{},
		}))
		return
	}

	labels := make([]string, 0, len(stats))
	rxTotal := make([]float64, 0, len(stats))
	txTotal := make([]float64, 0, len(stats))
	rxRate := make([]float64, 0, len(stats))
	txRate := make([]float64, 0, len(stats))

	for i, s := range stats {
		labels = append(labels, s.Timestamp.Format("15:04"))
		rxTotal = append(rxTotal, float64(s.InBytes))
		txTotal = append(txTotal, float64(s.OutBytes))

		var rRate, tRate float64
		if i > 0 {
			prev := stats[i-1]
			deltaBytesR := float64(s.InBytes) - float64(prev.InBytes)
			deltaBytesT := float64(s.OutBytes) - float64(prev.OutBytes)
			deltaTime := s.Timestamp.Sub(prev.Timestamp).Seconds()
			if deltaTime > 0 {
				rRate = (deltaBytesR * 8) / deltaTime / 1000000
				tRate = (deltaBytesT * 8) / deltaTime / 1000000
			}
		}
		rxRate = append(rxRate, rRate)
		txRate = append(txRate, tRate)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"labels":   labels,
		"rx_total": rxTotal,
		"tx_total": txTotal,
		"rx_rate":  rxRate,
		"tx_rate":  txRate,
		"view":     viewType,
		"range":    rangeStr,
	}))
}

func (h *Handler) GetPublicVPN(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	deviceID, hasDevice := h.resolvePublicDeviceID(c)

	if h.db != nil && hasDevice {
		vpnStatuses, err := h.db.GetLatestVPNStatuses(deviceID)
		if err == nil && vpnStatuses != nil {
			result := make([]gin.H, 0, len(vpnStatuses))
			for _, vpn := range vpnStatuses {
				result = append(result, gin.H{
					"tunnel_name":   vpn.TunnelName,
					"tunnel_type":   vpn.TunnelType,
					"remote_ip":     vpn.RemoteIP,
					"status":        vpn.Status,
					"state":         vpn.State,
					"phase1_name":   vpn.Phase1Name,
					"bytes_in":      vpn.BytesIn,
					"bytes_out":     vpn.BytesOut,
					"tunnel_uptime": vpn.TunnelUptime,
				})
			}
			c.JSON(http.StatusOK, models.SuccessResponse(result))
			return
		}
	}

	c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("No VPN data available"))
}

func (h *Handler) GetPublicConnections(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("No connections available"))
		return
	}

	var connections []models.DeviceConnection
	if err := h.db.Gorm().Preload("SourceDevice").Preload("DestDevice").Limit(100).Find(&connections).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get connections"))
		return
	}

	result := make([]gin.H, 0, len(connections))
	for _, conn := range connections {
		sourceName := ""
		destName := ""
		if conn.SourceDevice != nil {
			sourceName = conn.SourceDevice.Name
		}
		if conn.DestDevice != nil {
			destName = conn.DestDevice.Name
		}
		result = append(result, gin.H{
			"id":     conn.ID,
			"name":   conn.Name,
			"source": sourceName,
			"dest":   destName,
			"type":   conn.ConnectionType,
			"status": conn.Status,
			"notes":  "",
		})
	}
	c.JSON(http.StatusOK, models.SuccessResponse(result))
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
		DeviceID     uint       `json:"device_id"`
		HasStatus    bool       `json:"has_status"`
		StatusTime   *time.Time `json:"status_time,omitempty"`
		StatusRows   int64      `json:"status_rows"`
		CPUUsage     float64    `json:"cpu_usage"`
		MemoryUsage  float64    `json:"memory_usage"`
		SessionCount int        `json:"session_count"`
		IfaceTotal   int        `json:"iface_total"`
		IfaceUp      int        `json:"iface_up"`
		IfaceDown    int        `json:"iface_down"`
		VPNTotal     int        `json:"vpn_total"`
		VPNUp        int        `json:"vpn_up"`
		HAMode       string     `json:"ha_mode,omitempty"`
		HAMembers    int        `json:"ha_members,omitempty"`
		SDWANTotal   int        `json:"sdwan_total,omitempty"`
		SDWANAlive   int        `json:"sdwan_alive,omitempty"`
	}

	enrichments := make(map[uint]*DeviceEnrichment)
	if h.db != nil {
		for _, dev := range devices {
			e := &DeviceEnrichment{DeviceID: dev.ID}
			// Count total system_status rows for this device
			h.db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", dev.ID).Count(&e.StatusRows)
			// Latest system status
			var ss models.SystemStatus
			if err := h.db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&ss).Error; err == nil {
				e.HasStatus = true
				e.StatusTime = &ss.Timestamp
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
			// HA status summary
			var latestHA models.HAStatus
			if err := h.db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&latestHA).Error; err == nil {
				e.HAMode = latestHA.SystemMode
				var memberCount int64
				h.db.Gorm().Model(&models.HAStatus{}).Where("device_id = ? AND timestamp = ?", dev.ID, latestHA.Timestamp).Count(&memberCount)
				e.HAMembers = int(memberCount)
			}
			// SD-WAN health summary
			var latestSDWAN models.SDWANHealth
			if err := h.db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&latestSDWAN).Error; err == nil {
				var sdTotal, sdAlive int64
				h.db.Gorm().Model(&models.SDWANHealth{}).Where("device_id = ? AND timestamp = ?", dev.ID, latestSDWAN.Timestamp).Count(&sdTotal)
				h.db.Gorm().Model(&models.SDWANHealth{}).Where("device_id = ? AND timestamp = ? AND state = 'alive'", dev.ID, latestSDWAN.Timestamp).Count(&sdAlive)
				e.SDWANTotal = int(sdTotal)
				e.SDWANAlive = int(sdAlive)
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

// GetDeviceDataDiag returns per-device system_status record counts and latest values.
// Used to diagnose why some devices may show "No data" in the UI.
func (h *Handler) GetDeviceDataDiag(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(nil))
		return
	}

	var devices []models.Device
	h.db.Gorm().Select("id, name, ip_address, status, last_polled, probe_id").Find(&devices)

	type DeviceDiag struct {
		DeviceID   uint       `json:"device_id"`
		Name       string     `json:"name"`
		IPAddress  string     `json:"ip_address"`
		Status     string     `json:"status"`
		LastPolled time.Time  `json:"last_polled"`
		ProbeID    *uint      `json:"probe_id"`
		StatusRows int64      `json:"status_rows"`
		LatestCPU  float64    `json:"latest_cpu"`
		LatestMem  float64    `json:"latest_mem"`
		LatestTime *time.Time `json:"latest_time,omitempty"`
	}

	results := make([]DeviceDiag, 0, len(devices))
	for _, dev := range devices {
		diag := DeviceDiag{
			DeviceID:   dev.ID,
			Name:       dev.Name,
			IPAddress:  dev.IPAddress,
			Status:     dev.Status,
			LastPolled: dev.LastPolled,
			ProbeID:    dev.ProbeID,
		}

		h.db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", dev.ID).Count(&diag.StatusRows)

		var ss models.SystemStatus
		if err := h.db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&ss).Error; err == nil {
			diag.LatestCPU = ss.CPUUsage
			diag.LatestMem = ss.MemoryUsage
			diag.LatestTime = &ss.Timestamp
		}

		results = append(results, diag)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(results))
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
