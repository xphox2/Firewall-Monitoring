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
	"gorm.io/gorm"
)

func (h *Handler) GetPublicDevices(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]gin.H{}))
		return
	}

	var devices []models.Device
	if err := h.db.Gorm().Where("enabled = ? AND public_visible = ?", true, true).Find(&devices).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get devices"))
		return
	}

	// Return only safe public fields
	result := make([]gin.H, 0, len(devices))
	for _, d := range devices {
		result = append(result, gin.H{
			"id":             d.ID,
			"name":           d.Name,
			"status":         d.Status,
			"wan_speed_mbps": d.WanSpeedMbps,
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
	// Default to first enabled + public-visible device
	if h.db != nil {
		var dev models.Device
		if err := h.db.Gorm().Where("enabled = ? AND public_visible = ?", true, true).Order("id ASC").First(&dev).Error; err == nil {
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
			if err := h.db.Gorm().Select("name").Where("id = ?", deviceID).First(&dev).Error; err != nil {
				log.Printf("Device %d: failed to get device name: %v", deviceID, err)
			}
			var uptimeStats *uptime.UptimeStats
			if h.uptimeTrack != nil {
				stats := h.uptimeTrack.GetStats()
				uptimeStats = &stats
			}
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
			if err := h.db.Gorm().Where("device_id = ? AND timestamp = ?", deviceID, latestIface.Timestamp).Find(&ifaces).Error; err != nil {
				log.Printf("Device %d: failed to get interfaces at timestamp: %v", deviceID, err)
			}
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

	type bucketResult struct {
		Bucket   string
		InBytes  float64
		OutBytes float64
	}

	var hours int
	var maxPoints int

	switch rangeStr {
	case "5m":
		hours = 0 // special case - use minutes
		maxPoints = 10
	case "15m":
		hours = 0
		maxPoints = 20
	case "6h":
		hours = 6
		maxPoints = 360
	case "24h":
		hours = 24
		maxPoints = 96
	case "7d":
		hours = 168
		maxPoints = 168
	case "720":
		hours = 720
		maxPoints = 90
	case "8760":
		hours = 8760
		maxPoints = 365
	case "90d":
		hours = 2160
		maxPoints = 90
	default: // 1h or numeric fallback
		if parsed, err := strconv.Atoi(rangeStr); err == nil && parsed > 0 {
			hours = parsed
			maxPoints = 180
		} else {
			hours = 1
			maxPoints = 60
		}
	}

	// Calculate cutoff time
	var cutoff time.Time
	if rangeStr == "5m" {
		cutoff = time.Now().Add(-5 * time.Minute)
	} else if rangeStr == "15m" {
		cutoff = time.Now().Add(-15 * time.Minute)
	} else {
		cutoff = time.Now().Add(-time.Duration(hours) * time.Hour)
	}

	// Get raw data points
	var stats []models.InterfaceStats
	err = h.db.Gorm().Where("device_id = ? AND \"index\" = ? AND timestamp > ?", deviceID, ifIndex, cutoff).
		Order("timestamp ASC").Find(&stats).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get interface data"))
		return
	}

	if len(stats) < 2 {
		c.JSON(http.StatusOK, models.SuccessResponse(map[string]interface{}{
			"labels":   []string{},
			"rx_total": []float64{},
			"tx_total": []float64{},
			"rx_rate":  []float64{},
			"tx_rate":  []float64{},
			"total_rx": float64(0),
			"total_tx": float64(0),
			"view":     viewType,
			"range":    rangeStr,
		}))
		return
	}

	// Downsample if too many points
	var sampled []models.InterfaceStats
	if len(stats) > maxPoints {
		step := len(stats) / maxPoints
		for i := 0; i < len(stats); i += step {
			sampled = append(sampled, stats[i])
			if len(sampled) >= maxPoints {
				break
			}
		}
		// Always include last point
		if len(sampled) == 0 || sampled[len(sampled)-1].Timestamp != stats[len(stats)-1].Timestamp {
			sampled = append(sampled, stats[len(stats)-1])
		}
	} else {
		sampled = stats
	}

	labels := make([]string, 0, len(sampled))
	timestamps := make([]string, 0, len(sampled))
	rxTotalVals := make([]float64, 0, len(sampled))
	txTotalVals := make([]float64, 0, len(sampled))
	rxRate := make([]float64, 0, len(sampled))
	txRate := make([]float64, 0, len(sampled))

	// Calculate totals
	var totalRx, totalTx float64
	if len(sampled) > 1 {
		last := sampled[len(sampled)-1]
		first := sampled[0]
		totalRx = float64(last.InBytes) - float64(first.InBytes)
		totalTx = float64(last.OutBytes) - float64(first.OutBytes)
		if totalRx < 0 {
			totalRx = float64(last.InBytes)
		}
		if totalTx < 0 {
			totalTx = float64(last.OutBytes)
		}
	}

	for i, p := range sampled {
		// Use appropriate time format based on range
		var labelFormat string
		if rangeStr == "5m" || rangeStr == "15m" {
			labelFormat = "15:04:05" // include seconds for short ranges
		} else if rangeStr == "7d" {
			labelFormat = "01-02 15:00" // date and hour for 7 days
		} else if rangeStr == "90d" {
			labelFormat = "01-02" // just date for 90 days
		} else {
			labelFormat = "15:04" // hour:minute for 1h, 6h, 24h
		}
		labels = append(labels, p.Timestamp.Format(labelFormat))
		timestamps = append(timestamps, p.Timestamp.Format("2006-01-02T15:04:05Z"))
		rxTotalVals = append(rxTotalVals, float64(p.InBytes))
		txTotalVals = append(txTotalVals, float64(p.OutBytes))

		var rRate, tRate float64
		if i > 0 {
			prev := sampled[i-1]
			deltaBytesR := float64(p.InBytes) - float64(prev.InBytes)
			deltaBytesT := float64(p.OutBytes) - float64(prev.OutBytes)
			deltaTime := p.Timestamp.Sub(prev.Timestamp).Seconds()

			if deltaTime > 0 && deltaBytesR >= 0 {
				rRate = (deltaBytesR * 8) / deltaTime / 1000000
			}
			if deltaTime > 0 && deltaBytesT >= 0 {
				tRate = (deltaBytesT * 8) / deltaTime / 1000000
			}
		}
		rxRate = append(rxRate, rRate)
		txRate = append(txRate, tRate)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(map[string]interface{}{
		"labels":     labels,
		"rx_total":   rxTotalVals,
		"tx_total":   txTotalVals,
		"rx_rate":    rxRate,
		"tx_rate":    txRate,
		"total_rx":   float64(totalRx),
		"total_tx":   float64(totalTx),
		"view":       viewType,
		"range":      rangeStr,
		"timestamps": timestamps,
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

func (h *Handler) GetPublicStatusHistory(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("No data available"))
		return
	}

	deviceID, hasDevice := h.resolvePublicDeviceID(c)
	if !hasDevice {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("No device specified"))
		return
	}

	// Unified parsing (v0.10.217, bundle D2). httputil.ParseHours enforces
	// the 24h default + 8760h (1 year) cap shared by every endpoint that
	// accepts an `hours` query parameter.
	hours := httputil.ParseHours(c)

	statuses, err := h.db.GetSystemStatusHistory(deviceID, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get status history"))
		return
	}

	type publicPoint struct {
		Timestamp   string  `json:"timestamp"`
		CPUUsage    float64 `json:"cpu_usage"`
		MemoryUsage float64 `json:"memory_usage"`
	}
	result := make([]publicPoint, 0, len(statuses))
	for _, s := range statuses {
		result = append(result, publicPoint{
			Timestamp:   s.Timestamp.Format("2006-01-02T15:04:05Z"),
			CPUUsage:    s.CPUUsage,
			MemoryUsage: s.MemoryUsage,
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
		alerts, err := h.db.GetAlerts(10, nil)
		if err != nil {
			log.Printf("Failed to get recent alerts: %v", err)
		}
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
		// Defensive bounds (v0.10.217, bundle D3). Devices + connections
		// are configuration tables, but on a fleet with thousands of
		// auto-detected connections the previous unbounded Find could
		// pull an enormous payload. 1000 is well above any realistic
		// admin-managed fleet, low enough to fit in a single response.
		if err := h.db.Gorm().Preload("Site").Preload("Probe").Limit(1000).Find(&devices).Error; err != nil {
			log.Printf("Failed to get devices: %v", err)
		}

		if err := h.db.Gorm().Preload("SourceDevice").Preload("DestDevice").Limit(1000).Find(&connections).Error; err != nil {
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

	// AUDIT-033: pre-fix this ran ~13 queries PER device (count + latest +
	// per-metric counts for status/iface/vpn/ha/sdwan) — ~650 queries at 50
	// devices. Replaced with a fixed set of batched aggregate queries (one per
	// data type) that compute every device's summary at once using the
	// codebase's max-timestamp self-join pattern (portable across Postgres and
	// the SQLite test backend). Query count is now O(1) in the device count.
	enrichments := make(map[uint]*DeviceEnrichment)
	if h.db != nil && len(devices) > 0 {
		ids := make([]uint, len(devices))
		for i, dev := range devices {
			ids[i] = dev.ID
			enrichments[dev.ID] = &DeviceEnrichment{DeviceID: dev.ID}
		}
		g := h.db.Gorm()

		// latest builds "the row(s) at MAX(timestamp) per device" subquery for
		// a given time-series table, scoped to the dashboard's device set.
		latest := func(table string) *gorm.DB {
			return g.Table(table).Select("device_id, MAX(timestamp) AS mx").
				Where("device_id IN ?", ids).Group("device_id")
		}

		// 1. system_status total row counts per device.
		type cntRow struct {
			DeviceID uint
			C        int64
		}
		var statusCounts []cntRow
		if err := g.Model(&models.SystemStatus{}).Select("device_id, COUNT(*) AS c").
			Where("device_id IN ?", ids).Group("device_id").Scan(&statusCounts).Error; err != nil {
			log.Printf("dashboard: status counts: %v", err)
		}
		for _, r := range statusCounts {
			if e := enrichments[r.DeviceID]; e != nil {
				e.StatusRows = r.C
			}
		}

		// 2. latest system_status values per device.
		type statusRow struct {
			DeviceID     uint
			Timestamp    time.Time
			CPUUsage     float64
			MemoryUsage  float64
			SessionCount int
		}
		var statusLatest []statusRow
		if err := g.Table("system_status AS s").
			Joins("JOIN (?) AS l ON s.device_id = l.device_id AND s.timestamp = l.mx", latest("system_status")).
			Where("s.device_id IN ?", ids).
			Select("s.device_id AS device_id, s.timestamp AS timestamp, s.cpu_usage AS cpu_usage, s.memory_usage AS memory_usage, s.session_count AS session_count").
			Scan(&statusLatest).Error; err != nil {
			log.Printf("dashboard: latest status: %v", err)
		}
		for i := range statusLatest {
			r := statusLatest[i]
			if e := enrichments[r.DeviceID]; e != nil {
				e.HasStatus = true
				ts := r.Timestamp
				e.StatusTime = &ts
				e.CPUUsage = r.CPUUsage
				e.MemoryUsage = r.MemoryUsage
				e.SessionCount = r.SessionCount
			}
		}

		// 3+4. interface and VPN summaries (total + up at the latest timestamp).
		type upAgg struct {
			DeviceID uint
			Total    int64
			Up       int64
		}
		runUpAgg := func(table string) []upAgg {
			var rows []upAgg
			if err := g.Table(table+" AS s").
				Joins("JOIN (?) AS l ON s.device_id = l.device_id AND s.timestamp = l.mx", latest(table)).
				Where("s.device_id IN ?", ids).Group("s.device_id").
				Select("s.device_id AS device_id, COUNT(*) AS total, SUM(CASE WHEN s.status = 'up' THEN 1 ELSE 0 END) AS up").
				Scan(&rows).Error; err != nil {
				log.Printf("dashboard: %s summary: %v", table, err)
			}
			return rows
		}
		for _, r := range runUpAgg("interface_stats") {
			if e := enrichments[r.DeviceID]; e != nil {
				e.IfaceTotal = int(r.Total)
				e.IfaceUp = int(r.Up)
				e.IfaceDown = int(r.Total - r.Up)
			}
		}
		for _, r := range runUpAgg("vpn_status") {
			if e := enrichments[r.DeviceID]; e != nil {
				e.VPNTotal = int(r.Total)
				e.VPNUp = int(r.Up)
			}
		}

		// 5. HA summary: mode + member count at the latest timestamp.
		type haRow struct {
			DeviceID uint
			Mode     string
			Members  int64
		}
		var haAgg []haRow
		if err := g.Table("ha_status AS s").
			Joins("JOIN (?) AS l ON s.device_id = l.device_id AND s.timestamp = l.mx", latest("ha_status")).
			Where("s.device_id IN ?", ids).Group("s.device_id").
			Select("s.device_id AS device_id, MAX(s.system_mode) AS mode, COUNT(*) AS members").
			Scan(&haAgg).Error; err != nil {
			log.Printf("dashboard: ha summary: %v", err)
		}
		for _, r := range haAgg {
			if e := enrichments[r.DeviceID]; e != nil {
				e.HAMode = r.Mode
				e.HAMembers = int(r.Members)
			}
		}

		// 6. SD-WAN summary: total + alive at the latest timestamp.
		type sdRow struct {
			DeviceID uint
			Total    int64
			Alive    int64
		}
		var sdAgg []sdRow
		if err := g.Table("sdwan_health AS s").
			Joins("JOIN (?) AS l ON s.device_id = l.device_id AND s.timestamp = l.mx", latest("sdwan_health")).
			Where("s.device_id IN ?", ids).Group("s.device_id").
			Select("s.device_id AS device_id, COUNT(*) AS total, SUM(CASE WHEN s.state = 'alive' THEN 1 ELSE 0 END) AS alive").
			Scan(&sdAgg).Error; err != nil {
			log.Printf("dashboard: sdwan summary: %v", err)
		}
		for _, r := range sdAgg {
			if e := enrichments[r.DeviceID]; e != nil {
				e.SDWANTotal = int(r.Total)
				e.SDWANAlive = int(r.Alive)
			}
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

	// Defensive cap (v0.10.217, bundle D3).
	var devices []models.Device
	if err := h.db.Gorm().Select("id, name, ip_address, status, last_polled, probe_id").Limit(1000).Find(&devices).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get devices"))
		return
	}

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

		if err := h.db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", dev.ID).Count(&diag.StatusRows).Error; err != nil {
			log.Printf("Device %d: failed to count status rows: %v", dev.ID, err)
		}

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
