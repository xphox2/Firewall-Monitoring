package handlers

import (
	"log"
	"math"
	"net/http"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) ReceiveSyslogMessages(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var messages []models.SyslogMessage
	if err := c.ShouldBindJSON(&messages); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(messages) > 1000 {
		messages = messages[:1000]
	}
	saved := 0
	for i := range messages {
		messages[i].ProbeID = probe.ID
		if messages[i].Timestamp.IsZero() {
			messages[i].Timestamp = time.Now()
		}
		if err := h.db.SaveSyslogMessage(&messages[i]); err != nil {
			log.Printf("Failed to save syslog message: %v", err)
			continue
		}
		saved++
		// Fire alerts for critical syslog messages (severity 0-2)
		if h.alertManager != nil && messages[i].Severity <= 2 {
			if err := h.alertManager.ProcessSyslog(&messages[i]); err != nil {
				log.Printf("Failed to process syslog alert: %v", err)
			}
		}
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": saved}))
}

func (h *Handler) ReceiveTrapEvents(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var traps []models.TrapEvent
	if err := c.ShouldBindJSON(&traps); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(traps) > 1000 {
		traps = traps[:1000]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	saved := 0
	for i := range traps {
		if traps[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[traps[i].DeviceID] {
			continue
		}
		traps[i].ProbeID = probe.ID
		if traps[i].Timestamp.IsZero() {
			traps[i].Timestamp = time.Now()
		}
		if err := h.db.SaveTrapEvent(&traps[i]); err != nil {
			log.Printf("Failed to save trap event: %v", err)
			continue
		}
		saved++
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": saved}))
}

func (h *Handler) ReceiveFlowSamples(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var samples []models.FlowSample
	if err := c.ShouldBindJSON(&samples); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(samples) > 1000 {
		samples = samples[:1000]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	filtered := samples[:0]
	for i := range samples {
		samples[i].ProbeID = probe.ID
		if samples[i].Timestamp.IsZero() {
			samples[i].Timestamp = time.Now()
		}
		// Server-side device resolution fallback for unresolved samples
		if samples[i].DeviceID == 0 && samples[i].SamplerAddress != "" && h.db != nil {
			if devID := h.db.ResolveDeviceByIP(samples[i].SamplerAddress); devID > 0 {
				samples[i].DeviceID = devID
			}
		}
		if samples[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[samples[i].DeviceID] {
			continue
		}
		filtered = append(filtered, samples[i])
	}
	if err := h.db.SaveFlowSamples(filtered); err != nil {
		log.Printf("ReceiveFlowSamples: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save flow samples"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceivePingResults(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var results []models.PingResult
	if err := c.ShouldBindJSON(&results); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(results) > 1000 {
		results = results[:1000]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	saved := 0
	for i := range results {
		if results[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[results[i].DeviceID] {
			continue
		}
		results[i].ProbeID = probe.ID
		if results[i].Timestamp.IsZero() {
			results[i].Timestamp = time.Now()
		}
		if err := h.db.SavePingResult(&results[i]); err != nil {
			log.Printf("Failed to save ping result: %v", err)
			continue
		}
		saved++

		// Aggregate into PingStats
		h.updatePingStats(results[i].DeviceID, probe.ID, results[i].TargetIP, results[i].Latency, results[i].PacketLoss)
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": saved}))
}

func (h *Handler) updatePingStats(deviceID, probeID uint, targetIP string, latency, packetLoss float64) {
	existing, err := h.db.GetPingStatsByTarget(deviceID, probeID, targetIP)
	if err != nil {
		log.Printf("Failed to get existing ping stats: %v", err)
		return
	}

	if existing == nil {
		stats := &models.PingStats{
			DeviceID:   deviceID,
			ProbeID:    probeID,
			TargetIP:   targetIP,
			MinLatency: latency,
			MaxLatency: latency,
			AvgLatency: latency,
			PacketLoss: packetLoss,
			Samples:    1,
			UpdatedAt:  time.Now(),
		}
		if err := h.db.SavePingStats(stats); err != nil {
			log.Printf("Failed to save new ping stats: %v", err)
		}
		return
	}

	newSamples := existing.Samples + 1
	existing.MinLatency = math.Min(existing.MinLatency, latency)
	existing.MaxLatency = math.Max(existing.MaxLatency, latency)
	existing.AvgLatency = ((existing.AvgLatency * float64(existing.Samples)) + latency) / float64(newSamples)
	existing.PacketLoss = packetLoss
	existing.Samples = newSamples
	existing.UpdatedAt = time.Now()

	if err := h.db.SavePingStats(existing); err != nil {
		log.Printf("Failed to update ping stats: %v", err)
	}
}

func (h *Handler) ReceiveInterfaceAddresses(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var addrs []models.InterfaceAddress
	if err := c.ShouldBindJSON(&addrs); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(addrs) > 1000 {
		addrs = addrs[:1000]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := addrs[:0]
	for i := range addrs {
		if addrs[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[addrs[i].DeviceID] {
			continue
		}
		if addrs[i].Timestamp.IsZero() {
			addrs[i].Timestamp = now
		}
		filtered = append(filtered, addrs[i])
	}
	if err := h.db.SaveInterfaceAddresses(filtered); err != nil {
		log.Printf("ReceiveInterfaceAddresses: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save interface addresses"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveProcessorStats(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var stats []models.ProcessorStats
	if err := c.ShouldBindJSON(&stats); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(stats) > 500 {
		stats = stats[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := stats[:0]
	for i := range stats {
		if stats[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[stats[i].DeviceID] {
			continue
		}
		if stats[i].Timestamp.IsZero() {
			stats[i].Timestamp = now
		}
		filtered = append(filtered, stats[i])
	}
	if err := h.db.SaveProcessorStats(filtered); err != nil {
		log.Printf("ReceiveProcessorStats: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save processor stats"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveHardwareSensors(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var sensors []models.HardwareSensor
	if err := c.ShouldBindJSON(&sensors); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(sensors) > 500 {
		sensors = sensors[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := sensors[:0]
	for i := range sensors {
		if sensors[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[sensors[i].DeviceID] {
			continue
		}
		if sensors[i].Timestamp.IsZero() {
			sensors[i].Timestamp = now
		}
		filtered = append(filtered, sensors[i])
	}
	if len(filtered) == 0 {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": 0}))
		return
	}
	if err := h.db.Gorm().Create(&filtered).Error; err != nil {
		log.Printf("ReceiveHardwareSensors: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save hardware sensors"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveSystemStatuses(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var statuses []models.SystemStatus
	if err := c.ShouldBindJSON(&statuses); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(statuses) > 100 {
		statuses = statuses[:100]
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	saved := 0
	deviceIDs := make(map[uint]bool)
	for i := range statuses {
		if statuses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[statuses[i].DeviceID] {
			continue // skip data for devices not assigned to this probe
		}
		if statuses[i].Timestamp.IsZero() {
			statuses[i].Timestamp = time.Now()
		}
		if err := h.db.SaveSystemStatus(&statuses[i]); err != nil {
			log.Printf("Probe %d: failed to save system status for device %d: %v", probe.ID, statuses[i].DeviceID, err)
			continue
		}
		saved++
		if statuses[i].DeviceID > 0 {
			deviceIDs[statuses[i].DeviceID] = true
		}
	}

	// Mark devices that sent data as online
	now := time.Now()
	for deviceID := range deviceIDs {
		h.db.Gorm().Model(&models.Device{}).Where("id = ?", deviceID).Updates(map[string]interface{}{
			"status":      "online",
			"last_polled": now,
		})
	}

	log.Printf("Probe %d: saved %d/%d system status records (devices: %v)", probe.ID, saved, len(statuses), deviceIDs)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": saved}))
}

func (h *Handler) ReceiveInterfaceStats(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var stats []models.InterfaceStats
	if err := c.ShouldBindJSON(&stats); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(stats) > 1000 {
		stats = stats[:1000]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	deviceIDs := make(map[uint]bool)
	filtered := stats[:0]
	for i := range stats {
		if stats[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[stats[i].DeviceID] {
			continue
		}
		if stats[i].Timestamp.IsZero() {
			stats[i].Timestamp = time.Now()
		}
		if stats[i].DeviceID > 0 {
			deviceIDs[stats[i].DeviceID] = true
		}
		filtered = append(filtered, stats[i])
	}
	if err := h.db.SaveInterfaceStats(filtered); err != nil {
		log.Printf("ReceiveInterfaceStats: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save interface stats"))
		return
	}

	// Mark devices that sent data as online
	now := time.Now()
	for deviceID := range deviceIDs {
		h.db.Gorm().Model(&models.Device{}).Where("id = ?", deviceID).Updates(map[string]interface{}{
			"status":      "online",
			"last_polled": now,
		})
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveVPNStatuses(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var statuses []models.VPNStatus
	if err := c.ShouldBindJSON(&statuses); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(statuses) > 500 {
		statuses = statuses[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	deviceIDs := make(map[uint]bool)
	filtered := statuses[:0]
	for i := range statuses {
		if statuses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[statuses[i].DeviceID] {
			continue
		}
		if statuses[i].Timestamp.IsZero() {
			statuses[i].Timestamp = time.Now()
		}
		if statuses[i].DeviceID > 0 {
			deviceIDs[statuses[i].DeviceID] = true
		}
		filtered = append(filtered, statuses[i])
	}
	if err := h.db.SaveVPNStatuses(filtered); err != nil {
		log.Printf("ReceiveVPNStatuses: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save VPN statuses"))
		return
	}

	now := time.Now()
	for deviceID := range deviceIDs {
		h.db.Gorm().Model(&models.Device{}).Where("id = ?", deviceID).Updates(map[string]interface{}{
			"status":      "online",
			"last_polled": now,
		})
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveHAStatuses(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var statuses []models.HAStatus
	if err := c.ShouldBindJSON(&statuses); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(statuses) > 500 {
		statuses = statuses[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := statuses[:0]
	for i := range statuses {
		if statuses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[statuses[i].DeviceID] {
			continue
		}
		if statuses[i].Timestamp.IsZero() {
			statuses[i].Timestamp = now
		}
		filtered = append(filtered, statuses[i])
	}
	if err := h.db.SaveHAStatuses(filtered); err != nil {
		log.Printf("ReceiveHAStatuses: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save HA statuses"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveSecurityStats(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var stats []models.SecurityStats
	if err := c.ShouldBindJSON(&stats); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(stats) > 500 {
		stats = stats[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := stats[:0]
	for i := range stats {
		if stats[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[stats[i].DeviceID] {
			continue
		}
		if stats[i].Timestamp.IsZero() {
			stats[i].Timestamp = now
		}
		filtered = append(filtered, stats[i])
	}
	if err := h.db.SaveSecurityStats(filtered); err != nil {
		log.Printf("ReceiveSecurityStats: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save security stats"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveSDWANHealth(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var health []models.SDWANHealth
	if err := c.ShouldBindJSON(&health); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(health) > 500 {
		health = health[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := health[:0]
	for i := range health {
		if health[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[health[i].DeviceID] {
			continue
		}
		if health[i].Timestamp.IsZero() {
			health[i].Timestamp = now
		}
		filtered = append(filtered, health[i])
	}
	if err := h.db.SaveSDWANHealth(filtered); err != nil {
		log.Printf("ReceiveSDWANHealth: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save SD-WAN health"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveLicenseInfo(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var licenses []models.LicenseInfo
	if err := c.ShouldBindJSON(&licenses); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(licenses) > 500 {
		licenses = licenses[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := licenses[:0]
	for i := range licenses {
		if licenses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[licenses[i].DeviceID] {
			continue
		}
		if licenses[i].Timestamp.IsZero() {
			licenses[i].Timestamp = now
		}
		filtered = append(filtered, licenses[i])
	}
	if err := h.db.SaveLicenseInfo(filtered); err != nil {
		log.Printf("ReceiveLicenseInfo: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save license info"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}
