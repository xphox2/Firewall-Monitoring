package handlers

import (
	"crypto/md5"
	"encoding/hex"
	"log"
	"math"
	"net/http"
	"time"

	"firewall-mon/internal/configdiff"
	"firewall-mon/internal/models"
	"firewall-mon/internal/snmp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// batchDedupCheck implements the AUDIT-042 idempotency check for probe batch
// endpoints. If the request carries an `X-Probe-Batch-ID` already recorded for
// this probe, it writes a 200 "deduped" response and returns dup=true (the
// caller must return immediately). Otherwise it returns the batch id (possibly
// "") for the caller to pass to markBatchIfOK via defer.
func (h *Handler) batchDedupCheck(c *gin.Context, probeID uint) (batchID string, dup bool) {
	batchID = c.GetHeader("X-Probe-Batch-ID")
	if batchID == "" || h.db == nil {
		return "", false
	}
	if h.db.BatchAlreadyProcessed(probeID, batchID) {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"deduped": true, "saved": 0}))
		return "", true
	}
	return batchID, false
}

// markBatchIfOK records the idempotency key, but ONLY if the response was a 2xx
// (i.e. the batch actually saved). Recording on failure would dedupe-drop the
// collector's legitimate retry of a batch that never persisted. Call via defer.
func (h *Handler) markBatchIfOK(c *gin.Context, probeID uint, batchID string) {
	if batchID == "" || h.db == nil {
		return
	}
	if s := c.Writer.Status(); s >= 200 && s < 300 {
		if err := h.db.MarkBatchProcessed(probeID, batchID); err != nil {
			log.Printf("markBatchIfOK: probe %d batch %s: %v", probeID, batchID, err)
		}
	}
}

func (h *Handler) ReceiveSyslogMessages(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var messages []models.SyslogMessage
	if err := c.ShouldBindJSON(&messages); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	originalLen := len(messages)
	if originalLen > 1000 {
		messages = messages[:1000]
		if h.alertManager != nil && originalLen > 1200 {
			h.alertManager.RecordProbeDataTruncation(probe.ID, probe.Name, originalLen, 1000)
		}
	}
	now := time.Now()
	for i := range messages {
		messages[i].ProbeID = probe.ID
		if messages[i].Timestamp.IsZero() {
			messages[i].Timestamp = now
		}
		if messages[i].DeviceID == 0 && messages[i].SourceIP != "" && h.db != nil {
			if devID := h.db.ResolveDeviceByIP(messages[i].SourceIP); devID > 0 {
				messages[i].DeviceID = devID
			}
		}
	}
	if err := h.db.SaveSyslogMessages(messages); err != nil {
		log.Printf("Failed to batch save syslog messages: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save syslog messages"))
		return
	}
	// Fire alerts for critical syslog messages (severity 0-2)
	if h.alertManager != nil {
		for i := range messages {
			if messages[i].Severity <= 2 {
				if err := h.alertManager.ProcessSyslog(&messages[i], nil); err != nil {
					log.Printf("Failed to process syslog alert: %v", err)
				}
			}
		}
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(messages)}))
}

func (h *Handler) ReceiveTrapEvents(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var traps []models.TrapEvent
	if err := c.ShouldBindJSON(&traps); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	originalLen := len(traps)
	if originalLen > 1000 {
		traps = traps[:1000]
		if h.alertManager != nil && originalLen > 1200 {
			h.alertManager.RecordProbeDataTruncation(probe.ID, probe.Name, originalLen, 1000)
		}
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := traps[:0]
	for i := range traps {
		if traps[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[traps[i].DeviceID] {
			continue
		}
		traps[i].ProbeID = probe.ID
		if traps[i].Timestamp.IsZero() {
			traps[i].Timestamp = now
		}
		filtered = append(filtered, traps[i])
	}
	if err := h.db.SaveTrapEvents(filtered); err != nil {
		log.Printf("Failed to batch save trap events: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save trap events"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveFlowSamples(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
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
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var results []models.PingResult
	if err := c.ShouldBindJSON(&results); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(results) > 1000 {
		results = results[:1000]
	}
	log.Printf("ReceivePingResults: probe %d received %d results", probe.ID, len(results))
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := results[:0]
	for i := range results {
		if results[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[results[i].DeviceID] {
			log.Printf("ReceivePingResults: device %d not allowed for probe %d", results[i].DeviceID, probe.ID)
			continue
		}
		results[i].ProbeID = probe.ID
		if results[i].Timestamp.IsZero() {
			results[i].Timestamp = now
		}
		filtered = append(filtered, results[i])
	}
	if err := h.db.SavePingResults(filtered); err != nil {
		log.Printf("Failed to batch save ping results: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save ping results"))
		return
	}
	// Aggregate into PingStats
	for _, r := range filtered {
		h.updatePingStats(r.DeviceID, probe.ID, r.TargetIP, r.Latency, r.PacketLoss)
	}
	log.Printf("ReceivePingResults: probe %d saved %d results", probe.ID, len(filtered))
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
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
		if stats[i].TypeName == "" && stats[i].Type > 0 {
			if name, ok := snmp.IfTypeNames[stats[i].Type]; ok {
				stats[i].TypeName = name
			}
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

const (
	maxConfigTextSize = 50 * 1024 * 1024 // 50MB max config size to prevent DoS
)

func (h *Handler) ReceiveConfigRevision(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		log.Printf("ReceiveConfigRevision: validateProbe failed")
		return
	}
	log.Printf("ReceiveConfigRevision: probe %d (%s) receiving config", probe.ID, probe.Name)

	var rev models.DeviceConfigRevision
	if err := c.ShouldBindJSON(&rev); err != nil {
		log.Printf("ReceiveConfigRevision: Invalid JSON: %v", err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	log.Printf("ReceiveConfigRevision: received DeviceID=%d, Length=%d, ConfigText len=%d", rev.DeviceID, rev.Length, len(rev.ConfigText))

	allowedDevices := h.probeDeviceIDs(probe.ID)
	log.Printf("ReceiveConfigRevision: probe %d has %d devices assigned", probe.ID, len(allowedDevices))

	if allowedDevices != nil && !allowedDevices[rev.DeviceID] {
		log.Printf("ReceiveConfigRevision: REJECTED - device %d not in probe %d's device list (probe name: %s)", rev.DeviceID, probe.ID, probe.Name)
		c.JSON(http.StatusForbidden, models.ErrorResponse("Device not assigned to probe"))
		return
	}

	// Validate ConfigText size to prevent DoS
	if len(rev.ConfigText) > maxConfigTextSize {
		log.Printf("ReceiveConfigRevision: Rejected config for device %d - size %d exceeds limit %d", rev.DeviceID, len(rev.ConfigText), maxConfigTextSize)
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Config too large"))
		return
	}

	if rev.Timestamp.IsZero() {
		rev.Timestamp = time.Now()
	}

	// Compute the vendor-aware normalized checksum. This is what change-detection
	// alerts compare against — raw checksums drift on every backup for FortiOS
	// devices because of random-IV ENC ciphertext, so they're useless for "did
	// the operator actually change something?".
	vendor := ""
	if dev, err := h.db.GetDevice(rev.DeviceID); err == nil && dev != nil {
		vendor = dev.Vendor
	}
	normalized, quality := configdiff.Normalize(vendor, []byte(rev.ConfigText))
	normalizedSum := md5.Sum(normalized)
	rev.NormalizedChecksum = hex.EncodeToString(normalizedSum[:])

	// Honor a TriggerSource the collector explicitly set (e.g. "syslog"). If it
	// didn't, default to "poll" — this is the safety-net floor cadence.
	if rev.TriggerSource == "" {
		rev.TriggerSource = "poll"
	}

	// Honor a BackupQuality the collector explicitly set; otherwise use what the
	// normalizer detected (e.g. FortiOS 7.2.1+ password masking).
	if rev.BackupQuality == "" {
		rev.BackupQuality = quality
	}

	// Validate the bytes look like a real FortiOS backup BEFORE we consider
	// merging into the prior row. If validation fails we will still INSERT
	// (so we don't lose the data), but we won't OVERWRITE good prior bytes
	// with bad ones — the row will be tagged "suspect" and treated as a new
	// state so it gets visibility instead of silently replacing good data.
	suspect := false
	if vendor == "fortigate" {
		if err := configdiff.ValidateFortiGateBackup([]byte(rev.ConfigText)); err != nil {
			log.Printf("ReceiveConfigRevision: validation failed for device %d, treating as suspect: %v",
				rev.DeviceID, err)
			suspect = true
			rev.BackupQuality = "suspect"
		}
	}

	// Merge-into-latest model (v0.10.198+):
	//   - Same NormalizedChecksum as prior revision → UPDATE in place,
	//     refresh ConfigText (latest ENC ciphertext for restore), bump
	//     LastVerifiedAt, increment VerifyCount. No alert.
	//   - Different NormalizedChecksum, OR no prior revision, OR suspect →
	//     INSERT a new row, alert if a prior row existed.
	//
	// All wrapped in a transaction with a SELECT ... FOR UPDATE to serialize
	// concurrent backups for the same device.
	now := time.Now()
	var (
		mergedID       uint
		mergedAction   string // "merge" | "insert-first" | "insert-change" | "insert-suspect"
		prevNormalized string
	)

	txErr := h.db.Gorm().Transaction(func(tx *gorm.DB) error {
		var prevRev models.DeviceConfigRevision
		// Lock the latest row for this device. On Postgres this is a real row
		// lock; on SQLite the entire DB is serialized under transactions, so
		// the same correctness property holds.
		err := tx.Set("gorm:query_option", "FOR UPDATE").
			Where("device_id = ?", rev.DeviceID).
			Order("id DESC").Limit(1).
			First(&prevRev).Error

		hasPrev := err == nil
		if hasPrev {
			prevNormalized = prevRev.NormalizedChecksum
		}

		// MERGE path: same vendor-normalized state, validation OK.
		if hasPrev && !suspect && prevRev.NormalizedChecksum == rev.NormalizedChecksum && rev.NormalizedChecksum != "" {
			updates := map[string]interface{}{
				"checksum":         rev.Checksum,
				"config_text":      rev.ConfigText,
				"length":           len(rev.ConfigText),
				"last_verified_at": now,
				"verify_count":     prevRev.VerifyCount + 1,
				"trigger_source":   rev.TriggerSource,
			}
			// Backup quality can shift (e.g. FortiOS 7.2.1+ password masking
			// was just enabled). Keep the latest value.
			if rev.BackupQuality != "" {
				updates["backup_quality"] = rev.BackupQuality
			}
			if err := tx.Model(&models.DeviceConfigRevision{}).
				Where("id = ?", prevRev.ID).
				Updates(updates).Error; err != nil {
				return err
			}
			mergedID = prevRev.ID
			mergedAction = "merge"
			return nil
		}

		// INSERT path: new state (or first-ever, or suspect bytes).
		if rev.FirstSeenAt.IsZero() {
			rev.FirstSeenAt = now
		}
		if rev.LastVerifiedAt.IsZero() {
			rev.LastVerifiedAt = now
		}
		if rev.VerifyCount == 0 {
			rev.VerifyCount = 1
		}
		if rev.Timestamp.IsZero() {
			rev.Timestamp = now
		}
		if err := tx.Create(&rev).Error; err != nil {
			return err
		}
		mergedID = rev.ID
		switch {
		case suspect:
			mergedAction = "insert-suspect"
		case !hasPrev:
			mergedAction = "insert-first"
		default:
			mergedAction = "insert-change"
		}
		return nil
	})
	if txErr != nil {
		log.Printf("ReceiveConfigRevision: tx error for device %d: %v", rev.DeviceID, txErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save config revision"))
		return
	}

	actualLen := len(rev.ConfigText)
	if rev.Length != actualLen {
		log.Printf("WARNING: ReceiveConfigRevision: device %d Length mismatch - reported=%d actual=%d",
			rev.DeviceID, rev.Length, actualLen)
	}
	log.Printf("ReceiveConfigRevision: %s for device %d (rev.ID=%d, len=%d, raw=%s norm=%s trigger=%s quality=%s)",
		mergedAction, rev.DeviceID, mergedID, actualLen,
		rev.Checksum, rev.NormalizedChecksum, rev.TriggerSource, rev.BackupQuality)

	// Alert only on real INSERT-change (not merge, not first-ever, not suspect).
	// Suspect insertions are visible in the History UI as "suspect" rows; a
	// CONFIG_CHANGE alert there would be misleading because we can't actually
	// confirm what changed.
	if mergedAction == "insert-change" {
		if h.alertManager != nil {
			h.alertManager.CheckConfigRevision(rev.DeviceID, prevNormalized, rev.NormalizedChecksum)
		}
	}

	h.incBackupQuality(rev.BackupQuality)

	h.db.Gorm().Model(&models.Device{}).Where("id = ?", rev.DeviceID).Updates(map[string]interface{}{
		"status":      "online",
		"last_polled": time.Now(),
	})

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"saved":               mergedID,
		"action":              mergedAction,
		"normalized_checksum": rev.NormalizedChecksum,
		"trigger_source":      rev.TriggerSource,
		"backup_quality":      rev.BackupQuality,
	}))
}

func (h *Handler) ReceiveProcessSnapshot(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var snap models.ProcessStats
	if err := c.ShouldBindJSON(&snap); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	if allowedDevices != nil && !allowedDevices[snap.DeviceID] {
		c.JSON(http.StatusForbidden, models.ErrorResponse("Device not assigned to probe"))
		return
	}

	if snap.Timestamp.IsZero() {
		snap.Timestamp = time.Now()
	}

	if err := h.db.Gorm().Create(&snap).Error; err != nil {
		log.Printf("ReceiveProcessSnapshot: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save process snapshot"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": snap.ID}))
}

func (h *Handler) ReceiveInterfaceErrors(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var errs []models.InterfaceErrors
	if err := c.ShouldBindJSON(&errs); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(errs) > 500 {
		errs = errs[:500]
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := errs[:0]
	for i := range errs {
		if errs[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[errs[i].DeviceID] {
			continue
		}
		if errs[i].Timestamp.IsZero() {
			errs[i].Timestamp = now
		}
		filtered = append(filtered, errs[i])
	}

	if err := h.db.Gorm().Create(&filtered).Error; err != nil {
		log.Printf("ReceiveInterfaceErrors: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save interface errors"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveSensorDetails(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var sensors []models.HardwareSensor
	if err := c.ShouldBindJSON(&sensors); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	log.Printf("ReceiveSensorDetails: probe=%d received %d sensors", probe.ID, len(sensors))
	if len(sensors) > 500 {
		sensors = sensors[:500]
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	log.Printf("ReceiveSensorDetails: probe=%d allowed devices=%v", probe.ID, allowedDevices)
	now := time.Now()
	filtered := sensors[:0]
	for i := range sensors {
		log.Printf("ReceiveSensorDetails: sensor[%d] device_id=%d name=%q value=%.1f unit=%q status=%q", i, sensors[i].DeviceID, sensors[i].Name, sensors[i].Value, sensors[i].Unit, sensors[i].Status)
		if sensors[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[sensors[i].DeviceID] {
			log.Printf("ReceiveSensorDetails: filtering out device_id=%d (not in allowed list)", sensors[i].DeviceID)
			continue
		}
		if sensors[i].Timestamp.IsZero() {
			sensors[i].Timestamp = now
		}
		filtered = append(filtered, sensors[i])
	}
	log.Printf("ReceiveSensorDetails: probe=%d filtered to %d sensors", probe.ID, len(filtered))

	if err := h.db.Gorm().Create(&filtered).Error; err != nil {
		log.Printf("ReceiveSensorDetails: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save sensor details"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveLicenseDetails(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var licenses []models.LicenseInfo
	if err := c.ShouldBindJSON(&licenses); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(licenses) > 100 {
		licenses = licenses[:100]
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

	if err := h.db.Gorm().Create(&filtered).Error; err != nil {
		log.Printf("ReceiveLicenseDetails: DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save license details"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(filtered)}))
}
