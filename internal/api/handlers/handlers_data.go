package handlers

import (
	"log"
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
	saved := 0
	for i := range traps {
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
	for i := range samples {
		samples[i].ProbeID = probe.ID
		if samples[i].Timestamp.IsZero() {
			samples[i].Timestamp = time.Now()
		}
	}
	if err := h.db.SaveFlowSamples(samples); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to save flow samples"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(samples)}))
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
	saved := 0
	for i := range results {
		results[i].ProbeID = probe.ID
		if results[i].Timestamp.IsZero() {
			results[i].Timestamp = time.Now()
		}
		if err := h.db.SavePingResult(&results[i]); err != nil {
			log.Printf("Failed to save ping result: %v", err)
			continue
		}
		saved++
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": saved}))
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
	saved := 0
	deviceIDs := make(map[uint]bool)
	for i := range statuses {
		_ = probe // probe validated above
		if statuses[i].Timestamp.IsZero() {
			statuses[i].Timestamp = time.Now()
		}
		if err := h.db.SaveSystemStatus(&statuses[i]); err != nil {
			log.Printf("Failed to save system status: %v", err)
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
	deviceIDs := make(map[uint]bool)
	for i := range stats {
		_ = probe
		if stats[i].Timestamp.IsZero() {
			stats[i].Timestamp = time.Now()
		}
		if stats[i].DeviceID > 0 {
			deviceIDs[stats[i].DeviceID] = true
		}
	}
	if err := h.db.SaveInterfaceStats(stats); err != nil {
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

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(stats)}))
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
	deviceIDs := make(map[uint]bool)
	for i := range statuses {
		_ = probe
		if statuses[i].Timestamp.IsZero() {
			statuses[i].Timestamp = time.Now()
		}
		if statuses[i].DeviceID > 0 {
			deviceIDs[statuses[i].DeviceID] = true
		}
	}
	if err := h.db.SaveVPNStatuses(statuses); err != nil {
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

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"saved": len(statuses)}))
}
