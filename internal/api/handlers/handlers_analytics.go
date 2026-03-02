package handlers

import (
	"net/http"
	"strconv"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetAlerts(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.Alert{}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	query := h.db.Gorm().Order("timestamp DESC").Limit(limit).Offset(offset)

	if deviceID := c.Query("device_id"); deviceID != "" {
		query = query.Where("device_id = ?", deviceID)
	}
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if alertType := c.Query("alert_type"); alertType != "" {
		query = query.Where("alert_type = ?", alertType)
	}
	if ack := c.Query("acknowledged"); ack != "" {
		query = query.Where("acknowledged = ?", ack == "true")
	}

	var alerts []models.Alert
	if err := query.Find(&alerts).Error; err != nil {
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

	limit, offset := httputil.ParsePagination(c)

	query := h.db.Gorm().Order("timestamp DESC").Limit(limit).Offset(offset)

	if deviceID := c.Query("device_id"); deviceID != "" {
		query = query.Where("device_id = ?", deviceID)
	}
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if trapType := c.Query("trap_type"); trapType != "" {
		query = query.Where("trap_type = ?", trapType)
	}

	var traps []models.TrapEvent
	if err := query.Find(&traps).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get traps"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(traps))
}

func (h *Handler) GetSyslogMessages(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.SyslogMessage{}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	query := h.db.Gorm().Order("timestamp DESC").Limit(limit).Offset(offset)

	if probeID := c.Query("probe_id"); probeID != "" {
		query = query.Where("probe_id = ?", probeID)
	}
	if deviceID := c.Query("device_id"); deviceID != "" {
		query = query.Where("device_id = ?", deviceID)
	}
	if severity := c.Query("severity"); severity != "" {
		if s, err := strconv.Atoi(severity); err == nil {
			query = query.Where("severity <= ?", s)
		}
	}
	if search := c.Query("search"); search != "" {
		like := "%" + search + "%"
		query = query.Where("message LIKE ? OR hostname LIKE ? OR app_name LIKE ?", like, like, like)
	}

	var messages []models.SyslogMessage
	if err := query.Find(&messages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get syslog messages"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(messages))
}

func (h *Handler) GetFlowSamples(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.FlowSample{}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	query := h.db.Gorm().Order("timestamp DESC").Limit(limit).Offset(offset)

	if probeID := c.Query("probe_id"); probeID != "" {
		query = query.Where("probe_id = ?", probeID)
	}
	if deviceID := c.Query("device_id"); deviceID != "" {
		query = query.Where("device_id = ?", deviceID)
	}
	if src := c.Query("src_addr"); src != "" {
		query = query.Where("src_addr = ?", src)
	}
	if dst := c.Query("dst_addr"); dst != "" {
		query = query.Where("dst_addr = ?", dst)
	}
	if proto := c.Query("protocol"); proto != "" {
		query = query.Where("protocol = ?", proto)
	}

	var samples []models.FlowSample
	if err := query.Find(&samples).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get flow samples"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(samples))
}

func (h *Handler) GetFlowStats(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(nil))
		return
	}

	hours := httputil.ParseHours(c)

	stats, err := h.db.GetFlowStats(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get flow stats"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(stats))
}

func (h *Handler) GetAlertStats(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(nil))
		return
	}

	hours := httputil.ParseHours(c)

	stats, err := h.db.GetAlertStats(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get alert stats"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(stats))
}

func (h *Handler) GetTrapStats(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(nil))
		return
	}

	hours := httputil.ParseHours(c)

	stats, err := h.db.GetTrapStats(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get trap stats"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(stats))
}

func (h *Handler) GetSyslogStats(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(nil))
		return
	}

	hours := httputil.ParseHours(c)

	stats, err := h.db.GetSyslogStats(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get syslog stats"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(stats))
}

func (h *Handler) AcknowledgeAlert(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := h.db.AcknowledgeAlert(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to acknowledge alert"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Alert acknowledged"))
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
