package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetAlerts(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"alerts": []models.Alert{}, "total": 0}))
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

	var total int64
	countQuery := h.db.Gorm().Model(&models.Alert{})
	if deviceID := c.Query("device_id"); deviceID != "" {
		countQuery = countQuery.Where("device_id = ?", deviceID)
	}
	if severity := c.Query("severity"); severity != "" {
		countQuery = countQuery.Where("severity = ?", severity)
	}
	if alertType := c.Query("alert_type"); alertType != "" {
		countQuery = countQuery.Where("alert_type = ?", alertType)
	}
	if ack := c.Query("acknowledged"); ack != "" {
		countQuery = countQuery.Where("acknowledged = ?", ack == "true")
	}
	countQuery.Count(&total)

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"alerts": alerts, "total": total}))
}

func (h *Handler) GetAlert(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Alert not found"))
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var alert models.Alert
	if err := h.db.Gorm().First(&alert, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Alert not found"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(alert))
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
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"messages": []models.SyslogMessage{}, "total": 0}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	query := h.db.Gorm().Order("timestamp DESC")

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
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(search)
		like := "%" + escaped + "%"
		query = query.Where("message LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\' OR app_name LIKE ? ESCAPE '\\'", like, like, like)
	}

	var messages []models.SyslogMessage
	if err := query.Limit(limit).Offset(offset).Find(&messages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get syslog messages"))
		return
	}

	var total int64
	countQuery := h.db.Gorm().Model(&models.SyslogMessage{})
	if probeID := c.Query("probe_id"); probeID != "" {
		countQuery = countQuery.Where("probe_id = ?", probeID)
	}
	if deviceID := c.Query("device_id"); deviceID != "" {
		countQuery = countQuery.Where("device_id = ?", deviceID)
	}
	if severity := c.Query("severity"); severity != "" {
		if s, err := strconv.Atoi(severity); err == nil {
			countQuery = countQuery.Where("severity <= ?", s)
		}
	}
	if search := c.Query("search"); search != "" {
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(search)
		like := "%" + escaped + "%"
		countQuery = countQuery.Where("message LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\' OR app_name LIKE ? ESCAPE '\\'", like, like, like)
	}
	countQuery.Count(&total)

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"messages": messages, "total": total}))
}

func (h *Handler) GetSyslogMessage(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Syslog message not found"))
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var msg models.SyslogMessage
	if err := h.db.Gorm().First(&msg, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Syslog message not found"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(msg))
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
	var deviceID uint
	if did := c.Query("device_id"); did != "" {
		if v, err := strconv.ParseUint(did, 10, 32); err == nil {
			deviceID = uint(v)
		}
	}

	stats, err := h.db.GetFlowStats(hours, deviceID)
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

	var body struct {
		Notes string `json:"notes"`
	}
	// Allow empty body for backward compatibility
	c.ShouldBindJSON(&body)

	if err := h.db.AcknowledgeAlertEnhanced(id, body.Notes); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to acknowledge alert"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Alert acknowledged"))
}

// maxBulkAckIDs caps how many alerts can be acked in a single bulk request.
// Picked to keep SQL parameter lists comfortable across SQLite and Postgres.
const maxBulkAckIDs = 500

// BulkAcknowledgeAlerts acks every alert whose ID is in the request body, in a
// single SQL UPDATE. Used by the admin UI's "Acknowledge selected" toolbar so
// the user doesn't have to ack alerts one at a time.
func (h *Handler) BulkAcknowledgeAlerts(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	var body struct {
		IDs   []uint `json:"ids"`
		Notes string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid JSON"))
		return
	}
	if len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("ids must be a non-empty array"))
		return
	}
	if len(body.IDs) > maxBulkAckIDs {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("too many ids (max %d per request)", maxBulkAckIDs)))
		return
	}

	affected, err := h.db.AcknowledgeAlertsBulk(body.IDs, body.Notes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to acknowledge alerts"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"acknowledged": affected,
		"requested":    len(body.IDs),
	}))
}

func (h *Handler) UpdateAlertNotes(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var body struct {
		Notes string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if len(body.Notes) > 4000 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Notes must be under 4000 characters"))
		return
	}

	if err := h.db.UpdateAlertNotes(id, body.Notes); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update alert notes"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Alert notes updated"))
}

func (h *Handler) GetUptime(c *gin.Context) {
	stats := h.uptimeTrack.GetStats()
	fiveNines := h.uptimeTrack.CalculateFiveNines()

	var records []models.UptimeRecord
	if h.db != nil {
		var err error
		records, err = h.db.GetUptimeRecords(100)
		if err != nil {
			log.Printf("Failed to get uptime records: %v", err)
		}
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
