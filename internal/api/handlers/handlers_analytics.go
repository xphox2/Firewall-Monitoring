package handlers

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ipFilterClause turns a user-supplied `src_addr` or `dst_addr` query value
// into a WHERE clause + bound argument. Supports:
//
//   - exact match:        "10.0.0.5"           → column = ?
//   - octet-aligned CIDR: "10.0.0.0/8|16|24"   → column LIKE prefix.%
//   - /32 CIDR:           "10.0.0.5/32"        → column = ? (network IP)
//   - any other input:    fall back to exact match against the raw string,
//     so a malformed CIDR doesn't crash and the operator still sees something
//
// We use prefix matching on the text column rather than casting to inet
// because flow_samples.src_addr/dst_addr are stored as strings and we want
// the same code path to work on SQLite (test DB) and Postgres (prod).
// Non-octet-aligned CIDRs (e.g. /20, /28) fall back to exact match on the
// network address — improving that needs a numeric range query on a parsed
// IPv4-as-int column, which is a bigger refactor.
//
// Returns (sqlFragment, boundArg, applied). applied=false means caller
// should NOT apply this filter (invalid CIDR, etc.).
func ipFilterClause(column, val string) (string, interface{}, bool) {
	val = strings.TrimSpace(val)
	if val == "" {
		return "", nil, false
	}
	if !strings.Contains(val, "/") {
		return column + " = ?", val, true
	}
	_, ipNet, err := net.ParseCIDR(val)
	if err != nil {
		return column + " = ?", val, true
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		// IPv6 CIDR — fall back to exact match for now. Proper IPv6 CIDR
		// matching on a text column needs lexicographic prefixing on the
		// canonical form, which our store doesn't guarantee.
		return column + " = ?", ipNet.IP.String(), true
	}
	netStr := ipNet.IP.To4().String()
	parts := strings.Split(netStr, ".")
	if len(parts) != 4 {
		return column + " = ?", val, true
	}
	switch ones {
	case 8:
		return column + " LIKE ?", parts[0] + ".%", true
	case 16:
		return column + " LIKE ?", parts[0] + "." + parts[1] + ".%", true
	case 24:
		return column + " LIKE ?", parts[0] + "." + parts[1] + "." + parts[2] + ".%", true
	case 32:
		return column + " = ?", netStr, true
	default:
		return column + " = ?", netStr, true
	}
}

// applyAlertFilters writes every query-string filter into the GORM
// chain. Extracted from the listing + count paths (v0.10.218, bundle G2)
// so a new snooze filter only needs to be added in one place.
//
// Snooze behavior: by default, alerts with `snoozed_until > now` are
// hidden — the operator who snoozed them doesn't want to see them. Pass
// `include_snoozed=true` to override (used by the bulk-ack flow + the
// snoozed-alerts view).
func applyAlertFilters(c *gin.Context, q *gorm.DB) *gorm.DB {
	if deviceID := c.Query("device_id"); deviceID != "" {
		q = q.Where("device_id = ?", deviceID)
	}
	if severity := c.Query("severity"); severity != "" {
		q = q.Where("severity = ?", severity)
	}
	if alertType := c.Query("alert_type"); alertType != "" {
		q = q.Where("alert_type = ?", alertType)
	}
	if ack := c.Query("acknowledged"); ack != "" {
		q = q.Where("acknowledged = ?", ack == "true")
	}
	if c.Query("include_snoozed") != "true" {
		q = q.Where("snoozed_until IS NULL OR snoozed_until < ?", time.Now())
	}
	return q
}

func (h *Handler) GetAlerts(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"alerts": []models.Alert{}, "total": 0}))
		return
	}

	limit, offset := httputil.ParsePagination(c)

	query := applyAlertFilters(c, h.db.Gorm().Order("timestamp DESC").Limit(limit).Offset(offset))

	var alerts []models.Alert
	if err := query.Find(&alerts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get alerts"))
		return
	}

	var total int64
	applyAlertFilters(c, h.db.Gorm().Model(&models.Alert{})).Count(&total)

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
		if frag, arg, ok := ipFilterClause("src_addr", src); ok {
			query = query.Where(frag, arg)
		}
	}
	if dst := c.Query("dst_addr"); dst != "" {
		if frag, arg, ok := ipFilterClause("dst_addr", dst); ok {
			query = query.Where(frag, arg)
		}
	}
	// Optional dst port filter — top-port drill-down sends this.
	if dport := c.Query("dst_port"); dport != "" {
		if p, err := strconv.ParseUint(dport, 10, 16); err == nil {
			query = query.Where("dst_port = ?", p)
		}
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

// parseStatsDeviceFilter reads an optional device_id query parameter from
// /stats endpoints (v0.10.217, bundle D4). Returns 0 if absent or invalid,
// matching the "no filter" sentinel used by the database layer.
func parseStatsDeviceFilter(c *gin.Context) uint {
	raw := c.Query("device_id")
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0
	}
	return uint(n)
}

func (h *Handler) GetAlertStats(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(nil))
		return
	}

	hours := httputil.ParseHours(c)
	deviceID := parseStatsDeviceFilter(c)

	stats, err := h.db.GetAlertStats(hours, deviceID)
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
	deviceID := parseStatsDeviceFilter(c)

	stats, err := h.db.GetTrapStats(hours, deviceID)
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
	deviceID := parseStatsDeviceFilter(c)

	stats, err := h.db.GetSyslogStats(hours, deviceID)
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

// SnoozeAlert temporarily silences an alert until SnoozedUntil. Distinct
// from acknowledge: the alert resurfaces in the default list once the
// snooze expires (v0.10.218, bundle G2). Common operator pattern is
// "snooze for 4 hours while I finish unrelated triage".
//
// Body: { "hours": 4, "reason": "weekly rotation, check Monday" }
// `hours` is clamped to [1, 720] (30 days max). Empty/zero hours = 1.
func (h *Handler) SnoozeAlert(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var body struct {
		Hours  int    `json:"hours"`
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&body)

	hours := body.Hours
	if hours < 1 {
		hours = 1
	}
	if hours > 720 {
		hours = 720
	}

	until := time.Now().Add(time.Duration(hours) * time.Hour)
	// Best-effort capture of who snoozed for the audit fields. Username
	// lookup happens in the database layer to avoid threading session
	// state through this handler.
	user, _ := c.Get("username")
	username, _ := user.(string)

	if err := h.db.SnoozeAlert(id, until, username, body.Reason); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to snooze alert"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"snoozed_until": until,
		"hours":         hours,
	}))
}

// UnsnoozeAlert clears the snooze, re-surfacing the alert immediately
// (v0.10.218, bundle G2).
func (h *Handler) UnsnoozeAlert(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := h.db.UnsnoozeAlert(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to unsnooze alert"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Alert unsnoozed"))
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

// BulkAcknowledgeAlertsByFilter acks every alert matching the filter (same
// query parameters as GET /api/alerts: device_id, alert_type, severity,
// acknowledged). Body carries the optional notes. Used by the admin UI's
// "Select all N matching" flow when the result set exceeds maxBulkAckIDs and
// can't be shipped as an ID list.
//
// At least one filter must be specified to prevent accidental "ack everything
// in the database" calls.
func (h *Handler) BulkAcknowledgeAlertsByFilter(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	var body struct {
		Notes string `json:"notes"`
	}
	c.ShouldBindJSON(&body) // body is optional

	filter := database.AlertFilter{}
	hasAnyFilter := false
	if v := c.Query("device_id"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 32); err == nil && id > 0 {
			filter.DeviceID = uint(id)
			hasAnyFilter = true
		}
	}
	if v := c.Query("alert_type"); v != "" {
		filter.AlertType = v
		hasAnyFilter = true
	}
	if v := c.Query("severity"); v != "" {
		filter.Severity = v
		hasAnyFilter = true
	}
	if v := c.Query("acknowledged"); v != "" {
		ack := v == "true"
		filter.Acknowledged = &ack
		hasAnyFilter = true
	}

	if !hasAnyFilter {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("at least one filter is required (device_id, alert_type, severity, acknowledged)"))
		return
	}

	affected, err := h.db.AcknowledgeAlertsByFilter(filter, body.Notes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to acknowledge alerts"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"acknowledged": affected,
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
