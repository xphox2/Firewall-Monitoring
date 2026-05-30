package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/report"

	"github.com/gin-gonic/gin"
)

// reportWindow maps the period query/body value to (hours, label).
func reportWindow(period string) (int, string) {
	if strings.EqualFold(period, "weekly") {
		return 168, "Weekly"
	}
	return 24, "Daily"
}

// reportTimezone resolves the report timezone from settings, falling back to
// config and finally UTC.
func (h *Handler) reportTimezone() string {
	if tz := h.getNotificationSetting("report_timezone"); tz != "" {
		return tz
	}
	if h.config != nil && h.config.Alerts.ReportTimezone != "" {
		return h.config.Alerts.ReportTimezone
	}
	return "UTC"
}

// reportSpikeThreshold resolves the spike std-dev threshold from settings,
// falling back to config and finally 3.0.
func (h *Handler) reportSpikeThreshold() float64 {
	if v := h.getNotificationSetting("spike_stddev_threshold"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	if h.config != nil && h.config.Alerts.SpikeStdDevThreshold > 0 {
		return h.config.Alerts.SpikeStdDevThreshold
	}
	return 3.0
}

// buildReportHTML gathers fleet data and renders the report to a single HTML
// document. collapsible wraps per-device detail in <details> for the admin
// preview.
func (h *Handler) buildReportHTML(period string, collapsible bool) (subject, html string, err error) {
	hours, label := reportWindow(period)
	tz := h.reportTimezone()
	spikeThreshold := h.reportSpikeThreshold()

	pollInterval := 60
	if h.config != nil {
		if s := int(h.config.SNMP.PollInterval.Seconds()); s >= 30 {
			pollInterval = s
		}
	}

	devices, err := h.db.GetAllDevices()
	if err != nil {
		return "", "", err
	}

	deviceData := make([]*report.DeviceReportData, len(devices))
	for i := range devices {
		deviceData[i] = report.GatherDeviceData(h.db, &devices[i], hours, pollInterval, spikeThreshold)
	}

	h.mu.RLock()
	version := h.version
	h.mu.RUnlock()

	return report.BuildReport(devices, deviceData, tz, hours, label, version, collapsible)
}

// PreviewReport renders the executive report as HTML for in-panel viewing.
// GET /admin/api/reports/preview?period=daily|weekly
func (h *Handler) PreviewReport(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	period := c.DefaultQuery("period", "daily")
	subject, html, err := h.buildReportHTML(period, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to build report: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"subject": subject,
		"html":    html,
	}))
}

// SendReportNow generates the report and emails it immediately, reusing the
// SMTP settings configured for scheduled reports.
// POST /admin/api/reports/send  body: {"period":"daily|weekly"}
func (h *Handler) SendReportNow(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}
	if h.notifier == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Mailer not available"))
		return
	}

	var req struct {
		Period string `json:"period"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.Period == "" {
		req.Period = "daily"
	}

	// Resolve SMTP settings (same source as the Test Email path).
	smtpHost := h.getNotificationSetting("smtp_host")
	smtpFrom := h.getNotificationSetting("smtp_from")
	recipients := h.getNotificationSetting("report_recipients")
	if recipients == "" {
		recipients = h.getNotificationSetting("smtp_to")
	}

	if smtpHost == "" || smtpFrom == "" || recipients == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("SMTP host, sender, and a report recipient must be configured"))
		return
	}
	// Guard against SSRF / internal port scanning via the SMTP host.
	if !isValidExternalIP(smtpHost) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("SMTP host resolves to a blocked address"))
		return
	}

	smtpPort := 587
	if p := h.getNotificationSetting("smtp_port"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			smtpPort = v
		}
	}

	subject, html, err := h.buildReportHTML(req.Period, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to build report: "+err.Error()))
		return
	}

	nc := notifier.NotifyConfig{
		EmailEnabled: true,
		SMTPHost:     smtpHost,
		SMTPPort:     smtpPort,
		SMTPUsername: h.getNotificationSetting("smtp_username"),
		SMTPPassword: h.getNotificationSetting("smtp_password"),
		SMTPFrom:     smtpFrom,
		SMTPTo:       recipients,
	}

	if err := h.notifier.SendHTMLEmail(subject, html, nil, nc, recipients); err != nil {
		log.Printf("Send report failed: %v", err)
		c.JSON(http.StatusBadGateway, models.ErrorResponse("Failed to send report: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"success": true,
		"message": "Report sent to " + recipients,
	}))
}
