package handlers

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
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

// reportSpikeFloorMbps resolves the absolute spike noise floor (v0.11.121)
// from settings, falling back to config and finally the 1 Mbps default. The
// `v != ""` + ParseFloat pattern is deliberately 0-safe: a saved 0 (floor
// disabled) applies.
func (h *Handler) reportSpikeFloorMbps() float64 {
	if v := h.getNotificationSetting("spike_min_throughput_mbps"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
	}
	if h.config != nil && h.config.Alerts.SpikeMinThroughputMbps >= 0 {
		return h.config.Alerts.SpikeMinThroughputMbps
	}
	return 1.0
}

// buildReportHTML gathers fleet data and renders the report to a single HTML
// document. collapsible wraps per-device detail in <details> for the admin
// preview. db is the request-scoped handle (AUDIT-032) so the heavy fleet-wide
// data gather is cancelled if the operator navigates away mid-render.
// theme selects the light/dark token set (report.ThemeByName semantics).
// text is the model-generated text/plain alternative; atts are the themed
// chart PNGs (email render only — collapsible=true yields none). The web
// preview path discards both.
func (h *Handler) buildReportHTML(db database.Store, period string, collapsible bool, theme string) (subject, html, text string, atts []notifier.Attachment, err error) {
	hours, label := reportWindow(period)
	tz := h.reportTimezone()
	spikeThreshold := h.reportSpikeThreshold()

	pollInterval := 60
	if h.config != nil {
		if s := int(h.config.SNMP.PollInterval.Seconds()); s >= 30 {
			pollInterval = s
		}
	}

	devices, err := db.GetAllDevices()
	if err != nil {
		return "", "", "", nil, err
	}

	// The report subsystem (internal/report) reads a richer DB surface than the
	// handler Store (per-device poll counts, top-talker rollups). The Store
	// handed in is always the GORM-backed *database.Database, so recover it for
	// that path; everything else here stays on the interface.
	cdb, ok := db.(*database.Database)
	if !ok {
		return "", "", "", nil, fmt.Errorf("report: concrete database backend unavailable")
	}

	deviceData := make([]*report.DeviceReportData, len(devices))
	for i := range devices {
		deviceData[i] = report.GatherDeviceData(cdb, &devices[i], hours, pollInterval, spikeThreshold, h.reportSpikeFloorMbps())
	}

	h.mu.RLock()
	version := h.version
	h.mu.RUnlock()

	return report.BuildReportWithOps(devices, deviceData, tz, hours, label, version, collapsible, report.GatherOpsStats(cdb), report.ThemeByName(theme))
}

// PreviewReport renders the executive report as HTML for in-panel viewing.
// GET /admin/api/reports/preview?period=daily|weekly
func (h *Handler) PreviewReport(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	db := h.reqDB(c)

	period := c.DefaultQuery("period", "daily")
	// Default dark: the pre-theming preview was hardcoded dark, so a client
	// that doesn't send ?theme= sees what it always saw.
	theme := c.DefaultQuery("theme", "dark")
	// layout=email renders the REAL email HTML (IsEmail=true, PNG charts,
	// device cap) with cid: references swapped for data: URIs — browsers
	// render those fine; only mail clients strip them. Validates the exact
	// email output without an SMTP round-trip.
	layout := c.DefaultQuery("layout", "web")
	subject, html, _, atts, err := h.buildReportHTML(db, period, layout != "email", theme)
	if err != nil {
		httputil.InternalError(c, "Failed to build report", err)
		return
	}
	if layout == "email" {
		for _, att := range atts {
			// Boundary-safe: match through the attribute's closing quote —
			// "cid:report_cpumem_1" is a string prefix of "…_10"/"…_11" and
			// a bare-prefix ReplaceAll would corrupt those anchors.
			html = strings.ReplaceAll(html, `cid:`+att.ContentID+`"`,
				"data:"+att.MIMEType+";base64,"+base64.StdEncoding.EncodeToString(att.Data)+`"`)
		}
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"subject": subject,
		"html":    html,
	}))
}

// SendReportNow generates the report and emails it immediately, reusing the
// SMTP settings configured for scheduled reports.
// POST /admin/api/reports/send  body: {"period":"daily|weekly"}
func (h *Handler) SendReportNow(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	if h.notifier == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Mailer not available"))
		return
	}
	db := h.reqDB(c)

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
		c.JSON(http.StatusBadRequest, response.Error("SMTP host, sender, and a report recipient must be configured"))
		return
	}
	// Guard against SSRF / internal port scanning via the SMTP host.
	if !isValidExternalIP(smtpHost) {
		c.JSON(http.StatusBadRequest, response.Error("SMTP host resolves to a blocked address"))
		return
	}

	smtpPort := 587
	if p := h.getNotificationSetting("smtp_port"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			smtpPort = v
		}
	}

	// Email theme: honors report_email_theme when set (missing/blank = light).
	subject, html, text, atts, err := h.buildReportHTML(db, req.Period, false, h.getNotificationSetting("report_email_theme"))
	if err != nil {
		httputil.InternalError(c, "Failed to build report", err)
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

	if err := h.notifier.SendHTMLEmail(subject, text, html, atts, nc, recipients); err != nil {
		// AUDIT API3: log the raw SMTP/dial error (may carry internal
		// hostnames/ports/TLS detail) but don't echo it to the client — every
		// other server-side failure path uses this generic-message pattern.
		log.Printf("Send report failed: %v", err)
		c.JSON(http.StatusBadGateway, response.Error("Failed to send report (see server logs for detail)"))
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"success": true,
		"message": "Report sent to " + recipients,
	}))
}
