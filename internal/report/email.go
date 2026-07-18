package report

import (
	"bytes"
	"fmt"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// BuildDailyReport builds a self-contained HTML daily report (no attachments).
func BuildDailyReport(devices []models.Device, deviceData []*DeviceReportData, tz string) (string, string, error) {
	return buildReport(devices, deviceData, tz, 24, "Daily", "")
}

// BuildWeeklyReport builds a self-contained HTML weekly report (no attachments).
func BuildWeeklyReport(devices []models.Device, deviceData []*DeviceReportData, tz string) (string, string, error) {
	return buildReport(devices, deviceData, tz, 168, "Weekly", "")
}

// BuildReport renders a report HTML body + subject for the given window. The
// collapsible flag wraps per-device detail in <details> (admin preview); email
// sends always-open blocks. Returns (subject, html, error). Renders in the
// light theme — theme-aware callers use BuildReportWithOps.
func BuildReport(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period, version string, collapsible bool) (string, string, error) {
	return BuildReportWithOps(devices, deviceData, tz, hours, period, version, collapsible, nil, ThemeByName(""))
}

// BuildReportWithOps is BuildReport plus the F05/F06 Operations section
// (nil ops = section omitted) and an explicit theme (v0.11.116 — the web
// preview follows the SPA Day/Night choice; email follows the
// report_email_theme setting).
func BuildReportWithOps(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period, version string, collapsible bool, ops *OpsStats, theme ReportTheme) (string, string, error) {
	m := BuildReportModel(devices, deviceData, tz, hours, period)
	m.Ops = ops
	m.Version = version
	m.Collapsible = collapsible
	m.IsEmail = !collapsible
	m.Theme = theme
	if m.Theme.Name == "" {
		m.Theme = ThemeByName("") // zero-value guard: never render unthemed
	}
	for i := range m.Devices {
		m.Devices[i].IsEmail = m.IsEmail
	}
	html, err := RenderReportHTML(m)
	if err != nil {
		return "", "", err
	}
	loc, e := time.LoadLocation(tz)
	if e != nil {
		loc = time.UTC
	}
	subject := fmt.Sprintf("Firewall Monitor — %s Report — %s", period, time.Now().In(loc).Format("2006-01-02"))
	return subject, html, nil
}

func buildReport(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period, version string) (string, string, error) {
	return BuildReport(devices, deviceData, tz, hours, period, version, false)
}

// CriticalAlertData holds data for the critical alert template.
type CriticalAlertData struct {
	Timestamp      string
	AlertType      string
	DeviceName     string
	DeviceIP       string
	Message        string
	MetricName     string
	CurrentValue   float64
	Threshold      float64
	DeviceStatus   string
	CPUMemChartCID string
	Theme          ReportTheme
}

// BuildCriticalAlertEmail builds an HTML email for a critical alert, themed
// with the same flat instrument-panel system as the fleet report. Callers
// resolve the theme (the poller reads report_email_theme from the DB at send
// time — its env-frozen config copy must NOT be the source).
func BuildCriticalAlertEmail(alert *models.Alert, device *models.Device, recentHistory []models.SystemStatus, theme ReportTheme) (string, string, []notifier.Attachment, error) {
	if theme.Name == "" {
		theme = ThemeByName("")
	}
	data := CriticalAlertData{
		Timestamp:    alert.Timestamp.Format(time.RFC3339),
		AlertType:    string(alert.AlertType),
		DeviceName:   device.Name,
		DeviceIP:     device.IPAddress,
		Message:      alert.Message,
		MetricName:   alert.MetricName,
		CurrentValue: alert.CurrentValue,
		Threshold:    alert.Threshold,
		DeviceStatus: device.Status,
		Theme:        theme,
	}

	var attachments []notifier.Attachment

	// Add recent CPU/mem chart if we have history
	if len(recentHistory) > 0 {
		chartPNG, err := RenderCPUMemChart(recentHistory, fmt.Sprintf("%s — Recent Status", device.Name))
		if err == nil && chartPNG != nil {
			cid := "cpumem_critical"
			data.CPUMemChartCID = cid
			attachments = append(attachments, notifier.Attachment{
				ContentID: cid,
				Data:      chartPNG,
				MIMEType:  "image/png",
			})
		}
	}

	var buf bytes.Buffer
	if err := criticalAlertTemplate.Execute(&buf, data); err != nil {
		return "", "", nil, fmt.Errorf("render critical template: %w", err)
	}

	subject := fmt.Sprintf("[CRITICAL] %s — %s (%s)",
		notifier.SanitizeHeader(string(alert.AlertType)),
		notifier.SanitizeHeader(device.Name),
		notifier.SanitizeHeader(device.IPAddress))
	return subject, buf.String(), attachments, nil
}
