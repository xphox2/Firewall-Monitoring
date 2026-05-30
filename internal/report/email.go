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
// sends always-open blocks. Returns (subject, html, error).
func BuildReport(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period, version string, collapsible bool) (string, string, error) {
	m := BuildReportModel(devices, deviceData, tz, hours, period)
	m.Version = version
	m.Collapsible = collapsible
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
}

// BuildCriticalAlertEmail builds an HTML email for a critical alert.
func BuildCriticalAlertEmail(alert *models.Alert, device *models.Device, recentHistory []models.SystemStatus) (string, string, []notifier.Attachment, error) {
	data := CriticalAlertData{
		Timestamp:    alert.Timestamp.Format(time.RFC3339),
		AlertType:    alert.AlertType,
		DeviceName:   device.Name,
		DeviceIP:     device.IPAddress,
		Message:      alert.Message,
		MetricName:   alert.MetricName,
		CurrentValue: alert.CurrentValue,
		Threshold:    alert.Threshold,
		DeviceStatus: device.Status,
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

	subject := fmt.Sprintf("[CRITICAL] %s — %s (%s)", alert.AlertType, device.Name, device.IPAddress)
	return subject, buf.String(), attachments, nil
}
