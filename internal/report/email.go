package report

import (
	"bytes"
	"fmt"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// DeviceReportSection holds pre-computed data for one device in a report.
type DeviceReportSection struct {
	DeviceName      string
	IPAddress       string
	Status          string
	CPUAvg          float64
	CPUMax          float64
	MemAvg          float64
	MemMax          float64
	DiskUsage       float64
	SessionCount    int
	AlertCount      int
	UptimeChartCID  string
	CPUMemChartCID  string
	TrafficChartCID string
	Spikes          []TrafficSpike
}

// DailyReportData holds all data for the daily report template.
type DailyReportData struct {
	Date           string
	Timezone       string
	Hours          int
	TotalDevices   int
	OnlineDevices  int
	OfflineDevices int
	TotalAlerts    int
	Devices        []DeviceReportSection
	AlertTrendCID  string
}

// BuildDailyReport builds an HTML daily report with embedded chart images.
func BuildDailyReport(devices []models.Device, deviceData []*DeviceReportData, tz string) (string, string, []notifier.Attachment, error) {
	return buildReport(devices, deviceData, tz, 24, "Daily")
}

// BuildWeeklyReport builds an HTML weekly report with embedded chart images.
func BuildWeeklyReport(devices []models.Device, deviceData []*DeviceReportData, tz string) (string, string, []notifier.Attachment, error) {
	return buildReport(devices, deviceData, tz, 168, "Weekly")
}

func buildReport(devices []models.Device, deviceData []*DeviceReportData, tz string, hours int, period string) (string, string, []notifier.Attachment, error) {
	now := time.Now()
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}

	data := DailyReportData{
		Date:         now.In(loc).Format("Monday, January 2, 2006"),
		Timezone:     tz,
		Hours:        hours,
		TotalDevices: len(devices),
	}

	var attachments []notifier.Attachment
	chartIdx := 0

	for i, device := range devices {
		if device.Status == "online" {
			data.OnlineDevices++
		} else {
			data.OfflineDevices++
		}

		if i >= len(deviceData) || deviceData[i] == nil {
			continue
		}
		dd := deviceData[i]
		data.TotalAlerts += dd.AlertCount

		section := DeviceReportSection{
			DeviceName:   device.Name,
			IPAddress:    device.IPAddress,
			Status:       device.Status,
			CPUAvg:       dd.CPUAvg,
			CPUMax:       dd.CPUMax,
			MemAvg:       dd.MemAvg,
			MemMax:       dd.MemMax,
			DiskUsage:    dd.DiskUsage,
			SessionCount: dd.SessionCount,
			AlertCount:   dd.AlertCount,
			Spikes:       dd.Spikes,
		}

		// Uptime chart
		if dd.UptimeChart != nil {
			cid := fmt.Sprintf("uptime_%d", chartIdx)
			chartIdx++
			section.UptimeChartCID = cid
			attachments = append(attachments, notifier.Attachment{
				ContentID: cid,
				Data:      dd.UptimeChart,
				MIMEType:  "image/png",
			})
		}

		// CPU/Mem chart
		if dd.CPUMemChart != nil {
			cid := fmt.Sprintf("cpumem_%d", chartIdx)
			chartIdx++
			section.CPUMemChartCID = cid
			attachments = append(attachments, notifier.Attachment{
				ContentID: cid,
				Data:      dd.CPUMemChart,
				MIMEType:  "image/png",
			})
		}

		// Traffic chart
		if dd.TrafficChart != nil {
			cid := fmt.Sprintf("traffic_%d", chartIdx)
			chartIdx++
			section.TrafficChartCID = cid
			attachments = append(attachments, notifier.Attachment{
				ContentID: cid,
				Data:      dd.TrafficChart,
				MIMEType:  "image/png",
			})
		}

		data.Devices = append(data.Devices, section)
	}

	// Alert trend chart
	if len(deviceData) > 0 {
		var allAlerts []models.Alert
		for _, dd := range deviceData {
			if dd != nil {
				allAlerts = append(allAlerts, dd.Alerts...)
			}
		}
		if trendPNG, err := RenderAlertTrend(allAlerts, hours); err == nil && trendPNG != nil {
			cid := "alert_trend"
			data.AlertTrendCID = cid
			attachments = append(attachments, notifier.Attachment{
				ContentID: cid,
				Data:      trendPNG,
				MIMEType:  "image/png",
			})
		}
	}

	var buf bytes.Buffer
	if err := dailyTemplate.Execute(&buf, data); err != nil {
		return "", "", nil, fmt.Errorf("render template: %w", err)
	}

	subject := fmt.Sprintf("Firewall Monitor — %s Report — %s", period, now.In(loc).Format("2006-01-02"))
	return subject, buf.String(), attachments, nil
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
