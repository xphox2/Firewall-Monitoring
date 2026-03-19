package report

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// DeviceReportData holds all aggregated data for a single device in a report.
type DeviceReportData struct {
	CPUAvg       float64
	CPUMax       float64
	MemAvg       float64
	MemMax       float64
	DiskUsage    float64
	SessionCount int
	AlertCount   int
	Alerts       []models.Alert
	Spikes       []TrafficSpike

	// Pre-rendered chart PNGs
	UptimeChart  []byte
	CPUMemChart  []byte
	TrafficChart []byte
}

// GatherDeviceData collects all report data for a single device over the given hours.
func GatherDeviceData(db *database.Database, device *models.Device, hours int, pollIntervalSec int, spikeThreshold float64) *DeviceReportData {
	data := &DeviceReportData{}

	// Get system status history
	history, err := db.GetSystemStatusHistory(device.ID, hours)
	if err != nil {
		log.Printf("Report: failed to get status history for %s: %v", device.Name, err)
	}

	// Compute CPU/Mem averages and maxes
	if len(history) > 0 {
		var cpuSum, memSum float64
		for _, h := range history {
			cpuSum += h.CPUUsage
			memSum += h.MemoryUsage
			if h.CPUUsage > data.CPUMax {
				data.CPUMax = h.CPUUsage
			}
			if h.MemoryUsage > data.MemMax {
				data.MemMax = h.MemoryUsage
			}
		}
		data.CPUAvg = cpuSum / float64(len(history))
		data.MemAvg = memSum / float64(len(history))
		data.DiskUsage = history[len(history)-1].DiskUsage
		data.SessionCount = history[len(history)-1].SessionCount
	}

	// Get alerts
	alerts, err := db.GetAlertsByDeviceAndHours(device.ID, hours)
	if err != nil {
		log.Printf("Report: failed to get alerts for %s: %v", device.Name, err)
	}
	data.Alerts = alerts
	data.AlertCount = len(alerts)

	// Get top interfaces for traffic chart
	topIfaces, err := db.GetTopInterfacesByTraffic(device.ID, hours, 3)
	if err != nil {
		log.Printf("Report: failed to get top interfaces for %s: %v", device.Name, err)
	}

	// Render traffic chart for top interface
	if len(topIfaces) > 0 {
		rangeStr := "24h"
		if hours >= 168 {
			rangeStr = "7d"
		}
		chartData, err := db.GetInterfaceChartData(device.ID, topIfaces[0].Index, rangeStr)
		if err == nil && len(chartData) > 0 {
			title := fmt.Sprintf("%s — %s Traffic", device.Name, topIfaces[0].Name)
			png, err := RenderTrafficChart(chartData, title)
			if err != nil {
				log.Printf("Report: failed to render traffic chart for %s: %v", device.Name, err)
			} else {
				data.TrafficChart = png
			}

			// Spike detection on chart data
			if spikeThreshold > 0 {
				spikes := DetectTrafficSpikes(chartData, spikeThreshold, topIfaces[0].Name)
				data.Spikes = append(data.Spikes, spikes...)
			}
		}
	}

	// Render CPU/Mem chart
	if len(history) > 0 {
		title := fmt.Sprintf("%s — CPU/Memory", device.Name)
		png, err := RenderCPUMemChart(history, title)
		if err != nil {
			log.Printf("Report: failed to render CPU/mem chart for %s: %v", device.Name, err)
		} else {
			data.CPUMemChart = png
		}
	}

	// Uptime calculation and chart
	uptime, err := CalculateDeviceUptime(db, device.ID, 30, pollIntervalSec)
	if err != nil {
		log.Printf("Report: failed to calculate uptime for %s: %v", device.Name, err)
	} else if uptime.DaysTracked > 0 {
		png, err := RenderUptimeMeter(uptime.Percent, uptime.DaysTracked, uptime.MaxDays)
		if err != nil {
			log.Printf("Report: failed to render uptime meter for %s: %v", device.Name, err)
		} else {
			data.UptimeChart = png
		}
	}

	return data
}

// GatherRecentHistory returns the last 2 hours of system status for a device.
func GatherRecentHistory(db *database.Database, deviceID uint) []models.SystemStatus {
	history, err := db.GetSystemStatusHistory(deviceID, 2)
	if err != nil {
		log.Printf("Report: failed to get recent history for device %d: %v", deviceID, err)
		return nil
	}
	return history
}

// durationUntilTime returns the duration until the next occurrence of HH:MM in the given timezone.
func DurationUntilTime(targetTime string, tz string) time.Duration {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)

	var hour, minute int
	fmt.Sscanf(targetTime, "%d:%d", &hour, &minute)

	target := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, loc)
	if target.Before(now) {
		target = target.Add(24 * time.Hour)
	}
	return target.Sub(now)
}

// DurationUntilWeekday returns the duration until the next occurrence of the given weekday at HH:MM.
func DurationUntilWeekday(targetDay, targetTime, tz string) time.Duration {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)

	dayMap := map[string]time.Weekday{
		"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday,
		"wednesday": time.Wednesday, "thursday": time.Thursday,
		"friday": time.Friday, "saturday": time.Saturday,
	}
	targetWeekday, ok := dayMap[targetDay]
	if !ok {
		targetWeekday = time.Monday
	}

	var hour, minute int
	fmt.Sscanf(targetTime, "%d:%d", &hour, &minute)

	daysUntil := int(targetWeekday - now.Weekday())
	if daysUntil < 0 {
		daysUntil += 7
	}
	if daysUntil == 0 {
		target := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, loc)
		if target.Before(now) {
			daysUntil = 7
		}
	}

	target := time.Date(now.Year(), now.Month(), now.Day()+daysUntil, hour, minute, 0, 0, loc)
	return target.Sub(now)
}
