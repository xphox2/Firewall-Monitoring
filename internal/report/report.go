package report

import (
	"log"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/notifier"
)

// ReportScheduler manages scheduled daily/weekly HTML email reports.
type ReportScheduler struct {
	cfg      *config.Config
	db       *database.Database
	notifier *notifier.Notifier
	stopChan chan struct{}
	mu       sync.RWMutex
}

// NewReportScheduler creates a new report scheduler.
func NewReportScheduler(cfg *config.Config, db *database.Database, notif *notifier.Notifier) *ReportScheduler {
	return &ReportScheduler{
		cfg:      cfg,
		db:       db,
		notifier: notif,
		stopChan: make(chan struct{}),
	}
}

// Start launches the daily and weekly report goroutines.
func (rs *ReportScheduler) Start() {
	go rs.runDaily()
	go rs.runWeekly()
	log.Println("Report scheduler started")
}

// Stop signals the scheduler to stop.
func (rs *ReportScheduler) Stop() {
	select {
	case <-rs.stopChan:
	default:
		close(rs.stopChan)
	}
}

func (rs *ReportScheduler) runDaily() {
	for {
		rs.mu.RLock()
		enabled := rs.cfg.Alerts.ReportDailyEnabled
		targetTime := rs.cfg.Alerts.ReportDailyTime
		tz := rs.cfg.Alerts.ReportTimezone
		rs.mu.RUnlock()

		if !enabled {
			// Check again in 5 minutes
			select {
			case <-time.After(5 * time.Minute):
				continue
			case <-rs.stopChan:
				return
			}
		}

		delay := DurationUntilTime(targetTime, tz)
		log.Printf("Report scheduler: daily report in %v", delay.Round(time.Minute))

		select {
		case <-time.After(delay):
			rs.RefreshSettings()
			rs.mu.RLock()
			stillEnabled := rs.cfg.Alerts.ReportDailyEnabled
			rs.mu.RUnlock()
			if stillEnabled {
				rs.generateAndSendReport(24)
			}
		case <-rs.stopChan:
			return
		}
	}
}

func (rs *ReportScheduler) runWeekly() {
	for {
		rs.mu.RLock()
		enabled := rs.cfg.Alerts.ReportWeeklyEnabled
		targetDay := rs.cfg.Alerts.ReportWeeklyDay
		targetTime := rs.cfg.Alerts.ReportDailyTime
		tz := rs.cfg.Alerts.ReportTimezone
		rs.mu.RUnlock()

		if !enabled {
			select {
			case <-time.After(5 * time.Minute):
				continue
			case <-rs.stopChan:
				return
			}
		}

		delay := DurationUntilWeekday(strings.ToLower(targetDay), targetTime, tz)
		log.Printf("Report scheduler: weekly report in %v", delay.Round(time.Minute))

		select {
		case <-time.After(delay):
			rs.RefreshSettings()
			rs.mu.RLock()
			stillEnabled := rs.cfg.Alerts.ReportWeeklyEnabled
			rs.mu.RUnlock()
			if stillEnabled {
				rs.generateAndSendReport(168)
			}
		case <-rs.stopChan:
			return
		}
	}
}

func (rs *ReportScheduler) generateAndSendReport(hours int) {
	if rs.db == nil {
		return
	}

	devices, err := rs.db.GetAllDevices()
	if err != nil {
		log.Printf("Report: failed to get devices: %v", err)
		return
	}
	if len(devices) == 0 {
		return
	}

	rs.mu.RLock()
	pollInterval := int(rs.cfg.SNMP.PollInterval.Seconds())
	spikeThreshold := rs.cfg.Alerts.SpikeStdDevThreshold
	tz := rs.cfg.Alerts.ReportTimezone
	recipients := rs.cfg.Alerts.ReportRecipients
	rs.mu.RUnlock()

	if pollInterval < 30 {
		pollInterval = 60
	}

	// Gather data for each device
	deviceData := make([]*DeviceReportData, len(devices))
	for i := range devices {
		deviceData[i] = GatherDeviceData(rs.db, &devices[i], hours, pollInterval, spikeThreshold)
	}

	// Build report
	var subject, htmlBody string
	var attachments []notifier.Attachment
	if hours <= 24 {
		subject, htmlBody, attachments, err = BuildDailyReport(devices, deviceData, tz)
	} else {
		subject, htmlBody, attachments, err = BuildWeeklyReport(devices, deviceData, tz)
	}
	if err != nil {
		log.Printf("Report: failed to build report: %v", err)
		return
	}

	// Send
	rs.mu.RLock()
	nc := notifier.SnapshotConfig(&rs.cfg.Alerts)
	rs.mu.RUnlock()

	if err := rs.notifier.SendHTMLEmail(subject, htmlBody, attachments, nc, recipients); err != nil {
		log.Printf("Report: failed to send report: %v", err)
	} else {
		log.Printf("Report: %dh report sent successfully to %s", hours, recipients)
	}
}

// RefreshSettings reads report-related settings from the database.
func (rs *ReportScheduler) RefreshSettings() {
	if rs.db == nil {
		return
	}

	type settingRow struct {
		Key   string
		Value string
	}
	var settings []settingRow
	if err := rs.db.Gorm().Table("system_settings").Where("\"key\" IN ?", []string{
		"report_daily_enabled", "report_daily_time", "report_weekly_enabled",
		"report_weekly_day", "report_recipients", "report_timezone",
		"spike_stddev_threshold", "spike_alert_enabled",
	}).Find(&settings).Error; err != nil {
		log.Printf("Report: failed to refresh settings: %v", err)
		return
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	for _, s := range settings {
		if s.Value == "" {
			continue
		}
		switch s.Key {
		case "report_daily_enabled":
			rs.cfg.Alerts.ReportDailyEnabled = s.Value == "true"
		case "report_daily_time":
			rs.cfg.Alerts.ReportDailyTime = s.Value
		case "report_weekly_enabled":
			rs.cfg.Alerts.ReportWeeklyEnabled = s.Value == "true"
		case "report_weekly_day":
			rs.cfg.Alerts.ReportWeeklyDay = s.Value
		case "report_recipients":
			rs.cfg.Alerts.ReportRecipients = s.Value
		case "report_timezone":
			rs.cfg.Alerts.ReportTimezone = s.Value
		}
	}
}
