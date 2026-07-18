package report

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/logging"
	"firewall-mon/internal/notifier"
)

// ReportScheduler manages scheduled daily/weekly HTML email reports.
//
// M15 of the 2026-07-01 audit: the scheduler and the AlertManager previously
// mutated the SAME shared *config.Config.Alerts fields under two DIFFERENT
// mutexes (rs.mu vs am.mu) — no mutual exclusion, a data race (torn string
// headers could send a report to a garbage recipient or panic). The scheduler
// now owns a PRIVATE copy of AlertsConfig (alertCfg), seeded at construction
// and refreshed from the DB (the same source AM reads), so it never touches
// AM's config. cfg is retained only for the read-only SNMP.PollInterval.
type ReportScheduler struct {
	cfg      *config.Config
	db       *database.Database
	notifier *notifier.Notifier
	stopChan chan struct{}
	mu       sync.RWMutex
	alertCfg config.AlertsConfig // private copy; guarded by mu
}

// NewReportScheduler creates a new report scheduler.
func NewReportScheduler(cfg *config.Config, db *database.Database, notif *notifier.Notifier) *ReportScheduler {
	return &ReportScheduler{
		cfg:      cfg,
		db:       db,
		notifier: notif,
		stopChan: make(chan struct{}),
		alertCfg: cfg.Alerts, // one-time value copy at construction (no goroutines running yet)
	}
}

// Start launches the daily and weekly report goroutines.
func (rs *ReportScheduler) Start() {
	// REL-01: a panic in either scheduler loop must not crash the whole poller
	// process — contain and log it instead.
	logging.SafeGo("report-daily", rs.runDaily)
	logging.SafeGo("report-weekly", rs.runWeekly)
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
		enabled := rs.alertCfg.ReportDailyEnabled
		targetTime := rs.alertCfg.ReportDailyTime
		tz := rs.alertCfg.ReportTimezone
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
			stillEnabled := rs.alertCfg.ReportDailyEnabled
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
		enabled := rs.alertCfg.ReportWeeklyEnabled
		targetDay := rs.alertCfg.ReportWeeklyDay
		targetTime := rs.alertCfg.ReportDailyTime
		tz := rs.alertCfg.ReportTimezone
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
			stillEnabled := rs.alertCfg.ReportWeeklyEnabled
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
	spikeThreshold := rs.alertCfg.SpikeStdDevThreshold
	tz := rs.alertCfg.ReportTimezone
	recipients := rs.alertCfg.ReportRecipients
	rs.mu.RUnlock()

	if pollInterval < 30 {
		pollInterval = 60
	}

	// Gather data for each device
	deviceData := make([]*DeviceReportData, len(devices))
	for i := range devices {
		deviceData[i] = GatherDeviceData(rs.db, &devices[i], hours, pollInterval, spikeThreshold)
	}

	// Build report (single self-contained HTML body, no attachments).
	// Theme: the report_email_theme setting lands with the PNG-charts release;
	// until then scheduled emails render light (identical default to before).
	var subject, htmlBody string
	ops := GatherOpsStats(rs.db) // F05/F06 Operations section
	theme := ThemeByName(rs.emailThemeSetting())
	if hours <= 24 {
		subject, htmlBody, err = BuildReportWithOps(devices, deviceData, tz, 24, "Daily", "", false, ops, theme)
	} else {
		subject, htmlBody, err = BuildReportWithOps(devices, deviceData, tz, 168, "Weekly", "", false, ops, theme)
	}
	if err != nil {
		log.Printf("Report: failed to build report: %v", err)
		return
	}

	// Send
	rs.mu.RLock()
	nc := notifier.SnapshotConfig(&rs.alertCfg)
	rs.mu.RUnlock()

	if err := rs.notifier.SendHTMLEmail(subject, htmlBody, nil, nc, recipients); err != nil {
		log.Printf("Report: failed to send report: %v", err)
	} else {
		log.Printf("Report: %dh report sent successfully to %s", hours, recipients)
	}
}

// emailThemeSetting reads report_email_theme directly from the DB at send
// time. Deliberately NOT part of RefreshSettings' key allowlist: a direct
// read on the (rare) send avoids two documented cache landmines — the
// hardcoded WHERE-IN list silently dropping unlisted keys, and the
// blank-value skip making a cleared setting stick forever. Missing/blank =
// light (ThemeByName's fallback).
func (rs *ReportScheduler) emailThemeSetting() string {
	if rs.db == nil {
		return ""
	}
	v, _ := rs.db.GetSettingValue("report_email_theme")
	return v
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
	// Load report fields AND the email/SMTP/webhook fields SnapshotConfig needs,
	// so the private alertCfg stays current when an operator changes SMTP or
	// recipients in the admin UI (M15 — the scheduler no longer piggybacks on
	// the AlertManager's shared cfg for that freshness).
	var settings []settingRow
	if err := rs.db.Gorm().Table("system_settings").Where("\"key\" IN ?", []string{
		"report_daily_enabled", "report_daily_time", "report_weekly_enabled",
		"report_weekly_day", "report_recipients", "report_timezone",
		"spike_stddev_threshold",
		"email_enabled", "smtp_host", "smtp_port", "smtp_username", "smtp_password",
		"smtp_from", "smtp_to", "slack_webhook", "discord_webhook", "webhook_url",
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
			rs.alertCfg.ReportDailyEnabled = s.Value == "true"
		case "report_daily_time":
			rs.alertCfg.ReportDailyTime = s.Value
		case "report_weekly_enabled":
			rs.alertCfg.ReportWeeklyEnabled = s.Value == "true"
		case "report_weekly_day":
			rs.alertCfg.ReportWeeklyDay = s.Value
		case "report_recipients":
			rs.alertCfg.ReportRecipients = s.Value
		case "report_timezone":
			rs.alertCfg.ReportTimezone = s.Value
		case "spike_stddev_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				rs.alertCfg.SpikeStdDevThreshold = v
			}
		case "email_enabled":
			rs.alertCfg.EmailEnabled = s.Value == "true"
		case "smtp_host":
			rs.alertCfg.SMTPHost = s.Value
		case "smtp_port":
			if v, err := strconv.Atoi(s.Value); err == nil && v > 0 {
				rs.alertCfg.SMTPPort = v
			}
		case "smtp_username":
			rs.alertCfg.SMTPUsername = s.Value
		case "smtp_password":
			// DecryptField is idempotent for plaintext, so this is safe whether
			// the password was stored "{enc}…" (admin UI) or as a raw env value.
			rs.alertCfg.SMTPPassword = rs.db.DecryptField(s.Value)
		case "smtp_from":
			rs.alertCfg.SMTPFrom = s.Value
		case "smtp_to":
			rs.alertCfg.SMTPTo = s.Value
		case "slack_webhook":
			rs.alertCfg.SlackWebhookURL = s.Value
		case "discord_webhook":
			rs.alertCfg.DiscordWebhookURL = s.Value
		case "webhook_url":
			rs.alertCfg.WebHookURL = s.Value
		}
	}
}
