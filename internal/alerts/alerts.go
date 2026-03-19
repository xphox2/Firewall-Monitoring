package alerts

import (
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"

	"gorm.io/gorm"
)

type AlertManager struct {
	config        *config.Config
	notifier      *notifier.Notifier
	db            *database.Database
	lastAlert     map[string]time.Time
	activeAlerts  map[string]bool // tracks currently-firing alert keys for recovery detection
	mu            sync.RWMutex
	alertCooldown time.Duration
	policyCache   PolicyCache
}

// firedEntry pairs an alert with its resolved policy config for deferred notification.
type firedEntry struct {
	alert    models.Alert
	resolved ResolvedAlertConfig
}

func NewAlertManager(cfg *config.Config, notif *notifier.Notifier, db *database.Database) *AlertManager {
	return &AlertManager{
		config:        cfg,
		notifier:      notif,
		db:            db,
		lastAlert:     make(map[string]time.Time),
		activeAlerts:  make(map[string]bool),
		alertCooldown: 5 * time.Minute,
	}
}

// checkThreshold creates an alert if the metric exceeds the threshold and the
// cooldown for the given key has expired. Must be called with am.mu held.
func (am *AlertManager) checkThreshold(now time.Time, deviceID uint, metricKey, alertType, severity, message, metricName string, current, threshold float64) *models.Alert {
	if am.canAlert(metricKey, now) {
		alert := models.Alert{
			Timestamp:    now,
			DeviceID:     deviceID,
			AlertType:    alertType,
			Severity:     severity,
			Message:      message,
			MetricName:   metricName,
			Threshold:    threshold,
			CurrentValue: current,
		}
		am.lastAlert[metricKey] = now
		return &alert
	}
	return nil
}

func (am *AlertManager) CheckSystemStatus(status *models.SystemStatus, siteID *uint) error {
	type metricCheck struct {
		alertType string
		metricKey string
		metric    string
		current   float64
	}

	checks := []metricCheck{
		{"CPU_HIGH", fmt.Sprintf("cpu_high_%d", status.DeviceID), "cpu_usage", status.CPUUsage},
		{"MEMORY_HIGH", fmt.Sprintf("memory_high_%d", status.DeviceID), "memory_usage", status.MemoryUsage},
		{"DISK_HIGH", fmt.Sprintf("disk_high_%d", status.DeviceID), "disk_usage", status.DiskUsage},
		{"SESSIONS_HIGH", fmt.Sprintf("sessions_high_%d", status.DeviceID), "session_count", float64(status.SessionCount)},
	}

	var fired []firedEntry

	am.mu.Lock()
	now := time.Now()
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)

	for _, chk := range checks {
		resolved := am.resolveAlertConfig(status.DeviceID, siteID, chk.alertType)
		if !resolved.AlertEnabled || resolved.Threshold == 0 {
			continue
		}

		if chk.current >= resolved.Threshold {
			cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
			if am.canAlertWithCooldown(chk.metricKey, now, cooldown) {
				msg := fmt.Sprintf("%s is %.1f (threshold: %.1f)", chk.metric, chk.current, resolved.Threshold)
				if chk.alertType == "SESSIONS_HIGH" {
					msg = fmt.Sprintf("Session count is %d (threshold: %d)", int(chk.current), int(resolved.Threshold))
				}
				alert := models.Alert{
					Timestamp:    now,
					DeviceID:     status.DeviceID,
					AlertType:    chk.alertType,
					Severity:     resolved.Severity,
					Message:      msg,
					MetricName:   chk.metric,
					Threshold:    resolved.Threshold,
					CurrentValue: chk.current,
					PolicyID:     resolved.PolicyID,
					Suppressed:   resolved.InMaintenance,
				}
				am.lastAlert[chk.metricKey] = now
				am.activeAlerts[chk.metricKey] = true
				fired = append(fired, firedEntry{alert, resolved})
			}
		}
	}
	am.mu.Unlock()

	for i := range fired {
		am.saveAlert(&fired[i].alert)
		if !fired[i].alert.Suppressed {
			nc := BuildNotifyConfigFromResolved(fired[i].resolved, globalNC)
			if err := am.notifier.SendAlert(&fired[i].alert, nc); err != nil {
				log.Printf("Failed to send alert %s: %v", fired[i].alert.AlertType, err)
			}
		}
	}

	// Recovery checks — batch resolve under one lock, skip if in maintenance
	am.mu.Lock()
	type recoveryCheck struct {
		metricCheck
		resolved ResolvedAlertConfig
	}
	recoveryChecks := make([]recoveryCheck, len(checks))
	for i, chk := range checks {
		recoveryChecks[i] = recoveryCheck{chk, am.resolveAlertConfig(status.DeviceID, siteID, chk.alertType)}
	}
	am.mu.Unlock()

	for _, rc := range recoveryChecks {
		if rc.resolved.InMaintenance {
			continue
		}
		if rc.resolved.Threshold > 0 && rc.current < rc.resolved.Threshold {
			am.sendRecovery(rc.metricKey, rc.alertType,
				fmt.Sprintf("%s recovered to %.1f", rc.metric, rc.current), status.DeviceID)
		}
	}

	return nil
}

func (am *AlertManager) CheckInterfaceStatus(interfaces []models.InterfaceStats, siteID *uint) error {
	var fired []firedEntry

	am.mu.Lock()
	now := time.Now()
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)

	for _, iface := range interfaces {
		if iface.Status != "down" || iface.AdminStatus != "up" {
			continue
		}
		resolved := am.resolveAlertConfig(iface.DeviceID, siteID, "INTERFACE_DOWN")
		if !resolved.AlertEnabled {
			continue
		}
		// Also check legacy toggle when no policy rule disables it
		if !am.config.Alerts.InterfaceDownAlert && !am.policyCache.loaded {
			continue
		}
		key := fmt.Sprintf("iface_down_%d_%s", iface.DeviceID, iface.Name)
		cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
		if am.canAlertWithCooldown(key, now, cooldown) {
			alert := models.Alert{
				Timestamp:    now,
				DeviceID:     iface.DeviceID,
				AlertType:    "INTERFACE_DOWN",
				Severity:     resolved.Severity,
				Message:      fmt.Sprintf("Interface %s is down", iface.Name),
				MetricName:   fmt.Sprintf("interface_%s", iface.Name),
				CurrentValue: 0,
				PolicyID:     resolved.PolicyID,
				Suppressed:   resolved.InMaintenance,
			}
			am.lastAlert[key] = now
			am.activeAlerts[key] = true
			fired = append(fired, firedEntry{alert, resolved})
		}
	}
	am.mu.Unlock()

	for i := range fired {
		am.saveAlert(&fired[i].alert)
		if !fired[i].alert.Suppressed {
			nc := BuildNotifyConfigFromResolved(fired[i].resolved, globalNC)
			if err := am.notifier.SendAlert(&fired[i].alert, nc); err != nil {
				log.Printf("Failed to send interface alert %s: %v", fired[i].alert.AlertType, err)
			}
		}
	}

	// Recovery: interfaces that are now up
	for _, iface := range interfaces {
		if iface.Status == "up" {
			key := fmt.Sprintf("iface_down_%d_%s", iface.DeviceID, iface.Name)
			am.sendRecovery(key, "INTERFACE_DOWN", fmt.Sprintf("Interface %s is back up", iface.Name), iface.DeviceID)
		}
	}

	return nil
}

func (am *AlertManager) ProcessTrap(trap *models.TrapEvent, siteID *uint) error {
	if trap.Severity != "critical" && trap.Severity != "warning" {
		return nil
	}

	key := fmt.Sprintf("trap_%s_%s", trap.TrapType, trap.SourceIP)

	am.mu.Lock()
	now := time.Now()
	resolved := am.resolveAlertConfig(trap.DeviceID, siteID, trap.TrapType)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	canSend := am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.lastAlert[key] = now
	}
	am.mu.Unlock()

	if !canSend || !resolved.AlertEnabled {
		return nil
	}

	alert := models.Alert{
		Timestamp:  trap.Timestamp,
		DeviceID:   trap.DeviceID,
		AlertType:  trap.TrapType,
		Severity:   trap.Severity,
		Message:    trap.Message,
		MetricName: "snmp_trap",
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notifier.SendAlert(&alert, nc); err != nil {
			return fmt.Errorf("failed to send trap alert: %w", err)
		}
	}

	return nil
}

// CheckInterfaceErrors alerts when interfaces accumulate errors or discards since last poll.
// prevMap maps "deviceID_ifName" to the previous InterfaceStats for delta computation.
func (am *AlertManager) CheckInterfaceErrors(interfaces []models.InterfaceStats, prevMap map[string]*models.InterfaceStats, siteID *uint) error {
	var fired []firedEntry

	am.mu.Lock()
	now := time.Now()
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)

	for _, iface := range interfaces {
		if iface.Status != "up" || iface.AdminStatus != "up" {
			continue
		}
		mapKey := fmt.Sprintf("%d_%s", iface.DeviceID, iface.Name)
		prev, ok := prevMap[mapKey]
		if !ok {
			continue
		}

		var errorDelta uint64
		totalErrors := iface.InErrors + iface.OutErrors + iface.InDiscards + iface.OutDiscards
		prevTotalErrors := prev.InErrors + prev.OutErrors + prev.InDiscards + prev.OutDiscards
		if totalErrors >= prevTotalErrors {
			errorDelta = totalErrors - prevTotalErrors
		}

		if errorDelta > 0 {
			resolved := am.resolveAlertConfig(iface.DeviceID, siteID, "INTERFACE_ERRORS")
			if !resolved.AlertEnabled {
				continue
			}
			alertKey := fmt.Sprintf("iface_errors_%d_%s", iface.DeviceID, iface.Name)
			cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
			if am.canAlertWithCooldown(alertKey, now, cooldown) {
				alert := models.Alert{
					Timestamp:    now,
					DeviceID:     iface.DeviceID,
					AlertType:    "INTERFACE_ERRORS",
					Severity:     resolved.Severity,
					Message:      fmt.Sprintf("Interface %s has %d new errors/discards (in_err: %d, out_err: %d, in_disc: %d, out_disc: %d)", iface.Name, errorDelta, iface.InErrors-prev.InErrors, iface.OutErrors-prev.OutErrors, iface.InDiscards-prev.InDiscards, iface.OutDiscards-prev.OutDiscards),
					MetricName:   fmt.Sprintf("interface_errors_%s", iface.Name),
					CurrentValue: float64(errorDelta),
					PolicyID:     resolved.PolicyID,
					Suppressed:   resolved.InMaintenance,
				}
				am.lastAlert[alertKey] = now
				fired = append(fired, firedEntry{alert, resolved})
			}
		}
	}
	am.mu.Unlock()

	for i := range fired {
		am.saveAlert(&fired[i].alert)
		if !fired[i].alert.Suppressed {
			nc := BuildNotifyConfigFromResolved(fired[i].resolved, globalNC)
			if err := am.notifier.SendAlert(&fired[i].alert, nc); err != nil {
				log.Printf("Failed to send interface error alert: %v", err)
			}
		}
	}
	return nil
}

// ProcessSyslog creates an alert from critical syslog messages (severity 0-2: Emergency/Alert/Critical).
func (am *AlertManager) ProcessSyslog(msg *models.SyslogMessage, siteID *uint) error {
	if msg.Severity > 2 {
		return nil
	}

	severityNames := map[int]string{0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL"}
	sevName := severityNames[msg.Severity]
	alertType := "SYSLOG_" + sevName

	key := fmt.Sprintf("syslog_%d_%s_%d", msg.DeviceID, msg.AppName, msg.Severity)

	am.mu.Lock()
	now := time.Now()
	resolved := am.resolveAlertConfig(msg.DeviceID, siteID, alertType)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	canSend := am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.lastAlert[key] = now
	}
	am.mu.Unlock()

	if !canSend || !resolved.AlertEnabled {
		return nil
	}

	alert := models.Alert{
		Timestamp:  msg.Timestamp,
		DeviceID:   msg.DeviceID,
		AlertType:  alertType,
		Severity:   resolved.Severity,
		Message:    fmt.Sprintf("[%s] %s: %s", sevName, msg.Hostname, msg.Message),
		MetricName: "syslog",
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notifier.SendAlert(&alert, nc); err != nil {
			return fmt.Errorf("failed to send syslog alert: %w", err)
		}
	}
	return nil
}

func (am *AlertManager) canAlert(key string, now time.Time) bool {
	if lastTime, exists := am.lastAlert[key]; exists {
		return now.Sub(lastTime) > am.alertCooldown
	}
	return true
}

// canAlertWithCooldown is like canAlert but uses a specific cooldown duration.
func (am *AlertManager) canAlertWithCooldown(key string, now time.Time, cooldown time.Duration) bool {
	if lastTime, exists := am.lastAlert[key]; exists {
		return now.Sub(lastTime) > cooldown
	}
	return true
}

// PruneExpiredCooldowns removes expired cooldown entries to prevent unbounded map growth.
func (am *AlertManager) PruneExpiredCooldowns() {
	am.mu.Lock()
	defer am.mu.Unlock()
	now := time.Now()
	for key, lastTime := range am.lastAlert {
		if now.Sub(lastTime) > am.alertCooldown*2 {
			delete(am.lastAlert, key)
		}
	}
}

// RefreshThresholds reads alert threshold settings from the database and updates
// the running config. This ensures admin UI changes take effect without restart.
func (am *AlertManager) RefreshThresholds(db *gorm.DB) {
	if db == nil {
		return
	}

	// Refresh policy cache alongside thresholds
	am.RefreshPolicyCache(am.db)

	var settings []models.SystemSetting
	if err := db.Where("\"key\" IN ?", []string{
		"cpu_threshold", "memory_threshold", "disk_threshold", "session_threshold",
		"email_enabled", "smtp_host", "smtp_port", "smtp_username", "smtp_password",
		"smtp_from", "smtp_to", "slack_webhook", "discord_webhook", "webhook_url",
		"report_daily_enabled", "report_daily_time", "report_weekly_enabled",
		"report_weekly_day", "report_recipients", "report_timezone",
		"spike_stddev_threshold", "spike_alert_enabled",
	}).Find(&settings).Error; err != nil {
		log.Printf("RefreshThresholds: failed to read settings: %v", err)
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	for _, s := range settings {
		if s.Value == "" {
			continue
		}
		switch s.Key {
		case "cpu_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				am.config.Alerts.CPUThreshold = v
			}
		case "memory_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				am.config.Alerts.MemoryThreshold = v
			}
		case "disk_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				am.config.Alerts.DiskThreshold = v
			}
		case "session_threshold":
			if v, err := strconv.Atoi(s.Value); err == nil && v > 0 {
				am.config.Alerts.SessionThreshold = v
			}
		case "email_enabled":
			am.config.Alerts.EmailEnabled = s.Value == "true"
		case "smtp_host":
			am.config.Alerts.SMTPHost = s.Value
		case "smtp_port":
			if v, err := strconv.Atoi(s.Value); err == nil && v > 0 {
				am.config.Alerts.SMTPPort = v
			}
		case "smtp_username":
			am.config.Alerts.SMTPUsername = s.Value
		case "smtp_password":
			am.config.Alerts.SMTPPassword = s.Value
		case "smtp_from":
			am.config.Alerts.SMTPFrom = s.Value
		case "smtp_to":
			am.config.Alerts.SMTPTo = s.Value
		case "slack_webhook":
			am.config.Alerts.SlackWebhookURL = s.Value
		case "discord_webhook":
			am.config.Alerts.DiscordWebhookURL = s.Value
		case "webhook_url":
			am.config.Alerts.WebHookURL = s.Value
		case "report_daily_enabled":
			am.config.Alerts.ReportDailyEnabled = s.Value == "true"
		case "report_daily_time":
			am.config.Alerts.ReportDailyTime = s.Value
		case "report_weekly_enabled":
			am.config.Alerts.ReportWeeklyEnabled = s.Value == "true"
		case "report_weekly_day":
			am.config.Alerts.ReportWeeklyDay = s.Value
		case "report_recipients":
			am.config.Alerts.ReportRecipients = s.Value
		case "report_timezone":
			am.config.Alerts.ReportTimezone = s.Value
		case "spike_stddev_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				am.config.Alerts.SpikeStdDevThreshold = v
			}
		case "spike_alert_enabled":
			am.config.Alerts.SpikeAlertEnabled = s.Value == "true"
		}
	}
}

func (am *AlertManager) SetCooldown(duration time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alertCooldown = duration
}

// sendRecovery sends a resolved notification if the given key was previously active.
// Must NOT be called with am.mu held — it acquires the lock internally.
func (am *AlertManager) sendRecovery(key, alertType, message string, deviceID uint) {
	am.mu.Lock()
	wasActive := am.activeAlerts[key]
	if wasActive {
		delete(am.activeAlerts, key)
	}
	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	if !wasActive {
		return
	}

	// Set ResolvedAt on unresolved alerts of this type for this device
	if am.db != nil {
		now := time.Now()
		am.db.Gorm().Model(&models.Alert{}).
			Where("device_id = ? AND alert_type = ? AND resolved_at IS NULL AND acknowledged = ?", deviceID, alertType, false).
			Update("resolved_at", now)
	}

	alert := models.Alert{
		Timestamp:  time.Now(),
		DeviceID:   deviceID,
		AlertType:  alertType + "_RESOLVED",
		Severity:   "info",
		Message:    message,
		MetricName: "recovery",
	}
	am.saveAlert(&alert)
	if err := am.notifier.SendAlert(&alert, nc); err != nil {
		log.Printf("Failed to send recovery notification: %v", err)
	}
}

func (am *AlertManager) saveAlert(alert *models.Alert) {
	if am.db == nil {
		return
	}
	if err := am.db.SaveAlert(alert); err != nil {
		log.Printf("Failed to persist alert %s: %v", alert.AlertType, err)
	}
}

func (am *AlertManager) CheckVPNStatus(vpnStatuses []models.VPNStatus, siteID *uint) error {
	var fired []firedEntry

	am.mu.Lock()
	now := time.Now()
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	for _, vpn := range vpnStatuses {
		if vpn.Status != "down" {
			continue
		}
		resolved := am.resolveAlertConfig(vpn.DeviceID, siteID, "VPN_TUNNEL_DOWN")
		if !resolved.AlertEnabled {
			continue
		}
		key := fmt.Sprintf("vpn_down_%d_%s", vpn.DeviceID, vpn.TunnelName)
		cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
		if am.canAlertWithCooldown(key, now, cooldown) {
			alert := models.Alert{
				Timestamp:  now,
				DeviceID:   vpn.DeviceID,
				AlertType:  "VPN_TUNNEL_DOWN",
				Severity:   resolved.Severity,
				Message:    fmt.Sprintf("VPN tunnel %s to %s is down", vpn.TunnelName, vpn.RemoteIP),
				MetricName: fmt.Sprintf("vpn_%s", vpn.TunnelName),
				PolicyID:   resolved.PolicyID,
				Suppressed: resolved.InMaintenance,
			}
			am.lastAlert[key] = now
			am.activeAlerts[key] = true
			fired = append(fired, firedEntry{alert, resolved})
		}
	}
	am.mu.Unlock()

	for i := range fired {
		am.saveAlert(&fired[i].alert)
		if !fired[i].alert.Suppressed {
			nc := BuildNotifyConfigFromResolved(fired[i].resolved, globalNC)
			if err := am.notifier.SendAlert(&fired[i].alert, nc); err != nil {
				log.Printf("Failed to send VPN alert: %v", err)
			}
		}
	}

	// Recovery: VPN tunnels that are now up
	for _, vpn := range vpnStatuses {
		if vpn.Status == "up" {
			key := fmt.Sprintf("vpn_down_%d_%s", vpn.DeviceID, vpn.TunnelName)
			am.sendRecovery(key, "VPN_TUNNEL_DOWN",
				fmt.Sprintf("VPN tunnel %s to %s is back up", vpn.TunnelName, vpn.RemoteIP), vpn.DeviceID)
		}
	}
	return nil
}

func (am *AlertManager) CheckDeviceOffline(device *models.Device) error {
	am.mu.Lock()
	now := time.Now()
	key := fmt.Sprintf("device_offline_%d", device.ID)
	resolved := am.resolveAlertConfig(device.ID, device.SiteID, "DEVICE_OFFLINE")
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	canSend := am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.lastAlert[key] = now
		am.activeAlerts[key] = true
	}
	am.mu.Unlock()

	if !canSend || !resolved.AlertEnabled {
		return nil
	}

	alert := models.Alert{
		Timestamp:  now,
		DeviceID:   device.ID,
		AlertType:  "DEVICE_OFFLINE",
		Severity:   resolved.Severity,
		Message:    fmt.Sprintf("Device %s (%s) is offline", device.Name, device.IPAddress),
		MetricName: "device_status",
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notifier.SendAlert(&alert, nc); err != nil {
			log.Printf("Failed to send device offline alert: %v", err)
		}
	}
	return nil
}

// CheckDeviceOnline sends a recovery notification if the device was previously marked offline.
func (am *AlertManager) CheckDeviceOnline(device *models.Device) {
	key := fmt.Sprintf("device_offline_%d", device.ID)
	am.sendRecovery(key, "DEVICE_OFFLINE",
		fmt.Sprintf("Device %s (%s) is back online", device.Name, device.IPAddress), device.ID)
}

// CheckEscalations scans unacknowledged alerts and re-sends notifications
// for those that have exceeded their escalation interval.
func (am *AlertManager) CheckEscalations() {
	if am.db == nil {
		return
	}

	am.mu.Lock()
	if !am.policyCache.loaded {
		am.mu.Unlock()
		return
	}

	// Collect policies with escalation enabled
	escalationPolicies := make(map[uint]*models.AlertPolicy)
	for i := range am.policyCache.policies {
		p := &am.policyCache.policies[i]
		if p.EscalationEnabled && p.EscalationMinutes > 0 {
			escalationPolicies[p.ID] = p
		}
	}
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	if len(escalationPolicies) == 0 {
		return
	}

	// Find unacknowledged, non-suppressed alerts
	cutoff := time.Now().Add(-24 * time.Hour) // only look at last 24h
	alerts, err := am.db.GetUnacknowledgedAlerts(cutoff)
	if err != nil {
		log.Printf("CheckEscalations: failed to get alerts: %v", err)
		return
	}

	for _, alert := range alerts {
		if alert.PolicyID == nil {
			continue
		}
		policy, ok := escalationPolicies[*alert.PolicyID]
		if !ok {
			continue
		}
		if alert.EscalationCount >= policy.EscalationRepeat {
			continue
		}
		// Check if enough time has passed since last escalation (or original alert)
		elapsed := time.Since(alert.Timestamp)
		expectedEscalations := int(elapsed.Minutes()) / policy.EscalationMinutes
		if expectedEscalations <= alert.EscalationCount {
			continue
		}

		// Re-send notification
		nc := notifier.NotifyConfig{
			PolicyActive:      true,
			EnableEmail:       policy.NotifyEmail,
			EnableSlack:       policy.NotifySlack,
			EnableDiscord:     policy.NotifyDiscord,
			EnableWebhook:     policy.NotifyWebhook,
			EmailEnabled:      globalNC.EmailEnabled,
			SMTPHost:          globalNC.SMTPHost,
			SMTPPort:          globalNC.SMTPPort,
			SMTPUsername:      globalNC.SMTPUsername,
			SMTPPassword:      globalNC.SMTPPassword,
			SMTPFrom:          globalNC.SMTPFrom,
			SMTPTo:            policy.EmailRecipients,
			SlackWebhookURL:   policy.SlackWebhookURL,
			DiscordWebhookURL: policy.DiscordWebhookURL,
			WebHookURL:        policy.WebhookURL,
		}
		if nc.SMTPTo == "" {
			nc.SMTPTo = globalNC.SMTPTo
		}
		if nc.SlackWebhookURL == "" {
			nc.SlackWebhookURL = globalNC.SlackWebhookURL
		}
		if nc.DiscordWebhookURL == "" {
			nc.DiscordWebhookURL = globalNC.DiscordWebhookURL
		}
		if nc.WebHookURL == "" {
			nc.WebHookURL = globalNC.WebHookURL
		}

		escalatedAlert := alert
		escalatedAlert.Message = fmt.Sprintf("[ESCALATION %d/%d] %s", alert.EscalationCount+1, policy.EscalationRepeat, alert.Message)

		if err := am.notifier.SendAlert(&escalatedAlert, nc); err != nil {
			log.Printf("CheckEscalations: failed to send escalation for alert %d: %v", alert.ID, err)
			continue
		}

		// Update escalation count
		am.db.Gorm().Model(&models.Alert{}).Where("id = ?", alert.ID).
			Update("escalation_count", alert.EscalationCount+1)
	}
}
