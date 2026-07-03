package alerts

import (
	"fmt"
	"log"
	"strconv"
	"strings"
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
	cooldownFor   map[string]time.Duration // L2: per-key effective cooldown, so prune evicts only past each key's OWN window
	activeAlerts  map[string]bool          // tracks currently-firing alert keys for recovery detection
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
		cooldownFor:   make(map[string]time.Duration),
		activeAlerts:  make(map[string]bool),
		alertCooldown: 5 * time.Minute,
	}
}

func (am *AlertManager) CheckSystemStatus(status *models.SystemStatus, siteID *uint) error {
	type metricCheck struct {
		alertType models.AlertType
		metricKey string
		metric    string
		current   float64
	}

	checks := []metricCheck{
		{models.AlertTypeCPUHigh, fmt.Sprintf("cpu_high_%d", status.DeviceID), "cpu_usage", status.CPUUsage},
		{models.AlertTypeMemoryHigh, fmt.Sprintf("memory_high_%d", status.DeviceID), "memory_usage", status.MemoryUsage},
		{models.AlertTypeDiskHigh, fmt.Sprintf("disk_high_%d", status.DeviceID), "disk_usage", status.DiskUsage},
		{models.AlertTypeSessionsHigh, fmt.Sprintf("sessions_high_%d", status.DeviceID), "session_count", float64(status.SessionCount)},
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
				if chk.alertType == models.AlertTypeSessionsHigh {
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
				am.recordCooldownLocked(chk.metricKey, now, cooldown)
				am.activeAlerts[chk.metricKey] = true
				fired = append(fired, firedEntry{alert, resolved})
			}
		}
	}
	am.mu.Unlock()

	am.dispatchFired(fired, globalNC, "system")

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
		// F14 hysteresis: with a ClearThreshold set (and sane — below the fire
		// threshold), recovery requires dropping below the CLEAR band, not just
		// under the fire threshold — a value hovering at the boundary stays in
		// the fired state instead of flapping. ClearThreshold=0 keeps the
		// legacy recover-at-threshold behavior bit-for-bit.
		recoverBelow := rc.resolved.Threshold
		if rc.resolved.ClearThreshold > 0 && rc.resolved.ClearThreshold < recoverBelow {
			recoverBelow = rc.resolved.ClearThreshold
		}
		if rc.resolved.Threshold > 0 && rc.current < recoverBelow {
			am.sendRecovery(rc.metricKey, rc.alertType, rc.metric,
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
			am.recordCooldownLocked(key, now, cooldown)
			am.activeAlerts[key] = true
			fired = append(fired, firedEntry{alert, resolved})
		}
	}
	am.mu.Unlock()

	am.dispatchFired(fired, globalNC, "interface")

	// Recovery: interfaces that are now up
	for _, iface := range interfaces {
		if iface.Status == "up" {
			key := fmt.Sprintf("iface_down_%d_%s", iface.DeviceID, iface.Name)
			am.sendRecovery(key, "INTERFACE_DOWN", fmt.Sprintf("interface_%s", iface.Name),
				fmt.Sprintf("Interface %s is back up", iface.Name), iface.DeviceID)
		}
	}

	return nil
}

// trapMetricName scopes a trap alert's MetricName to its source IP (M24), so a
// LINK_UP recovery resolves only the same source's LINK_DOWN, never another
// device's. Falls back to the bare "snmp_trap" when the source IP is unknown.
func trapMetricName(sourceIP string) string {
	if sourceIP == "" {
		return "snmp_trap"
	}
	return "snmp_trap_" + sourceIP
}

func (am *AlertManager) ProcessTrap(trap *models.TrapEvent, siteID *uint) error {
	// M24 of the 2026-07-01 audit: the direct trap-receiver pipeline never
	// populates trap.DeviceID (parseTrap doesn't resolve it), so EVERY direct
	// trap arrived with DeviceID=0 and MetricName="snmp_trap". A LINK_UP then
	// resolved WHERE device_id=0 AND metric_name='snmp_trap', which matched ALL
	// direct-trap LINK_DOWN alerts, so firewall B's LINK_UP silently closed
	// firewall A's still-open LINK_DOWN. Fix both: resolve the device from the
	// source IP (so per-device policies apply and device_id scopes recovery),
	// and scope the trap's MetricName by source IP as defense-in-depth for
	// traps from an unknown IP that stay DeviceID=0.
	if trap.DeviceID == 0 && trap.SourceIP != "" && am.db != nil {
		trap.DeviceID = am.db.ResolveDeviceByIP(trap.SourceIP)
	}
	metricName := trapMetricName(trap.SourceIP)

	// Handle LINK_UP as recovery for any active LINK_DOWN alert on this device
	if trap.TrapType == "LINK_UP" {
		key := fmt.Sprintf("trap_LINK_DOWN_%s", trap.SourceIP)
		am.sendRecovery(key, "LINK_DOWN", metricName, trap.Message, trap.DeviceID)
		return nil
	}

	if trap.Severity != "critical" && trap.Severity != "warning" {
		return nil
	}

	key := fmt.Sprintf("trap_%s_%s", trap.TrapType, trap.SourceIP)

	am.mu.Lock()
	now := time.Now()
	resolved := am.resolveAlertConfig(trap.DeviceID, siteID, models.AlertType(trap.TrapType))
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	canSend := am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if !canSend || !resolved.AlertEnabled {
		return nil
	}

	alert := models.Alert{
		Timestamp:  trap.Timestamp,
		DeviceID:   trap.DeviceID,
		AlertType:  models.AlertType(trap.TrapType),
		Severity:   models.Severity(trap.Severity),
		Message:    trap.Message,
		MetricName: metricName, // M24: source-scoped so LINK_UP recovery can't cross devices
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
				am.recordCooldownLocked(alertKey, now, cooldown)
				fired = append(fired, firedEntry{alert, resolved})
			}
		}
	}
	am.mu.Unlock()

	am.dispatchFired(fired, globalNC, "interface error")
	return nil
}

// ProcessSyslog creates an alert from critical syslog messages (severity 0-2: Emergency/Alert/Critical).
func (am *AlertManager) ProcessSyslog(msg *models.SyslogMessage, siteID *uint) error {
	if msg.Severity > 2 {
		return nil
	}

	severityNames := map[int]string{0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL"}
	sevName := severityNames[msg.Severity]
	alertType := models.AlertType("SYSLOG_" + sevName)

	key := fmt.Sprintf("syslog_%d_%s_%d", msg.DeviceID, msg.AppName, msg.Severity)

	am.mu.Lock()
	now := time.Now()
	resolved := am.resolveAlertConfig(msg.DeviceID, siteID, alertType)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	canSend := am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
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

// ProcessFlowDetection turns a persisted sFlow detection-engine finding into an
// alert, reusing the same cooldown / policy-resolution / notify machinery as
// ProcessSyslog and ProcessTrap. The AlertType is "SFLOW_" + the uppercased
// detector name (e.g. SFLOW_CLEARTEXT), so operators can tune these in alert
// policies like any other type. Observe-mode: the detector's own severity is
// honored (detectors ship at info/warning to avoid fatigue) rather than forcing
// the policy default. The detection is already persisted by the caller; this
// only handles alerting, so a suppressed/cooled-down finding still shows in the
// NOC's detections list.
func (am *AlertManager) ProcessFlowDetection(det *models.FlowDetection, siteID *uint) error {
	alertType := models.AlertType("SFLOW_" + strings.ToUpper(det.Detector))
	key := "flowdet_" + det.DedupKey

	am.mu.Lock()
	now := time.Now()
	resolved := am.resolveAlertConfig(det.DeviceID, siteID, alertType)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	canSend := am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if !canSend || !resolved.AlertEnabled {
		return nil
	}

	sev := models.Severity(det.Severity)
	if sev == "" {
		sev = resolved.Severity
	}

	alert := models.Alert{
		Timestamp:    det.DetectedAt,
		DeviceID:     det.DeviceID,
		AlertType:    alertType,
		Severity:     sev,
		Message:      det.Message,
		MetricName:   "sflow_" + det.Detector,
		CurrentValue: det.Score,
		PolicyID:     resolved.PolicyID,
		Suppressed:   resolved.InMaintenance,
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notifier.SendAlert(&alert, nc); err != nil {
			return fmt.Errorf("failed to send flow detection alert: %w", err)
		}
	}
	return nil
}

// canAlertWithCooldown reports whether the per-key cooldown has elapsed.
func (am *AlertManager) canAlertWithCooldown(key string, now time.Time, cooldown time.Duration) bool {
	if lastTime, exists := am.lastAlert[key]; exists {
		return now.Sub(lastTime) > cooldown
	}
	return true
}

// dbCooldownActive reports whether a still-open alert for the same
// (device, alertType, metric) already exists in the DB with a timestamp inside
// the cooldown window ending at ref. It backstops the in-memory cooldown across
// a process restart: AlertManager cooldown state (lastAlert/activeAlerts) lives
// only in memory, so after a poller/API restart every still-breaching condition
// would re-fire at once — a notification storm (one email/Slack/Discord/IRC per
// breaching condition, and a per-cycle storm under a crash-loop). Consulting the
// DB makes a restart transparent: the within-cooldown duplicate is suppressed,
// while the normal periodic reminder still fires once the window elapses (older
// open rows fall outside it). Only persistent STATE alerts (thresholds,
// interface/VPN down, device offline) are deduped here; event/transient alerts
// (traps, syslog, SSH host-key, config-change) fire on arrival and must not be
// collapsed. Queried only on the rare about-to-notify path, so it adds no cost
// to the common "condition healthy / within cooldown" cycles.
func (am *AlertManager) dbCooldownActive(deviceID uint, alertType models.AlertType, metricName string, ref time.Time, cooldown time.Duration) bool {
	if am.db == nil || cooldown <= 0 {
		return false
	}
	var cnt int64
	am.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NULL AND timestamp > ?",
			deviceID, alertType, metricName, ref.Add(-cooldown)).
		Count(&cnt)
	return cnt > 0
}

// maxLastAlertEntries hard-caps the in-memory cooldown map (M25 of the
// 2026-07-01 audit). PruneExpiredCooldowns bounds it in the poller (which runs
// a prune ticker), but the trap-receiver embeds its OWN AlertManager and never
// pruned, and its keys are "trap_<TYPE>_<sourceIP>" derived from SPOOFABLE
// source IPs, so a spoof-flood grew the map ~unbounded (hundreds of MB/day).
// This cap makes any embedding process safe by construction, independent of
// whether it runs the ticker.
const maxLastAlertEntries = 50000

// recordCooldownLocked records a cooldown timestamp for key, enforcing the
// map's size cap first. Caller holds am.mu. Replaces the raw
// `am.lastAlert[key] = now` writes so every cooldown-bearing alert path is
// bounded (M25).
func (am *AlertManager) recordCooldownLocked(key string, now time.Time, cooldown time.Duration) {
	if _, exists := am.lastAlert[key]; !exists && len(am.lastAlert) >= maxLastAlertEntries {
		// Adding a NEW key at the cap: prune expired entries first; if that
		// frees nothing (all still within cooldown), evict the oldest so the
		// map can never grow past the cap.
		am.pruneExpiredLocked(now)
		if len(am.lastAlert) >= maxLastAlertEntries {
			am.evictOldestLocked()
		}
	}
	am.lastAlert[key] = now
	// L2: remember this key's effective cooldown so prune respects it.
	if cooldown > 0 {
		am.cooldownFor[key] = cooldown
	}
}

// pruneExpiredLocked deletes cooldown entries past their OWN effective cooldown
// (L2 of the 2026-07-01 audit — the pre-fix fixed `alertCooldown*2` (10 min)
// threshold truncated any operator-set per-policy cooldown > 10 min, so the
// next detection re-alerted before the configured window elapsed). Keys with
// no recorded cooldown fall back to the base cooldown. Caller holds am.mu.
func (am *AlertManager) pruneExpiredLocked(now time.Time) {
	for key, lastTime := range am.lastAlert {
		cd := am.cooldownFor[key]
		if cd <= 0 {
			cd = am.alertCooldown
		}
		if now.Sub(lastTime) > cd {
			delete(am.lastAlert, key)
			delete(am.cooldownFor, key)
		}
	}
}

// evictOldestLocked removes the single oldest cooldown entry. Caller holds am.mu.
func (am *AlertManager) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, t := range am.lastAlert {
		if first || t.Before(oldestTime) {
			oldestKey, oldestTime, first = key, t, false
		}
	}
	if !first {
		delete(am.lastAlert, oldestKey)
		delete(am.cooldownFor, oldestKey)
	}
}

// PruneExpiredCooldowns removes expired cooldown entries to prevent unbounded map growth.
func (am *AlertManager) PruneExpiredCooldowns() {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.pruneExpiredLocked(time.Now())
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
		"spike_stddev_threshold", "spike_alert_enabled", "spike_min_duration_minutes",
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
			// v0.10.226: was assigning raw s.Value, which is "{enc}<base64>"
			// ciphertext for any password saved through the admin UI.
			// Result: every real alert email (CPU threshold, interface
			// down, VPN tunnel down, etc.) was sending ciphertext to the
			// SMTP server as the auth password, which never matched.
			// DecryptField is idempotent for unencrypted values, so this
			// is safe even when smtp_password was set via env var rather
			// than the admin UI.
			if am.db != nil {
				am.config.Alerts.SMTPPassword = am.db.DecryptField(s.Value)
			} else {
				am.config.Alerts.SMTPPassword = s.Value
			}
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
		case "spike_min_duration_minutes":
			if v, err := strconv.Atoi(s.Value); err == nil && v > 0 {
				am.config.Alerts.SpikeMinDurationMinutes = v
			}
		}
	}
}

func (am *AlertManager) SetCooldown(duration time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alertCooldown = duration
}

// sendRecovery auto-resolves the matching OPEN alert when a condition clears and,
// if the alert was active in this process, emits a recovery notification + companion
// _RESOLVED record. Must NOT be called with am.mu held — it acquires the lock internally.
//
// metricName scopes the resolution to the SPECIFIC resource that recovered (the value
// stored in Alert.MetricName, e.g. "interface_<name>", "vpn_<tunnel>", "device_status").
// Without it, a recovery for one interface would wrongly resolve every INTERFACE_DOWN
// alert on the device.
func (am *AlertManager) sendRecovery(key string, alertType models.AlertType, metricName, message string, deviceID uint) {
	am.mu.Lock()
	wasActive := am.activeAlerts[key]
	if wasActive {
		delete(am.activeAlerts, key)
	}
	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	// Always run the precisely-scoped DB resolve, independent of the in-memory
	// activeAlerts state. This is idempotent (the WHERE clause matches only OPEN,
	// unacknowledged rows) and survives a poller restart that lost activeAlerts —
	// an orphaned offline alert still auto-clears on the next recovery signal.
	//
	// We auto-ACKNOWLEDGE as well as resolve so the original alert leaves the NOC's
	// default open queue with zero manual clicks; resolved_at is retained for the
	// audit trail and the RESOLVED badge in the UI.
	//
	// AUDIT-144: also clear the snooze fields, so a snoozed alert that just resolved
	// doesn't linger in the "snoozed" view as if it were still active — when the
	// underlying issue clears, the recovery event unsnoozes it for the operator.
	if am.db != nil {
		now := time.Now()
		am.db.Gorm().Model(&models.Alert{}).
			Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NULL AND acknowledged = ?", deviceID, alertType, metricName, false).
			Updates(map[string]interface{}{
				"resolved_at":     now,
				"acknowledged":    true,
				"acknowledged_at": now,
				"notes":           "Auto-resolved: " + message,
				"snoozed_until":   nil,
				"snoozed_by":      "",
				"snoozed_reason":  "",
			})
	}

	// Only notify + record the companion when the alert was active in THIS process.
	// A cold resolve (post-restart, or a redundant per-poll up signal) clears the
	// ticket silently without re-sending a "back up" email.
	if !wasActive {
		return
	}

	now := time.Now()
	alert := models.Alert{
		Timestamp:      now,
		DeviceID:       deviceID,
		AlertType:      alertType + "_RESOLVED",
		Severity:       "info",
		Message:        message,
		MetricName:     "recovery",
		Acknowledged:   true,
		AcknowledgedAt: &now,
		ResolvedAt:     &now,
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

// dispatchFired persists each fired alert and sends it unless suppressed. The
// batch Check* methods collect alerts under am.mu and then call this AFTER
// releasing the lock, so the (potentially slow) notifier send never blocks other
// alert checks. label identifies the source in the send-failure log line.
func (am *AlertManager) dispatchFired(fired []firedEntry, globalNC notifier.NotifyConfig, label string) {
	for i := range fired {
		// Cross-restart dedup: skip the save+send if this state alert was already
		// raised (and is still open) within its cooldown window — see
		// dbCooldownActive. The in-memory cooldown set by the gate suppresses
		// duplicates only within this process; the DB check covers a restart.
		cooldown := time.Duration(fired[i].resolved.CooldownMinutes) * time.Minute
		if am.dbCooldownActive(fired[i].alert.DeviceID, fired[i].alert.AlertType, fired[i].alert.MetricName, fired[i].alert.Timestamp, cooldown) {
			continue
		}
		am.saveAlert(&fired[i].alert)
		if !fired[i].alert.Suppressed {
			nc := BuildNotifyConfigFromResolved(fired[i].resolved, globalNC)
			if err := am.notifier.SendAlert(&fired[i].alert, nc); err != nil {
				log.Printf("Failed to send %s alert %s: %v", label, fired[i].alert.AlertType, err)
			}
		}
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
			am.recordCooldownLocked(key, now, cooldown)
			am.activeAlerts[key] = true
			fired = append(fired, firedEntry{alert, resolved})
		}
	}
	am.mu.Unlock()

	am.dispatchFired(fired, globalNC, "VPN")

	// Recovery: VPN tunnels that are now up
	for _, vpn := range vpnStatuses {
		if vpn.Status == "up" {
			key := fmt.Sprintf("vpn_down_%d_%s", vpn.DeviceID, vpn.TunnelName)
			am.sendRecovery(key, "VPN_TUNNEL_DOWN", fmt.Sprintf("vpn_%s", vpn.TunnelName),
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
		am.recordCooldownLocked(key, now, cooldown)
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

	// Cross-restart dedup (see dbCooldownActive): DEVICE_OFFLINE is the canonical
	// persistent-state alert — without this, a poller restart re-pages for every
	// device still offline. The in-memory gate above already set lastAlert[key]
	// (reusing its cooldown here), so this DB check only gates the first
	// post-restart fire.
	if am.dbCooldownActive(device.ID, "DEVICE_OFFLINE", "device_status", now, cooldown) {
		return nil
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
	am.sendRecovery(key, "DEVICE_OFFLINE", "device_status",
		fmt.Sprintf("Device %s (%s) is back online", device.Name, device.IPAddress), device.ID)
}

// CheckSSHHostKeyChanged fires a CRITICAL alert when a device's reported SSH
// host-key fingerprint differs from the one previously pinned. It is a
// transient, point-in-time alert (cooldown-gated, no recovery state): the caller
// re-pins the new fingerprint after this returns, so it fires once per change.
// oldFP/newFP are SSH host-key fingerprints (e.g. "SHA256:...").
func (am *AlertManager) CheckSSHHostKeyChanged(device *models.Device, newFP string, haFailover bool) error {
	am.mu.Lock()
	now := time.Now()
	// Cooldown keyed per (device, fingerprint) so each distinct new key alerts
	// once even if several appear in quick succession.
	key := fmt.Sprintf("ssh_host_key_%d_%s", device.ID, newFP)
	resolved := am.resolveAlertConfig(device.ID, device.SiteID, "SSH_HOST_KEY_CHANGED")
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	canSend := am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if !canSend || !resolved.AlertEnabled {
		return nil
	}

	// A new key that correlates with a recent HA failover is an expected event
	// (cluster members present distinct host keys) — WARNING, not CRITICAL.
	severity := resolved.Severity
	message := fmt.Sprintf("SSH host key changed for device %s (%s): new fingerprint %s, with no matching HA failover. If this was not a planned change, treat the device admin credentials as exposed and rotate them.", device.Name, device.IPAddress, newFP)
	if haFailover {
		severity = "warning"
		message = fmt.Sprintf("New SSH host key %s observed for device %s (%s), correlated with a recent HA failover — learned as a known cluster-member key.", newFP, device.Name, device.IPAddress)
	}

	alert := models.Alert{
		Timestamp:  now,
		DeviceID:   device.ID,
		AlertType:  "SSH_HOST_KEY_CHANGED",
		Severity:   severity,
		Message:    message,
		MetricName: "ssh_host_key",
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notifier.SendAlert(&alert, nc); err != nil {
			log.Printf("Failed to send SSH host-key change alert: %v", err)
		}
	}
	return nil
}

// ConfigChangeInfo carries the semantic classification and attribution of a
// detected config change so the CONFIG_CHANGE alert can be severity-driven and
// accountable. All fields are optional — a zero value reproduces the legacy
// always-"warning", checksum-only alert. Severity uses the configdiff scale
// (info|medium|high|critical); the alerts layer maps it to info|warning|critical
// without importing configdiff.
type ConfigChangeInfo struct {
	Severity   string // configdiff severity of the most significant change
	Impact     string // human-readable "security impact" summary
	ChangedBy  string // admin user, if attributed
	Method     string // GUI | CLI(ssh) | jsconsole | API
	Attributed bool   // a matching authenticated session was found
}

// CheckConfigRevision creates a CONFIG_CHANGE alert when the config checksum
// differs from the previous. The alert severity reflects the security impact of
// the change, and the message reports who made it (or flags it as a possible
// out-of-band change when no authenticated session was found).
func (am *AlertManager) CheckConfigRevision(deviceID uint, oldChecksum, newChecksum string, info ConfigChangeInfo) {
	if am.db == nil {
		return
	}
	device, err := am.db.GetDevice(deviceID)
	if err != nil {
		return
	}
	key := fmt.Sprintf("config_change_%d", deviceID)
	cooldown := 60 * time.Minute

	am.mu.Lock()
	now := time.Now()
	canSend := am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if !canSend {
		return
	}

	oldShort, newShort := oldChecksum, newChecksum
	if len(oldChecksum) >= 8 {
		oldShort = oldChecksum[:8]
	}
	if len(newChecksum) >= 8 {
		newShort = newChecksum[:8]
	}

	severity := configSeverityToAlert(info.Severity)
	who := "unknown user"
	if info.ChangedBy != "" {
		who = info.ChangedBy
		if info.Method != "" {
			who += " via " + info.Method
		}
	}
	msg := fmt.Sprintf("Config change detected on %s by %s (checksum %s → %s)", device.Name, who, oldShort, newShort)
	if info.Impact != "" {
		msg += ". Impact: " + info.Impact
	}
	if !info.Attributed {
		// No authenticated admin session matched this change — escalate one notch
		// and flag it as a possible out-of-band / unauthorized change.
		severity = escalateSeverity(severity)
		msg += " [no authenticated admin session found — possible out-of-band change]"
	}

	am.saveAlert(&models.Alert{
		DeviceID:  deviceID,
		AlertType: "CONFIG_CHANGE",
		Severity:  severity,
		Message:   msg,
		Timestamp: time.Now(),
	})
}

// configSeverityToAlert maps a configdiff severity onto the alert vocabulary
// (info | warning | critical). Empty/unknown defaults to "warning" to preserve
// the legacy behavior.
func configSeverityToAlert(sev string) models.Severity {
	switch sev {
	case "info":
		return "info"
	case "high", "critical":
		return "critical"
	case "medium", "":
		return "warning"
	default:
		return "warning"
	}
}

// escalateSeverity bumps an alert severity one notch toward critical.
func escalateSeverity(sev models.Severity) models.Severity {
	switch sev {
	case "info":
		return "warning"
	default:
		return "critical"
	}
}

// CheckProbeDataFlow checks all approved probes and alerts if any have not sent
// data within the configured threshold (PROBE_DATA_LAG_ALERT_MINUTES).
// This catches issues like queue full, network problems, or systematic data loss
// that wouldn't be caught by heartbeat-based DEVICE_OFFLINE alerts.
func (am *AlertManager) CheckProbeDataFlow() error {
	if am.db == nil || am.config.Alerts.ProbeDataLagAlertMinutes <= 0 {
		return nil
	}

	probes, err := am.db.GetApprovedProbes()
	if err != nil {
		return fmt.Errorf("failed to get approved probes: %w", err)
	}

	now := time.Now()
	lagThreshold := time.Duration(am.config.Alerts.ProbeDataLagAlertMinutes) * time.Minute
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)

	for _, probe := range probes {
		// M28 of the 2026-07-01 audit: DecommissionProbe deliberately keeps
		// approval_status='approved' (telemetry attribution), so
		// GetApprovedProbes still returns retired probes — whose
		// LastDataReceived is frozen by design. Without this skip, the
		// documented soft-decommission path produced a PROBE_DATA_LAG alert
		// on every cooldown expiry, forever.
		if probe.DecommissionedAt != nil || !probe.Enabled {
			continue
		}
		if probe.LastDataReceived.IsZero() {
			continue
		}

		lag := now.Sub(probe.LastDataReceived)
		if lag < lagThreshold {
			key := fmt.Sprintf("probe_data_lag_%d", probe.ID)
			am.sendRecovery(key, "PROBE_DATA_LAG", "probe_data_flow",
				fmt.Sprintf("Probe %s is receiving data again (lag cleared)", probe.Name), 0)
			continue
		}

		key := fmt.Sprintf("probe_data_lag_%d", probe.ID)

		// Resolve config, check the cooldown, and record the firing state all
		// under am.mu — these read policyCache and the lastAlert/activeAlerts
		// maps, which other goroutines mutate. This block previously ran
		// unlocked, a latent data race with concurrent alert checks.
		am.mu.Lock()
		resolved := am.resolveAlertConfig(0, &probe.SiteID, "PROBE_DATA_LAG")
		cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
		canSend := resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
		if canSend {
			am.recordCooldownLocked(key, now, cooldown)
			am.activeAlerts[key] = true
		}
		am.mu.Unlock()
		if !canSend {
			continue
		}

		alert := models.Alert{
			Timestamp:  now,
			AlertType:  "PROBE_DATA_LAG",
			Severity:   resolved.Severity,
			Message:    fmt.Sprintf("Probe %s has not received data for %v (threshold: %d min)", probe.Name, lag.Round(time.Minute), am.config.Alerts.ProbeDataLagAlertMinutes),
			MetricName: "probe_data_flow",
			PolicyID:   resolved.PolicyID,
			Suppressed: resolved.InMaintenance,
			ProbeID:    &probe.ID,
		}

		am.saveAlert(&alert)
		if !alert.Suppressed {
			nc := BuildNotifyConfigFromResolved(resolved, globalNC)
			if err := am.notifier.SendAlert(&alert, nc); err != nil {
				log.Printf("Failed to send probe data lag alert: %v", err)
			}
		}
	}

	return nil
}

// CheckProbeDataTruncation should be called when a data batch is truncated.
// It flags the probe for monitoring - frequent truncation may indicate misconfiguration.
func (am *AlertManager) RecordProbeDataTruncation(probeID uint, probeName string, totalItems, retainedItems int) {
	if am.db == nil {
		return
	}

	key := fmt.Sprintf("probe_truncation_%d", probeID)
	now := time.Now()

	am.mu.Lock()
	lastTruncation := am.lastAlert[key]
	am.mu.Unlock()

	// Only alert if truncation happened recently (within 5 minutes) to avoid spam
	if lastTruncation.IsZero() || now.Sub(lastTruncation) > 5*time.Minute {
		return
	}

	nc := notifier.SnapshotConfig(&am.config.Alerts)

	alert := models.Alert{
		Timestamp:  now,
		AlertType:  "PROBE_DATA_TRUNCATED",
		Severity:   "warning",
		Message:    fmt.Sprintf("Probe %s sent batch of %d items, kept %d (truncated %d) — possible misconfiguration", probeName, totalItems, retainedItems, totalItems-retainedItems),
		MetricName: "probe_data_truncation",
		ProbeID:    &probeID,
	}

	am.saveAlert(&alert)
	if err := am.notifier.SendAlert(&alert, nc); err != nil {
		log.Printf("Failed to send probe truncation alert: %v", err)
	}
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

	// Collect escalated alert IDs for batch update
	type escalated struct {
		id       uint
		newCount int
	}
	var escalatedIDs []escalated

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
		elapsed := time.Since(alert.Timestamp)
		expectedEscalations := int(elapsed.Minutes()) / policy.EscalationMinutes
		if expectedEscalations <= alert.EscalationCount {
			continue
		}

		nc := BuildNotifyConfigFromResolved(ResolvedAlertConfig{
			PolicyID:        alert.PolicyID,
			NotifyEmail:     policy.NotifyEmail,
			NotifySlack:     policy.NotifySlack,
			NotifyDiscord:   policy.NotifyDiscord,
			NotifyWebhook:   policy.NotifyWebhook,
			EmailRecipients: policy.EmailRecipients,
			SlackURL:        policy.SlackWebhookURL,
			DiscordURL:      policy.DiscordWebhookURL,
			WebhookURL:      policy.WebhookURL,
		}, globalNC)

		escalatedAlert := alert
		escalatedAlert.Message = fmt.Sprintf("[ESCALATION %d/%d] %s", alert.EscalationCount+1, policy.EscalationRepeat, alert.Message)

		if err := am.notifier.SendAlert(&escalatedAlert, nc); err != nil {
			log.Printf("CheckEscalations: failed to send escalation for alert %d: %v", alert.ID, err)
			continue
		}

		escalatedIDs = append(escalatedIDs, escalated{alert.ID, alert.EscalationCount + 1})
	}

	// Batch update escalation counts
	for _, e := range escalatedIDs {
		am.db.Gorm().Model(&models.Alert{}).Where("id = ?", e.id).
			Update("escalation_count", e.newCount)
	}
}
