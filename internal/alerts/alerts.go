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

func (am *AlertManager) CheckSystemStatus(status *models.SystemStatus) error {
	var fired []models.Alert

	cpuKey := fmt.Sprintf("cpu_high_%d", status.DeviceID)
	memKey := fmt.Sprintf("memory_high_%d", status.DeviceID)
	diskKey := fmt.Sprintf("disk_high_%d", status.DeviceID)
	sessKey := fmt.Sprintf("sessions_high_%d", status.DeviceID)

	am.mu.Lock()
	now := time.Now()

	if status.CPUUsage >= am.config.Alerts.CPUThreshold {
		if a := am.checkThreshold(now, status.DeviceID, cpuKey, "CPU_HIGH", "warning",
			fmt.Sprintf("CPU usage is %.1f%% (threshold: %.1f%%)", status.CPUUsage, am.config.Alerts.CPUThreshold),
			"cpu_usage", status.CPUUsage, am.config.Alerts.CPUThreshold); a != nil {
			fired = append(fired, *a)
			am.activeAlerts[cpuKey] = true
		}
	}

	if status.MemoryUsage >= am.config.Alerts.MemoryThreshold {
		if a := am.checkThreshold(now, status.DeviceID, memKey, "MEMORY_HIGH", "warning",
			fmt.Sprintf("Memory usage is %.1f%% (threshold: %.1f%%)", status.MemoryUsage, am.config.Alerts.MemoryThreshold),
			"memory_usage", status.MemoryUsage, am.config.Alerts.MemoryThreshold); a != nil {
			fired = append(fired, *a)
			am.activeAlerts[memKey] = true
		}
	}

	if status.DiskUsage >= am.config.Alerts.DiskThreshold {
		if a := am.checkThreshold(now, status.DeviceID, diskKey, "DISK_HIGH", "critical",
			fmt.Sprintf("Disk usage is %.1f%% (threshold: %.1f%%)", status.DiskUsage, am.config.Alerts.DiskThreshold),
			"disk_usage", status.DiskUsage, am.config.Alerts.DiskThreshold); a != nil {
			fired = append(fired, *a)
			am.activeAlerts[diskKey] = true
		}
	}

	if status.SessionCount >= am.config.Alerts.SessionThreshold {
		if a := am.checkThreshold(now, status.DeviceID, sessKey, "SESSIONS_HIGH", "warning",
			fmt.Sprintf("Session count is %d (threshold: %d)", status.SessionCount, am.config.Alerts.SessionThreshold),
			"session_count", float64(status.SessionCount), float64(am.config.Alerts.SessionThreshold)); a != nil {
			fired = append(fired, *a)
			am.activeAlerts[sessKey] = true
		}
	}

	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	for i := range fired {
		am.saveAlert(&fired[i])
		if err := am.notifier.SendAlert(&fired[i], nc); err != nil {
			log.Printf("Failed to send alert %s: %v", fired[i].AlertType, err)
		}
	}

	// Recovery checks — send resolved if condition cleared
	if status.CPUUsage < am.config.Alerts.CPUThreshold {
		am.sendRecovery(cpuKey, "CPU_HIGH", fmt.Sprintf("CPU usage recovered to %.1f%%", status.CPUUsage), status.DeviceID)
	}
	if status.MemoryUsage < am.config.Alerts.MemoryThreshold {
		am.sendRecovery(memKey, "MEMORY_HIGH", fmt.Sprintf("Memory usage recovered to %.1f%%", status.MemoryUsage), status.DeviceID)
	}
	if status.DiskUsage < am.config.Alerts.DiskThreshold {
		am.sendRecovery(diskKey, "DISK_HIGH", fmt.Sprintf("Disk usage recovered to %.1f%%", status.DiskUsage), status.DeviceID)
	}
	if status.SessionCount < am.config.Alerts.SessionThreshold {
		am.sendRecovery(sessKey, "SESSIONS_HIGH", fmt.Sprintf("Session count recovered to %d", status.SessionCount), status.DeviceID)
	}

	return nil
}

func (am *AlertManager) CheckInterfaceStatus(interfaces []models.InterfaceStats) error {
	var fired []models.Alert

	am.mu.Lock()
	now := time.Now()

	for _, iface := range interfaces {
		key := fmt.Sprintf("iface_down_%d_%s", iface.DeviceID, iface.Name)
		if am.config.Alerts.InterfaceDownAlert && iface.Status == "down" && iface.AdminStatus == "up" {
			if am.canAlert(key, now) {
				alert := models.Alert{
					Timestamp:    now,
					DeviceID:     iface.DeviceID,
					AlertType:    "INTERFACE_DOWN",
					Severity:     "critical",
					Message:      fmt.Sprintf("Interface %s is down", iface.Name),
					MetricName:   fmt.Sprintf("interface_%s", iface.Name),
					CurrentValue: 0,
				}
				fired = append(fired, alert)
				am.lastAlert[key] = now
				am.activeAlerts[key] = true
			}
		}
	}
	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	for i := range fired {
		am.saveAlert(&fired[i])
		if err := am.notifier.SendAlert(&fired[i], nc); err != nil {
			log.Printf("Failed to send interface alert %s: %v", fired[i].AlertType, err)
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

func (am *AlertManager) ProcessTrap(trap *models.TrapEvent) error {
	if trap.Severity == "critical" || trap.Severity == "warning" {
		key := fmt.Sprintf("trap_%s_%s", trap.TrapType, trap.SourceIP)

		am.mu.Lock()
		now := time.Now()
		canSend := am.canAlert(key, now)
		if canSend {
			am.lastAlert[key] = now
		}
		nc := notifier.SnapshotConfig(&am.config.Alerts)
		am.mu.Unlock()

		if !canSend {
			return nil
		}

		alert := models.Alert{
			Timestamp:  trap.Timestamp,
			DeviceID:   trap.DeviceID,
			AlertType:  trap.TrapType,
			Severity:   trap.Severity,
			Message:    trap.Message,
			MetricName: "snmp_trap",
		}

		am.saveAlert(&alert)
		if err := am.notifier.SendAlert(&alert, nc); err != nil {
			return fmt.Errorf("failed to send trap alert: %w", err)
		}
	}

	return nil
}

// CheckInterfaceErrors alerts when interfaces accumulate errors or discards since last poll.
// prevMap maps "deviceID_ifName" to the previous InterfaceStats for delta computation.
func (am *AlertManager) CheckInterfaceErrors(interfaces []models.InterfaceStats, prevMap map[string]*models.InterfaceStats) error {
	var fired []models.Alert

	am.mu.Lock()
	now := time.Now()

	for _, iface := range interfaces {
		if iface.Status != "up" || iface.AdminStatus != "up" {
			continue
		}
		mapKey := fmt.Sprintf("%d_%s", iface.DeviceID, iface.Name)
		prev, ok := prevMap[mapKey]
		if !ok {
			continue
		}

		// Compute error delta (handle counter wraps)
		var errorDelta uint64
		totalErrors := iface.InErrors + iface.OutErrors + iface.InDiscards + iface.OutDiscards
		prevTotalErrors := prev.InErrors + prev.OutErrors + prev.InDiscards + prev.OutDiscards
		if totalErrors >= prevTotalErrors {
			errorDelta = totalErrors - prevTotalErrors
		}

		if errorDelta > 0 {
			alertKey := fmt.Sprintf("iface_errors_%d_%s", iface.DeviceID, iface.Name)
			if am.canAlert(alertKey, now) {
				alert := models.Alert{
					Timestamp:    now,
					DeviceID:     iface.DeviceID,
					AlertType:    "INTERFACE_ERRORS",
					Severity:     "warning",
					Message:      fmt.Sprintf("Interface %s has %d new errors/discards (in_err: %d, out_err: %d, in_disc: %d, out_disc: %d)", iface.Name, errorDelta, iface.InErrors-prev.InErrors, iface.OutErrors-prev.OutErrors, iface.InDiscards-prev.InDiscards, iface.OutDiscards-prev.OutDiscards),
					MetricName:   fmt.Sprintf("interface_errors_%s", iface.Name),
					CurrentValue: float64(errorDelta),
				}
				fired = append(fired, alert)
				am.lastAlert[alertKey] = now
			}
		}
	}

	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	for i := range fired {
		am.saveAlert(&fired[i])
		if err := am.notifier.SendAlert(&fired[i], nc); err != nil {
			log.Printf("Failed to send interface error alert: %v", err)
		}
	}
	return nil
}

// ProcessSyslog creates an alert from critical syslog messages (severity 0-2: Emergency/Alert/Critical).
func (am *AlertManager) ProcessSyslog(msg *models.SyslogMessage) error {
	if msg.Severity > 2 {
		return nil
	}

	severityNames := map[int]string{0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL"}
	sevName := severityNames[msg.Severity]

	key := fmt.Sprintf("syslog_%d_%s_%d", msg.DeviceID, msg.AppName, msg.Severity)

	am.mu.Lock()
	now := time.Now()
	canSend := am.canAlert(key, now)
	if canSend {
		am.lastAlert[key] = now
	}
	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	if !canSend {
		return nil
	}

	alertSeverity := "critical"
	if msg.Severity > 0 {
		alertSeverity = "warning"
	}

	alert := models.Alert{
		Timestamp:  msg.Timestamp,
		DeviceID:   msg.DeviceID,
		AlertType:  "SYSLOG_" + sevName,
		Severity:   alertSeverity,
		Message:    fmt.Sprintf("[%s] %s: %s", sevName, msg.Hostname, msg.Message),
		MetricName: "syslog",
	}

	am.saveAlert(&alert)
	if err := am.notifier.SendAlert(&alert, nc); err != nil {
		return fmt.Errorf("failed to send syslog alert: %w", err)
	}
	return nil
}

func (am *AlertManager) canAlert(key string, now time.Time) bool {
	if lastTime, exists := am.lastAlert[key]; exists {
		return now.Sub(lastTime) > am.alertCooldown
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

	var settings []models.SystemSetting
	if err := db.Where("`key` IN ?", []string{
		"cpu_threshold", "memory_threshold", "disk_threshold", "session_threshold",
		"email_enabled", "smtp_host", "smtp_port", "smtp_username", "smtp_password",
		"smtp_from", "smtp_to", "slack_webhook", "discord_webhook", "webhook_url",
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

func (am *AlertManager) CheckVPNStatus(vpnStatuses []models.VPNStatus) error {
	var fired []models.Alert

	am.mu.Lock()
	now := time.Now()
	for _, vpn := range vpnStatuses {
		key := fmt.Sprintf("vpn_down_%d_%s", vpn.DeviceID, vpn.TunnelName)
		if vpn.Status == "down" {
			if am.canAlert(key, now) {
				alert := models.Alert{
					Timestamp:  now,
					DeviceID:   vpn.DeviceID,
					AlertType:  "VPN_TUNNEL_DOWN",
					Severity:   "critical",
					Message:    fmt.Sprintf("VPN tunnel %s to %s is down", vpn.TunnelName, vpn.RemoteIP),
					MetricName: fmt.Sprintf("vpn_%s", vpn.TunnelName),
				}
				fired = append(fired, alert)
				am.lastAlert[key] = now
				am.activeAlerts[key] = true
			}
		}
	}
	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	for i := range fired {
		am.saveAlert(&fired[i])
		if err := am.notifier.SendAlert(&fired[i], nc); err != nil {
			log.Printf("Failed to send VPN alert: %v", err)
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
	canSend := am.canAlert(key, now)
	if canSend {
		am.lastAlert[key] = now
		am.activeAlerts[key] = true
	}
	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	if !canSend {
		return nil
	}

	alert := models.Alert{
		Timestamp:  now,
		DeviceID:   device.ID,
		AlertType:  "DEVICE_OFFLINE",
		Severity:   "critical",
		Message:    fmt.Sprintf("Device %s (%s) is offline", device.Name, device.IPAddress),
		MetricName: "device_status",
	}

	am.saveAlert(&alert)
	if err := am.notifier.SendAlert(&alert, nc); err != nil {
		log.Printf("Failed to send device offline alert: %v", err)
	}
	return nil
}

// CheckDeviceOnline sends a recovery notification if the device was previously marked offline.
func (am *AlertManager) CheckDeviceOnline(device *models.Device) {
	key := fmt.Sprintf("device_offline_%d", device.ID)
	am.sendRecovery(key, "DEVICE_OFFLINE",
		fmt.Sprintf("Device %s (%s) is back online", device.Name, device.IPAddress), device.ID)
}
