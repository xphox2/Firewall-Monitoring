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
	mu            sync.RWMutex
	alertCooldown time.Duration
}

func NewAlertManager(cfg *config.Config, notif *notifier.Notifier, db *database.Database) *AlertManager {
	return &AlertManager{
		config:        cfg,
		notifier:      notif,
		db:            db,
		lastAlert:     make(map[string]time.Time),
		alertCooldown: 5 * time.Minute,
	}
}

func (am *AlertManager) CheckSystemStatus(status *models.SystemStatus) error {
	alerts := []models.Alert{}

	am.mu.Lock()
	now := time.Now()

	if status.CPUUsage >= am.config.Alerts.CPUThreshold {
		key := fmt.Sprintf("cpu_high_%d", status.DeviceID)
		if am.canAlert(key, now) {
			alert := models.Alert{
				Timestamp:    now,
				DeviceID:     status.DeviceID,
				AlertType:    "CPU_HIGH",
				Severity:     "warning",
				Message:      fmt.Sprintf("CPU usage is %.1f%% (threshold: %.1f%%)", status.CPUUsage, am.config.Alerts.CPUThreshold),
				MetricName:   "cpu_usage",
				Threshold:    am.config.Alerts.CPUThreshold,
				CurrentValue: status.CPUUsage,
			}
			alerts = append(alerts, alert)
			am.lastAlert[key] = now
		}
	}

	if status.MemoryUsage >= am.config.Alerts.MemoryThreshold {
		key := fmt.Sprintf("memory_high_%d", status.DeviceID)
		if am.canAlert(key, now) {
			alert := models.Alert{
				Timestamp:    now,
				DeviceID:     status.DeviceID,
				AlertType:    "MEMORY_HIGH",
				Severity:     "warning",
				Message:      fmt.Sprintf("Memory usage is %.1f%% (threshold: %.1f%%)", status.MemoryUsage, am.config.Alerts.MemoryThreshold),
				MetricName:   "memory_usage",
				Threshold:    am.config.Alerts.MemoryThreshold,
				CurrentValue: status.MemoryUsage,
			}
			alerts = append(alerts, alert)
			am.lastAlert[key] = now
		}
	}

	if status.DiskUsage >= am.config.Alerts.DiskThreshold {
		key := fmt.Sprintf("disk_high_%d", status.DeviceID)
		if am.canAlert(key, now) {
			alert := models.Alert{
				Timestamp:    now,
				DeviceID:     status.DeviceID,
				AlertType:    "DISK_HIGH",
				Severity:     "critical",
				Message:      fmt.Sprintf("Disk usage is %.1f%% (threshold: %.1f%%)", status.DiskUsage, am.config.Alerts.DiskThreshold),
				MetricName:   "disk_usage",
				Threshold:    am.config.Alerts.DiskThreshold,
				CurrentValue: status.DiskUsage,
			}
			alerts = append(alerts, alert)
			am.lastAlert[key] = now
		}
	}

	if status.SessionCount >= am.config.Alerts.SessionThreshold {
		key := fmt.Sprintf("sessions_high_%d", status.DeviceID)
		if am.canAlert(key, now) {
			alert := models.Alert{
				Timestamp:    now,
				DeviceID:     status.DeviceID,
				AlertType:    "SESSIONS_HIGH",
				Severity:     "warning",
				Message:      fmt.Sprintf("Session count is %d (threshold: %d)", status.SessionCount, am.config.Alerts.SessionThreshold),
				MetricName:   "session_count",
				Threshold:    float64(am.config.Alerts.SessionThreshold),
				CurrentValue: float64(status.SessionCount),
			}
			alerts = append(alerts, alert)
			am.lastAlert[key] = now
		}
	}
	am.mu.Unlock()

	for i := range alerts {
		am.saveAlert(&alerts[i])
		if err := am.notifier.SendAlert(&alerts[i]); err != nil {
			log.Printf("Failed to send alert %s: %v", alerts[i].AlertType, err)
		}
	}

	return nil
}

func (am *AlertManager) CheckInterfaceStatus(interfaces []models.InterfaceStats) error {
	alerts := []models.Alert{}

	am.mu.Lock()
	now := time.Now()

	for _, iface := range interfaces {
		if am.config.Alerts.InterfaceDownAlert && iface.Status == "down" && iface.AdminStatus == "up" {
			key := fmt.Sprintf("iface_down_%d_%s", iface.DeviceID, iface.Name)
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
				alerts = append(alerts, alert)
				am.lastAlert[key] = now
			}
		}
	}
	am.mu.Unlock()

	for i := range alerts {
		am.saveAlert(&alerts[i])
		if err := am.notifier.SendAlert(&alerts[i]); err != nil {
			log.Printf("Failed to send interface alert %s: %v", alerts[i].AlertType, err)
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
		if err := am.notifier.SendAlert(&alert); err != nil {
			return fmt.Errorf("failed to send trap alert: %w", err)
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
	}).Find(&settings).Error; err != nil {
		log.Printf("RefreshThresholds: failed to read settings: %v", err)
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	for _, s := range settings {
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
		}
	}
}

func (am *AlertManager) SetCooldown(duration time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alertCooldown = duration
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
	var alerts []models.Alert

	am.mu.Lock()
	now := time.Now()
	for _, vpn := range vpnStatuses {
		if vpn.Status == "down" {
			key := fmt.Sprintf("vpn_down_%d_%s", vpn.DeviceID, vpn.TunnelName)
			if am.canAlert(key, now) {
				alert := models.Alert{
					Timestamp:  now,
					DeviceID:   vpn.DeviceID,
					AlertType:  "VPN_TUNNEL_DOWN",
					Severity:   "critical",
					Message:    fmt.Sprintf("VPN tunnel %s to %s is down", vpn.TunnelName, vpn.RemoteIP),
					MetricName: fmt.Sprintf("vpn_%s", vpn.TunnelName),
				}
				alerts = append(alerts, alert)
				am.lastAlert[key] = now
			}
		}
	}
	am.mu.Unlock()

	for i := range alerts {
		am.saveAlert(&alerts[i])
		if err := am.notifier.SendAlert(&alerts[i]); err != nil {
			log.Printf("Failed to send VPN alert: %v", err)
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
	}
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
	if err := am.notifier.SendAlert(&alert); err != nil {
		log.Printf("Failed to send device offline alert: %v", err)
	}
	return nil
}
