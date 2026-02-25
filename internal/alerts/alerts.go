package alerts

import (
	"fmt"
	"sync"
	"time"

	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/models"
	"fortiGate-Mon/internal/notifier"
)

type AlertManager struct {
	config        *config.Config
	notifier      *notifier.Notifier
	lastAlert     map[string]time.Time
	mu            sync.RWMutex
	alertCooldown time.Duration
}

func NewAlertManager(cfg *config.Config, notif *notifier.Notifier) *AlertManager {
	return &AlertManager{
		config:        cfg,
		notifier:      notif,
		lastAlert:     make(map[string]time.Time),
		alertCooldown: 5 * time.Minute,
	}
}

func (am *AlertManager) CheckSystemStatus(status *models.SystemStatus) error {
	alerts := []models.Alert{}

	am.mu.RLock()
	now := time.Now()

	if status.CPUUsage >= am.config.Alerts.CPUThreshold {
		key := fmt.Sprintf("cpu_%f", status.CPUUsage)
		if am.canAlert(key, now) {
			alert := models.Alert{
				Timestamp:    now,
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
		key := fmt.Sprintf("memory_%f", status.MemoryUsage)
		if am.canAlert(key, now) {
			alert := models.Alert{
				Timestamp:    now,
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
		key := fmt.Sprintf("disk_%f", status.DiskUsage)
		if am.canAlert(key, now) {
			alert := models.Alert{
				Timestamp:    now,
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
		key := fmt.Sprintf("sessions_%d", status.SessionCount)
		if am.canAlert(key, now) {
			alert := models.Alert{
				Timestamp:    now,
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
	am.mu.RUnlock()

	for _, alert := range alerts {
		if err := am.notifier.SendAlert(&alert); err != nil {
			return fmt.Errorf("failed to send alert: %w", err)
		}
	}

	return nil
}

func (am *AlertManager) CheckInterfaceStatus(interfaces []models.InterfaceStats) error {
	alerts := []models.Alert{}

	am.mu.RLock()
	now := time.Now()

	for _, iface := range interfaces {
		if am.config.Alerts.InterfaceDownAlert && iface.Status == "down" && iface.AdminStatus == "up" {
			key := fmt.Sprintf("iface_down_%s", iface.Name)
			if am.canAlert(key, now) {
				alert := models.Alert{
					Timestamp:    now,
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
	am.mu.RUnlock()

	for _, alert := range alerts {
		if err := am.notifier.SendAlert(&alert); err != nil {
			return fmt.Errorf("failed to send alert: %w", err)
		}
	}

	return nil
}

func (am *AlertManager) ProcessTrap(trap *models.TrapEvent) error {
	if trap.Severity == "critical" || trap.Severity == "warning" {
		alert := models.Alert{
			Timestamp:  trap.Timestamp,
			AlertType:  trap.TrapType,
			Severity:   trap.Severity,
			Message:    trap.Message,
			MetricName: "snmp_trap",
		}

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

func (am *AlertManager) SetCooldown(duration time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alertCooldown = duration
}
