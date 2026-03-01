package uptime

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/models"
)

type UptimeTracker struct {
	config     *config.Config
	mu         sync.RWMutex
	baseline   *UptimeBaseline
	downtime   float64
	downEvents int
	lastUptime uint64
}

type UptimeBaseline struct {
	StartTime   time.Time `json:"start_time"`
	StartUptime uint64    `json:"start_uptime"`
}

type UptimeStats struct {
	UptimePercent  float64   `json:"uptime_percent"`
	TotalDowntime  float64   `json:"total_downtime_seconds"`
	DowntimeEvents int       `json:"downtime_events"`
	CurrentUptime  uint64    `json:"current_uptime"`
	StartTime      time.Time `json:"start_time"`
}

func NewUptimeTracker(cfg *config.Config) *UptimeTracker {
	ut := &UptimeTracker{
		config:     cfg,
		downtime:   0,
		downEvents: 0,
		lastUptime: 0,
	}

	if cfg.Uptime.TrackingEnabled {
		ut.loadBaseline()
	}

	return ut
}

func (ut *UptimeTracker) loadBaseline() {
	if ut.config.Uptime.BaselineFile == "" {
		return
	}

	data, err := os.ReadFile(ut.config.Uptime.BaselineFile)
	if err != nil {
		ut.baseline = &UptimeBaseline{
			StartTime:   time.Now(),
			StartUptime: 0,
		}
		return
	}

	var baseline UptimeBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		ut.baseline = &UptimeBaseline{
			StartTime:   time.Now(),
			StartUptime: 0,
		}
		return
	}

	ut.baseline = &baseline
}

func (ut *UptimeTracker) saveBaselineToFile(baseline *UptimeBaseline) error {
	if ut.config.Uptime.BaselineFile == "" {
		return nil
	}

	data, err := json.Marshal(baseline)
	if err != nil {
		return err
	}

	dir := filepath.Dir(ut.config.Uptime.BaselineFile)
	if dir == "." {
		dir = "/var/lib/fortigate-mon"
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(ut.config.Uptime.BaselineFile, data, 0600)
}

func (ut *UptimeTracker) RecordUptime(currentUptime uint64) {
	ut.mu.Lock()

	if ut.baseline == nil {
		ut.baseline = &UptimeBaseline{
			StartTime:   time.Now(),
			StartUptime: currentUptime,
		}
	}

	if ut.lastUptime > 0 && currentUptime < ut.lastUptime {
		ut.downEvents++
	}

	ut.lastUptime = currentUptime

	baselineToSave := ut.baseline
	ut.mu.Unlock()

	if err := ut.saveBaselineToFile(baselineToSave); err != nil {
		log.Printf("Failed to save baseline: %v", err)
	}
}

func (ut *UptimeTracker) GetStats() UptimeStats {
	ut.mu.RLock()
	defer ut.mu.RUnlock()

	stats := UptimeStats{
		CurrentUptime:  ut.lastUptime,
		DowntimeEvents: ut.downEvents,
		TotalDowntime:  ut.downtime,
	}

	if ut.baseline != nil {
		stats.StartTime = ut.baseline.StartTime
	}

	if ut.baseline != nil && ut.lastUptime > 0 {
		elapsedTime := time.Since(ut.baseline.StartTime).Seconds()
		// Guard against uint64 underflow if device rebooted
		var deviceUptime float64
		if ut.lastUptime >= ut.baseline.StartUptime {
			deviceUptime = float64(ut.lastUptime-ut.baseline.StartUptime) / 100
		}

		if elapsedTime > 0 && deviceUptime > 0 {
			pct := (deviceUptime / elapsedTime) * 100
			if pct > 100 {
				pct = 100
			}
			stats.UptimePercent = pct
		}
	}

	return stats
}

func (ut *UptimeTracker) GetUptimeRecord() *models.UptimeRecord {
	stats := ut.GetStats()

	return &models.UptimeRecord{
		Timestamp:      time.Now(),
		DeviceUptime:   stats.CurrentUptime,
		TotalDowntime:  stats.TotalDowntime,
		UptimePercent:  stats.UptimePercent,
		DowntimeEvents: stats.DowntimeEvents,
	}
}

func (ut *UptimeTracker) CalculateFiveNines() string {
	stats := ut.GetStats()

	if stats.UptimePercent >= 99.999 {
		return "Achieved"
	}

	targetDowntime := 315.576 // Max allowed downtime per year for 99.999% uptime (5 min 15.576 sec)
	downtimeRemaining := targetDowntime - stats.TotalDowntime
	if downtimeRemaining < 0 {
		downtimeRemaining = 0
	}

	return fmt.Sprintf("%.2f seconds remaining for 99.999%% uptime", downtimeRemaining)
}

func (ut *UptimeTracker) Reset() error {
	ut.mu.Lock()

	ut.baseline = &UptimeBaseline{
		StartTime:   time.Now(),
		StartUptime: ut.lastUptime,
	}
	ut.downtime = 0
	ut.downEvents = 0

	baselineToSave := ut.baseline
	ut.mu.Unlock()

	return ut.saveBaselineToFile(baselineToSave)
}

func FormatUptime(uptime uint64) string {
	seconds := uptime / 100

	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, secs)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, secs)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, secs)
	} else {
		return fmt.Sprintf("%ds", secs)
	}
}
