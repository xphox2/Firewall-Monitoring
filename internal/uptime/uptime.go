// Package uptime derives per-device availability from persisted system_status
// history. It is a PURE function library (AUDIT-318): there is no stateful
// global tracker. The old singleton was dead end-to-end — its write side had
// zero callers so its stats were frozen at zero, and its `downtime` field was
// never incremented so five-nines was a constant. Availability is now computed
// at read time from the per-device SNMP sysUpTime series, so there is no
// global-mutable-state / last-writer-wins problem across a multi-device fleet.
package uptime

import (
	"fmt"
	"time"

	"firewall-mon/internal/models"
)

// UptimeStats is the read-time availability summary for ONE device.
type UptimeStats struct {
	UptimePercent  float64   `json:"uptime_percent"`
	TotalDowntime  float64   `json:"total_downtime_seconds"`
	DowntimeEvents int       `json:"downtime_events"`
	CurrentUptime  uint64    `json:"current_uptime"`
	StartTime      time.Time `json:"start_time"`
}

// fiveNinesBudgetSeconds is the maximum downtime per year permitted by a
// 99.999% ("five nines") availability target: 5 min 15.576 sec.
const fiveNinesBudgetSeconds = 315.576

// ComputeStats derives availability for a single device from its system_status
// history. `rows` must be for ONE device, ordered oldest→newest by timestamp;
// `start` is the window start used for the elapsed-time denominator (callers
// typically pass rows[0].Timestamp).
//
// A DOWN EVENT is a reboot: the SNMP sysUpTime counter (timeticks, hundredths
// of a second, cumulative) DROPS below the previous sample's value. Downtime is
// ESTIMATED per reboot as the wall-clock gap between the pre-reboot and
// post-reboot samples MINUS the uptime the device already reports in the
// post-reboot sample (i.e. how long it had been back up when we first observed
// it again), clamped ≥0. This fixes the historical bug where downtime was never
// accumulated (only the event count was), which made five-nines a constant.
//
// UptimePercent is (elapsed − totalDowntime) / elapsed × 100, clamped to
// [0,100] — the standard availability ratio, so it moves off the frozen
// zero-state and directly reflects accumulated downtime.
func ComputeStats(rows []models.SystemStatus, start time.Time) UptimeStats {
	stats := UptimeStats{StartTime: start}
	if len(rows) == 0 {
		return stats
	}

	stats.CurrentUptime = rows[len(rows)-1].Uptime

	for i := 1; i < len(rows); i++ {
		prev := rows[i-1]
		cur := rows[i]
		if cur.Uptime < prev.Uptime {
			// Reboot detected between prev and cur.
			stats.DowntimeEvents++

			gap := cur.Timestamp.Sub(prev.Timestamp).Seconds()
			// Seconds the device had already been up when first seen back.
			backUpFor := float64(cur.Uptime) / 100
			down := gap - backUpFor
			if down < 0 {
				down = 0
			}
			stats.TotalDowntime += down
		}
	}

	effStart := start
	if effStart.IsZero() {
		effStart = rows[0].Timestamp
	}
	elapsed := rows[len(rows)-1].Timestamp.Sub(effStart).Seconds()
	if elapsed > 0 {
		pct := (elapsed - stats.TotalDowntime) / elapsed * 100
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		stats.UptimePercent = pct
	}

	return stats
}

// CalculateFiveNines reports the remaining annual downtime budget for a 99.999%
// availability target, given accumulated downtime. It is a pure function of the
// supplied stats (not a receiver), so the value is MEANINGFUL: it moves as
// downtime accumulates instead of being a constant.
func CalculateFiveNines(stats UptimeStats) string {
	if stats.UptimePercent >= 99.999 {
		return "Achieved"
	}

	downtimeRemaining := fiveNinesBudgetSeconds - stats.TotalDowntime
	if downtimeRemaining < 0 {
		downtimeRemaining = 0
	}

	return fmt.Sprintf("%.2f seconds remaining for 99.999%% uptime", downtimeRemaining)
}

// NewRecord builds a persistable models.UptimeRecord from computed stats with
// the DeviceID SET. The old tracker built records with DeviceID left at 0
// (GetUptimeRecord had no device context), so every persisted row collided on
// device 0; every producer now routes through here so the record is correctly
// device-tagged.
func NewRecord(deviceID uint, stats UptimeStats) *models.UptimeRecord {
	return &models.UptimeRecord{
		Timestamp:      time.Now(),
		DeviceID:       deviceID,
		DeviceUptime:   stats.CurrentUptime,
		TotalDowntime:  stats.TotalDowntime,
		UptimePercent:  stats.UptimePercent,
		DowntimeEvents: stats.DowntimeEvents,
	}
}

// FormatUptime renders SNMP sysUpTime timeticks (hundredths of a second) as a
// human-readable d/h/m/s string.
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
