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

// UptimeStats is the read-time availability summary for ONE device. It is
// scoped to the OBSERVED window (the retained system_status samples), not a
// year — StartTime and ObservedSeconds describe exactly what was measured, so
// the presentation layer never claims a window the data doesn't cover.
type UptimeStats struct {
	UptimePercent   float64   `json:"uptime_percent"`
	TotalDowntime   float64   `json:"total_downtime_seconds"`
	DowntimeEvents  int       `json:"downtime_events"`
	CurrentUptime   uint64    `json:"current_uptime"`
	StartTime       time.Time `json:"start_time"`       // oldest retained readable sample
	ObservedSeconds float64   `json:"observed_seconds"` // width of the observed window
	SampleCount     int       `json:"sample_count"`     // readable (nonzero-uptime) samples
}

// fiveNinesUnavailability is the unavailability fraction permitted by a 99.999%
// ("five nines") target: 0.001% of the window.
const fiveNinesUnavailability = 1e-5

// rebootSlackSeconds is how far a device's CLAIMED boot instant must move into
// the future of the previous sample before we count a reboot. It comfortably
// exceeds both the ~60s SNMP poll cadence and the ≤60s minute-truncation jitter
// of the SSH-perf writer (system_status is a dual-writer table: 60s-cadence,
// 10ms-granular SNMP uptime interleaved with 15m-cadence, minute-truncated
// SSH-perf uptime). Below this threshold a claimed-boot shift is jitter, not a
// real restart.
const rebootSlackSeconds = 90.0

// ComputeStats derives availability for a single device from its system_status
// history. `rows` must be for ONE device, ordered oldest→newest by timestamp;
// `start` seeds StartTime only when there is data-derived start to prefer.
//
// Readability: a row with Uptime==0 means "unknown/unreadable" (an SSH parse
// miss, an SNMP NoSuchInstance/timeout), NEVER "0 seconds up", so such rows are
// SKIPPED entirely — otherwise they masquerade as a reboot-to-zero and invent
// downtime, and an all-zeros series would read as a false 100%.
//
// Reboot detection is by CLAIMED BOOT TIME, not a raw counter drop. A device's
// boot instant ≈ sample.Timestamp − sample.Uptime/100 (seconds). A reboot is
// counted between two readable samples only when the later sample claims to
// have booted AFTER the earlier sample's timestamp by more than
// rebootSlackSeconds. This makes a monotonic series and minute-truncation
// jitter both yield ZERO reboots (the claimed boot only jitters within slack),
// while a genuine restart (claimed boot jumps to recent) yields one. It also
// sidesteps the missing timestamp tie-break in GetRecentSystemStatus (no
// secondary ORDER BY): two near-simultaneous dual-writer rows differ only
// within slack.
//
// Downtime for a detected reboot = max(0, claimedBoot − prev.Timestamp): the
// device was last confirmed up at prev.Timestamp and reports booting at
// claimedBoot, so that interval is the (conservative, provable) outage. It is
// bounded by the inter-sample gap.
//
// COUNTER WRAP: 32-bit sysUpTime wraps to 0 about every 497 days. A wrap looks
// like a fresh, recent boot, so the claimed-boot test counts it as one reboot
// plus up to one inter-sample interval of downtime. This is a once-per-~497-day
// edge we accept rather than special-case; a 64-bit counter or a
// device-provided boot-time OID would remove it.
//
// UptimePercent is (observed − totalDowntime) / observed × 100, clamped [0,100].
func ComputeStats(rows []models.SystemStatus, start time.Time) UptimeStats {
	stats := UptimeStats{StartTime: start}

	// Keep only readable samples (Uptime != 0).
	valid := make([]models.SystemStatus, 0, len(rows))
	for _, r := range rows {
		if r.Uptime == 0 {
			continue
		}
		valid = append(valid, r)
	}
	stats.SampleCount = len(valid)
	if len(valid) == 0 {
		// No signal at all — return a no-data zero-state, NEVER 100%.
		return stats
	}

	stats.CurrentUptime = valid[len(valid)-1].Uptime
	windowStart := valid[0].Timestamp
	stats.StartTime = windowStart

	// claimedBootUnix computes a sample's boot instant in float Unix seconds.
	// Working in float seconds (rather than time.Duration) avoids int64
	// overflow for absurd uptime values (e.g. the property test's MaxUint64).
	claimedBootUnix := func(s models.SystemStatus) float64 {
		return float64(s.Timestamp.Unix()) - float64(s.Uptime)/100.0
	}

	for i := 1; i < len(valid); i++ {
		prevUnix := float64(valid[i-1].Timestamp.Unix())
		boot := claimedBootUnix(valid[i])
		if boot > prevUnix+rebootSlackSeconds {
			stats.DowntimeEvents++
			down := boot - prevUnix
			if down < 0 {
				down = 0
			}
			stats.TotalDowntime += down
		}
	}

	elapsed := valid[len(valid)-1].Timestamp.Sub(windowStart).Seconds()
	stats.ObservedSeconds = elapsed
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

// CalculateFiveNines reports the remaining downtime budget for a 99.999% target
// OVER THE OBSERVED WINDOW (not a mislabeled annual figure): the budget is
// ObservedSeconds × 0.001%. It is a pure function of the supplied stats, so the
// value is meaningful and moves as downtime accumulates. With no observed
// window it reports insufficient data rather than a false "Achieved".
func CalculateFiveNines(stats UptimeStats) string {
	if stats.SampleCount == 0 || stats.ObservedSeconds <= 0 {
		return "Insufficient data"
	}
	if stats.UptimePercent >= 99.999 {
		return "Achieved for the observed window"
	}

	budget := stats.ObservedSeconds * fiveNinesUnavailability
	remaining := budget - stats.TotalDowntime
	if remaining < 0 {
		remaining = 0
	}

	return fmt.Sprintf("%.2f seconds of downtime budget remaining for 99.999%% over the observed window", remaining)
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
