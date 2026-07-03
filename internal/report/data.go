package report

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// IfaceTraffic holds correctly-derived traffic figures for one interface over
// the report window. Totals/rates come from SNMP octet-counter DELTAS (see
// computeTraffic), not from summing the raw cumulative counters.
type IfaceTraffic struct {
	Name       string
	TotalBytes float64 // total bytes transferred (in+out) over the window
	PeakBps    float64 // peak throughput (bits/sec) in any single bucket
	AvgBps     float64 // average throughput (bits/sec) over the window
}

// DeviceReportData holds all aggregated data for a single device in a report.
type DeviceReportData struct {
	CPUAvg       float64
	CPUMax       float64
	MemAvg       float64
	MemMax       float64
	DiskUsage    float64
	SessionCount int
	AlertCount   int
	Alerts       []models.Alert
	Spikes       []TrafficSpike
	SpikeFlows   []SpikeFlow // top sFlow conversations during the spike window (if sFlow data exists)

	// Bandwidth (image-free, v0.10.236)
	Talkers        []IfaceTraffic // top interfaces by bytes transferred
	Sparkline      []float64      // per-bucket throughput (bps) for the busiest interface
	SparklineTimes []time.Time    // timestamps for each bucket in the sparkline

	// CPU & Memory trends (NOC daily report)
	CPUHistory []float64   // downsampled CPU usage history
	MemHistory []float64   // downsampled memory usage history
	SysTimes   []time.Time // timestamps for the CPU/Mem history

	// Uptime
	UptimePct         float64
	UptimeDaysTracked int
}

// rangeForHours maps a report window to the GetInterfaceChartData range string
// and the bucket width in seconds used for that range.
func rangeForHours(hours int) (rangeStr string, bucketSeconds float64) {
	if hours >= 168 {
		return "7d", 3600 // hourly buckets
	}
	return "24h", 60 // minute buckets
}

// baselineRangeForHours picks a multi-day, hourly history window for seasonal
// spike baselining. 30 days of hourly history gives ~4 samples per (weekday,
// hour) slot — enough to learn each weekday's normal time-of-day profile (so a
// workload that pauses on weekends, or a backup that runs a little late, isn't
// flagged). Used for both daily and weekly reports; the test window is still
// just the last `hours`.
func baselineRange() (rangeStr string, bucketSeconds float64) {
	return "30d", 3600
}

// spikeWindow returns the [earliest, latest] timestamps across a set of spikes,
// extending the end by one hour to cover the full (hourly) bucket of the last
// spike — the window used to pull correlated sFlow conversations.
func spikeWindow(spikes []TrafficSpike) (from, to time.Time) {
	for _, s := range spikes {
		if s.Timestamp.IsZero() {
			continue
		}
		if from.IsZero() || s.Timestamp.Before(from) {
			from = s.Timestamp
		}
		if s.Timestamp.After(to) {
			to = s.Timestamp
		}
	}
	if !to.IsZero() {
		to = to.Add(time.Hour)
	}
	return from, to
}

// BuildSeasonalProfileFromChart converts interface chart buckets (cumulative
// counters) into a seasonal throughput profile via computeTraffic. bucketSeconds
// is the bucket width (3600 for hourly). Returns nil when there isn't enough
// data to form a profile. Used by the poller's real-time spike detector.
func BuildSeasonalProfileFromChart(buckets []database.InterfaceChartBucket, bucketSeconds float64) *SeasonalProfile {
	_, _, _, series, times := computeTraffic(buckets, bucketSeconds)
	if len(series) < minSeasonalSamples {
		return nil
	}
	return BuildSeasonalProfile(series, times)
}

// computeTraffic derives honest traffic figures from a series of interface
// chart buckets whose values are cumulative octet counters. It returns total
// bytes transferred, peak/avg throughput (bps), and the per-bucket throughput
// series (aligned with the returned times) for sparkline + spike detection.
//
// Each consecutive bucket delta is the bytes transferred in that bucket window.
// Negative deltas (counter reset or 32-bit wrap) are clamped to zero.
func computeTraffic(buckets []database.InterfaceChartBucket, bucketSeconds float64) (total, peak, avg float64, series []float64, times []time.Time) {
	if len(buckets) < 2 || bucketSeconds <= 0 {
		return 0, 0, 0, nil, nil
	}
	for i := 1; i < len(buckets); i++ {
		delta := (buckets[i].InBytes + buckets[i].OutBytes) - (buckets[i-1].InBytes + buckets[i-1].OutBytes)
		if delta < 0 {
			delta = 0 // counter reset / wrap
		}
		total += delta
		bps := delta * 8 / bucketSeconds
		if bps > peak {
			peak = bps
		}
		series = append(series, bps)
		times = append(times, parseBucketTime(buckets[i].Bucket))
	}
	windowSeconds := bucketSeconds * float64(len(buckets)-1)
	if windowSeconds > 0 {
		avg = total * 8 / windowSeconds
	}
	return total, peak, avg, series, times
}

// parseBucketTime tolerates the timestamp formats the dialects emit. The
// Postgres/SQLite TimeBucket helpers (internal/database/dialect.go) render
// buckets via to_char/strftime WITHOUT seconds — minute = "2006-01-02 15:04",
// hour = "2006-01-02 15:00", day = "2006-01-02" — so those layouts MUST come
// first. The seconds/RFC3339 variants are kept for robustness (raw timestamps,
// tests). A missed format previously fell back to the zero time, rendering
// every spike as "Jan 1 00:00".
func parseBucketTime(s string) time.Time {
	layouts := []string{
		"2006-01-02 15:04", // minute / 5min / hour buckets (HH:00 also matches)
		"2006-01-02",       // day buckets
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GatherDeviceData collects all report data for a single device over the given hours.
func GatherDeviceData(db *database.Database, device *models.Device, hours int, pollIntervalSec int, spikeThreshold float64) *DeviceReportData {
	data := &DeviceReportData{}

	// Get system status history
	history, err := db.GetSystemStatusHistory(device.ID, hours)
	if err != nil {
		log.Printf("Report: failed to get status history for %s: %v", device.Name, err)
	}

	// Compute CPU/Mem averages and maxes
	if len(history) > 0 {
		var cpuSum, memSum float64
		for _, h := range history {
			cpuSum += h.CPUUsage
			memSum += h.MemoryUsage
			if h.CPUUsage > data.CPUMax {
				data.CPUMax = h.CPUUsage
			}
			if h.MemoryUsage > data.MemMax {
				data.MemMax = h.MemoryUsage
			}
		}
		data.CPUAvg = cpuSum / float64(len(history))
		data.MemAvg = memSum / float64(len(history))
		data.DiskUsage = history[len(history)-1].DiskUsage
		data.SessionCount = history[len(history)-1].SessionCount
	}

	// Get alerts
	alerts, err := db.GetAlertsByDeviceAndHours(device.ID, hours)
	if err != nil {
		log.Printf("Report: failed to get alerts for %s: %v", device.Name, err)
	}
	data.Alerts = alerts
	data.AlertCount = len(alerts)

	// Get top interfaces (ranking heuristic), then derive honest per-interface
	// traffic from counter deltas.
	rangeStr, bucketSeconds := rangeForHours(hours)
	topIfaces, err := db.GetTopInterfacesByTraffic(device.ID, hours, 3)
	if err != nil {
		log.Printf("Report: failed to get top interfaces for %s: %v", device.Name, err)
	}

	for idx, ti := range topIfaces {
		chartData, err := db.GetInterfaceChartData(device.ID, ti.Index, rangeStr)
		if err != nil {
			log.Printf("Report: failed to get chart data for %s/%s: %v", device.Name, ti.Name, err)
			continue
		}
		total, peak, avg, series, times := computeTraffic(chartData, bucketSeconds)
		data.Talkers = append(data.Talkers, IfaceTraffic{
			Name:       ti.Name,
			TotalBytes: total,
			PeakBps:    peak,
			AvgBps:     avg,
		})

		// Sparkline + spike detection run on the busiest interface only.
		if idx == 0 {
			data.Sparkline = series
			data.SparklineTimes = times
			if spikeThreshold > 0 {
				// Judge spikes against the interface's own time-of-day baseline
				// (multi-day hourly history) so recurring scheduled traffic
				// (e.g. nightly backups) isn't flagged as anomalous. Falls back
				// to the single-window detector when history is thin or the
				// baseline query fails.
				baseRange, baseBucket := baselineRange()
				if bd, berr := db.GetInterfaceChartData(device.ID, ti.Index, baseRange); berr == nil {
					_, _, _, bSeries, bTimes := computeTraffic(bd, baseBucket)
					data.Spikes = detectSpikesTimeOfDay(bSeries, bTimes, hours, spikeThreshold, ti.Name)
				} else {
					data.Spikes = detectSpikesInSeries(series, times, spikeThreshold, ti.Name)
				}

				// Correlate spikes with sFlow: pull the top conversations on this
				// interface during the spike window so the report shows what the
				// traffic was (src→dst:port/proto). Best-effort — no flow data
				// (sFlow off for this device) just leaves SpikeFlows empty.
				if len(data.Spikes) > 0 {
					from, to := spikeWindow(data.Spikes)
					if convos, ferr := db.GetInterfaceFlowConversations(device.ID, ti.Index, from, to, 5); ferr == nil {
						for _, c := range convos {
							dst := c.DstAddr
							if c.DstPort > 0 {
								dst = fmt.Sprintf("%s:%d", c.DstAddr, c.DstPort)
							}
							data.SpikeFlows = append(data.SpikeFlows, SpikeFlow{
								Src:        c.SrcAddr,
								Dst:        dst,
								Protocol:   c.Protocol,
								BytesHuman: formatBytes(float64(c.Bytes)),
							})
						}
					}
				}
			}
		}
	}

	// Get downsampled system status history for NOC charts (CPU/Mem trends)
	if sysBuckets, err := db.GetSystemStatusBuckets(device.ID, rangeStr); err == nil {
		var cpuHistory []float64
		var memHistory []float64
		var sysTimes []time.Time
		for _, b := range sysBuckets {
			cpuHistory = append(cpuHistory, b.CPUUsage)
			memHistory = append(memHistory, b.MemoryUsage)
			sysTimes = append(sysTimes, time.UnixMilli(b.BucketMillis))
		}
		data.CPUHistory = cpuHistory
		data.MemHistory = memHistory
		data.SysTimes = sysTimes
	} else {
		log.Printf("Report: failed to get system status buckets for %s: %v", device.Name, err)
	}

	// Uptime calculation
	uptime, err := CalculateDeviceUptime(db, device.ID, 30, pollIntervalSec)
	if err != nil {
		log.Printf("Report: failed to calculate uptime for %s: %v", device.Name, err)
	} else if uptime != nil {
		data.UptimePct = uptime.Percent
		data.UptimeDaysTracked = uptime.DaysTracked
	}

	return data
}

// GatherRecentHistory returns the last 2 hours of system status for a device.
func GatherRecentHistory(db *database.Database, deviceID uint) []models.SystemStatus {
	history, err := db.GetSystemStatusHistory(deviceID, 2)
	if err != nil {
		log.Printf("Report: failed to get recent history for device %d: %v", deviceID, err)
		return nil
	}
	return history
}

// DurationUntilTime returns the duration until the next occurrence of HH:MM in the given timezone.
func DurationUntilTime(targetTime string, tz string) time.Duration {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)

	var hour, minute int
	fmt.Sscanf(targetTime, "%d:%d", &hour, &minute)

	target := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, loc)
	if target.Before(now) {
		target = target.Add(24 * time.Hour)
	}
	return target.Sub(now)
}

// DurationUntilWeekday returns the duration until the next occurrence of the given weekday at HH:MM.
func DurationUntilWeekday(targetDay, targetTime, tz string) time.Duration {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)

	dayMap := map[string]time.Weekday{
		"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday,
		"wednesday": time.Wednesday, "thursday": time.Thursday,
		"friday": time.Friday, "saturday": time.Saturday,
	}
	targetWeekday, ok := dayMap[targetDay]
	if !ok {
		targetWeekday = time.Monday
	}

	var hour, minute int
	fmt.Sscanf(targetTime, "%d:%d", &hour, &minute)

	daysUntil := int(targetWeekday - now.Weekday())
	if daysUntil < 0 {
		daysUntil += 7
	}
	if daysUntil == 0 {
		target := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, loc)
		if target.Before(now) {
			daysUntil = 7
		}
	}

	target := time.Date(now.Year(), now.Month(), now.Day()+daysUntil, hour, minute, 0, 0, loc)
	return target.Sub(now)
}

// GatherOpsStats loads the F05/F06 operations metrics (30-day horizon).
// Returns nil on error or nil db so the report simply omits the section.
func GatherOpsStats(db *database.Database) *OpsStats {
	if db == nil {
		return nil
	}
	const days = 30
	mtta, mttr, acked, resolved, err := db.GetAlertResponseStats(days)
	if err != nil {
		return nil
	}
	noisy, err := db.GetNoisiestAlerts(days, 10)
	if err != nil {
		return nil
	}
	ops := &OpsStats{Days: days, MTTAMinutes: mtta, MTTRMinutes: mttr, AckedCount: acked, ResolvedCount: resolved}
	for _, n := range noisy {
		name := n.DeviceName
		if name == "" {
			name = fmt.Sprintf("device %d", n.DeviceID)
		}
		ops.Noise = append(ops.Noise, NoiseRow{AlertType: n.AlertType, DeviceName: name, Count: n.Count, Suppressed: n.Suppressed})
	}
	return ops
}
