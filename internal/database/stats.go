package database

import (
	"fmt"
	"sort"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// TimeBucket is a generic time-series count bucket
type TimeBucket struct {
	Bucket string `json:"bucket"`
	Count  int64  `json:"count"`
}

// KeyCount is a generic key-value count pair
type KeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// EventStatsResult holds aggregated event statistics (alerts, traps, syslog)
type EventStatsResult struct {
	Total      int64        `json:"total"`
	BySeverity []KeyCount   `json:"by_severity"`
	ByType     []KeyCount   `json:"by_type"`
	OverTime   []TimeBucket `json:"over_time"`
	// WindowFrom, when set, is where the counted window actually starts: the
	// syslog meter counts whole UTC hours, so it is the cutoff floored to the
	// hour. Absent on the exact paths (raw rows over exactly N hours).
	WindowFrom *time.Time `json:"window_from,omitempty"`
	// Partial is true when the meter's history starts after WindowFrom, so the
	// counts cover only CoverageFrom onward.
	Partial      bool       `json:"partial,omitempty"`
	CoverageFrom *time.Time `json:"coverage_from,omitempty"`
}

// syslogMeterMinHours is the shortest window served from the ingest meter
// instead of syslog_messages. The meter counts whole UTC hours, so a short
// window would overstate itself badly (1h reads as up to 2h); below this the
// exact raw path is cheap anyway — measured on production 2026-09-26, 6 h of
// raw rows (810k) costs ~1.8 s across the three queries, while 24 h cost ~24 s.
const syslogMeterMinHours = 12

// syslogSeverityName maps a numeric syslog severity to its display name.
func syslogSeverityName(sev int) string {
	switch sev {
	case 0:
		return "Emergency"
	case 1:
		return "Alert"
	case 2:
		return "Critical"
	case 3:
		return "Error"
	case 4:
		return "Warning"
	case 5:
		return "Notice"
	case 6:
		return "Info"
	case 7:
		return "Debug"
	}
	return fmt.Sprintf("Severity %d", sev)
}

// syslogStatsFromMeter answers the fleet-wide Syslog stats from
// syslog_ingest_hourly — a few hundred rows — instead of counting
// syslog_messages, which at production volume (4.7M rows/day) took ~24 s for
// one 24 h view and could not finish a 7 d one inside the 30 s timeouts.
//
// It counts messages RECEIVED per whole UTC hour from the cutoff's hour,
// which differs from the raw path's "messages still stored whose own
// timestamp is in the window" in three ways: a collector backlog replay lands
// in the hour it arrived, rows later deleted or summarised by retention are
// still counted, and the window starts up to 59 minutes early. On production
// the two agreed to 35 rows in 8.9M over 48 h. WindowFrom reports the real
// start so the page can say so. Every figure comes from the same cells, so
// the total, the severity split and the chart always agree with each other.
func (d *Database) syslogStatsFromMeter(cutoff time.Time) (*EventStatsResult, error) {
	from := cutoff.UTC().Truncate(time.Hour)
	result := &EventStatsResult{WindowFrom: &from}

	oldest, have, err := d.oldestMeterHour()
	if err != nil {
		return nil, fmt.Errorf("failed to read syslog meter coverage: %w", err)
	}
	if have && oldest.After(from) {
		result.Partial = true
		result.CoverageFrom = &oldest
	}

	hours, err := d.meterHours(from)
	if err != nil {
		return nil, fmt.Errorf("failed to read syslog meter: %w", err)
	}
	var bySev [SyslogSeverityCount]int64
	keys := make([]time.Time, 0, len(hours))
	for h := range hours {
		keys = append(keys, h)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
	for _, h := range keys {
		var n int64
		for sev, c := range hours[h] {
			bySev[sev] += c
			n += c
		}
		if n == 0 {
			continue
		}
		result.Total += n
		// Same text both dialects' TimeBucket("hour") produces.
		result.OverTime = append(result.OverTime, TimeBucket{Bucket: h.Format("2006-01-02 15:00"), Count: n})
	}
	for sev, c := range bySev {
		if c > 0 {
			result.BySeverity = append(result.BySeverity, KeyCount{Key: syslogSeverityName(sev), Count: c})
		}
	}
	return result, nil
}

// timeSeriesCount queries hourly time-bucketed counts for model since cutoff.
// timeSeriesCount returns per-hour COUNT buckets for the given model
// since cutoff. deviceID = 0 means "all devices" (v0.10.217, bundle D4).
func (d *Database) timeSeriesCount(model interface{}, cutoff time.Time, deviceID uint) []TimeBucket {
	var rows []struct {
		Bucket string
		Count  int64
	}
	q := d.db.Model(model).Where("timestamp > ?", cutoff)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	q.Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, COUNT(*) as count").
		Group("bucket").Order("bucket ASC").Scan(&rows)
	buckets := make([]TimeBucket, 0, len(rows))
	for _, r := range rows {
		buckets = append(buckets, TimeBucket{Bucket: r.Bucket, Count: r.Count})
	}
	return buckets
}

// groupByString queries COUNT grouped by groupCol on model since cutoff.
// deviceID = 0 means "all devices". (v0.10.217, bundle D4)
func (d *Database) groupByString(model interface{}, cutoff time.Time, groupCol string, deviceID uint) []KeyCount {
	var rows []struct {
		Key   string
		Count int64
	}
	qCol := d.dialect.QuoteIdent(groupCol)
	q := d.db.Model(model).Where("timestamp > ?", cutoff)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	q.Select(qCol + " as key, COUNT(*) as count").Group(qCol).Order("count DESC").Scan(&rows)
	counts := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		counts = append(counts, KeyCount{Key: r.Key, Count: r.Count})
	}
	return counts
}

// GetAlertStats returns aggregated alert statistics. deviceID = 0 means
// "all devices" (the existing /admin/alerts page passes 0); a non-zero
// value scopes the stats to a single device for the per-device noise
// view added in v0.10.217 (bundle D4).
func (d *Database) GetAlertStats(hours int, deviceID uint) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	q := d.db.Model(&models.Alert{}).Where("timestamp > ?", cutoff)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	q.Count(&result.Total)
	result.BySeverity = d.groupByString(&models.Alert{}, cutoff, "severity", deviceID)
	result.ByType = d.groupByString(&models.Alert{}, cutoff, "alert_type", deviceID)
	result.OverTime = d.timeSeriesCount(&models.Alert{}, cutoff, deviceID)

	return result, nil
}

// GetTrapStats returns aggregated trap statistics. deviceID semantics
// same as GetAlertStats. Trap rows are matched on `device_id` when set;
// trap events arriving from unknown sources are excluded from a per-
// device filter (they have device_id = 0).
func (d *Database) GetTrapStats(hours int, deviceID uint) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	q := d.db.Model(&models.TrapEvent{}).Where("timestamp > ?", cutoff)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	q.Count(&result.Total)
	result.BySeverity = d.groupByString(&models.TrapEvent{}, cutoff, "severity", deviceID)
	result.ByType = d.groupByString(&models.TrapEvent{}, cutoff, "trap_type", deviceID)
	result.OverTime = d.timeSeriesCount(&models.TrapEvent{}, cutoff, deviceID)

	return result, nil
}

// GetSyslogStats returns aggregated syslog statistics (raw + summaries
// combined). deviceID = 0 means "all devices" (v0.10.217, bundle D4).
func (d *Database) GetSyslogStats(hours int, deviceID uint) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	if deviceID == 0 && hours >= syslogMeterMinHours {
		return d.syslogStatsFromMeter(cutoff)
	}
	result := &EventStatsResult{}

	// applyDevFilter is a small helper to keep the device_id WHERE
	// clause out of every chain below.
	applyDevFilter := func(q *gorm.DB) *gorm.DB {
		if deviceID != 0 {
			return q.Where("device_id = ?", deviceID)
		}
		return q
	}

	// Total: raw syslog + summaries
	var rawCount int64
	if err := applyDevFilter(d.db.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff)).
		Count(&rawCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count raw syslog: %w", err)
	}
	var summaryCount int64
	if err := applyDevFilter(d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff)).
		Select("COALESCE(SUM(count), 0)").Scan(&summaryCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count syslog summaries: %w", err)
	}
	result.Total = rawCount + summaryCount

	var bySev []struct {
		Severity int
		Count    int64
	}
	// Get severity counts from raw syslog
	if err := applyDevFilter(d.db.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff)).
		Select("severity, COUNT(*) as count").Group("severity").Scan(&bySev).Error; err != nil {
		return nil, fmt.Errorf("failed to get raw syslog severity counts: %w", err)
	}
	// Get severity counts from summaries
	var summaryBySev []struct {
		Severity int
		Count    int64
	}
	if err := applyDevFilter(d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff)).
		Select("severity, SUM(count) as count").Group("severity").Scan(&summaryBySev).Error; err != nil {
		return nil, fmt.Errorf("failed to get summary severity counts: %w", err)
	}
	// Merge summary counts into bySev
	sevMap := make(map[int]int64)
	for _, s := range bySev {
		sevMap[s.Severity] += s.Count
	}
	for _, s := range summaryBySev {
		sevMap[s.Severity] += s.Count
	}
	for sev, count := range sevMap {
		result.BySeverity = append(result.BySeverity, KeyCount{Key: syslogSeverityName(sev), Count: count})
	}

	// OverTime: combine raw time series with summary counts
	rawTimeSeries := d.timeSeriesCount(&models.SyslogMessage{}, cutoff, deviceID)
	// Get summary time series grouped by hour
	var summaryTimeSeries []struct {
		Bucket string
		Count  int64
	}
	if err := applyDevFilter(d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff)).
		Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, SUM(count) as count").
		Group("bucket").Order("bucket ASC").Scan(&summaryTimeSeries).Error; err != nil {
		return nil, fmt.Errorf("failed to get summary time series: %w", err)
	}
	// Merge summary time series into raw time series
	summaryMap := make(map[string]int64)
	for _, r := range summaryTimeSeries {
		summaryMap[r.Bucket] += r.Count
	}
	for _, r := range rawTimeSeries {
		summaryMap[r.Bucket] += r.Count
	}
	// Sort by bucket for consistent ordering
	buckets := make([]string, 0, len(summaryMap))
	for bucket := range summaryMap {
		buckets = append(buckets, bucket)
	}
	sort.Strings(buckets)
	for _, bucket := range buckets {
		result.OverTime = append(result.OverTime, TimeBucket{Bucket: bucket, Count: summaryMap[bucket]})
	}

	return result, nil
}

// DashboardTimeSeries holds overview metrics over time
type DashboardTimeSeries struct {
	FlowsOverTime   []TimeBucket `json:"flows_over_time"`
	AlertsOverTime  []TimeBucket `json:"alerts_over_time"`
	SyslogOverTime  []TimeBucket `json:"syslog_over_time"`
	TrapsOverTime   []TimeBucket `json:"traps_over_time"`
	DeviceStatusMap []KeyCount   `json:"device_status"`
}

// GetAlertsTimeSeries returns ONLY the hourly alert counts, in the same envelope
// as GetDashboardTimeSeries.
//
// The system-health composite renders a single alerts sparkline and reads only
// `alerts_over_time` — but it used to call GetDashboardTimeSeries, which also
// builds hourly GROUP BYs over flow_samples, syslog_messages and trap_events and
// then throws all three away. On production the syslog one alone was measured at
// 7.0s (an external merge sort spilling 52MB), for a series nothing displays.
//
// The envelope is deliberately the same *DashboardTimeSeries: the browser reads
// `trend.alerts_over_time`, so returning a bare slice here would silently leave
// an empty sparkline with no error anywhere. The unused series stay nil.
func (d *Database) GetAlertsTimeSeries(hours int) (*DashboardTimeSeries, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	return &DashboardTimeSeries{
		AlertsOverTime: d.timeSeriesCount(&models.Alert{}, cutoff, 0),
	}, nil
}

// GetDashboardTimeSeries returns dashboard-level time-series data
func (d *Database) GetDashboardTimeSeries(hours int) (*DashboardTimeSeries, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &DashboardTimeSeries{
		FlowsOverTime:  d.timeSeriesCount(&models.FlowSample{}, cutoff, 0),
		AlertsOverTime: d.timeSeriesCount(&models.Alert{}, cutoff, 0),
		SyslogOverTime: d.timeSeriesCount(&models.SyslogMessage{}, cutoff, 0),
		TrapsOverTime:  d.timeSeriesCount(&models.TrapEvent{}, cutoff, 0),
	}

	// Device status distribution
	var deviceStatus []struct {
		Status string
		Count  int64
	}
	d.db.Model(&models.Device{}).Where("enabled = ?", true).
		Select("status, COUNT(*) as count").Group("status").Scan(&deviceStatus)
	for _, s := range deviceStatus {
		result.DeviceStatusMap = append(result.DeviceStatusMap, KeyCount{Key: s.Status, Count: s.Count})
	}

	return result, nil
}
