package database

import (
	"fmt"
	"log"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// InterfaceChartBucket holds a single time-bucket for interface chart data.
type InterfaceChartBucket struct {
	Bucket     string  `json:"bucket"`
	BucketMs   int64   `json:"bucket_ms"` // epoch ms, derived for the chart x-axis + drag-to-zoom windowing
	InBytes    float64 `json:"in_bytes"`
	OutBytes   float64 `json:"out_bytes"`
	InPackets  float64 `json:"in_packets"`
	OutPackets float64 `json:"out_packets"`
	InErrors   float64 `json:"in_errors"`
	OutErrors  float64 `json:"out_errors"`
}

// bucketUnitForWindow picks a TimeBucket granularity that keeps a chart for the
// given span readable — roughly 90–360 points — instead of cramming raw
// poll-cadence samples in. It backs the drag-to-zoom re-query: a narrower
// window selects a finer bucket, revealing detail that was averaged away at the
// wider zoom. Units must exist in dialect.go's TimeBucket.
func bucketUnitForWindow(dur time.Duration) string {
	switch {
	case dur <= 3*time.Hour:
		return "minute" // ≤180 pts
	case dur <= 30*time.Hour:
		return "5min" // ≤360 pts (24h → 288)
	case dur <= 8*24*time.Hour:
		return "hour" // ≤192 pts (7d → 168)
	case dur <= 60*24*time.Hour:
		return "6hour" // ≤240 pts (30d → 120)
	default:
		return "day" // ≤366 pts (1y)
	}
}

// maxChartWindow caps a chart window so a pathological from/to can't ask the DB
// to bucket centuries of rows.
const maxChartWindow = 400 * 24 * time.Hour

// GetInterfaceChartData returns downsampled interface stats for charting.
func (d *Database) GetInterfaceChartData(deviceID uint, ifIndex int, rangeStr string) ([]InterfaceChartBucket, error) {
	var hours int
	var bucketExpr string
	switch rangeStr {
	case "7d":
		hours = 168
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "30d":
		hours = 720
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "90d":
		hours = 2160
		bucketExpr = d.dialect.TimeBucket("day", "timestamp")
	default: // 24h
		hours = 24
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	quotedIndex := d.dialect.QuoteIdent("index")

	var rows []InterfaceChartBucket
	err := d.db.Model(&models.InterfaceStats{}).
		Where(fmt.Sprintf("device_id = ? AND %s = ? AND timestamp > ?", quotedIndex), deviceID, ifIndex, cutoff).
		Select(fmt.Sprintf("%s as bucket, AVG(in_bytes) as in_bytes, AVG(out_bytes) as out_bytes, AVG(in_packets) as in_packets, AVG(out_packets) as out_packets, AVG(in_errors) as in_errors, AVG(out_errors) as out_errors", bucketExpr)).
		Group("bucket").Order("bucket ASC").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// GetInterfaceChartWindow returns downsampled interface stats for an explicit
// [from, to] window with an adaptive bucket size (see bucketUnitForWindow) and
// a per-row epoch-ms timestamp. It backs the admin chart's default range view
// AND its drag-to-zoom re-query: the frontend selects a sub-window and asks for
// it back at finer resolution. GetInterfaceChartData (fixed minute/hour/day
// bucketing, no bucket_ms) is left untouched for the report + connection-detail
// consumers that depend on its exact granularity.
func (d *Database) GetInterfaceChartWindow(deviceID uint, ifIndex int, from, to time.Time) ([]InterfaceChartBucket, error) {
	if !to.After(from) {
		return []InterfaceChartBucket{}, nil
	}
	if to.Sub(from) > maxChartWindow {
		from = to.Add(-maxChartWindow)
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnitForWindow(to.Sub(from)), "timestamp")
	quotedIndex := d.dialect.QuoteIdent("index")

	var rows []InterfaceChartBucket
	err := d.db.Model(&models.InterfaceStats{}).
		Where(fmt.Sprintf("device_id = ? AND %s = ? AND timestamp > ? AND timestamp <= ?", quotedIndex), deviceID, ifIndex, from, to).
		Select(fmt.Sprintf("%s as bucket, AVG(in_bytes) as in_bytes, AVG(out_bytes) as out_bytes, AVG(in_packets) as in_packets, AVG(out_packets) as out_packets, AVG(in_errors) as in_errors, AVG(out_errors) as out_errors", bucketExpr)).
		Group("bucket").Order("bucket ASC").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].BucketMs = parseBucketToMillis(rows[i].Bucket)
	}
	return rows, nil
}

// GetSystemStatusHistory returns time-series system status data for a device
func (d *Database) GetSystemStatusHistory(deviceID uint, hours int) ([]models.SystemStatus, error) {
	var statuses []models.SystemStatus
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp ASC").Limit(2000).Find(&statuses).Error
	return statuses, err
}

// SystemStatusBucket holds a single time-bucket for system-status charting.
// Mirrors InterfaceChartBucket but for the per-device system metrics
// surfaced on the device-detail page (CPU, memory, disk, sessions, network
// throughput). All numeric fields are AVG over the bucket window.
type SystemStatusBucket struct {
	Bucket         string  `json:"bucket"`
	BucketMillis   int64   `json:"bucket_ms"` // epoch ms, derived for the chart x-axis
	CPUUsage       float64 `json:"cpu_usage"`
	MemoryUsage    float64 `json:"memory_usage"`
	DiskUsage      float64 `json:"disk_usage"`
	SessionCount   float64 `json:"session_count"`
	NetworkInKbps  float64 `json:"network_in_kbps"`
	NetworkOutKbps float64 `json:"network_out_kbps"`
	CPUUser        float64 `json:"cpu_user"`
	CPUSystem      float64 `json:"cpu_system"`
	CPUIdle        float64 `json:"cpu_idle"`
	CPUIOWait      float64 `json:"cpu_iowait"`
	CPUIRQ         float64 `json:"cpu_irq"`
	CPUSoftIRQ     float64 `json:"cpu_softirq"`
	CPUNice        float64 `json:"cpu_nice"`
}

// GetSystemStatusBuckets returns server-side-bucketed system status data for
// the device-detail page charts. Mirrors GetInterfaceChartData's pattern:
// pick a bucket size based on the requested range, AVG raw poll samples into
// fixed bins, return one row per bin. Replaces the previous "ship raw
// poll-cadence rows" behavior, which capped at 2000 points and looked spiky
// because every poll outlier was rendered as-is.
//
// rangeStr accepts: 1h, 6h, 12h, 24h, 7d, 30d, 90d, 365d. Unknown values
// fall back to 24h. Bucket sizes are tuned so each range produces between
// ~60 and ~720 buckets — enough resolution to see real movement, few enough
// to draw cleanly without LTTB downsampling on the client.
func (d *Database) GetSystemStatusBuckets(deviceID uint, rangeStr string) ([]SystemStatusBucket, error) {
	var hours int
	var bucketExpr string
	// Bucket-size tuning (v0.10.209): the goal is to keep each range under
	// roughly 300 points so a typical 800-1000px chart gets multiple pixels
	// per bucket. Minute-cadence buckets at 6h+ produced 360-1440 points
	// each, which painted as sub-pixel-spaced jitter — the "tiny bumps"
	// the user complained about. Switching the 6h/12h/24h ranges to 5-minute
	// buckets reduces the count to 72/144/288 respectively, smoothing the
	// visual without losing real movement (5-min AVG still catches every
	// real sustained change in CPU/memory/network).
	switch rangeStr {
	case "1h":
		hours = 1
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	case "6h":
		hours = 6
		bucketExpr = d.dialect.TimeBucket("5min", "timestamp")
	case "12h":
		hours = 12
		bucketExpr = d.dialect.TimeBucket("5min", "timestamp")
	case "7d":
		hours = 168
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "30d":
		hours = 720
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "90d":
		hours = 2160
		bucketExpr = d.dialect.TimeBucket("day", "timestamp")
	case "365d":
		hours = 8760
		bucketExpr = d.dialect.TimeBucket("day", "timestamp")
	default: // 24h
		hours = 24
		bucketExpr = d.dialect.TimeBucket("5min", "timestamp")
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	type row struct {
		Bucket         string
		CPUUsage       float64
		MemoryUsage    float64
		DiskUsage      float64
		SessionCount   float64
		NetworkInKbps  float64
		NetworkOutKbps float64
		CPUUser        float64
		CPUSystem      float64
		CPUIdle        float64
		CPUIOWait      float64
		CPUIRQ         float64
		CPUSoftIRQ     float64
		CPUNice        float64
	}
	var rows []row
	err := d.db.Model(&models.SystemStatus{}).
		Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Select(fmt.Sprintf(`%s as bucket,
			AVG(cpu_usage) as cpu_usage,
			AVG(memory_usage) as memory_usage,
			AVG(disk_usage) as disk_usage,
			AVG(session_count) as session_count,
			AVG(network_in_kbps) as network_in_kbps,
			AVG(network_out_kbps) as network_out_kbps,
			AVG(cpu_user) as cpu_user,
			AVG(cpu_system) as cpu_system,
			AVG(cpu_idle) as cpu_idle,
			AVG(cpu_iowait) as cpu_iowait,
			AVG(cpu_irq) as cpu_irq,
			AVG(cpu_softirq) as cpu_softirq,
			AVG(cpu_nice) as cpu_nice`, bucketExpr)).
		Group("bucket").Order("bucket ASC").Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	out := make([]SystemStatusBucket, 0, len(rows))
	for _, r := range rows {
		millis := parseBucketToMillis(r.Bucket)
		// AUDIT-145: skip rows whose bucket string we couldn't
		// parse. Pre-fix these would render as 1970 datapoints in
		// the chart. Filtering at the data layer (vs. letting the
		// chart deal with the sentinel) means the API response
		// itself is clean — `bucket_ms` is always a real epoch
		// value, never -1.
		if millis == bucketUnparseableMillis {
			log.Printf("system_status time-series: skipping row with unparseable bucket %q", r.Bucket)
			continue
		}
		out = append(out, SystemStatusBucket{
			Bucket:         r.Bucket,
			BucketMillis:   millis,
			CPUUsage:       r.CPUUsage,
			MemoryUsage:    r.MemoryUsage,
			DiskUsage:      r.DiskUsage,
			SessionCount:   r.SessionCount,
			NetworkInKbps:  r.NetworkInKbps,
			NetworkOutKbps: r.NetworkOutKbps,
			CPUUser:        r.CPUUser,
			CPUSystem:      r.CPUSystem,
			CPUIdle:        r.CPUIdle,
			CPUIOWait:      r.CPUIOWait,
			CPUIRQ:         r.CPUIRQ,
			CPUSoftIRQ:     r.CPUSoftIRQ,
			CPUNice:        r.CPUNice,
		})
	}
	return out, nil
}

// parseBucketToMillis converts the dialect's TimeBucket() string output to
// epoch milliseconds for the chart x-axis. Postgres date_trunc returns ISO
// timestamps; SQLite strftime returns "2006-01-02 15:04" or "2006-01-02"
// depending on the bucket size. Both forms are parsed here.
//
// AUDIT-145: the pre-fix return value for an unparseable input was 0
// (Jan 1 1970 epoch ms), which the chart then rendered as a literal
// "1970" datapoint. The pre-fix assumption was that the bucket
// string is always well-formed (database produced it, the format
// is known) — but a future migration that changes the bucket format
// without updating this function, or a corrupted row that lost the
// bucket column, would surface as a 1970 spike in every chart. The
// fix: return the sentinel `bucketUnparseableMillis = -1` for
// unparseable inputs, and have the consuming code skip the
// row entirely. -1 is a fine sentinel here because the input set
// (year >= 2000, anything after the platform epoch) never
// legitimately produces a negative UnixMilli.
const bucketUnparseableMillis int64 = -1

// BucketMillisUnparseableSentinel is the value parseBucketToMillis
// returns for an input it can't parse. Exposed (with a doc comment
// rather than as a public const) so the regression test can pin
// the contract without re-reading the implementation.
func BucketMillisUnparseableSentinel() int64 { return bucketUnparseableMillis }

func parseBucketToMillis(bucket string) int64 {
	if strings.TrimSpace(bucket) == "" {
		return bucketUnparseableMillis
	}
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, bucket); err == nil {
			return t.UnixMilli()
		}
	}
	return bucketUnparseableMillis
}

// GetPingResultHistory returns time-series ping results for a device
func (d *Database) GetPingResultHistory(deviceID uint, hours int) ([]models.PingResult, error) {
	var results []models.PingResult
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp ASC").Limit(2000).Find(&results).Error
	return results, err
}

// VPNChartBucket holds a single time-bucket for VPN tunnel chart data.
type VPNChartBucket struct {
	Bucket     string  `json:"bucket"`
	BucketMs   int64   `json:"bucket_ms"` // epoch ms, derived for the chart x-axis + drag-to-zoom windowing
	InBytes    float64 `json:"in_bytes"`
	OutBytes   float64 `json:"out_bytes"`
	InPackets  float64 `json:"in_packets"`
	OutPackets float64 `json:"out_packets"`
}

// GetVPNChartData returns downsampled VPN tunnel stats for charting.
func (d *Database) GetVPNChartData(deviceID uint, tunnelName string, rangeStr string) ([]VPNChartBucket, error) {
	var hours int
	var bucketExpr string
	switch rangeStr {
	case "1h":
		hours = 1
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	case "7d":
		hours = 168
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "30d":
		hours = 720
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	default: // 24h
		hours = 24
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	var rows []VPNChartBucket
	err := d.db.Raw(vpnDeltaQuery(bucketExpr, "timestamp > ?"), deviceID, tunnelName, cutoff).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// vpnDeltaQuery builds the LAG()-based per-bucket delta query for VPN tunnel
// traffic. timeWhere is the timestamp predicate ("timestamp > ?" for a cutoff,
// "timestamp > ? AND timestamp <= ?" for an explicit window); its placeholders
// are bound after device_id and tunnel_name.
//
// Use LAG() to compute per-sample deltas from cumulative SNMP counters. The
// first row per partition (LAG is NULL) returns NULL and is filtered by the
// outer WHERE. Counter resets (new value < old value) use the raw value as the
// delta. AUDIT-043: the named `WINDOW w AS (...)` clause runs on BOTH Postgres
// (prod) and the modernc SQLite test backend — no dialect gating needed.
// `vpnchart_window_audit043_test.go` exercises this path on SQLite and pins the
// delta + reset-clamp math.
func vpnDeltaQuery(bucketExpr, timeWhere string) string {
	return fmt.Sprintf(`
		SELECT bucket, SUM(delta_in) as in_bytes, SUM(delta_out) as out_bytes,
		       SUM(delta_pin) as in_packets, SUM(delta_pout) as out_packets
		FROM (
			SELECT %s as bucket,
				CASE WHEN LAG(bytes_in) OVER w IS NULL THEN NULL
					WHEN bytes_in >= LAG(bytes_in) OVER w THEN bytes_in - LAG(bytes_in) OVER w
					ELSE bytes_in END as delta_in,
				CASE WHEN LAG(bytes_out) OVER w IS NULL THEN NULL
					WHEN bytes_out >= LAG(bytes_out) OVER w THEN bytes_out - LAG(bytes_out) OVER w
					ELSE bytes_out END as delta_out,
				CASE WHEN LAG(packets_in) OVER w IS NULL THEN NULL
					WHEN packets_in >= LAG(packets_in) OVER w THEN packets_in - LAG(packets_in) OVER w
					ELSE packets_in END as delta_pin,
				CASE WHEN LAG(packets_out) OVER w IS NULL THEN NULL
					WHEN packets_out >= LAG(packets_out) OVER w THEN packets_out - LAG(packets_out) OVER w
					ELSE packets_out END as delta_pout
			FROM vpn_status
			WHERE device_id = ? AND tunnel_name = ? AND %s
			WINDOW w AS (ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY bucket ORDER BY bucket ASC`, bucketExpr, timeWhere)
}

// GetVPNChartWindow returns per-bucket VPN tunnel deltas for an explicit
// [from, to] window with adaptive bucketing and per-row epoch-ms timestamps.
// Backs the admin/connection-detail tunnel chart's default view and its
// drag-to-zoom re-query. GetVPNChartData (fixed bucketing, no bucket_ms) is
// retained for its regression test.
func (d *Database) GetVPNChartWindow(deviceID uint, tunnelName string, from, to time.Time) ([]VPNChartBucket, error) {
	if !to.After(from) {
		return []VPNChartBucket{}, nil
	}
	if to.Sub(from) > maxChartWindow {
		from = to.Add(-maxChartWindow)
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnitForWindow(to.Sub(from)), "timestamp")

	var rows []VPNChartBucket
	err := d.db.Raw(vpnDeltaQuery(bucketExpr, "timestamp > ? AND timestamp <= ?"), deviceID, tunnelName, from, to).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].BucketMs = parseBucketToMillis(rows[i].Bucket)
	}
	return rows, nil
}
