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

// GetFlowInterfaceChartWindow is the sFlow-native counterpart of
// GetInterfaceChartWindow: it buckets flow_if_counters (agent-pushed sFlow
// interface counters) instead of the SNMP-polled interface_stats. It returns the
// SAME InterfaceChartBucket shape with averaged CUMULATIVE octets mapped onto
// in_bytes/out_bytes, so the device-detail frontend's existing delta+rate
// normalisation (normalizeIfaceSeries) renders it identically — the two sources
// stay visually consistent, and sFlow bandwidth is available even where SNMP is
// unreachable/host-restricted. flow_if_counters has no packet counters, so
// in_packets/out_packets stay zero (the frontend's rate/transfer uses bytes).
func (d *Database) GetFlowInterfaceChartWindow(deviceID uint, ifIndex int, from, to time.Time) ([]InterfaceChartBucket, error) {
	if !to.After(from) {
		return []InterfaceChartBucket{}, nil
	}
	if to.Sub(from) > maxChartWindow {
		from = to.Add(-maxChartWindow)
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnitForWindow(to.Sub(from)), "timestamp")

	var rows []InterfaceChartBucket
	err := d.db.Model(&models.FlowInterfaceCounter{}).
		Where("device_id = ? AND if_index = ? AND timestamp > ? AND timestamp <= ?", deviceID, ifIndex, from, to).
		Select(fmt.Sprintf("%s as bucket, AVG(in_octets) as in_bytes, AVG(out_octets) as out_bytes, AVG(in_errors) as in_errors, AVG(out_errors) as out_errors", bucketExpr)).
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

// GetRecentSystemStatus returns up to limit system-status rows for a device
// within the trailing window, NEWEST FIRST (AUDIT-245). It exists for the F17
// baseline builder: GetSystemStatusHistory orders ASC + LIMIT 2000, so on a
// device producing more than 2000 rows per window the limit keeps the OLDEST
// samples and the "trailing 24h baseline" silently becomes a stale one.
// GetSystemStatusHistory itself must keep its ASC ordering — four chart/report
// consumers render it as a left-to-right time series. Rows here are returned
// in DESC order without a reverse: the baseline's mean/stddev is
// order-independent.
func (d *Database) GetRecentSystemStatus(deviceID uint, hours, limit int) ([]models.SystemStatus, error) {
	var statuses []models.SystemStatus
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp DESC").Limit(limit).Find(&statuses).Error
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
//
// Rows with BOTH byte counters zero are excluded from the window: vpn_status
// has a second writer — the collector's SSH phase1/phase2 poll — whose rows
// carry status/remote_ip but no counters. Inside a LAG partition each such row
// reads as a counter reset, and the next real sample then contributes the FULL
// cumulative counter as one "delta" (~the tunnel's lifetime bytes, every SSH
// poll). A both-zero row carries no throughput information either way; a
// genuine reset is still handled by the ELSE clamp on the next nonzero sample.
// vpnDeltaQueryGrouped is vpnDeltaQuery over SEVERAL tunnel names at once, for
// a chart that shows one logical tunnel reported as multiple rows.
//
// The only material difference is the window: PARTITION BY tunnel_name.
// vpnDeltaQuery gets away with a bare `ORDER BY timestamp` because its WHERE
// pins exactly one series — widen that to an IN-list without partitioning and
// LAG walks across interleaved rows from different tunnels, so every delta is
// computed against the wrong predecessor and the whole chart is garbage. This
// is not hypothetical: a FortiGate's two dialup children of one peer share a
// synthesized name today, which is the shape that first exposes it.
//
// Rows with no counters at all are already excluded by the shared
// `NOT (bytes_in = 0 AND bytes_out = 0)` predicate, which is what stops a
// config-derived row (SSH phase1, no counters) from contributing an empty
// series — the cause of the blank half of today's two-chart display.
//
// Scoped to ONE device on purpose. The two ends of a tunnel each report the
// same traffic from their own side; summing across devices would double it.
//
// The same duplication happens WITHIN one device, which is subtler and was a
// live 4x overstatement before this collapse existed. A FortiGate's SNMP table
// carries one counter series per phase1, and the collector writes it once per
// phase2 NAME — so a hub with four phase2 selectors under one phase1 emits four
// rows per poll with byte-identical counters and a microsecond-identical
// timestamp. Those are one measurement reported four times, not four series, and
// summing them multiplies the tunnel's traffic by the number of selectors.
//
// The inner GROUP BY collapses rows that are the same measurement: same device,
// same instant, same counters. MIN(tunnel_name) picks a stable representative
// (the set is identical every poll, so the same name wins every time), which is
// what the window then partitions by. Members with genuinely independent
// counters differ in at least one counter and so survive as separate series and
// still sum — which is the whole point of a group chart.
func vpnDeltaQueryGrouped(bucketExpr, timeWhere string) string {
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
			FROM (
				SELECT MIN(tunnel_name) as tunnel_name, timestamp,
					bytes_in, bytes_out, packets_in, packets_out
				FROM vpn_status
				WHERE device_id = ? AND tunnel_name IN (?) AND %s
					AND NOT (bytes_in = 0 AND bytes_out = 0)
				GROUP BY timestamp, bytes_in, bytes_out, packets_in, packets_out
			) AS src
			WINDOW w AS (PARTITION BY tunnel_name ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY bucket ORDER BY bucket ASC`, bucketExpr, timeWhere)
}

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
				AND NOT (bytes_in = 0 AND bytes_out = 0)
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

// GetVPNChartGroupWindow returns per-bucket deltas summed across every tunnel
// name that makes up ONE logical tunnel on ONE device.
//
// It exists because a single tunnel is reported as several rows under unrelated
// names (see models.VPNStatus.TunnelGroup), so the per-name chart shows a
// fraction of the traffic — or, for a config-derived row, nothing at all.
// Callers pass the names of one group; scoping to a single device is the
// caller's job and is deliberate, since both ends report the same bytes.
func (d *Database) GetVPNChartGroupWindow(deviceID uint, tunnelNames []string, from, to time.Time) ([]VPNChartBucket, error) {
	if len(tunnelNames) == 0 || !to.After(from) {
		return []VPNChartBucket{}, nil
	}
	// One name is the overwhelmingly common case; use the single-series query so
	// grouping cannot change existing behaviour for it.
	if len(tunnelNames) == 1 {
		return d.GetVPNChartWindow(deviceID, tunnelNames[0], from, to)
	}
	if to.Sub(from) > maxChartWindow {
		from = to.Add(-maxChartWindow)
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnitForWindow(to.Sub(from)), "timestamp")

	var rows []VPNChartBucket
	err := d.db.Raw(vpnDeltaQueryGrouped(bucketExpr, "timestamp > ? AND timestamp <= ?"),
		deviceID, tunnelNames, from, to).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].BucketMs = parseBucketToMillis(rows[i].Bucket)
	}
	return rows, nil
}

// VPNWindowTotal is one tunnel's reset-safe byte delta over a window.
type VPNWindowTotal struct {
	TunnelName string `json:"tunnel_name"`
	InBytes    uint64 `json:"in_bytes"`
	OutBytes   uint64 `json:"out_bytes"`
}

// GetVPNWindowTotalsByTunnel returns each named tunnel's total delta over the
// window, keyed by its own name.
//
// This is deliberately NOT vpnDeltaQueryGrouped with the buckets summed. That
// query collapses rows that are the same measurement — same instant, identical
// counters — which is correct for a chart of one logical tunnel but destroys the
// only thing this function exists to provide: attribution to a specific phase2
// name. Two genuinely distinct OPNsense children whose counters coincide for a
// single poll would be merged into one series and one of them would silently
// report nothing. Observed on connection 23984, so not hypothetical.
//
// The reset clamp and the both-zero exclusion carry over unchanged: a config
// row that counts nothing must not enter a series, and a child SA that rekeys
// mid-window must contribute its post-reset bytes rather than a negative.
func (d *Database) GetVPNWindowTotalsByTunnel(deviceID uint, tunnelNames []string, from, to time.Time) (map[string]VPNWindowTotal, error) {
	out := map[string]VPNWindowTotal{}
	if len(tunnelNames) == 0 || !to.After(from) {
		return out, nil
	}
	var rows []VPNWindowTotal
	err := d.db.Raw(`
		SELECT tunnel_name, SUM(delta_in) as in_bytes, SUM(delta_out) as out_bytes
		FROM (
			SELECT tunnel_name,
				CASE WHEN LAG(bytes_in) OVER w IS NULL THEN NULL
					WHEN bytes_in >= LAG(bytes_in) OVER w THEN bytes_in - LAG(bytes_in) OVER w
					ELSE bytes_in END as delta_in,
				CASE WHEN LAG(bytes_out) OVER w IS NULL THEN NULL
					WHEN bytes_out >= LAG(bytes_out) OVER w THEN bytes_out - LAG(bytes_out) OVER w
					ELSE bytes_out END as delta_out
			FROM vpn_status
			WHERE device_id = ? AND tunnel_name IN (?)
				AND timestamp > ? AND timestamp <= ?
				AND NOT (bytes_in = 0 AND bytes_out = 0)
			WINDOW w AS (PARTITION BY tunnel_name ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY tunnel_name`, deviceID, tunnelNames, from, to).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.TunnelName] = r
	}
	return out, nil
}

// VPNCounterProvenance says how far a device's per-phase2 counters can be
// trusted to mean "this path", as opposed to "this tunnel, repeated".
type VPNCounterProvenance struct {
	// SharedCounter: this device replicates ONE counter series across all the
	// group's phase2 names, so no per-path number can be attributed. A FortiGate
	// does this — its SNMP table carries one series per phase1 and the collector
	// writes it once per phase2 name.
	SharedCounter bool `json:"shared_counter"`
	// Interleaved names carry MORE THAN ONE child under a single name, so a
	// LAG partition walks two counter series as if they were one and every
	// alternation reads as a reset. A FortiGate's two dialup children of one
	// peer share a synthesized name today.
	Interleaved map[string]bool `json:"interleaved,omitempty"`
}

// GetVPNCounterProvenance derives both signals in one pass over the window.
//
// SharedCounter is a RATIO, never "did it ever happen". Two independent children
// legitimately report identical counters at the odd poll — observed on connection
// 23984 — so a `> 0` test would condemn the one device that does report real
// per-path numbers. A device that genuinely replicates collapses at essentially
// every instant where more than one of its names reported, hence the 90% floor.
//
// Interleaved needs a different predicate entirely and cannot come from the
// collapse count: its shape is ONE name at one instant with DIFFERING counters,
// which lands in separate collapse groups and never registers as a collapse.
func (d *Database) GetVPNCounterProvenance(deviceID uint, tunnelNames []string, from, to time.Time) (VPNCounterProvenance, error) {
	p := VPNCounterProvenance{Interleaved: map[string]bool{}}
	if len(tunnelNames) == 0 || !to.After(from) {
		return p, nil
	}

	// Per instant: how many distinct names reported, and how many distinct
	// counter tuples they carried. names > tuples => a collapse happened.
	var stamps []struct {
		Names  int64
		Tuples int64
	}
	if err := d.db.Raw(`
		SELECT COUNT(DISTINCT tunnel_name) as names,
		       COUNT(DISTINCT CAST(bytes_in AS TEXT) || '/' || CAST(bytes_out AS TEXT)) as tuples
		FROM vpn_status
		WHERE device_id = ? AND tunnel_name IN (?)
			AND timestamp > ? AND timestamp <= ?
			AND NOT (bytes_in = 0 AND bytes_out = 0)
		GROUP BY timestamp`, deviceID, tunnelNames, from, to).Scan(&stamps).Error; err != nil {
		return p, err
	}
	var eligible, collapsed int
	for _, s := range stamps {
		if s.Names < 2 {
			continue // one reporter proves nothing either way
		}
		eligible++
		if s.Tuples < s.Names {
			collapsed++
		}
	}
	// A floor as well as a ratio. With one eligible sample a single coincidental
	// collapse is 100%, which would condemn the very device that DOES report
	// per-path numbers — the outcome the ratio exists to prevent. Five samples is
	// under a minute of polling, and the flag self-heals as the window fills.
	const minSamplesForVerdict = 5
	if eligible >= minSamplesForVerdict && float64(collapsed)/float64(eligible) >= 0.9 {
		p.SharedCounter = true
	}

	// A name that appears more than once at the same instant is two children
	// wearing one name.
	//
	// Filtered to counting rows for the same reason the delta query is: this flag
	// exists because a LAG partition would walk two counter series as if they
	// were one, and a row with no counters never enters that partition. Without
	// the filter, one counting row plus one 0/0 row at the same instant would
	// flag a series whose deltas are perfectly clean, and the UI would suppress a
	// real number.
	var dupes []struct{ TunnelName string }
	if err := d.db.Raw(`
		SELECT tunnel_name FROM vpn_status
		WHERE device_id = ? AND tunnel_name IN (?)
			AND timestamp > ? AND timestamp <= ?
			AND NOT (bytes_in = 0 AND bytes_out = 0)
		GROUP BY tunnel_name, timestamp HAVING COUNT(*) > 1`,
		deviceID, tunnelNames, from, to).Scan(&dupes).Error; err != nil {
		return p, err
	}
	for _, r := range dupes {
		p.Interleaved[r.TunnelName] = true
	}
	return p, nil
}
