package database

import (
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// Boundary sampling for the public dashboard charts.
//
// The public bandwidth tile used to read EVERY interface_stats row of the
// window and keep every Nth one in Go: at the 1-year range that was 82,323
// rows and ~76k buffers (~600 MB of heap) for one tile, 5.7 s cold on
// production, fired once per tile at the same moment. The counters are
// cumulative, so the average rate over an interval only needs the samples at
// its two ends — the handler already computes rates between the rows it keeps.
// These readers return just those rows: the earliest row in each of `buckets`
// equal intervals, plus the newest row in the window so the chart reaches
// "now". On production the PostgreSQL form below reads 1,585 buffers in
// 6.4 ms at the 1-year range.
//
// Zone: interface_stats and system_status are written with time.Now() in the
// process zone, so the bounds here are used as the caller computes them from
// time.Now() and are NOT converted to UTC. PostgreSQL compares instants, so the
// zone is irrelevant there; SQLite compares the rendered text, offset
// included, so a bound in another zone than the rows would compare wrongly.

const (
	minSampleBuckets = 2
	maxSampleBuckets = 1000
)

// sampleSpec names the table and the equality filter that selects one series.
type sampleSpec struct {
	table    string
	keyWhere string
	keyArgs  []interface{}
}

// SampleInterfaceStats returns the boundary samples of one interface's
// counters over [from, to]; see the file comment.
func (d *Database) SampleInterfaceStats(deviceID uint, ifIndex int, from, to time.Time, buckets int) ([]models.InterfaceStats, error) {
	var rows []models.InterfaceStats
	spec := sampleSpec{"interface_stats", `device_id = ? AND "index" = ?`, []interface{}{deviceID, ifIndex}}
	if err := d.sampleRows(spec, from, to, buckets, &rows); err != nil {
		return nil, err
	}
	return dropTrailingSameInstant(rows, func(r models.InterfaceStats) time.Time { return r.Timestamp }), nil
}

// SampleSystemStatus returns the boundary samples of one device's status rows
// over [from, to]. CPU and memory are gauges, so these are instantaneous
// readings at each boundary, not averages over the interval.
func (d *Database) SampleSystemStatus(deviceID uint, from, to time.Time, buckets int) ([]models.SystemStatus, error) {
	var rows []models.SystemStatus
	spec := sampleSpec{"system_status", `device_id = ?`, []interface{}{deviceID}}
	if err := d.sampleRows(spec, from, to, buckets, &rows); err != nil {
		return nil, err
	}
	return dropTrailingSameInstant(rows, func(r models.SystemStatus) time.Time { return r.Timestamp }), nil
}

// sampleRows runs the dialect's sampling statement into dest.
func (d *Database) sampleRows(spec sampleSpec, from, to time.Time, buckets int, dest interface{}) error {
	if buckets < minSampleBuckets {
		buckets = minSampleBuckets
	}
	if buckets > maxSampleBuckets {
		buckets = maxSampleBuckets
	}
	step := to.Sub(from) / time.Duration(buckets)
	if step <= 0 {
		return nil
	}
	var sql string
	var args []interface{}
	if d.dialect.IsPostgres() {
		sql, args = lateralSampleSQL(spec, from, to, step, buckets)
	} else {
		sql, args = portableSampleSQL(spec, from, to, step, buckets)
	}
	return d.db.Raw(sql, args...).Scan(dest).Error
}

// lateralSampleSQL is the PostgreSQL statement: one index probe per bucket
// through LATERAL, planned once. The bucket edges are computed in SQL from an
// integer series — interval arithmetic on a bound parameter (`$n - $m`) is an
// ambiguous-operator error — so each probe is `[from + step·i, from + step·(i+1))`.
// The newest-row arm covers [from, to]. `, id` breaks same-instant ties the
// same way in every arm and in the portable form.
func lateralSampleSQL(spec sampleSpec, from, to time.Time, step time.Duration, buckets int) (string, []interface{}) {
	sql := fmt.Sprintf(`(SELECT s.* FROM generate_series(0, ? - 1) AS g(i)
  CROSS JOIN LATERAL (
    SELECT * FROM %[1]s
    WHERE %[2]s
      AND timestamp >= ?::timestamptz + make_interval(secs => ?) * g.i
      AND timestamp <  ?::timestamptz + make_interval(secs => ?) * (g.i + 1)
    ORDER BY timestamp, id LIMIT 1) s)
UNION ALL
(SELECT * FROM %[1]s WHERE %[2]s AND timestamp >= ? AND timestamp <= ?
  ORDER BY timestamp DESC, id DESC LIMIT 1)
ORDER BY timestamp, id`, spec.table, spec.keyWhere)
	secs := step.Seconds()
	args := []interface{}{buckets}
	args = append(args, spec.keyArgs...)
	args = append(args, from, secs, from, secs)
	args = append(args, spec.keyArgs...)
	args = append(args, from, to)
	return sql, args
}

// portableSampleSQL selects the same rows without LATERAL, which SQLite does
// not have: an IN-list of scalar subqueries, one per bucket plus the newest
// row. Not a UNION ALL compound, which SQLite caps at 500 terms. The edges are
// computed in Go (nanoseconds) where PostgreSQL computes them in microseconds;
// for every range the public dashboard sends the step is a whole number of
// seconds, so the two coincide. Valid on PostgreSQL too.
func portableSampleSQL(spec sampleSpec, from, to time.Time, step time.Duration, buckets int) (string, []interface{}) {
	probes := make([]string, 0, buckets+1)
	args := make([]interface{}, 0, (buckets+1)*(len(spec.keyArgs)+2))
	for i := 0; i < buckets; i++ {
		probes = append(probes, fmt.Sprintf(
			"(SELECT id FROM %s WHERE %s AND timestamp >= ? AND timestamp < ? ORDER BY timestamp, id LIMIT 1)",
			spec.table, spec.keyWhere))
		args = append(args, spec.keyArgs...)
		args = append(args, from.Add(time.Duration(i)*step), from.Add(time.Duration(i+1)*step))
	}
	probes = append(probes, fmt.Sprintf(
		"(SELECT id FROM %s WHERE %s AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC, id DESC LIMIT 1)",
		spec.table, spec.keyWhere))
	args = append(args, spec.keyArgs...)
	args = append(args, from, to)
	sql := fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s) ORDER BY timestamp, id",
		spec.table, strings.Join(probes, ", "))
	return sql, args
}

// dropTrailingSameInstant removes the newest-row arm's row when it shares its
// timestamp with the row before it. Buckets are disjoint and each yields one
// row, so the only possible equal-timestamp pair is the last bucket's row and
// the newest row: identical when the newest row IS that bucket's earliest, or
// a same-instant duplicate (the FortiGate path writes those). Keeping both
// would emit a point with zero elapsed time, which the rate calculation turns
// into a spurious 0. Rows arrive ordered by (timestamp, id), so the newest-arm
// row — highest id on a tie — is last.
func dropTrailingSameInstant[T any](rows []T, ts func(T) time.Time) []T {
	n := len(rows)
	if n >= 2 && ts(rows[n-1]).Equal(ts(rows[n-2])) {
		return rows[:n-1]
	}
	return rows
}

// SystemStatusSummary is a device's CPU/memory over a window, as the report
// shows it.
type SystemStatusSummary struct {
	N            int64
	CPUAvg       float64
	CPUMax       float64
	MemAvg       float64
	MemMax       float64
	DiskUsage    float64 // from the newest row in the window
	SessionCount int     // from the newest row in the window
}

// GetSystemStatusSummary aggregates every status row of the window in SQL. The
// report used to average the rows GetSystemStatusHistory returned, but that
// returns the OLDEST 2,000 rows — about 31 hours at production's ~1,500 rows a
// day — so a weekly report described its first day and a half, and took disk
// usage and session count from a 31-hour-old row. The mean is still an
// unweighted mean of rows (both status writers counted alike, as before), now
// over the whole window. With no rows every field is zero.
func (d *Database) GetSystemStatusSummary(deviceID uint, from, to time.Time) (SystemStatusSummary, error) {
	var s SystemStatusSummary
	const newest = `FROM system_status WHERE device_id = ? AND timestamp > ? AND timestamp <= ? ORDER BY timestamp DESC, id DESC LIMIT 1`
	err := d.db.Raw(`SELECT COUNT(*) AS n,
		COALESCE(AVG(cpu_usage), 0) AS cpu_avg, COALESCE(MAX(cpu_usage), 0) AS cpu_max,
		COALESCE(AVG(memory_usage), 0) AS mem_avg, COALESCE(MAX(memory_usage), 0) AS mem_max,
		COALESCE((SELECT disk_usage `+newest+`), 0) AS disk_usage,
		COALESCE((SELECT session_count `+newest+`), 0) AS session_count
		FROM system_status WHERE device_id = ? AND timestamp > ? AND timestamp <= ?`,
		deviceID, from, to, deviceID, from, to, deviceID, from, to).Scan(&s).Error
	return s, err
}
