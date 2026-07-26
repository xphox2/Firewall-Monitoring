package database

import (
	"fmt"
	"time"

	"firewall-mon/internal/models"
)

// SaveServerMetric records one sample of the Firewall-Mon server's own resource
// usage. Written by the poller's server-health tick; never on an API path.
func (d *Database) SaveServerMetric(m *models.ServerMetric) error {
	return d.db.Create(m).Error
}

// ServerMetricBucket is one aggregated point on the server charts.
//
// The data-disk fields are POINTERS all the way through. A sample taken while
// the database volume was unprobeable stores NULL, and AVG() over a bucket
// containing only such rows yields NULL — which must reach the client as null so
// the chart omits the point. Coercing it to 0 would draw a 0%-used flatline:
// "the probe failed" rendered as "the disk is empty", which is the same
// failure-reads-as-healthy shape that let the disk fill unnoticed.
type ServerMetricBucket struct {
	Bucket            string   `json:"bucket"`
	BucketMS          int64    `json:"bucket_ms"`
	CPUPercent        float64  `json:"cpu_percent"`
	MemPercent        float64  `json:"mem_percent"`
	Load1             float64  `json:"load1"`
	RootDiskPercent   float64  `json:"root_disk_percent"`
	RootDiskFreeBytes float64  `json:"root_disk_free_bytes"`
	DataDiskPercent   *float64 `json:"data_disk_percent"`
	DataDiskFreeBytes *float64 `json:"data_disk_free_bytes"`
}

// GetServerMetricWindow returns bucketed server metrics between from and to.
//
// Bucketing is adaptive like the device charts, but floors at 5 minutes because
// that is the sampling cadence — minute buckets would yield mostly-empty bins
// with one populated in five.
func (d *Database) GetServerMetricWindow(from, to time.Time) ([]ServerMetricBucket, error) {
	unit := bucketUnitForWindow(to.Sub(from))
	if unit == "minute" {
		unit = "hour"
	}
	bucketExpr := d.dialect.TimeBucket(unit, "timestamp")

	var rows []ServerMetricBucket
	q := fmt.Sprintf(`
		SELECT %s as bucket,
			AVG(cpu_percent) as cpu_percent,
			AVG(mem_percent) as mem_percent,
			AVG(load1) as load1,
			AVG(root_disk_percent) as root_disk_percent,
			AVG(root_disk_free_bytes) as root_disk_free_bytes,
			AVG(data_disk_percent) as data_disk_percent,
			AVG(data_disk_free_bytes) as data_disk_free_bytes
		FROM server_metrics
		WHERE timestamp > ? AND timestamp <= ?
		GROUP BY bucket ORDER BY bucket ASC`, bucketExpr)
	if err := d.db.Raw(q, from, to).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}
