package database

import (
	"context"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// Reads behind the raw archive's status (archive plan PR 8): the admin status
// API, `fwmon-api archive --status` and the archive alerts
// (internal/archive/status). All of them are short reads of the manifest
// tables; nothing here writes except the worker's own runtime snapshot.

// ArchiveWorkerStateKey is the system setting the archive worker writes its
// runtime state to (JSON, internal/archive/status.Runtime) under its advisory
// lock, about once a minute: what the database does not hold — why a table's
// next chunk waits and who holds it, the last error of each stage, the
// staging directory's free space. The API runs in another process and reads
// it from here.
const ArchiveWorkerStateKey = "archive_worker_state"

// SaveArchiveWorkerState stores the worker's runtime snapshot.
func (d *Database) SaveArchiveWorkerState(ctx context.Context, value string) error {
	return d.WithContext(ctx).UpsertSetting(&models.SystemSetting{
		Key: ArchiveWorkerStateKey, Value: value, Type: "json", Category: "archive",
		Label: "Archive worker runtime state (written by the poller)",
	})
}

// ArchiveWorkerState reads the worker's runtime snapshot; ok is false while
// none was written. A Pluck, not GetSettingValue: First's "record not found"
// would log on every read of an install that never archived.
func (d *Database) ArchiveWorkerState(ctx context.Context) (value string, ok bool, err error) {
	var vals []string
	if err := d.db.WithContext(ctx).Model(&models.SystemSetting{}).Where("\"key\" = ?", ArchiveWorkerStateKey).
		Limit(1).Pluck("value", &vals).Error; err != nil {
		return "", false, err
	}
	if len(vals) == 0 || strings.TrimSpace(vals[0]) == "" {
		return "", false, nil
	}
	return vals[0], true, nil
}

// ArchiveMonthRows returns stream's archive_months rows, oldest first.
func (d *Database) ArchiveMonthRows(ctx context.Context, stream string) ([]models.ArchiveMonth, error) {
	var ms []models.ArchiveMonth
	err := d.db.WithContext(ctx).Where("stream = ?", stream).Order("month").Find(&ms).Error
	return ms, err
}

// ArchiveTableTimes are the latest successes of a table's archive the
// database records.
type ArchiveTableTimes struct {
	// LastVerified is the newest verified_at of its chunks (nil: none yet).
	LastVerified *time.Time
	// LastMark is the newest taken_at of its id marks (flow tables only).
	LastMark *time.Time
}

// ArchiveTableTimes reads table's latest chunk verification and id mark. Both
// are aggregates over the table's own rows of two small manifest tables (a
// few hundred syslog days, 24 flow hours a day).
func (d *Database) ArchiveTableTimes(ctx context.Context, table string) (ArchiveTableTimes, error) {
	var out ArchiveTableTimes
	var v []time.Time
	if err := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).Where("table_name = ? AND verified_at IS NOT NULL", table).
		Order("verified_at DESC").Limit(1).Pluck("verified_at", &v).Error; err != nil {
		return out, err
	}
	if len(v) == 1 {
		t := v[0].UTC()
		out.LastVerified = &t
	}
	var m []time.Time
	if err := d.db.WithContext(ctx).Model(&models.ArchiveIDMark{}).Where("table_name = ?", table).
		Order("boundary_ts DESC").Limit(1).Pluck("taken_at", &m).Error; err != nil {
		return out, err
	}
	if len(m) == 1 {
		t := m[0].UTC()
		out.LastMark = &t
	}
	return out, nil
}

// ServerDataDiskFreeAt returns the database volume's free bytes in the newest
// server_metrics sample taken in [from, to] that measured it (nil when none
// did: an external database, or no sample in the window). The bound keeps the
// backward walk of the timestamp index short even when no row qualifies.
func (d *Database) ServerDataDiskFreeAt(ctx context.Context, from, to time.Time) (*uint64, error) {
	var free []uint64
	if err := d.db.WithContext(ctx).Model(&models.ServerMetric{}).
		Where("timestamp >= ? AND timestamp <= ? AND data_disk_free_bytes IS NOT NULL", from, to).
		Order("timestamp DESC").Limit(1).Pluck("data_disk_free_bytes", &free).Error; err != nil {
		return nil, err
	}
	if len(free) == 0 {
		return nil, nil
	}
	return &free[0], nil
}

// SettingValues reads the stored values of keys in one query (absent keys are
// absent from the map). A batch read, not GetIntSetting per key: First's
// "record not found" would log a line per unset key on every 5-minute tick.
func (d *Database) SettingValues(ctx context.Context, keys []string) (map[string]string, error) {
	var rows []models.SystemSetting
	if err := d.db.WithContext(ctx).Where("\"key\" IN ?", keys).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Key] = r.Value
	}
	return out, nil
}
