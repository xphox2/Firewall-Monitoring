package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

func (d *Database) SavePingResult(result *models.PingResult) error {
	if d.pingBatch != nil {
		d.pingBatch.Add(*result)
		return nil
	}
	return d.db.Create(result).Error
}

func (d *Database) SavePingResults(results []models.PingResult) error {
	return batchInsertWithFallback(d.db, "ping_results", results)
}

func (d *Database) GetPingResults(deviceID uint, limit int) ([]models.PingResult, error) {
	var results []models.PingResult
	err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").Limit(limit).Find(&results).Error
	return results, err
}

func (d *Database) SavePingStats(stats *models.PingStats) error {
	if stats.ID == 0 {
		return d.db.Create(stats).Error
	}
	return d.db.Save(stats).Error
}

// FoldPingStats atomically folds one batch's aggregate (min/max/sum/count for a
// single device+target) into the running PingStats series with a single
// INSERT … ON CONFLICT DO UPDATE, so concurrent folds for the same
// (device_id, target_ip) can no longer lose or double-count a whole batch the
// way the previous read-modify-write did (audit L16). The running average is
// recomputed in-SQL against the row's pre-update samples/avg —
// (avg·samples + Σ) / (samples + K) — which is exact regardless of interleaving
// because each conflicting statement reads the current row under the upsert's
// row lock. probe_id/packet_loss keep last-writer semantics.
//
// count must be > 0 (the caller only folds targets that had samples), so the
// divisors are always positive.
func (d *Database) FoldPingStats(deviceID, probeID uint, targetIP string, minL, maxL, sum float64, count int, packetLoss float64, now time.Time) error {
	avg := sum / float64(count)
	// SQLite exposes scalar min()/max(); PostgreSQL spells them LEAST/GREATEST.
	minFn, maxFn := "min", "max"
	if d.dialect.IsPostgres() {
		minFn, maxFn = "LEAST", "GREATEST"
	}
	sql := fmt.Sprintf(`INSERT INTO ping_stats
  (device_id, probe_id, target_ip, min_latency, max_latency, avg_latency, packet_loss, samples, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (device_id, target_ip) DO UPDATE SET
  min_latency = %s(ping_stats.min_latency, excluded.min_latency),
  max_latency = %s(ping_stats.max_latency, excluded.max_latency),
  avg_latency = (ping_stats.avg_latency * ping_stats.samples + ?) / (ping_stats.samples + excluded.samples),
  packet_loss = excluded.packet_loss,
  samples     = ping_stats.samples + excluded.samples,
  probe_id    = excluded.probe_id,
  updated_at  = excluded.updated_at`, minFn, maxFn)
	return d.db.Exec(sql, deviceID, probeID, targetIP, minL, maxL, avg, packetLoss, count, now, sum).Error
}

// GetPingStatsByTarget returns the single ping-stats series for a device+target,
// independent of which probe collected it. Ping stats are unified per
// (device_id, target_ip) so reachability history stays continuous across probe
// replacements (see migration v3). probe_id is last-writer provenance only.
func (d *Database) GetPingStatsByTarget(deviceID uint, targetIP string) (*models.PingStats, error) {
	var stats models.PingStats
	err := d.db.Where("device_id = ? AND target_ip = ?", deviceID, targetIP).First(&stats).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &stats, err
}

// GetLatestInterfaceCountersByDevice returns the most recent sFlow counter
// sample for each distinct if_index of a device (audit L18). Used to surface
// interface cards for SNMP-host-restricted devices that push sFlow if_counters
// but have no interface_stats snapshot — without this the device-detail page
// renders zero interfaces and the sflow-chart endpoint is never reached.
func (d *Database) GetLatestInterfaceCountersByDevice(deviceID uint) ([]models.FlowInterfaceCounter, error) {
	var ifIndexes []uint32
	if err := d.db.Model(&models.FlowInterfaceCounter{}).
		Where("device_id = ?", deviceID).
		Distinct("if_index").Pluck("if_index", &ifIndexes).Error; err != nil {
		return nil, err
	}
	out := make([]models.FlowInterfaceCounter, 0, len(ifIndexes))
	for _, idx := range ifIndexes {
		c, err := d.GetLatestInterfaceCounter(deviceID, idx)
		if err != nil {
			return nil, err
		}
		if c != nil {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (d *Database) SaveProcessorStats(stats []models.ProcessorStats) error {
	return batchInsertWithFallback(d.db, "processor_stats", stats)
}

func (d *Database) GetLatestProcessorStats(deviceID uint) ([]models.ProcessorStats, error) {
	var latest models.ProcessorStats
	if err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&latest).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var stats []models.ProcessorStats
	err := d.db.Where("device_id = ? AND timestamp = ?", deviceID, latest.Timestamp).
		Order(d.dialect.QuoteIdent("index") + " ASC").Find(&stats).Error
	return stats, err
}

func (d *Database) SaveHardwareSensors(sensors []models.HardwareSensor) error {
	return batchInsertWithFallback(d.db, "hardware_sensors", sensors)
}

func (d *Database) SaveHAStatuses(statuses []models.HAStatus) error {
	return batchInsertWithFallback(d.db, "ha_status", statuses)
}

func (d *Database) SaveSecurityStats(stats []models.SecurityStats) error {
	return batchInsertWithFallback(d.db, "security_stats", stats)
}

func (d *Database) SaveSDWANHealth(health []models.SDWANHealth) error {
	return batchInsertWithFallback(d.db, "sdwan_health", health)
}

// GetLatestSecurityStats returns the most recent security stats for a device.
func (d *Database) GetLatestSecurityStats(deviceID uint) (*models.SecurityStats, error) {
	var stats models.SecurityStats
	err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&stats).Error
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

// GetSecurityStatsHistory returns security stats time series for a device.
func (d *Database) GetSecurityStatsHistory(deviceID uint, hours int) ([]models.SecurityStats, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	var stats []models.SecurityStats
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp ASC").Find(&stats).Error
	return stats, err
}

// GetLatestSDWANHealth returns the most recent SD-WAN health records for a device.
func (d *Database) GetLatestSDWANHealth(deviceID uint) ([]models.SDWANHealth, error) {
	// Get distinct health monitor names, then fetch latest for each
	var names []string
	d.db.Model(&models.SDWANHealth{}).Where("device_id = ?", deviceID).
		Distinct("name").Pluck("name", &names)

	var results []models.SDWANHealth
	for _, name := range names {
		var h models.SDWANHealth
		if err := d.db.Where("device_id = ? AND name = ?", deviceID, name).
			Order("timestamp DESC").First(&h).Error; err == nil {
			results = append(results, h)
		}
	}
	return results, nil
}

// GetLatestHAStatus returns the most recent HA status records for a device.
func (d *Database) GetLatestHAStatus(deviceID uint) ([]models.HAStatus, error) {
	// Get distinct member serials, then fetch latest for each
	var serials []string
	d.db.Model(&models.HAStatus{}).Where("device_id = ?", deviceID).
		Distinct("member_serial").Pluck("member_serial", &serials)

	var results []models.HAStatus
	for _, serial := range serials {
		var h models.HAStatus
		if err := d.db.Where("device_id = ? AND member_serial = ?", deviceID, serial).
			Order("timestamp DESC").First(&h).Error; err == nil {
			results = append(results, h)
		}
	}
	return results, nil
}

func (d *Database) SaveLicenseInfo(licenses []models.LicenseInfo) error {
	if len(licenses) == 0 {
		return nil
	}
	return d.db.Create(&licenses).Error
}

func (d *Database) SaveSyslogMessage(msg *models.SyslogMessage) error {
	if d.syslogBatch != nil {
		d.syslogBatch.Add(*msg)
		return nil
	}
	return d.db.Create(msg).Error
}

func (d *Database) SaveSyslogMessages(msgs []models.SyslogMessage) error {
	return batchInsertWithFallback(d.db, "syslog_messages", msgs)
}

func (d *Database) GetSyslogMessages(limit int) ([]models.SyslogMessage, error) {
	var messages []models.SyslogMessage
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&messages).Error
	return messages, err
}

// SaveFlowSamples persists a batch of sFlow samples. On PostgreSQL it uses
// the dedicated *pgxpool.Pool (initialized in Connect) and the COPY protocol —
// measured ~30-70x over per-row Create and ~120k rows/s at batch 1000
// (bench_ingest_integration_test.go; docs/OPERATIONS.md), which clears the
// 100k samples/sec design target from the audit at
// docs/audit-archive/audit-2026-06-22-taocp.md [critical] #4. On the SQLite test backend the
// pgxPool is nil and we fall back to GORM Create, which works correctly but
// is the slow path; this is intentional (tests use SQLite in-memory and the
// performance differential doesn't matter).
//
// The GORM session's context (set via WithContext, AUDIT-032) propagates to
// pgx via the Statement.Context lookup, so a client disconnect on the HTTP
// handler cancels the in-flight COPY and frees the pooled connection — same
// cancellation contract as the GORM path.
func (d *Database) SaveFlowSamples(samples []models.FlowSample) error {
	if len(samples) == 0 {
		return nil
	}
	if d.pgxPool == nil {
		// SQLite / no-pool fallback. The slow path; correct.
		return batchInsertWithFallback(d.db, "flow_samples", samples)
	}
	// Extract the GORM session context so pgx honors the same deadline /
	// cancellation as the GORM session (AUDIT-032 invariant).
	ctx := d.db.Statement.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return saveFlowSamplesPGX(ctx, d.pgxPool, samples)
}

func (d *Database) GetFlowSamples(limit int) ([]models.FlowSample, error) {
	var samples []models.FlowSample
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&samples).Error
	return samples, err
}

// SaveFlowInterfaceCounters persists a batch of sFlow interface counter samples
// (schema v2). Plain GORM batch insert — the row rate is per-interface, far
// below the flow firehose, so the pgx COPY fast path isn't needed.
func (d *Database) SaveFlowInterfaceCounters(counters []models.FlowInterfaceCounter) error {
	return batchInsertWithFallback(d.db, "flow_if_counters", counters)
}

// GetLatestInterfaceCounter returns the most recent sFlow counter sample for a
// (device, ifIndex), or nil if none. Used as a bandwidth/ifSpeed source when
// SNMP interface_stats is unavailable.
func (d *Database) GetLatestInterfaceCounter(deviceID uint, ifIndex uint32) (*models.FlowInterfaceCounter, error) {
	var c models.FlowInterfaceCounter
	err := d.db.Where("device_id = ? AND if_index = ?", deviceID, ifIndex).
		Order("timestamp DESC").Limit(1).First(&c).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}
