package database

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/configdiff"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// BatchAlreadyProcessed reports whether a (probeID, batchID) idempotency key
// has already been recorded (AUDIT-042). batchID == "" is never considered
// processed (no idempotency requested).
func (d *Database) BatchAlreadyProcessed(probeID uint, batchID string) bool {
	if batchID == "" {
		return false
	}
	var count int64
	if err := d.db.Model(&models.ProcessedBatch{}).
		Where("probe_id = ? AND batch_id = ?", probeID, batchID).
		Count(&count).Error; err != nil {
		// Fail open: a dedup-store read error must not drop a legitimate batch.
		log.Printf("BatchAlreadyProcessed: probe %d batch %s: %v", probeID, batchID, err)
		return false
	}
	return count > 0
}

// MarkBatchProcessed records a (probeID, batchID) idempotency key after a batch
// has been successfully ingested (AUDIT-042). A unique-index conflict (the key
// was recorded concurrently) is treated as success — the goal state is "this
// key is recorded".
func (d *Database) MarkBatchProcessed(probeID uint, batchID string) error {
	if batchID == "" {
		return nil
	}
	err := d.db.Create(&models.ProcessedBatch{
		ProbeID: probeID, BatchID: batchID, Timestamp: time.Now(),
	}).Error
	if err != nil && (strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate")) {
		return nil // already recorded — that's the desired state
	}
	if err != nil {
		return fmt.Errorf("mark batch processed: %w", err)
	}
	return nil
}

// cleanupDeleteBatchSize is the row cap per cleanup DELETE. A package var (not
// a const) so tests can shrink it to exercise the multi-batch loop without
// seeding 10k+ rows.
var cleanupDeleteBatchSize = 10000

// batchedDeleteOlderThan deletes rows with `timestamp < cutoff` in bounded
// batches instead of one giant DELETE (AUDIT-038). A single
// `DELETE FROM interface_stats WHERE timestamp < ?` on a 100M-row table takes a
// long row lock, bloats the table, and blocks concurrent writes. Each batch
// deletes at most cleanupDeleteBatchSize rows (`id IN (SELECT id ... LIMIT N)`,
// a form valid on both Postgres and SQLite) so locks stay short; on Postgres a
// per-batch `SET LOCAL lock_timeout` bounds lock waits, and a 100ms sleep
// between batches yields to other writers.
func (d *Database) batchedDeleteOlderThan(model interface{}, cutoff time.Time) error {
	return d.batchedDeleteOlderThanWhere(model, cutoff, "")
}

// batchedDeleteOlderThanWhere is batchedDeleteOlderThan with an extra predicate
// ANDed onto the `timestamp < cutoff` selector. Used by the syslog cleanup,
// whose dual critical(<6)/info(>=6) retention windows need a severity filter —
// previously those deletes were single unbounded DELETEs on syslog_messages
// (the table that dominates DB size), which on a populated prod table take one
// long lock touching millions of rows, block ingestion, burst the WAL, and can
// be killed by statement_timeout then re-attempted every cleanup tick
// (crash-loop shape). Routing them through the same 10k-row batched loop with
// `lock_timeout='5s'` and an inter-batch sleep keeps each statement short.
func (d *Database) batchedDeleteOlderThanWhere(model interface{}, cutoff time.Time, extraWhere string, args ...interface{}) error {
	return d.batchedDeleteOlderThanOn(model, "timestamp", cutoff, extraWhere, args...)
}

// batchedDeleteOlderThanOn is the column-parameterized core of the batched
// cleanup deletes. Most tables age on `timestamp`, but flow_detections ages on
// `detected_at` and flow_agent_drops on `window_start` (H4 of the 2026-07-01
// audit). timeColumn is always a compile-time literal from this package, never
// caller/user input.
func (d *Database) batchedDeleteOlderThanOn(model interface{}, timeColumn string, cutoff time.Time, extraWhere string, args ...interface{}) error {
	batchSize := cleanupDeleteBatchSize
	for {
		var affected int64
		err := d.db.Transaction(func(tx *gorm.DB) error {
			if d.dialect.IsPostgres() {
				if e := tx.Exec("SET LOCAL lock_timeout = '5s'").Error; e != nil {
					return e
				}
			}
			sub := tx.Model(model).Select("id").Where(timeColumn+" < ?", cutoff)
			if extraWhere != "" {
				sub = sub.Where(extraWhere, args...)
			}
			sub = sub.Limit(batchSize)
			res := tx.Where("id IN (?)", sub).Delete(model)
			affected = res.RowsAffected
			return res.Error
		})
		if err != nil {
			return fmt.Errorf("batched delete (batch size %d): %w", batchSize, err)
		}
		if affected < int64(batchSize) {
			return nil // last (partial) batch — nothing more to delete
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// dropPartitionsOlderThan drops whole monthly partitions of a RANGE-partitioned
// table whose entire range is older than cutoff (AUDIT-028) — instant
// space reclamation, vs. row-by-row DELETE that bloats. It only ever drops a
// partition whose upper bound (the exclusive `TO ('YYYY-MM-DD')`) is <= cutoff,
// so the current/future and the straddling partition are never touched (the
// caller still runs batchedDeleteOlderThan for the straddling tail). Returns
// whether the table was partitioned (false → caller relies on batched DELETE).
// Postgres-only; no-op on SQLite.
func (d *Database) dropPartitionsOlderThan(table string, cutoff time.Time) (bool, error) {
	if !d.dialect.IsPostgres() {
		return false, nil
	}
	var isPartitioned bool
	if err := d.db.Raw(`SELECT EXISTS (
		SELECT 1 FROM pg_partitioned_table pt
		JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = ?)`, table).Scan(&isPartitioned).Error; err != nil {
		return false, err
	}
	if !isPartitioned {
		return false, nil
	}

	type childPart struct {
		Name  string
		Bound string
	}
	var children []childPart
	if err := d.db.Raw(`
		SELECT c.relname AS name, pg_get_expr(c.relpartbound, c.oid) AS bound
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class parent ON parent.oid = i.inhparent
		WHERE parent.relname = ?`, table).Scan(&children).Error; err != nil {
		return true, err
	}
	for _, ch := range children {
		upper, ok := parsePartitionUpperBound(ch.Bound)
		if !ok {
			continue // unparseable (DEFAULT partition, custom bound) — leave it
		}
		if upper.After(cutoff) {
			continue // range reaches into the retention window — keep it
		}
		if err := d.execMaintenanceDDL(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, ch.Name)); err != nil {
			return true, fmt.Errorf("drop old partition %s: %w", ch.Name, err)
		}
		log.Printf("cleanup: dropped old partition %s (range entirely before %s)", ch.Name, cutoff.Format("2006-01-02"))
	}
	return true, nil
}

// parsePartitionUpperBound pulls the exclusive upper bound date out of a
// monthly RANGE partition's bound expression, e.g.
// "FOR VALUES FROM ('2026-01-01') TO ('2026-02-01')" → 2026-02-01.
//
// Even though EnsurePartitions creates the bounds with date-only literals,
// Postgres renders the bound of a timestamp/timestamptz-typed partition key
// WITH a time component (and possibly a timezone), e.g.
// "... TO ('2026-02-01 00:00:00')" or "... TO ('2026-02-01 00:00:00+00')".
// Parsing only "2006-01-02" therefore failed on every real partition, so
// dropPartitionsOlderThan treated them all as unparseable and never dropped
// anything. Accept the date-only, timestamp, and timestamptz renderings, and
// fall back to the leading YYYY-MM-DD date (which is all a monthly bound needs).
func parsePartitionUpperBound(bound string) (time.Time, bool) {
	const marker = "TO ('"
	i := strings.Index(bound, marker)
	if i < 0 {
		return time.Time{}, false
	}
	rest := bound[i+len(marker):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return time.Time{}, false
	}
	val := rest[:j]
	for _, layout := range []string{
		"2006-01-02",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05-07:00",
	} {
		if t, err := time.Parse(layout, val); err == nil {
			return t, true
		}
	}
	// Fall back to the leading date portion (monthly bounds are first-of-month
	// midnight, so the date alone is sufficient and unambiguous).
	if len(val) >= 10 {
		if t, err := time.Parse("2006-01-02", val[:10]); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// statusFallback resolves a per-table retention knob for the charted per-poll
// status tables (LC-20): the table's own knob when set, otherwise the shared
// statusDays window its chart siblings (system_status/interface_stats) use.
func statusFallback(perTable, statusDays int) int {
	if perTable > 0 {
		return perTable
	}
	return statusDays
}

// syslogPartitionDropDays returns the age in days past which an ENTIRE
// syslog_messages monthly partition is provably expired under EVERY retention
// window — the max of the critical (severity 0-5) and informational (6-7)
// windows — so dropPartitionsOlderThan may reclaim it wholesale (LC-23).
// Returns 0 ("never drop") when any severity class is kept forever:
//   - SyslogCriticalDays > 0: both windows are bounded → max of the two.
//   - legacy single-window mode (SyslogCriticalDays == 0 && SyslogInfoDays == 0
//     && SyslogDays > 0): every row ages out by max(SyslogDays, effInfoDays)
//     (the info DELETE always runs at the effective default).
//   - otherwise SyslogCriticalDays == 0 means critical rows are kept forever,
//     so no partition is ever wholly expired.
//
// effInfoDays is the caller's effective informational window (SyslogInfoDays
// with its 7-day default applied).
func syslogPartitionDropDays(ret config.RetentionConfig, effInfoDays int) int {
	switch {
	case ret.SyslogCriticalDays > 0:
		return max(ret.SyslogCriticalDays, effInfoDays)
	case ret.SyslogInfoDays == 0 && ret.SyslogDays > 0:
		return max(ret.SyslogDays, effInfoDays)
	default:
		return 0
	}
}

func (d *Database) CleanupOldData(ret config.RetentionConfig) error {
	type cleanupEntry struct {
		model interface{}
		name  string
		days  int
	}

	statusDays := ret.Days(ret.StatusDays)
	flowDays := ret.Days(ret.FlowDays)
	trapDays := ret.Days(ret.TrapDays)
	pingDays := ret.Days(ret.PingDays)
	alertDays := ret.Days(ret.AlertDays)
	defaultDays := ret.Days(0)

	entries := []cleanupEntry{
		{&models.SystemStatus{}, "system_status", statusDays},
		{&models.InterfaceStats{}, "interface_stats", statusDays},
		{&models.ProcessorStats{}, "processor_stats", ret.Days(ret.ProcessorStatsDays)},
		{&models.HardwareSensor{}, "hardware_sensors", statusDays},
		{&models.DiskUsage{}, "disk_usage", statusDays},
		{&models.LoadAverage{}, "load_average", statusDays},
		{&models.TrapEvent{}, "trap_events", trapDays},
		{&models.LoginAttempt{}, "login_attempts", defaultDays},
		{&models.FlowSample{}, "flow_samples", flowDays},
		{&models.FlowInterfaceCounter{}, "flow_if_counters", flowDays},
		{&models.InterfaceAddress{}, "interface_addresses", statusDays},
		// L2 topology state tables (snapshot-replaced every topology cycle):
		// retention only sweeps rows of deleted/offline devices — active
		// devices refresh their timestamps every ~5 minutes.
		{&models.TopologyEntry{}, "topology_entries", statusDays},
		{&models.TopologyNeighbor{}, "topology_neighbors", statusDays},
		{&models.PingResult{}, "ping_results", pingDays},
		// AUDIT-029: the four tables that previously had no
		// retention knob and grew unbounded on long-running
		// deployments. Defaults are 30 days for the
		// error/processor/process stats (configurable per table)
		// and 7 days for IRC message logs (higher-volume,
		// lower-signal). The fields are on the RetentionConfig
		// struct and read from RETENTION_*_DAYS env vars (see
		// config.env.example). The retention is per-table so
		// operators can tune for their device mix without
		// affecting the other tables.
		{&models.InterfaceErrors{}, "interface_errors", ret.Days(ret.InterfaceErrorsDays)},
		{&models.ProcessStats{}, "process_stats", ret.Days(ret.ProcessStatsDays)},
		{&models.IRCMessageLog{}, "irc_message_logs", ret.Days(ret.IRCMessageLogDays)},
		// AUDIT-042: idempotency keys only matter for the probe's retry window
		// (seconds); 2 days is far more than enough and keeps the table tiny.
		{&models.ProcessedBatch{}, "processed_batches", 2},
		// H4 of the 2026-07-01 audit: flow_rollups had no retention at all —
		// terminal '1d' rollups (one row per distinct conversation per day,
		// 10^5-10^6 rows/day on a busy network) accumulated forever. The
		// cutoff applies to every interval_type: 5m/1h rollups are consumed by
		// promotion long before a year, so anything older than the window —
		// whatever its interval — is stale and safe to drop even if promotion
		// were broken or disabled.
		{&models.FlowRollup{}, "flow_rollups", ret.Days(ret.FlowRollupDays)},
		// LC-20 (2026-07-04 audit): the five per-poll status tables the
		// AUDIT-029 and H4 retention passes both missed — appended every poll
		// cycle by the poller AND per push by every collector, with no delete
		// path anywhere (vpn_status alone is tunnels × 1440 rows/day at a 60s
		// interval). The four charted tables follow statusDays (like their
		// chart siblings system_status/interface_stats) unless their own
		// RETENTION_*_DAYS knob is set; license_info has its own longer knob
		// (default 365 — expiry snapshots are low-volume and useful
		// year-over-year).
		{&models.VPNStatus{}, "vpn_status", statusFallback(ret.VPNStatusDays, statusDays)},
		{&models.HAStatus{}, "ha_status", statusFallback(ret.HAStatusDays, statusDays)},
		{&models.SecurityStats{}, "security_stats", statusFallback(ret.SecurityStatsDays, statusDays)},
		{&models.SDWANHealth{}, "sdwan_health", statusFallback(ret.SDWANHealthDays, statusDays)},
		{&models.LicenseInfo{}, "license_info", ret.Days(ret.LicenseInfoDays)},
	}

	for _, e := range entries {
		cutoff := time.Now().AddDate(0, 0, -e.days)
		// AUDIT-028: if the table is RANGE-partitioned, drop whole old
		// partitions first (instant, reclaims space); a no-op for plain tables.
		// Drop errors are non-fatal — fall through to the batched DELETE, which
		// also trims the straddling/current partition's rows for exact retention.
		if _, err := d.dropPartitionsOlderThan(e.name, cutoff); err != nil {
			log.Printf("cleanup: drop-old-partitions warning for %s: %v", e.name, err)
		}
		if err := d.batchedDeleteOlderThan(e.model, cutoff); err != nil {
			return fmt.Errorf("failed to cleanup %s: %w", e.name, err)
		}
	}

	// H4 of the 2026-07-01 audit: flow_detections and flow_agent_drops age on
	// their own time columns (detected_at / window_start), so they can't ride
	// the `timestamp`-keyed entries loop above. flow_detections rows are
	// appended every 5-min detection cycle and only ever got an `acknowledged`
	// flip; flow_agent_drops appends one row per (agent, sampling_rate, window)
	// — the "bounded by the number of monitored agents" assumption in models.go
	// was wrong because windows accumulate. Neither table is partitioned.
	detCutoff := time.Now().AddDate(0, 0, -ret.Days(ret.FlowDetectionDays))
	if err := d.batchedDeleteOlderThanOn(&models.FlowDetection{}, "detected_at", detCutoff, ""); err != nil {
		return fmt.Errorf("failed to cleanup flow_detections: %w", err)
	}
	dropsCutoff := time.Now().AddDate(0, 0, -ret.Days(ret.AgentDropsDays))
	if err := d.batchedDeleteOlderThanOn(&models.AgentDrops{}, "window_start", dropsCutoff, ""); err != nil {
		return fmt.Errorf("failed to cleanup flow_agent_drops: %w", err)
	}

	// Relay schema v4 (server→collector command channel): TERMINAL
	// probe_commands rows (succeeded/failed/expired) are an audit trail, not
	// live state — keep 30 days, then drop. Live rows (pending/dispatched) are
	// never touched here; ClaimProbeCommands owns the expires_at transition.
	// Ages on updated_at (the terminal-transition time — the table has no
	// `timestamp` column), hence batchedDeleteOlderThanOn.
	cmdCutoff := time.Now().AddDate(0, 0, -30)
	if err := d.batchedDeleteOlderThanOn(&models.ProbeCommand{}, "updated_at", cmdCutoff,
		"status IN ('succeeded','failed','expired')"); err != nil {
		return fmt.Errorf("failed to cleanup probe_commands: %w", err)
	}

	// Syslog: handle critical (0-5) and informational (6-7) differently.
	// infoDays is the effective informational window (default 7), shared by the
	// info DELETE, the summaries cutoff, and the partition-drop bound below.
	infoDays := ret.SyslogInfoDays
	if infoDays <= 0 {
		infoDays = 7 // default fallback
	}

	// LC-23 (2026-07-04 audit): partition-drop fast path for syslog_messages —
	// the table that dominates prod DB size. The old blanket "never
	// partition-drop syslog" rule over-generalized: a partition can straddle
	// the two severity cutoffs, but one whose entire range is older than BOTH
	// windows (max of critical + informational) holds only expired rows and is
	// safe to drop wholesale — instant space reclamation instead of the
	// batched DELETE bloating it with dead tuples and leaving empty monthly
	// children behind forever. syslogPartitionDropDays returns 0 (never drop)
	// whenever any severity class is kept forever; straddling/newer partitions
	// still rely on the severity-scoped DELETEs below for exact retention.
	if dropDays := syslogPartitionDropDays(ret, infoDays); dropDays > 0 {
		dropCutoff := time.Now().AddDate(0, 0, -dropDays)
		if _, err := d.dropPartitionsOlderThan("syslog_messages", dropCutoff); err != nil {
			log.Printf("cleanup: drop-old-partitions warning for syslog_messages: %v", err)
		}
	}

	// Critical syslog (severity 0-5): delete after SyslogCriticalDays (0 = never delete)
	if ret.SyslogCriticalDays > 0 {
		criticalCutoff := time.Now().AddDate(0, 0, -ret.SyslogCriticalDays)
		if err := d.batchedDeleteOlderThanWhere(&models.SyslogMessage{}, criticalCutoff, "severity < 6"); err != nil {
			return fmt.Errorf("failed to cleanup syslog_message: %w", err)
		}
	}

	// Informational syslog (severity 6-7): delete after SyslogInfoDays
	// This catches any informational syslog that wasn't aggregated (aggregation runs every 5 min)
	infoCutoff := time.Now().AddDate(0, 0, -infoDays)
	if err := d.batchedDeleteOlderThanWhere(&models.SyslogMessage{}, infoCutoff, "severity >= 6"); err != nil {
		return fmt.Errorf("failed to cleanup informational syslog_message: %w", err)
	}

	// Syslog summaries: delete after SyslogInfoDays (they are derived from
	// informational syslog). AUDIT-028: drop whole old partitions first
	// (no-op if plain).
	summaryCutoff := time.Now().AddDate(0, 0, -infoDays)
	if _, err := d.dropPartitionsOlderThan("syslog_summaries", summaryCutoff); err != nil {
		log.Printf("cleanup: drop-old-partitions warning for syslog_summaries: %v", err)
	}
	if err := d.batchedDeleteOlderThan(&models.SyslogSummary{}, summaryCutoff); err != nil {
		return fmt.Errorf("failed to cleanup syslog_summary: %w", err)
	}

	// Legacy SyslogDays applies only when neither new config is set (backwards compat)
	if ret.SyslogDays > 0 && ret.SyslogCriticalDays == 0 && ret.SyslogInfoDays == 0 {
		cutoff := time.Now().AddDate(0, 0, -ret.SyslogDays)
		if err := d.batchedDeleteOlderThan(&models.SyslogMessage{}, cutoff); err != nil {
			return fmt.Errorf("failed to cleanup syslog_message: %w", err)
		}
	}

	// Alerts: AUDIT-031
	//
	// Two separate cleanup windows, both of which used to be a
	// single query that ignored unacked alerts entirely:
	//
	//   1. AcKed alerts: deleted after `alertDays` (default 30,
	//      from `RETENTION_ALERT_DAYS`). The pre-fix behavior.
	//
	//   2. UnACKed alerts: deleted after `unackDays` (default
	//      90, from `RETENTION_UNACK_ALERT_DAYS`). Pre-fix
	//      these were left in the table forever — a critical
	//      device that paged off-hours and went unacked would
	//      accumulate alert rows indefinitely. The auto-delete
	//      fires a warning log so the operator can reconstruct
	//      the "stale unack" event from the logs (and so the
	//      table growth stops being unbounded).
	//
	// The 90-day default is intentionally longer than the
	// 30-day acked default: an operator who is on vacation
	// shouldn't come back to find that an unacked alert from
	// their first week off has been auto-archived. After 90
	// days, though, the alert is unlikely to be actionable
	// (the device has either recovered, been replaced, or the
	// condition has escalated to a separate alert that has
	// itself been handled).
	alertCutoff := time.Now().AddDate(0, 0, -alertDays)
	if err := d.db.Where("acknowledged = true AND timestamp < ?", alertCutoff).Delete(&models.Alert{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup acked alert: %w", err)
	}
	unackCutoff := time.Now().AddDate(0, 0, -ret.Days(ret.UnackAlertDays))
	if unackCutoff.After(alertCutoff) {
		// Defensive: the unack window should always be at
		// least as long as the acked window, otherwise we'd
		// auto-archive unacked alerts before acked ones
		// (which would be a backwards default). When the
		// unack window is shorter, we pin it to the acked
		// window (deleting more, not less). The semantics:
		// "unack window >= ack window, always".
		unackCutoff = alertCutoff
	}
	// Find first, log a warning per row, then bulk-delete.
	// The find-then-log-then-delete is two queries instead of
	// one, but it gives us the "what got archived" trace for
	// free. The alternative (a single DELETE...RETURNING) is
	// not portable across SQLite.
	var staleUnack []models.Alert
	if err := d.db.Where("acknowledged = false AND timestamp < ?", unackCutoff).Find(&staleUnack).Error; err != nil {
		return fmt.Errorf("failed to query stale unack alerts: %w", err)
	}
	for _, a := range staleUnack {
		log.Printf("WARNING: AUDIT-031 auto-archiving stale unacked alert ID=%d device_id=%d severity=%s message=%q timestamp=%s (older than %d days; an operator should have acked this)",
			a.ID, a.DeviceID, a.Severity, a.Message, a.Timestamp.Format(time.RFC3339), ret.Days(ret.UnackAlertDays))
	}
	if len(staleUnack) > 0 {
		var ids []uint
		for _, a := range staleUnack {
			ids = append(ids, a.ID)
		}
		if err := d.db.Where("id IN ?", ids).Delete(&models.Alert{}).Error; err != nil {
			return fmt.Errorf("failed to cleanup stale unack alerts: %w", err)
		}
	}

	// Incidents: LC-22 (2026-07-04 audit). The T2 incidents table (migration
	// v27) shipped with no retention — one row per device outage accumulated
	// forever on flapping networks, long after the alerts attached to it were
	// aged out above. RESOLVED incidents older than the window are deleted
	// (aging on resolved_at, the moment the record became history); OPEN
	// incidents are never touched — they are live state, closed only by device
	// recovery or a device delete (LC-21). Plain DELETE like the alerts above:
	// the table is small (one row per outage, not per poll).
	incidentCutoff := time.Now().AddDate(0, 0, -ret.Days(ret.IncidentDays))
	if err := d.db.Where("resolved_at IS NOT NULL AND resolved_at < ?", incidentCutoff).
		Delete(&models.Incident{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup resolved incidents: %w", err)
	}

	// v0.11.93: expired TEMPORARY event rules. A "suppress this source for 24h"
	// rule (the unified replacement for Silence-Source) self-lifts once its window
	// elapses; expiry is enforced at match time, so this is just housekeeping to
	// keep the table tidy. Non-fatal: a prune failure shouldn't fail cleanup.
	if err := d.PruneExpiredEventRules(); err != nil {
		log.Printf("cleanup: prune expired event rules warning: %v", err)
	}

	return nil
}

// auditDeviceVendors backfills empty vendor → "fortigate" (the in-code default)
// and logs the fleet's vendor distribution at startup. For each distinct
// vendor value, it cross-references configdiff.HasRichNormalizer — any vendor
// with config revisions but no rich normalizer is flagged in the log as a
// likely source of false CONFIG_CHANGE alerts. No data is mutated beyond the
// empty-vendor backfill.
func (d *Database) auditDeviceVendors() {
	// Step 1: backfill empty vendor to the in-code default. This preserves
	// pre-vendor-field behavior for any rows that predate the column.
	res := d.db.Exec("UPDATE devices SET vendor = 'fortigate' WHERE vendor = '' OR vendor IS NULL")
	if res.Error != nil {
		log.Printf("vendor backfill: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("vendor backfill: set %d devices with empty vendor → 'fortigate'", res.RowsAffected)
	}

	// Step 2: count devices per vendor.
	type vendorCount struct {
		Vendor string
		N      int64
	}
	var counts []vendorCount
	if err := d.db.Model(&models.Device{}).
		Select("vendor as vendor, COUNT(*) as n").
		Group("vendor").
		Find(&counts).Error; err != nil {
		log.Printf("vendor audit: %v", err)
		return
	}
	if len(counts) == 0 {
		return
	}

	// Step 3: log distribution + warn on missing rich normalizer.
	// A device with no rich normalizer will hash by byte equality, which makes
	// random-IV ENC ciphertext look like a real change every backup. That's
	// the false-alert root cause we already fixed for fortigate.
	sort.Slice(counts, func(i, j int) bool { return counts[i].N > counts[j].N })
	var unsupported []string
	for _, c := range counts {
		marker := "rich"
		if !configdiff.HasRichNormalizer(c.Vendor) {
			marker = "IDENTITY (false-alert risk on config-backup diffs)"
			unsupported = append(unsupported, fmt.Sprintf("%s=%d", c.Vendor, c.N))
		}
		log.Printf("vendor audit: vendor=%q devices=%d normalizer=%s", c.Vendor, c.N, marker)
	}
	if len(unsupported) > 0 {
		log.Printf("vendor audit: WARNING — %d vendor(s) lack rich normalization in internal/configdiff (%s). Config-backup diffs for these devices will hash by byte equality and may false-alert on encrypted-field drift. Consider switching the device's vendor to a supported value, or extending configdiff with a normalizer for the missing vendor.",
			len(unsupported), strings.Join(unsupported, ", "))
	}
}
