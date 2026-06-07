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
	batchSize := cleanupDeleteBatchSize
	for {
		var affected int64
		err := d.db.Transaction(func(tx *gorm.DB) error {
			if d.dialect.IsPostgres() {
				if e := tx.Exec("SET LOCAL lock_timeout = '5s'").Error; e != nil {
					return e
				}
			}
			sub := tx.Model(model).Select("id").Where("timestamp < ?", cutoff).Limit(batchSize)
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
		if err := d.db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, ch.Name)).Error; err != nil {
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
		{&models.TrapEvent{}, "trap_events", trapDays},
		{&models.LoginAttempt{}, "login_attempts", defaultDays},
		{&models.FlowSample{}, "flow_samples", flowDays},
		{&models.InterfaceAddress{}, "interface_addresses", statusDays},
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

	// Syslog: handle critical (0-5) and informational (6-7) differently
	// Critical syslog (severity 0-5): delete after SyslogCriticalDays (0 = never delete)
	if ret.SyslogCriticalDays > 0 {
		criticalCutoff := time.Now().AddDate(0, 0, -ret.SyslogCriticalDays)
		if err := d.db.Where("timestamp < ? AND severity < 6", criticalCutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
			return fmt.Errorf("failed to cleanup syslog_message: %w", err)
		}
	}

	// Informational syslog (severity 6-7): delete after SyslogInfoDays
	// This catches any informational syslog that wasn't aggregated (aggregation runs every 5 min)
	infoDays := ret.SyslogInfoDays
	if infoDays <= 0 {
		infoDays = 7 // default fallback
	}
	infoCutoff := time.Now().AddDate(0, 0, -infoDays)
	if err := d.db.Where("timestamp < ? AND severity >= 6", infoCutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup informational syslog_message: %w", err)
	}

	// Syslog summaries: delete after SyslogInfoDays (they are derived from informational syslog)
	summaryDays := ret.SyslogInfoDays
	if summaryDays <= 0 {
		summaryDays = 7 // default fallback
	}
	summaryCutoff := time.Now().AddDate(0, 0, -summaryDays)
	// AUDIT-028: drop whole old partitions first (no-op if plain). syslog_messages
	// is intentionally NOT partition-dropped here — its dual critical(<6)/info(>=6)
	// retention means a partition can hold rows under two different cutoffs, so it
	// stays on the severity-scoped DELETEs above.
	if _, err := d.dropPartitionsOlderThan("syslog_summaries", summaryCutoff); err != nil {
		log.Printf("cleanup: drop-old-partitions warning for syslog_summaries: %v", err)
	}
	if err := d.db.Where("timestamp < ?", summaryCutoff).Delete(&models.SyslogSummary{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup syslog_summary: %w", err)
	}

	// Legacy SyslogDays applies only when neither new config is set (backwards compat)
	if ret.SyslogDays > 0 && ret.SyslogCriticalDays == 0 && ret.SyslogInfoDays == 0 {
		cutoff := time.Now().AddDate(0, 0, -ret.SyslogDays)
		if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
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
