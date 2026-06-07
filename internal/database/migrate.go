package database

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// migrateBaseline is the v1 "baseline" migration (AUDIT-044): it brings an empty
// database up to the full current schema and is idempotent, so on an existing
// (already-AutoMigrated) deployment every step is a no-op and the migration
// runner simply records v1 as applied. It is invoked via the registry in
// migrations.go — do not call it directly; call RunMigrations.
func (d *Database) migrateBaseline() error {
	allModels := []interface{}{
		&models.SystemStatus{},
		&models.InterfaceStats{},
		&models.VPNStatus{},
		&models.HAStatus{},
		&models.HardwareSensor{},
		&models.ProcessorStats{},
		&models.TrapEvent{},
		&models.Alert{},
		&models.UptimeRecord{},
		&models.LoginAttempt{},
		&models.AuditLog{},
		&models.Device{},
		&models.DeviceTunnel{},
		&models.DeviceConnection{},
		&models.SystemSetting{},
		&models.Admin{},
		&models.Site{},
		&models.Probe{},
		&models.ProbeApproval{},
		&models.ProbeHeartbeat{},
		&models.PingResult{},
		&models.PingStats{},
		&models.SyslogMessage{},
		&models.SyslogSummary{},
		&models.FlowSample{},
		&models.FlowRollup{},
		&models.SiteDatabase{},
		&models.SecurityStats{},
		&models.SDWANHealth{},
		&models.LicenseInfo{},
		&models.InterfaceAddress{},
		&models.IRCServer{},
		&models.IRCChannel{},
		&models.IRCCommand{},
		&models.IRCMessageLog{},
		&models.AlertPolicy{},
		&models.AlertRule{},
		&models.DeviceAlertConfig{},
		&models.SiteAlertConfig{},
		&models.MaintenanceWindow{},
		&models.DeviceConfigRevision{},
		&models.ProcessStats{},
		&models.InterfaceErrors{},
		&models.ProcessedBatch{},
	}

	// Migrate each model individually so one failure doesn't block others.
	// GORM may attempt table recreation which may fail with "already exists" on upgrades.
	for _, model := range allModels {
		if err := d.db.AutoMigrate(model); err != nil {
			log.Printf("AutoMigrate warning for %T: %v", model, err)
		}
	}

	// Repair the interface_addresses unique index that AutoMigrate cannot
	// create on a deployment carrying legacy duplicate rows. Must run after
	// the AutoMigrate loop (the table has to exist) and before any probe
	// ingestion, since SaveInterfaceAddresses' UPSERT depends on the index.
	d.ensureInterfaceAddrUniqueIndex()

	// AUDIT-017: hash any plaintext probe registration keys at rest. Must run
	// at startup BEFORE the HTTP server accepts requests, so probe auth (which
	// now hashes the incoming token and compares to the stored hash) matches
	// from the first request. Idempotent via the sha256: prefix.
	d.migrateProbeKeysToHash()

	// AUDIT-044: the legacy IRC drop-and-recreate heuristic was removed here. It
	// fired only when the IRCServer table existed but lacked the ServerPassword
	// column — a long-dead schema state that is false on any recently-booted
	// deployment — and it was destructive (dropped/recreated the four IRC tables,
	// losing rows). The IRC tables are maintained by the AutoMigrate loop above
	// like every other table.
	m := d.db.Migrator()

	// Add missing columns for SystemStatus extended fields (SSH performance data)
	if m.HasTable(&models.SystemStatus{}) {
		systemStatusCols := []struct {
			name string
			col  string
		}{
			{"NetworkInKbps", "network_in_kbps"},
			{"NetworkOutKbps", "network_out_kbps"},
			{"CPUUser", "cpu_user"},
			{"CPUSystem", "cpu_system"},
			{"CPUNice", "cpu_nice"},
			{"CPUIdle", "cpu_idle"},
			{"CPUIowait", "cpu_iowait"},
			{"CPUIrq", "cpu_irq"},
			{"CPUSoftirq", "cpu_softirq"},
			{"MemoryFree", "memory_free"},
			{"MemoryFreeable", "memory_freeable"},
		}
		for _, f := range systemStatusCols {
			if !m.HasColumn(&models.SystemStatus{}, f.col) {
				if err := m.AddColumn(&models.SystemStatus{}, f.col); err != nil {
					log.Printf("migrate: add SystemStatus.%s: %v", f.name, err)
				} else {
					log.Printf("migrate: added SystemStatus.%s", f.name)
				}
			}
		}
	}

	// Add tftp_server_ip column on Probe (admin-set IP firewalls reach the collector at)
	if m.HasTable(&models.Probe{}) && !m.HasColumn(&models.Probe{}, "tftp_server_ip") {
		if err := m.AddColumn(&models.Probe{}, "TFTPServerIP"); err != nil {
			log.Printf("migrate: add Probe.TFTPServerIP: %v", err)
		} else {
			log.Printf("migrate: added Probe.TFTPServerIP")
		}
	}

	// Add normalized_checksum / backup_quality / trigger_source on DeviceConfigRevision.
	// Drives FortiOS-aware change detection and per-row provenance/quality flagging.
	// Also adds first_seen_at / last_verified_at / verify_count for the
	// merge-into-latest storage model (v0.10.198+).
	if m.HasTable(&models.DeviceConfigRevision{}) {
		revisionCols := []struct {
			name string
			col  string
		}{
			{"NormalizedChecksum", "normalized_checksum"},
			{"BackupQuality", "backup_quality"},
			{"TriggerSource", "trigger_source"},
			{"FirstSeenAt", "first_seen_at"},
			{"LastVerifiedAt", "last_verified_at"},
			{"VerifyCount", "verify_count"},
		}
		for _, f := range revisionCols {
			if !m.HasColumn(&models.DeviceConfigRevision{}, f.col) {
				if err := m.AddColumn(&models.DeviceConfigRevision{}, f.name); err != nil {
					log.Printf("migrate: add DeviceConfigRevision.%s: %v", f.name, err)
				} else {
					log.Printf("migrate: added DeviceConfigRevision.%s", f.name)
				}
			}
		}
	}

	// Add missing columns for VPNStatus extended fields (interface name and mode)
	if m.HasTable(&models.VPNStatus{}) {
		vpnStatusCols := []struct {
			name string
			col  string
		}{
			{"InterfaceName", "interface_name"},
			{"Mode", "mode"},
		}
		for _, f := range vpnStatusCols {
			if !m.HasColumn(&models.VPNStatus{}, f.col) {
				if err := m.AddColumn(&models.VPNStatus{}, f.col); err != nil {
					log.Printf("migrate: add VPNStatus.%s: %v", f.name, err)
				} else {
					log.Printf("migrate: added VPNStatus.%s", f.name)
				}
			}
		}
	}

	return nil
}

// EnsurePartitions creates monthly range partitions for high-volume tables on PostgreSQL.
// Partitions are created for the current month + 6 months ahead.
// This is safe for existing servers - it only creates new partitions, never modifies existing data.
func (d *Database) EnsurePartitions() error {
	if !d.dialect.IsPostgres() {
		return nil // Partitioning is PostgreSQL-only
	}

	type partitionDef struct {
		tableName string
		column    string
	}
	tables := []partitionDef{
		{"syslog_messages", "timestamp"},
		{"syslog_summaries", "timestamp"},
		{"trap_events", "timestamp"},
		{"flow_samples", "timestamp"},
	}

	// Filter the candidate list to only tables that are actually partitioned
	// parents. Deployments that ran GORM AutoMigrate before partitioning was
	// added carry these tables as plain (non-partitioned) tables — attaching
	// a partition there fails with SQLSTATE 42P17 and spams 28 lines per
	// startup. Probe pg_partitioned_table once and emit a single info line
	// per plain table so the operator knows a separate migration is needed.
	partitioned := make([]partitionDef, 0, len(tables))
	for _, def := range tables {
		var isPartitioned bool
		err := d.db.Raw(`
			SELECT EXISTS (
				SELECT 1 FROM pg_partitioned_table pt
				JOIN pg_class c ON c.oid = pt.partrelid
				WHERE c.relname = ?
			)`, def.tableName).Scan(&isPartitioned).Error
		if err != nil {
			log.Printf("Partition probe warning for %s: %v", def.tableName, err)
			continue
		}
		if !isPartitioned {
			// AUDIT-146: surface this as a clear WARNING, not
			// a per-table info line. The pre-fix message used
			// log.Printf with no prefix, which made it easy
			// to miss in startup noise. The WARNING prefix
			// is grep-able (`grep WARNING firewall-mon.log`)
			// and matches the AUDIT-146 fix's recommendation.
			log.Printf("WARNING: AUDIT-146 partition setup: %q is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.", def.tableName)
			continue
		}
		partitioned = append(partitioned, def)
	}
	if len(partitioned) == 0 {
		return nil
	}

	// Create partitions for current month + 6 months ahead
	now := time.Now()
	for i := 0; i <= 6; i++ {
		year, month, _ := now.Date()
		month = month + time.Month(i)
		yearOffset := 0
		for month > 12 {
			month -= 12
			yearOffset++
		}
		year += yearOffset
		partitionStart := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
		partitionEnd := partitionStart.AddDate(0, 1, 0)

		startStr := partitionStart.Format("2006-01-02")
		endStr := partitionEnd.Format("2006-01-02")

		for _, def := range partitioned {
			partitionName := fmt.Sprintf("%s_%d%02d", def.tableName, year, month)
			// Check if partition already exists
			var count int
			d.db.Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename = ?", partitionName).Scan(&count)
			if count > 0 {
				continue // Partition exists
			}

			// Create the partition
			sql := fmt.Sprintf(`
				CREATE TABLE %s PARTITION OF %s
				FOR VALUES FROM ('%s') TO ('%s')`,
				partitionName, def.tableName, startStr, endStr)
			if err := d.db.Exec(sql).Error; err != nil {
				log.Printf("Partition creation warning for %s: %v", partitionName, err)
				continue
			}

			// Create indexes on the partition for efficient queries
			indexes := []struct {
				name  string
				cols  string
				where string
			}{
				{fmt.Sprintf("idx_%s_device_ts", partitionName), fmt.Sprintf("(%s, %s)", "device_id", def.column), ""},
				{fmt.Sprintf("idx_%s_timestamp", partitionName), fmt.Sprintf("(%s)", def.column), ""},
			}

			// Add severity index for syslog/trap tables
			if def.tableName == "syslog_messages" {
				indexes = append(indexes,
					struct {
						name  string
						cols  string
						where string
					}{fmt.Sprintf("idx_%s_severity", partitionName), "(severity)", ""})
			}
			if def.tableName == "trap_events" {
				indexes = append(indexes,
					struct {
						name  string
						cols  string
						where string
					}{fmt.Sprintf("idx_%s_severity", partitionName), "(severity)", ""})
			}

			for _, idx := range indexes {
				createIdxSQL := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s %s", idx.name, partitionName, idx.cols)
				if idx.where != "" {
					createIdxSQL += " WHERE " + idx.where
				}
				if err := d.db.Exec(createIdxSQL).Error; err != nil {
					log.Printf("Index creation warning on %s: %v", partitionName, err)
				}
			}

			log.Printf("Created partition: %s", partitionName)
		}
	}

	return nil
}

// defaultAutovacuumTables is the built-in set of high-write tables that get
// aggressive autovacuum (AUDIT-147). It now includes interface_stats and
// system_status — the two heaviest time-series writers, which the original
// list omitted — alongside the per-poll/per-probe tables. Override the whole
// set with the DB_AUTOVACUUM_TABLES env var.
var defaultAutovacuumTables = []string{
	"syslog_messages",
	"syslog_summaries",
	"trap_events",
	"flow_samples",
	"ping_results",
	"alerts",
	"interface_stats",
	"system_status",
	"processor_stats",
	"process_stats",
	"vpn_status",
	"ha_status",
	"interface_addresses",
}

// autovacuumTables returns the tables to tune. By default that's
// defaultAutovacuumTables; DB_AUTOVACUUM_TABLES (comma-separated) overrides
// the whole set for deployments with a different write profile (AUDIT-147).
// Blank entries are ignored; an all-blank/empty override falls back to the
// default rather than tuning nothing.
func autovacuumTables() []string {
	env := strings.TrimSpace(os.Getenv("DB_AUTOVACUUM_TABLES"))
	if env == "" {
		return defaultAutovacuumTables
	}
	var tables []string
	for _, t := range strings.Split(env, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tables = append(tables, t)
		}
	}
	if len(tables) == 0 {
		return defaultAutovacuumTables
	}
	return tables
}

// ConfigureAutovacuum sets aggressive autovacuum parameters for high-volume tables.
// This reduces table bloat and improves query performance on PostgreSQL.
func (d *Database) ConfigureAutovacuum() error {
	if !d.dialect.IsPostgres() {
		return nil // Autovacuum is PostgreSQL-only
	}

	// AUDIT-147: the high-volume table list is configurable (see
	// autovacuumTables) and now includes the biggest time-series writers.
	// Each ALTER is failure-tolerant (logs + continues), so listing a table
	// that doesn't exist on a given deployment is harmless.
	tables := autovacuumTables()

	// Autovacuum settings for high-volume tables:
	// - vacuum_scale_factor = 0.01 (1% vs default 20%) - vacuum more frequently
	// - analyze_scale_factor = 0.05 (5% vs default 10%) - analyze more frequently
	// - vacuum_cost_delay = 10ms (vs default 20ms) - vacuum more aggressively
	// - vacuum_cost_limit = 2000 (vs default 200) - allow more work per vacuum
	for _, table := range tables {
		sql := fmt.Sprintf(`
			ALTER TABLE %s SET (
				autovacuum_vacuum_scale_factor = 0.01,
				autovacuum_analyze_scale_factor = 0.05,
				autovacuum_vacuum_cost_delay = 10,
				autovacuum_vacuum_cost_limit = 2000
			)`, table)
		if err := d.db.Exec(sql).Error; err != nil {
			// Log but don't fail - table might not exist yet or be a partitioned table
			log.Printf("Autovacuum config warning for %s: %v", table, err)
			continue
		}
		log.Printf("Configured autovacuum for %s", table)
	}

	return nil
}

// ensureInterfaceAddrUniqueIndex repairs the unique index that
// SaveInterfaceAddresses' UPSERT targets.
//
// AUDIT-030 added an `INSERT ... ON CONFLICT (device_id, ip_address)`
// UPSERT whose conflict target is the unique index `idx_ifaddr_dev_ip`
// declared on the InterfaceAddress model. On a deployment that predates
// AUDIT-030, the table accumulated duplicate (device_id, ip_address)
// rows under the old plain-INSERT path, so GORM's AutoMigrate cannot
// create the unique index — `CREATE UNIQUE INDEX` fails on duplicate
// values, and AutoMigrate only logs that failure as a warning and moves
// on. The index ends up absent, and from then on every UPSERT fails with
// SQLSTATE 42P10 ("there is no unique or exclusion constraint matching
// the ON CONFLICT specification"). That 500s POST /api/probes/:id/
// interface-addresses on every poll, leaving interface IP data stale and
// burning ~4-6s per device per cycle on the probe's retry/backoff.
//
// This migration is idempotent: it no-ops when the index already exists
// (the common case — fresh installs get it from AutoMigrate), and
// otherwise deduplicates the table (keeping the highest id per pair, i.e.
// the most recent row) before creating the index. Failures are logged,
// not fatal, so a startup race or permission issue degrades to the
// pre-existing broken-but-running state rather than crashing the server.
func (d *Database) ensureInterfaceAddrUniqueIndex() {
	if d.db.Migrator().HasIndex(&models.InterfaceAddress{}, "idx_ifaddr_dev_ip") {
		return
	}
	log.Println("Migrating interface_addresses: unique index idx_ifaddr_dev_ip is missing (legacy duplicate rows); deduplicating and creating it — /interface-addresses ingestion is failing with SQLSTATE 42P10 until this completes")

	// Keep the highest id per (device_id, ip_address). The Postgres
	// self-join form is fast on large tables; SQLite (test) lacks
	// DELETE ... USING, so fall back to the portable subquery.
	var dedup string
	if d.dialect.IsPostgres() {
		dedup = `DELETE FROM interface_addresses a USING interface_addresses b
		         WHERE a.device_id = b.device_id AND a.ip_address = b.ip_address AND a.id < b.id`
	} else {
		dedup = `DELETE FROM interface_addresses
		         WHERE id NOT IN (SELECT MAX(id) FROM interface_addresses GROUP BY device_id, ip_address)`
	}
	res := d.db.Exec(dedup)
	if res.Error != nil {
		log.Printf("WARNING: interface_addresses dedup failed; idx_ifaddr_dev_ip not created, ingestion still broken: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("interface_addresses: removed %d duplicate (device_id, ip_address) row(s) before indexing", res.RowsAffected)
	}
	if err := d.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_ifaddr_dev_ip ON interface_addresses (device_id, ip_address)`).Error; err != nil {
		log.Printf("WARNING: failed to create idx_ifaddr_dev_ip after dedup: %v", err)
		return
	}
	log.Println("interface_addresses: idx_ifaddr_dev_ip created — UPSERT ingestion restored")
}

// migrateProbeKeysToHash converts any plaintext probe registration keys (and
// the plaintext embedded in their `probe_registration_<key>` SystemSetting) to
// the hashed at-rest form (AUDIT-017). Idempotent: rows/settings already in the
// `sha256:` form are skipped, so it is safe to run on every startup.
//
// Safety for a live probe: the collector keeps sending the SAME plaintext token
// from its config; after this runs, the probe row holds HashProbeKey(token), and
// validateProbe hashes the incoming token to the same value — so a probe that
// was authenticating before the upgrade keeps authenticating after it. The
// probe-row pass is what auth depends on; the SystemSetting pass (registration
// flow, cold path) is independent, so a partial run never locks out an
// already-approved probe.
func (d *Database) migrateProbeKeysToHash() {
	var probes []models.Probe
	if err := d.db.Where("registration_key <> ''").Find(&probes).Error; err != nil {
		log.Printf("migrateProbeKeysToHash: load probes: %v", err)
	}
	hashedRows := 0
	for i := range probes {
		if IsHashedProbeKey(probes[i].RegistrationKey) {
			continue
		}
		hashed := HashProbeKey(probes[i].RegistrationKey)
		if err := d.db.Model(&models.Probe{}).Where("id = ?", probes[i].ID).
			Update("registration_key", hashed).Error; err != nil {
			log.Printf("migrateProbeKeysToHash: hash probe %d: %v", probes[i].ID, err)
			continue
		}
		hashedRows++
	}

	var settings []models.SystemSetting
	if err := d.db.Where("key LIKE ?", "probe_registration_%").Find(&settings).Error; err != nil {
		log.Printf("migrateProbeKeysToHash: load registration settings: %v", err)
	}
	hashedSettings := 0
	for i := range settings {
		embedded := strings.TrimPrefix(settings[i].Key, "probe_registration_")
		if IsHashedProbeKey(embedded) {
			continue
		}
		newKey := "probe_registration_" + HashProbeKey(embedded)
		// Drop any pre-existing hashed setting with the target key (avoids a
		// unique-key collision if this somehow ran half-way before).
		d.db.Where("key = ?", newKey).Delete(&models.SystemSetting{})
		if err := d.db.Model(&models.SystemSetting{}).Where("id = ?", settings[i].ID).
			Update("key", newKey).Error; err != nil {
			log.Printf("migrateProbeKeysToHash: rehash setting %d: %v", settings[i].ID, err)
			continue
		}
		hashedSettings++
	}
	if hashedRows > 0 || hashedSettings > 0 {
		log.Printf("AUDIT-017: hashed %d plaintext probe key(s) and %d registration setting(s) at rest", hashedRows, hashedSettings)
	}
}
