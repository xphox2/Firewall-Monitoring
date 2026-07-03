package database

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
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
		&models.FlowDetection{},
		&models.ThreatIntel{},
		&models.FlowInterfaceCounter{},
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

type partitionDef struct {
	tableName string
	column    string
}

// partitionTables are the high-volume time-series tables that are monthly
// RANGE-partitioned on `timestamp` (AUDIT-028 for interface_stats/system_status;
// AUDIT-146 for the four syslog/trap/flow tables). The v2 migration
// (migratePartitionHighVolume) converts each to a partitioned parent when it's
// empty; EnsurePartitions then creates the monthly child partitions. All six
// share the same machinery — they only differ in a couple of per-partition
// indexes (see EnsurePartitions).
var partitionTables = []partitionDef{
	{"interface_stats", "timestamp"},
	{"system_status", "timestamp"},
	{"syslog_messages", "timestamp"},
	{"syslog_summaries", "timestamp"},
	{"trap_events", "timestamp"},
	{"flow_samples", "timestamp"},
}

// execMaintenanceDDL runs one maintenance DDL statement with the connection's
// statement_timeout lifted for just that statement (REL-04). Partition
// create/drop, autovacuum tuning, and the empty-table partition conversion can
// each exceed the default 30s statement_timeout (AUDIT-037) on a large or busy
// database and abort with SQLSTATE 57014 — at startup or in the cleanup cron,
// exactly when the work must be allowed to finish. SET LOCAL keeps the lifted
// timeout scoped to this short transaction, so it never leaks back to pooled
// connections. On non-Postgres backends (SQLite test/dev — no statement_timeout)
// it runs the statement directly.
func (d *Database) execMaintenanceDDL(sql string, args ...interface{}) error {
	if !d.dialect.IsPostgres() {
		return d.db.Exec(sql, args...).Error
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
			return fmt.Errorf("lift statement_timeout: %w", err)
		}
		return tx.Exec(sql, args...).Error
	})
}

// EnsurePartitions creates monthly range partitions for high-volume tables on PostgreSQL.
// Partitions are created for the current month + 6 months ahead.
// This is safe for existing servers - it only creates new partitions, never modifies existing data.
func (d *Database) EnsurePartitions() error {
	if !d.dialect.IsPostgres() {
		return nil // Partitioning is PostgreSQL-only
	}

	tables := partitionTables

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
			if err := d.execMaintenanceDDL(sql); err != nil {
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
			// AUDIT-028: interface_stats is also queried by (device_id, ifIndex,
			// timestamp) for per-interface charts; recreate that 3-col index per
			// partition (the plain-table idx_iface_device_idx_ts). "index" is a
			// reserved word — quote it.
			if def.tableName == "interface_stats" {
				indexes = append(indexes,
					struct {
						name  string
						cols  string
						where string
					}{fmt.Sprintf("idx_%s_device_idx_ts", partitionName), `(device_id, "index", timestamp)`, ""})
			}

			for _, idx := range indexes {
				createIdxSQL := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s %s", idx.name, partitionName, idx.cols)
				if idx.where != "" {
					createIdxSQL += " WHERE " + idx.where
				}
				if err := d.execMaintenanceDDL(createIdxSQL); err != nil {
					log.Printf("Index creation warning on %s: %v", partitionName, err)
				}
			}

			log.Printf("Created partition: %s", partitionName)
		}
	}

	return nil
}

// migratePartitionHighVolume is the v2 migration (AUDIT-028/146): it converts the
// high-volume time-series tables from plain to monthly RANGE-partitioned parents.
// It ONLY converts a table that is EMPTY (a fresh install) — converting a
// populated ~100M-row table is a copy-rewrite far too heavy to run at startup, so
// a populated table is left plain and the operator converts it in a maintenance
// window per docs/partition-migration.md. Postgres-only; a no-op (still recorded)
// on the SQLite test backend.
//
// Ordering safety: RunMigrations (this) runs in NewDatabase BEFORE
// EnsurePartitions and before the server accepts traffic, so there is no window
// where a freshly-converted parent (which has no child partitions yet) receives
// an insert.
func (d *Database) migratePartitionHighVolume() error {
	if !d.dialect.IsPostgres() {
		return nil // SQLite test backend: no-op (the runner still records v2)
	}
	for _, t := range partitionTables {
		var isPartitioned bool
		if err := d.db.Raw(`SELECT EXISTS (
			SELECT 1 FROM pg_partitioned_table pt
			JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = ?)`,
			t.tableName).Scan(&isPartitioned).Error; err != nil {
			return fmt.Errorf("partition probe %s: %w", t.tableName, err)
		}
		if isPartitioned {
			continue // already converted (idempotent re-run)
		}

		var exists bool
		if err := d.db.Raw(`SELECT to_regclass(?) IS NOT NULL`, t.tableName).Scan(&exists).Error; err != nil {
			return fmt.Errorf("table-exists probe %s: %w", t.tableName, err)
		}
		if !exists {
			continue // table not created yet — nothing to convert
		}

		var hasRows bool
		if err := d.db.Raw(fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s LIMIT 1)", t.tableName)).Scan(&hasRows).Error; err != nil {
			return fmt.Errorf("row probe %s: %w", t.tableName, err)
		}
		if hasRows {
			log.Printf("WARNING: AUDIT-028 partition migration: %q has existing rows; NOT auto-converting (a populated-table copy is too heavy at startup). Convert it in a maintenance window per docs/partition-migration.md. Until then the table stays plain and cleanup uses batched DELETE.", t.tableName)
			continue
		}

		if err := d.convertEmptyTableToPartitioned(t.tableName, t.column); err != nil {
			return fmt.Errorf("convert %s to partitioned: %w", t.tableName, err)
		}
		log.Printf("AUDIT-028: converted empty table %q to a monthly RANGE-partitioned parent on %s", t.tableName, t.column)
	}
	return nil
}

// convertEmptyTableToPartitioned rewrites an EMPTY plain table into a RANGE
// partitioned parent in one transaction (Postgres DDL is transactional, so a
// mid-conversion failure rolls back cleanly). The old single-column PK(id) is
// intentionally NOT copied (`INCLUDING DEFAULTS` only) because a partitioned
// parent's PK must include the partition key; we add the composite PK(id, col).
// `INCLUDING DEFAULTS` preserves the `id` serial default so inserts keep
// auto-assigning ids. Caller guarantees the table is empty.
func (d *Database) convertEmptyTableToPartitioned(table, col string) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		// REL-04: the rename + LIKE-copy + PK build + drop below can exceed the
		// 30s statement_timeout (AUDIT-037) on a wide table; lift it for the
		// duration of this transaction. Postgres-only — the caller is PG-gated
		// and the DDL is PARTITION BY ...; SET LOCAL stays scoped to this tx.
		if d.dialect.IsPostgres() {
			if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
				return fmt.Errorf("lift statement_timeout: %w", err)
			}
		}
		// Rename the plain table aside and recreate it as a partitioned parent
		// from the old table's shape. INCLUDING DEFAULTS copies the id serial's
		// nextval() default so inserts keep auto-assigning ids.
		stmts := []string{
			fmt.Sprintf(`ALTER TABLE %s RENAME TO %s_prepart`, table, table),
			fmt.Sprintf(`CREATE TABLE %s (LIKE %s_prepart INCLUDING DEFAULTS) PARTITION BY RANGE (%s)`, table, table, col),
			fmt.Sprintf(`ALTER TABLE %s ADD PRIMARY KEY (id, %s)`, table, col),
		}
		for _, s := range stmts {
			if err := tx.Exec(s).Error; err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}

		// The id serial's sequence is still OWNED BY <table>_prepart.id — the
		// ownership dependency followed the table on RENAME. INCLUDING DEFAULTS
		// gave the new partitioned parent a nextval() default pointing at that
		// same sequence, so the new parent now depends on it too. A plain
		// DROP TABLE <table>_prepart would therefore fail with SQLSTATE 2BP01
		// ("cannot drop table ... because other objects depend on it"), because
		// Postgres would have to cascade-drop a sequence the live parent needs.
		// Re-point the sequence's ownership to the new parent's id column first;
		// then the old table drops cleanly and the sequence (with its current
		// value) survives, bound to the new table. We must NOT use
		// DROP TABLE ... CASCADE here — that would drop the still-needed sequence.
		var seq string
		if err := tx.Raw(
			`SELECT COALESCE(pg_get_serial_sequence(?, 'id'), '')`,
			table+"_prepart",
		).Scan(&seq).Error; err != nil {
			return fmt.Errorf("locate id sequence for %s: %w", table, err)
		}
		if seq != "" {
			if err := tx.Exec(fmt.Sprintf(`ALTER SEQUENCE %s OWNED BY %s.id`, seq, table)).Error; err != nil {
				return fmt.Errorf("reassign sequence %s ownership to %s.id: %w", seq, table, err)
			}
		}

		if err := tx.Exec(fmt.Sprintf(`DROP TABLE %s_prepart`, table)).Error; err != nil {
			return fmt.Errorf("DROP TABLE %s_prepart: %w", table, err)
		}
		return nil
	})
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
		if err := d.execMaintenanceDDL(sql); err != nil {
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
	// Run the dedupe + index build with NO statement timeout. AUDIT-037 sets a
	// per-connection statement_timeout (default 30s) via the DSN, applied to
	// EVERY pooled connection — including this one. On a large
	// interface_addresses table the dedupe DELETE and CREATE UNIQUE INDEX exceed
	// 30s and get canceled ("canceling statement due to statement timeout"), so
	// the index is never built and every UPSERT keeps failing 42P10 — the exact
	// failure seen on a 32 GB production DB after a data relocation. A
	// transaction pins one connection; `SET LOCAL statement_timeout = 0` lifts
	// the cap for just this maintenance DDL (Postgres only; SQLite has no such
	// knob and its test data is tiny). The CREATE UNIQUE INDEX briefly locks the
	// table while it builds, but ingestion to it is already failing, so there's
	// nothing to block; for a zero-lock manual repair use CREATE UNIQUE INDEX
	// CONCURRENTLY outside a transaction.
	err := d.db.Transaction(func(tx *gorm.DB) error {
		if d.dialect.IsPostgres() {
			if e := tx.Exec("SET LOCAL statement_timeout = 0").Error; e != nil {
				return fmt.Errorf("lift statement_timeout: %w", e)
			}
		}
		res := tx.Exec(dedup)
		if res.Error != nil {
			return fmt.Errorf("dedup: %w", res.Error)
		}
		if res.RowsAffected > 0 {
			log.Printf("interface_addresses: removed %d duplicate (device_id, ip_address) row(s) before indexing", res.RowsAffected)
		}
		if e := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_ifaddr_dev_ip ON interface_addresses (device_id, ip_address)`).Error; e != nil {
			return fmt.Errorf("create index: %w", e)
		}
		return nil
	})
	if err != nil {
		log.Printf("WARNING: interface_addresses index repair failed; idx_ifaddr_dev_ip not created, ingestion still broken: %v", err)
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

// migrateUnifyPingStats (v3) re-keys ping stats from (device_id, probe_id,
// target_ip) to a single continuous series per (device_id, target_ip), so a
// device's reachability history stays unified across probe replacements and the
// device page stops showing one duplicate row per probe. It (1) merges existing
// duplicate rows in memory — min(min), max(max), sample-weighted avg latency &
// packet loss, sum(samples), latest updated_at/probe_id — then (2) swaps the
// uniqueness index. Idempotent: re-running merges nothing (already unique) and
// the IF (NOT) EXISTS index swaps are no-ops. ping_stats is small + unpartitioned.
func (d *Database) migrateUnifyPingStats() error {
	var all []models.PingStats
	if err := d.db.Find(&all).Error; err != nil {
		return fmt.Errorf("unify ping stats: load: %w", err)
	}
	type key struct {
		dev    uint
		target string
	}
	groups := map[key][]models.PingStats{}
	for _, s := range all {
		k := key{s.DeviceID, s.TargetIP}
		groups[k] = append(groups[k], s)
	}

	err := d.db.Transaction(func(tx *gorm.DB) error {
		for _, rows := range groups {
			if len(rows) < 2 {
				continue
			}
			survivor := rows[0]
			minLat, maxLat := rows[0].MinLatency, rows[0].MaxLatency
			maxUpd := rows[0].UpdatedAt
			var sumSamples int
			var wAvg, wLoss float64
			for _, r := range rows {
				if r.UpdatedAt.After(survivor.UpdatedAt) {
					survivor = r // latest writer wins for the survivor row + probe_id
				}
				if r.MinLatency < minLat {
					minLat = r.MinLatency
				}
				if r.MaxLatency > maxLat {
					maxLat = r.MaxLatency
				}
				if r.UpdatedAt.After(maxUpd) {
					maxUpd = r.UpdatedAt
				}
				sumSamples += r.Samples
				wAvg += r.AvgLatency * float64(r.Samples)
				wLoss += r.PacketLoss * float64(r.Samples)
			}
			avg, loss := survivor.AvgLatency, survivor.PacketLoss
			if sumSamples > 0 {
				avg = wAvg / float64(sumSamples)
				loss = wLoss / float64(sumSamples)
			}
			if err := tx.Model(&models.PingStats{}).Where("id = ?", survivor.ID).Updates(map[string]interface{}{
				"min_latency": minLat,
				"max_latency": maxLat,
				"avg_latency": avg,
				"packet_loss": loss,
				"samples":     sumSamples,
				"updated_at":  maxUpd,
			}).Error; err != nil {
				return fmt.Errorf("unify ping stats: update survivor %d: %w", survivor.ID, err)
			}
			for _, r := range rows {
				if r.ID == survivor.ID {
					continue
				}
				if err := tx.Delete(&models.PingStats{}, r.ID).Error; err != nil {
					return fmt.Errorf("unify ping stats: delete dup %d: %w", r.ID, err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Swap the uniqueness index. DROP/CREATE IF (NOT) EXISTS is idempotent and
	// valid on both Postgres and SQLite.
	if err := d.db.Exec(`DROP INDEX IF EXISTS idx_pingstats_device_probe_target`).Error; err != nil {
		return fmt.Errorf("unify ping stats: drop old index: %w", err)
	}
	if err := d.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_pingstats_device_target ON ping_stats (device_id, target_ip)`).Error; err != nil {
		return fmt.Errorf("unify ping stats: create new index: %w", err)
	}
	return nil
}

// migrateProbeDecommissionedAt (v4) adds Probe.decommissioned_at (+ its index)
// to existing databases. The v1 baseline AutoMigrate doesn't re-run once
// recorded, so a new column needs its own migration; AutoMigrate only adds
// what's missing, so this is idempotent. Fresh installs already have it from the
// baseline run against the current model.
func (d *Database) migrateProbeDecommissionedAt() error {
	return d.db.AutoMigrate(&models.Probe{})
}

// migrateDeviceSSHHostKey (v6) adds Device.ssh_host_key — the pinned SSH
// host-key fingerprint used for change detection. Additive nullable column;
// AutoMigrate adds only what's missing, so this is idempotent and safe on a
// populated database.
func (d *Database) migrateDeviceSSHHostKey() error {
	return d.db.AutoMigrate(&models.Device{})
}

// migrateConfigRevisionAttribution (v5) adds the change-attribution columns
// (changed_by, changed_from, change_method, attributed, attribution_checked) to
// existing device_config_revisions tables. AutoMigrate only adds what's missing,
// so this is idempotent; fresh installs already have them from the baseline run.
func (d *Database) migrateConfigRevisionAttribution() error {
	return d.db.AutoMigrate(&models.DeviceConfigRevision{})
}

// migrateFlowSamplesSamplingRateScale (v7) backfills flow_samples so that
// existing rows conform to the new sFlow sampling-rate scaling convention:
// the bytes/packets columns now hold `frame_length × sampling_rate` and
// `sampling_rate` respectively (instead of the raw `frame_length` and `1`).
// The audit (2026-06-22, docs/audit-archive/audit-2026-06-22-taocp.md [critical] #1
// and #2) found the server had been storing frame_length verbatim, so every
// dashboard chart / top-N list under-reported real traffic by 1:N.
//
// Idempotency: the WHERE clause selects only rows that haven't been migrated
// yet (sampling_rate > 1 AND packets = 1). New inserts already write
// Packets = sampling_rate (the parser change in internal/sflow/sflow.go),
// so they never match the predicate. sampling_rate = 1 rows are a no-op
// (scaling by 1 is identity) and packets = 1 stays correct.
//
// Fresh installs: no rows in flow_samples at the time the baseline v1
// migration runs, so this UPDATE matches zero rows and is a no-op (still
// recorded as v7 in schema_migrations).
func (d *Database) migrateFlowSamplesSamplingRateScale() error {
	if !d.dialect.IsPostgres() {
		// SQLite (test backend): still run — the SQL is identical and the
		// production path uses Postgres, but tests that pre-seed flow_samples
		// benefit from the backfill running the same way.
	}

	result := d.db.Exec(`
		UPDATE flow_samples
		SET bytes = bytes * sampling_rate,
		    packets = sampling_rate
		WHERE sampling_rate > 1 AND packets = 1
	`)
	if result.Error != nil {
		return fmt.Errorf("migrate v7 flow_samples scaling: %w", result.Error)
	}
	log.Printf("migrate v7 flow_samples scaling: %d rows backfilled (bytes=frame_length*sampling_rate, packets=sampling_rate)", result.RowsAffected)
	return nil
}

// migrateFlowAgentDropsTable (v8) creates the flow_agent_drops table for
// per-(agent, sampling_rate) rolling-window aggregate of sFlow sample-pool
// drops (sFlow v5 §3.1.1). The audit (2026-06-22, taocp [MEDIUM] #5
// + consolidated C-3) found the drops field was invisible end-to-end;
// this table is the storage layer that lets alert policies and the NOC
// surface agent-side congestion.
//
// Idempotency: AutoMigrate is idempotent — it adds only what's missing.
// Fresh installs get the table from the AutoMigrate loop in
// migrateBaseline (via the allModels slice), so this migration is a
// no-op there too (still recorded as v8 in schema_migrations).
func (d *Database) migrateFlowAgentDropsTable() error {
	return d.db.AutoMigrate(&models.AgentDrops{})
}

// migrateFlowSamplesWidenIntColumns (v9) widens flow_samples integer columns
// that GORM's baseline AutoMigrate created one size too narrow. GORM's Postgres
// dialect maps a Go int to a column type by bit width and IGNORES signedness,
// so the UNSIGNED FlowSample fields landed in signed columns that can't hold
// their full range:
//
//	src_port / dst_port        uint16 -> smallint (max 32767)  but ports reach 65535
//	sequence_number            uint32 -> integer  (max 2.15B)  but sFlow seq nums pass 2^31
//	sampling_rate              uint32 -> integer                (same overflow risk)
//	input_if_index / output_if_index  uint32 -> integer        (same overflow risk)
//
// A single out-of-range value (an ephemeral source port of 54321, say) makes
// the pgx COPY in saveFlowSamplesPGX fail the WHOLE batch with a 500; the
// collector re-queues the same flows every cycle and no flow data is ever
// persisted. This widens the columns to types that hold the full unsigned
// range (ports -> integer, the uint32 fields -> bigint), matching the struct's
// `gorm:"type:..."` tags that fix fresh installs.
//
// Idempotency: Postgres `ALTER COLUMN ... TYPE` is a no-op (no table rewrite)
// when the column already has the target type, so re-running after a crash —
// or after the startup AutoMigrate already widened them — is harmless.
//
// SQLite (test backend) uses dynamic typing and has no fixed-width integer
// columns to overflow, and does not support ALTER COLUMN ... TYPE, so this is
// Postgres-only; on SQLite it is a recorded no-op.
func (d *Database) migrateFlowSamplesWidenIntColumns() error {
	if !d.dialect.IsPostgres() {
		log.Printf("migrate v9 flow_samples widen: non-Postgres backend, skipping (no-op)")
		return nil
	}
	stmt := `
		ALTER TABLE flow_samples
			ALTER COLUMN src_port TYPE integer,
			ALTER COLUMN dst_port TYPE integer,
			ALTER COLUMN sequence_number TYPE bigint,
			ALTER COLUMN sampling_rate TYPE bigint,
			ALTER COLUMN input_if_index TYPE bigint,
			ALTER COLUMN output_if_index TYPE bigint
	`
	if err := d.db.Exec(stmt).Error; err != nil {
		return fmt.Errorf("migrate v9 flow_samples widen int columns: %w", err)
	}
	log.Printf("migrate v9 flow_samples widen: src_port/dst_port -> integer, sequence_number/sampling_rate/input_if_index/output_if_index -> bigint")
	return nil
}

// migrateFlowSamplesAddDropsColumn (v10) adds the `drops` column to existing
// flow_samples tables. This is the actual fix for the probe-side
// `Failed to send flows batch: status 500 {"error":"Failed to save flow
// samples"}` loop: the server logged `column "drops" of relation
// "flow_samples" does not exist (SQLSTATE 42703)` and the collector re-queued
// the same flows forever, so no sFlow data was persisted.
//
// Cause: the `Drops` field (sFlow v5 §3.1.1 sample-pool drops, added in the
// 2026-06-22 audit) was added to the FlowSample model and to
// saveFlowSamplesPGX's COPY column list, but no migration added the column to
// databases created before the field existed. cmd/api boots with
// RunMigrations() only — there is NO per-startup AutoMigrate — and the baseline
// AutoMigrate (v1) had already been recorded as applied, so it never re-ran to
// pick up the new field. Every COPY then named a column the table lacked and
// failed at parse time.
//
// `drops` is uint64 in the model (gorm column `drops`, default 0, not null), so
// the column is `bigint NOT NULL DEFAULT 0`. Adding a column with a constant
// default is metadata-only on PostgreSQL 11+ (no table rewrite), so it is fast
// even on a large flow_samples. Routed through execMaintenanceDDL so the lifted
// statement_timeout covers the case of a partitioned flow_samples propagating
// the ADD across many partitions on deployments that converted the table.
//
// Idempotency: `ADD COLUMN IF NOT EXISTS` no-ops once the column is present, so
// fresh installs (which get `drops` from the baseline AutoMigrate) and any
// re-run are safe. SQLite (the test backend) already has the column from
// AutoMigrate and does not support `ADD COLUMN IF NOT EXISTS`, so the
// non-Postgres path uses AutoMigrate, which adds the column only if missing.
func (d *Database) migrateFlowSamplesAddDropsColumn() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowSample{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS drops bigint NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("migrate v10 add flow_samples.drops: %w", err)
	}
	log.Printf("migrate v10 flow_samples.drops: ensured column exists (bigint not null default 0)")
	return nil
}

// migrateFlowClassificationColumns (v11) adds the ingest-time classification
// columns app_category and direction to flow_samples and flow_rollups. These
// hold internal/classify's Category (Web/DNS/VPN/…) and Direction
// (inbound/outbound/internal/external) so the Flows page can GROUP BY them
// without re-deriving on every read, and so the By-Application / By-Direction
// views survive after raw samples are rolled up.
//
// Both are `smallint NOT NULL DEFAULT 0` (0 = Unknown). Adding a column with a
// constant default is metadata-only on PostgreSQL 11+ (no table rewrite), so it
// is fast even on a large/partitioned flow_samples; routed through
// execMaintenanceDDL so the lifted statement_timeout covers a partitioned table
// propagating the ADD across many partitions.
//
// Idempotency: `ADD COLUMN IF NOT EXISTS` no-ops once the column exists, so
// fresh installs (which get the columns from the baseline AutoMigrate) and any
// re-run after a crash are safe. SQLite (test backend) does not support
// `ADD COLUMN IF NOT EXISTS`, so the non-Postgres path uses AutoMigrate, which
// adds the columns only if missing.
func (d *Database) migrateFlowClassificationColumns() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{})
	}
	stmts := []string{
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS app_category smallint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS direction smallint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS app_category smallint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS direction smallint NOT NULL DEFAULT 0`,
	}
	for _, s := range stmts {
		if err := d.execMaintenanceDDL(s); err != nil {
			return fmt.Errorf("migrate v11 flow classification columns: %w", err)
		}
	}
	log.Printf("migrate v11 flow classification: ensured app_category/direction on flow_samples and flow_rollups")
	return nil
}

// migrateFlowGeoIPColumns (v12) adds the MaxMind GeoLite2 enrichment columns:
// src_country/dst_country (ISO alpha-2) and src_asn/dst_asn on flow_samples, and
// the destination pair (dst_country/dst_asn) on flow_rollups for the Top
// Countries / Top ASNs views. Country is CHAR(2); ASN is bigint (AS numbers
// approach 2^32). All nullable / default-0 so pre-enrichment rows and the
// geo-disabled default remain valid.
//
// Adding a column (with or without a constant default) is metadata-only on
// PostgreSQL 11+, so this is fast even on a large/partitioned flow_samples;
// routed through execMaintenanceDDL for the partitioned-propagation case.
//
// Idempotency: `ADD COLUMN IF NOT EXISTS` no-ops once present. SQLite (test
// backend) lacks that clause, so the non-Postgres path uses AutoMigrate, which
// adds only missing columns.
func (d *Database) migrateFlowGeoIPColumns() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{})
	}
	stmts := []string{
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS src_country varchar(2)`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS dst_country varchar(2)`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS src_asn bigint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS dst_asn bigint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS dst_country varchar(2)`,
		`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS dst_asn bigint NOT NULL DEFAULT 0`,
	}
	for _, s := range stmts {
		if err := d.execMaintenanceDDL(s); err != nil {
			return fmt.Errorf("migrate v12 flow geoip columns: %w", err)
		}
	}
	log.Printf("migrate v12 flow geoip: ensured src/dst_country + src/dst_asn on flow_samples, dst_country/dst_asn on flow_rollups")
	return nil
}

// migrateFlowDetectionsTable (v13) creates the flow_detections table that backs
// the sFlow detection engine (internal/detect). Mirrors migrateFlowAgentDropsTable:
// AutoMigrate is idempotent and cross-dialect, fresh installs get the table from
// the baseline allModels loop, so this is a recorded no-op there. The table is
// not partitioned — its row volume is bounded (detectors × targets × cycles).
func (d *Database) migrateFlowDetectionsTable() error {
	return d.db.AutoMigrate(&models.FlowDetection{})
}

// migrateThreatIntelAndFlowThreatFlag (v14) creates the threat_intel feed table
// and adds the threat_flag bitfield column to flow_samples. The table is created
// via AutoMigrate (idempotent, cross-dialect, also in the baseline allModels
// loop). The column add is metadata-only on PG11+ and routed through
// execMaintenanceDDL for the partitioned-flow_samples case; on SQLite the
// non-Postgres path uses AutoMigrate.
func (d *Database) migrateThreatIntelAndFlowThreatFlag() error {
	if err := d.db.AutoMigrate(&models.ThreatIntel{}); err != nil {
		return fmt.Errorf("migrate v14 threat_intel table: %w", err)
	}
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowSample{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS threat_flag smallint NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("migrate v14 add flow_samples.threat_flag: %w", err)
	}
	log.Printf("migrate v14: ensured threat_intel table + flow_samples.threat_flag")
	return nil
}

// migrateFlowBGPColumns (v15) adds the as_path and next_hop columns to
// flow_samples for the sFlow extended_gateway (BGP) enrichment. Both are
// nullable text/varchar that stay empty for the common case (non-BGP samplers),
// so the storage cost on the flow firehose is negligible. Metadata-only column
// add on PG11+, routed through execMaintenanceDDL for the partitioned table;
// SQLite uses AutoMigrate.
func (d *Database) migrateFlowBGPColumns() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowSample{})
	}
	stmts := []string{
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS as_path text`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS next_hop varchar(45)`,
	}
	for _, s := range stmts {
		if err := d.execMaintenanceDDL(s); err != nil {
			return fmt.Errorf("migrate v15 (%s): %w", s, err)
		}
	}
	log.Printf("migrate v15: ensured flow_samples.as_path + next_hop")
	return nil
}

// migrateFlowIfCountersTable (v16) creates the flow_if_counters table for sFlow
// interface counter samples (schema_version 2). Created via AutoMigrate
// (idempotent, cross-dialect, also in the baseline allModels loop). Not
// partitioned — retention-pruned in CleanupOldData alongside flow_samples.
func (d *Database) migrateFlowIfCountersTable() error {
	if err := d.db.AutoMigrate(&models.FlowInterfaceCounter{}); err != nil {
		return fmt.Errorf("migrate v16 flow_if_counters table: %w", err)
	}
	log.Printf("migrate v16: ensured flow_if_counters table")
	return nil
}

// migrateThreatIntelCIDRColumnRename (v17) fixes a latent v14 naming bug: GORM
// derived the column name "c_id_r" from the CIDR field, but every OnConflict
// clause referenced "cidr" — so a duplicate (cidr, source) upsert errored. The
// model now pins `column:cidr`; this migration renames the existing column on
// Postgres (the unique index follows the rename). On SQLite the table is
// recreated from the model with the right name, so AutoMigrate suffices.
func (d *Database) migrateThreatIntelCIDRColumnRename() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.ThreatIntel{})
	}
	var hasOld, hasNew bool
	d.db.Raw(`SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='threat_intel' AND column_name='c_id_r')`).Scan(&hasOld)
	d.db.Raw(`SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='threat_intel' AND column_name='cidr')`).Scan(&hasNew)
	if hasOld && !hasNew {
		if err := d.execMaintenanceDDL(`ALTER TABLE threat_intel RENAME COLUMN c_id_r TO cidr`); err != nil {
			return fmt.Errorf("migrate v17 rename threat_intel.c_id_r -> cidr: %w", err)
		}
		log.Printf("migrate v17: renamed threat_intel.c_id_r -> cidr")
	}
	return nil
}

// migrateFlowIfCountersAddDirection (v18) adds flow_if_counters.if_direction
// (audit 2026-07-01 finding L12). The collector has always sent
// the sFlow ifDirection field on the schema-v2 counter-sample wire form, but the
// server model lacked the column, so GORM's JSON bind silently dropped it at
// ingest. Adding the column lets the value persist; existing rows backfill to 0
// (unknown), which is the correct "not observed" sentinel.
//
// `bigint NOT NULL DEFAULT 0` matches the uint32 model field's gorm type. Adding
// a column with a constant default is metadata-only on PostgreSQL 11+ (no table
// rewrite), routed through execMaintenanceDDL so the lifted statement_timeout
// covers propagation across flow_if_counters' partitions. Idempotent via
// `ADD COLUMN IF NOT EXISTS`; SQLite (tests/fresh installs) uses AutoMigrate.
func (d *Database) migrateFlowIfCountersAddDirection() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowInterfaceCounter{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE flow_if_counters ADD COLUMN IF NOT EXISTS if_direction bigint NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("migrate v18 add flow_if_counters.if_direction: %w", err)
	}
	log.Printf("migrate v18 flow_if_counters.if_direction: ensured column exists (bigint not null default 0)")
	return nil
}

// migrateAdminMustChangePassword adds the boolean that forces a first-login
// password change. Existing admins default to false (they set their password
// deliberately, or already rotated it) — only freshly-bootstrapped admins with
// an auto-generated password get the flag set, at InitAdmin time.
func (d *Database) migrateAdminMustChangePassword() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.Admin{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false`); err != nil {
		return fmt.Errorf("migrate v19 add admins.must_change_password: %w", err)
	}
	log.Printf("migrate v19 admins.must_change_password: ensured column exists (boolean not null default false)")
	return nil
}

// migrateAdminRoles (v20, RBAC / P0-1) adds admins.role + admins.disabled and
// backfills every pre-existing row to role='admin' — the pre-RBAC deployment
// had exactly one account and it was the admin, so this preserves its rights
// with no operator action. Also AutoMigrates AuditLog: deployments whose
// baseline ran before ActorID was added to the model never got the actor_id
// column (baseline only runs once), and RBAC makes per-actor attribution
// load-bearing.
func (d *Database) migrateAdminRoles() error {
	if !d.dialect.IsPostgres() {
		if err := d.db.AutoMigrate(&models.Admin{}); err != nil {
			return err
		}
		if err := d.db.Exec(`UPDATE admins SET role = 'admin' WHERE role IS NULL OR role = ''`).Error; err != nil {
			return fmt.Errorf("migrate v20 backfill admins.role: %w", err)
		}
		return d.db.AutoMigrate(&models.AuditLog{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'admin'`); err != nil {
		return fmt.Errorf("migrate v20 add admins.role: %w", err)
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS disabled boolean NOT NULL DEFAULT false`); err != nil {
		return fmt.Errorf("migrate v20 add admins.disabled: %w", err)
	}
	if err := d.db.Exec(`UPDATE admins SET role = 'admin' WHERE role IS NULL OR role = ''`).Error; err != nil {
		return fmt.Errorf("migrate v20 backfill admins.role: %w", err)
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_id bigint`); err != nil {
		return fmt.Errorf("migrate v20 add audit_logs.actor_id: %w", err)
	}
	log.Printf("migrate v20 admin_roles: ensured admins.role/disabled + audit_logs.actor_id exist; pre-existing accounts backfilled to role=admin")
	return nil
}

// migrateAPITokens (v21, P0-2) creates the api_tokens table. AutoMigrate is
// idempotent and the model is new, so this is safe on both dialects.
func (d *Database) migrateAPITokens() error {
	if err := d.db.AutoMigrate(&models.ApiToken{}); err != nil {
		return fmt.Errorf("migrate v21 api_tokens: %w", err)
	}
	log.Printf("migrate v21 api_tokens: table ensured")
	return nil
}

// migrateAdminTOTP (v22, P0-3) adds the TOTP columns to admins and creates the
// admin_recovery_codes table. All additive: TOTP is opt-in per account and
// defaults off, so upgrading changes nothing until a user enrolls.
func (d *Database) migrateAdminTOTP() error {
	if !d.dialect.IsPostgres() {
		if err := d.db.AutoMigrate(&models.Admin{}); err != nil {
			return fmt.Errorf("migrate v22 admins totp columns: %w", err)
		}
		return d.db.AutoMigrate(&models.AdminRecoveryCode{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_secret text NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate v22 add admins.totp_secret: %w", err)
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_enabled boolean NOT NULL DEFAULT false`); err != nil {
		return fmt.Errorf("migrate v22 add admins.totp_enabled: %w", err)
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_confirmed_at timestamptz`); err != nil {
		return fmt.Errorf("migrate v22 add admins.totp_confirmed_at: %w", err)
	}
	if err := d.db.AutoMigrate(&models.AdminRecoveryCode{}); err != nil {
		return fmt.Errorf("migrate v22 admin_recovery_codes: %w", err)
	}
	log.Printf("migrate v22 admin_totp: ensured admins TOTP columns + admin_recovery_codes table")
	return nil
}
