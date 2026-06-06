package database

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/configdiff"
	"firewall-mon/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type Database struct {
	db          *gorm.DB
	encKeys     keyChain
	dialect     Dialect
	syslogBatch *BatchInserter[models.SyslogMessage]
	trapBatch   *BatchInserter[models.TrapEvent]
	pingBatch   *BatchInserter[models.PingResult]
}

func (d *Database) Gorm() *gorm.DB {
	return d.db
}

func (d *Database) IsPostgres() bool {
	return d.dialect.IsPostgres()
}

// pgQuote quotes a value for use in a PostgreSQL key=value DSN.
// Wraps in single quotes and escapes embedded single quotes and backslashes.
func pgQuote(s string) string {
	if !strings.ContainsAny(s, " '\\") {
		return s
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

func NewDatabase(cfg *config.Config) (*Database, error) {
	var db *gorm.DB
	var dial Dialect
	var err error

	gormCfg := &gorm.Config{
		// AUDIT-149: pre-fix this was `logger.Silent`, which
		// swallowed every GORM-internal log (slow-query
		// warnings, transaction lifecycle, errors that GORM
		// recovered from). The audit's concern was twofold:
		//   1. Production deployments had no visibility into
		//      slow queries (no `>200ms` warnings, no query
		//      plan logs).
		//   2. Errors that GORM catches and recovers from
		//      (e.g. transient connection drops) were
		//      completely invisible.
		//
		// The fix: `logger.Warn` is the right minimum-noise
		// setting. It logs slow queries, errors, and
		// migration warnings, but NOT every successful
		// statement (which would flood the log). Operators
		// who want more visibility can switch to `logger.Info`
		// (every statement) via the `DB_LOG_LEVEL` env var.
		// The level-to-mode mapping is a small helper in
		// `internal/database/logging.go` (kept in this package
		// so it's testable).
		Logger: logger.Default.LogMode(dbLogLevelFromEnv()),
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port,
		pgQuote(cfg.Database.User), pgQuote(cfg.Database.Password),
		pgQuote(cfg.Database.Name), cfg.Database.SSLMode)
	// AUDIT-037: enforce a per-connection statement timeout
	// server-side. The timeout is set via the connection
	// string's `options=-c statement_timeout=...` so it
	// applies to every connection the pool opens (not just
	// the first one). The server-side enforcement survives
	// application code that forgets to set a
	// `context.WithTimeout` — AUDIT-032's
	// `WithContext(c.Request.Context())` rollout covers the
	// in-application side; this is the belt-and-suspenders
	// backstop. 0 disables the timeout (not recommended for
	// production; useful for migrations that need to run
	// large DDL).
	if cfg.Database.StatementTimeout > 0 {
		dsn = fmt.Sprintf("%s options='-c statement_timeout=%dms'",
			dsn, cfg.Database.StatementTimeout.Milliseconds())
	}
	db, err = gorm.Open(postgres.Open(dsn), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	sqlDB, dbErr := db.DB()
	if dbErr != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", dbErr)
	}
	// AUDIT-036: per-process pool size. cfg.Database.MaxOpenConns is set by the
	// daemon's main (15 api / 10 poller / 5 trap), overridable via
	// DB_MAX_OPEN_CONNS; 0 falls back to the legacy 25. Idle is capped at the
	// open limit (never larger) and at 10.
	maxOpen := cfg.Database.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 25
	}
	maxIdle := maxOpen
	if maxIdle > 10 {
		maxIdle = 10
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(1 * time.Minute)
	log.Printf("Database: pool max_open=%d max_idle=%d", maxOpen, maxIdle)
	dial = postgresDialect{}
	log.Printf("Database: connected to PostgreSQL at %s:%d/%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.Name)

	var encKey []byte
	if cfg.Server.EncryptionKey != "" {
		encKey = deriveKey(cfg.Server.EncryptionKey)
	} else if cfg.Server.JWTSecretKey != "" {
		log.Println("WARNING: ENCRYPTION_KEY not set — falling back to JWT secret for database encryption. To use a separate key, set ENCRYPTION_KEY to the SAME value as JWT_SECRET_KEY first, then rotate it.")
		encKey = deriveKey(cfg.Server.JWTSecretKey)
	}

	// AUDIT-009: load any legacy keys for decrypt-only fallback. Comma-
	// separated list in ENCRYPTION_KEY_HISTORY env, ordered newest-historical
	// first. Encrypt always uses the current key; decrypt tries current
	// first then each legacy key. Operators rotate by:
	//   1. Set new value of ENCRYPTION_KEY.
	//   2. Move the previous ENCRYPTION_KEY value into ENCRYPTION_KEY_HISTORY.
	//   3. Restart — new writes use the new key, old reads fall through.
	//   4. (Optional) run a re-encryption migration to re-save every
	//      {enc} row under the new key, then drop the entry from
	//      ENCRYPTION_KEY_HISTORY.
	var legacyKeys [][]byte
	if history := os.Getenv("ENCRYPTION_KEY_HISTORY"); history != "" {
		for _, k := range strings.Split(history, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				legacyKeys = append(legacyKeys, deriveKey(k))
			}
		}
		if len(legacyKeys) > 0 {
			log.Printf("Loaded %d legacy decryption key(s) from ENCRYPTION_KEY_HISTORY", len(legacyKeys))
		}
	}

	d := &Database{db: db, encKeys: keyChain{current: encKey, legacy: legacyKeys}, dialect: dial}

	// Initialize batch inserters
	d.syslogBatch = NewBatchInserter[models.SyslogMessage](500, 2*time.Second, func(items []models.SyslogMessage) error {
		return d.db.Create(&items).Error
	})
	d.trapBatch = NewBatchInserter[models.TrapEvent](100, 5*time.Second, func(items []models.TrapEvent) error {
		return d.db.Create(&items).Error
	})
	d.pingBatch = NewBatchInserter[models.PingResult](100, 5*time.Second, func(items []models.PingResult) error {
		return d.db.Create(&items).Error
	})

	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	// The chatty post-migration setup steps (partitions, autovacuum, legacy
	// duplicate collapse, default policy, vendor audit, secret encryption)
	// are all idempotent. The container runs 3 processes that each call
	// NewDatabase — without serialization, all three race to do the same
	// work and produce 2-3× duplicate log lines for every step. A Postgres
	// session-scoped advisory lock lets exactly ONE process do the work
	// (and log it); the other two skip silently with a single explanatory
	// line. AutoMigrate above is left running unconditionally because
	// (a) GORM's silent logger keeps it noiseless on no-op runs and
	// (b) schema must exist before any process queries, regardless of
	// which one wins the lock race.
	if !d.tryAcquireStartupLock() {
		log.Println("Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).")
		return d, nil
	}

	// Ensure PostgreSQL partitions exist for high-volume tables
	if err := d.EnsurePartitions(); err != nil {
		log.Printf("Partition setup warning: %v", err)
	}

	// Configure aggressive autovacuum for high-volume tables
	if err := d.ConfigureAutovacuum(); err != nil {
		log.Printf("Autovacuum config warning: %v", err)
	}

	// One-time migration: collapse legacy IV-drift duplicate revisions left
	// over from v0.10.187 → v0.10.197 (always-store era). Idempotent — safe
	// to run on every startup but does real work only when duplicates exist.
	if deleted, err := d.CollapseLegacyConfigRevisionDuplicates(); err != nil {
		log.Printf("Legacy config-revision collapse warning: %v", err)
	} else if deleted > 0 {
		log.Printf("Legacy config-revision collapse: removed %d duplicate revisions", deleted)
	}

	// Ensure a default alert policy exists
	d.EnsureDefaultPolicy()

	// Backfill empty vendor → fortigate (the in-code default per
	// internal/models/models.go) and audit the fleet's vendor distribution.
	// Any device whose vendor lacks a rich normalizer in internal/configdiff
	// will silently false-alert on every config backup, because byte-equality
	// hashing makes random-IV ENC ciphertext look like a real change. The
	// audit log makes that visible without mutating the data.
	d.auditDeviceVendors()

	// Encrypt any existing plaintext SNMP credentials
	d.migrateEncryptSecrets()

	return d, nil
}

// startupMigrationLockKey identifies the post-migration startup-setup
// advisory lock. Any stable int64 works — the only constraint is that all
// three processes (API, poller, trap-receiver) target the same key. Value
// is the ASCII bytes of "FWMNSTUP" packed into a uint64 so it's visible if
// it ever shows up in pg_locks.
const startupMigrationLockKey int64 = 0x46574d4e53545550

// tryAcquireStartupLock attempts a non-blocking Postgres advisory lock that
// serializes the chatty post-migration startup steps across processes that
// share a database. The lock is intentionally NOT released here — it's
// session-scoped, so Postgres drops it when the connection closes (at the
// 5-minute SetConnMaxLifetime boundary or at process exit, whichever comes
// first). By the time the lock is released, every sibling process has
// already passed the startup-setup branch and won't re-attempt.
//
// SQLite (tests) returns true unconditionally — single-process there.
func (d *Database) tryAcquireStartupLock() bool {
	if !d.dialect.IsPostgres() {
		return true
	}
	var acquired bool
	if err := d.db.Raw("SELECT pg_try_advisory_lock(?)", startupMigrationLockKey).Scan(&acquired).Error; err != nil {
		// Probe failure: bias toward running setup (idempotent) over
		// skipping. Duplicate log output is better than a missed startup
		// step on a transient error.
		log.Printf("Startup lock probe failed (%v); proceeding with setup anyway.", err)
		return true
	}
	return acquired
}

// pollerWorkLockKey is a stable int64 keyed to the ASCII bytes of
// "POLLERWORK"-ish content packed into a uint64 — chosen so it's visible
// in pg_locks if an operator ever inspects it. AUDIT-007: shared by all
// poller-process cron ticks (pollAllDevices, rollup, cleanup) so two
// poller instances don't run the same work twice.
const pollerWorkLockKey int64 = 0x504f4c4c45525357 // "POLLERSW"

// TryAcquirePollerWorkLock attempts a non-blocking Postgres advisory lock
// shared by all poller processes. Returns true if this caller owns the
// lock and should proceed with work; false if another poller already holds
// it (caller should skip the cron tick and try again on the next one).
//
// AUDIT-007: under a 2-poller deployment, both processes' cron tickers
// fire roughly concurrently. Without this lock both pollers poll every
// device on every tick (2× SNMP load), both fire alerts (cooldown map is
// in-memory and per-process, so dedup fails across processes), both email
// the daily report, and both contend on the 24h cleanup's row-lock
// schedule.
//
// Pair every call with `defer db.ReleasePollerWorkLock()`. If the caller
// crashes between acquire and release, the lock is dropped at session
// close (5 min `SetConnMaxLifetime` boundary or sooner) — a minor
// availability hit (one cron tick skipped) but not stuck forever.
//
// SQLite (tests) returns true unconditionally — single-process there.
func (d *Database) TryAcquirePollerWorkLock() bool {
	if !d.dialect.IsPostgres() {
		return true
	}
	var acquired bool
	if err := d.db.Raw("SELECT pg_try_advisory_lock(?)", pollerWorkLockKey).Scan(&acquired).Error; err != nil {
		// Probe failure: bias toward DOING the work over skipping it.
		// A duplicate poll cycle is recoverable; a missed one is not.
		log.Printf("Poller work lock probe failed (%v); proceeding with work anyway.", err)
		return true
	}
	return acquired
}

// ReleasePollerWorkLock releases the lock obtained by TryAcquirePollerWorkLock.
// Call via defer immediately after a successful acquire so the lock is
// released on any return path (including panic).
//
// SQLite (tests) is a no-op.
func (d *Database) ReleasePollerWorkLock() {
	if !d.dialect.IsPostgres() {
		return
	}
	if err := d.db.Exec("SELECT pg_advisory_unlock(?)", pollerWorkLockKey).Error; err != nil {
		// Best-effort release. On error the session-close fallback
		// (SetConnMaxLifetime) eventually drops the lock.
		log.Printf("Poller work lock release failed (%v); will auto-release on connection close.", err)
	}
}

func (d *Database) migrate() error {
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
		// AUDIT-067: per-request probe-token audit log. See models.ProbeTokenAudit
		// for the schema rationale (narrow fields tuned for "find every request
		// this probe/token made" + "find every request this source IP made" +
		// timeline reconstruction after a token compromise).
		&models.ProbeTokenAudit{},
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

	// One-time fix: if IRC tables have wrong column names from prior migrations,
	// drop and recreate them. Detect by checking for the correct server_password column.
	m := d.db.Migrator()
	if m.HasTable(&models.IRCServer{}) && !m.HasColumn(&models.IRCServer{}, "ServerPassword") {
		log.Println("IRC migrate: detected old schema, recreating IRC tables")
		ircTables := []interface{}{&models.IRCMessageLog{}, &models.IRCCommand{}, &models.IRCChannel{}, &models.IRCServer{}}
		err := d.db.Transaction(func(tx *gorm.DB) error {
			for _, tbl := range ircTables {
				if m.HasTable(tbl) {
					if err := m.DropTable(tbl); err != nil {
						return fmt.Errorf("IRC migrate: drop table %T: %w", tbl, err)
					}
				}
			}
			for _, tbl := range ircTables {
				if err := tx.AutoMigrate(tbl); err != nil {
					return fmt.Errorf("IRC migrate: recreate table %T: %w", tbl, err)
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("%v", err)
		}
	}

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

	// AUDIT-067: add tenant_id column on Probe. Existing rows backfill to
	// "default" so the v0.10.363 cross-tenant 403 is a no-op for pre-existing
	// single-tenant deployments (every probe has the same tenant → the
	// per-tenant check always passes). The column default in the Probe model
	// tag (`gorm:"default:default"`) handles new INSERTs, but the manual
	// ALTER above does NOT backfill the default into existing rows on every
	// backend (GORM's AddColumn emits a plain `ADD COLUMN … TYPE` on
	// Postgres/SQLite; the DEFAULT clause is part of the column definition
	// for new rows only). So we explicitly UPDATE here for the rare case the
	// default is empty. The index is added by AutoMigrate above (the
	// `index` tag in models.Probe); the AddColumn path here is for
	// pre-existing tables that predate the column entirely.
	if m.HasTable(&models.Probe{}) && !m.HasColumn(&models.Probe{}, "tenant_id") {
		if err := m.AddColumn(&models.Probe{}, "TenantID"); err != nil {
			log.Printf("migrate: add Probe.TenantID: %v", err)
		} else {
			log.Printf("migrate: added Probe.TenantID")
			// Backfill any existing rows (including those that might have
			// somehow ended up with a NULL or empty value, even though
			// the column DEFAULT applies to new INSERTs only).
			if err := d.db.Model(&models.Probe{}).
				Where("tenant_id IS NULL OR tenant_id = ''").
				Update("tenant_id", models.DefaultTenantID).Error; err != nil {
				log.Printf("migrate: backfill Probe.TenantID: %v", err)
			}
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

func (d *Database) SaveSystemStatus(status *models.SystemStatus) error {
	return d.db.Create(status).Error
}

func (d *Database) GetSystemStatus(limit int) ([]models.SystemStatus, error) {
	var statuses []models.SystemStatus
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&statuses).Error
	return statuses, err
}

func (d *Database) SaveInterfaceStats(stats []models.InterfaceStats) error {
	if len(stats) == 0 {
		return nil
	}
	return d.db.Create(&stats).Error
}

func (d *Database) GetInterfaceStats(limit int) ([]models.InterfaceStats, error) {
	var stats []models.InterfaceStats
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&stats).Error
	return stats, err
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

func (d *Database) SaveInterfaceAddresses(addrs []models.InterfaceAddress) error {
	if len(addrs) == 0 {
		return nil
	}
	// AUDIT-030: pre-fix this was a plain `Create` that appended
	// a row on every probe poll, even when the (device_id,
	// ip_address) pair was unchanged. With 50 devices × 4
	// polls/min × 90 days that's ~25M rows of mostly-redundant
	// data — the table grew unbounded.
	//
	// The fix is a portable UPSERT: GORM's `clause.OnConflict`
	// emits `INSERT ... ON CONFLICT (device_id, ip_address) DO
	// UPDATE SET ...` on Postgres, and the equivalent UPSERT
	// syntax on SQLite. The unique index `idx_ifaddr_dev_ip`
	// (declared on the InterfaceAddress model) is the conflict
	// target. We update `timestamp` (so the row reflects the
	// most recent poll), `if_index` (in case the IP moved
	// interfaces), and `net_mask` (in case the subnet was
	// reconfigured). The `id` field is left alone — GORM handles
	// the insert-vs-update distinction via the conflict clause.
	//
	// Operators who relied on the historical "this device had
	// this IP at this time" view (e.g. for forensics) will see
	// only the latest state. The intent of the table is current-
	// state, not history — historical IP data was always
	// effectively a time series, and the audit's "rows: 25M"
	// estimate showed that the original design was unusable at
	// scale. The proper historical view belongs in a separate
	// audit-log table if/when it's needed.
	return d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "device_id"}, {Name: "ip_address"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"timestamp", "if_index", "net_mask",
		}),
	}).Create(&addrs).Error
}

// GetLatestInterfaceAddresses returns the latest interface address snapshot per device.
func (d *Database) GetLatestInterfaceAddresses() ([]models.InterfaceAddress, error) {
	var addrs []models.InterfaceAddress
	err := d.db.Raw(`
		SELECT a.* FROM interface_addresses a
		INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
		ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts
	`).Scan(&addrs).Error
	return addrs, err
}

// GetAllLatestInterfaces returns the latest interface stats snapshot across all devices.
func (d *Database) GetAllLatestInterfaces() ([]models.InterfaceStats, error) {
	var ifaces []models.InterfaceStats
	err := d.db.Raw(`
		SELECT i.* FROM interface_stats i
		INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
		ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts
	`).Scan(&ifaces).Error
	return ifaces, err
}

func (d *Database) GetLatestSystemStatus() (*models.SystemStatus, error) {
	var status models.SystemStatus
	err := d.db.Order("timestamp DESC").First(&status).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func (d *Database) GetLatestInterfaceStats() ([]models.InterfaceStats, error) {
	// Get the most recent timestamp
	var latest models.InterfaceStats
	if err := d.db.Order("timestamp DESC").First(&latest).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	// Get all interfaces from that timestamp
	var stats []models.InterfaceStats
	err := d.db.Where("timestamp = ?", latest.Timestamp).Find(&stats).Error
	return stats, err
}

func (d *Database) SaveVPNStatuses(statuses []models.VPNStatus) error {
	if len(statuses) == 0 {
		return nil
	}
	return d.db.Create(&statuses).Error
}

func (d *Database) GetLatestVPNStatuses(deviceID uint) ([]models.VPNStatus, error) {
	var latest models.VPNStatus
	if err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&latest).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []models.VPNStatus{}, nil
		}
		return nil, err
	}
	var statuses []models.VPNStatus
	err := d.db.Where("device_id = ? AND timestamp = ?", deviceID, latest.Timestamp).Find(&statuses).Error
	if err != nil || len(statuses) == 0 {
		return statuses, err
	}

	// Cross-fill Phase 2 subnets from peer devices
	// Find connections involving this device
	var connections []models.DeviceConnection
	d.db.Where("source_device_id = ? OR dest_device_id = ?", deviceID, deviceID).Find(&connections)

	// Get all peer device IDs
	peerIDs := make(map[uint]bool)
	for _, conn := range connections {
		if conn.SourceDeviceID != deviceID {
			peerIDs[conn.SourceDeviceID] = true
		}
		if conn.DestDeviceID != deviceID {
			peerIDs[conn.DestDeviceID] = true
		}
	}

	// Pre-fetch all peer tunnels indexed by remote IP (more reliable than name matching)
	// A tunnel on device A with RemoteIP=X matched to device B means device B likely has
	// a tunnel with RemoteIP pointing back to A. Match by IP, not name.
	peerTunnelsByRemoteIP := make(map[string]models.VPNStatus) // remoteIP -> latest tunnel with subnets
	// AUDIT-035: previously this ran one `WHERE device_id = ? ORDER BY
	// timestamp DESC` full scan PER peer (e.g. 30 peers = 30 scans per
	// connection-map click). Now a single `device_id IN (...)` query covering
	// all peers, with the subnet filter pushed into SQL (the loop already
	// skipped rows without a subnet, so this also fetches fewer rows than the
	// original). `ORDER BY device_id, timestamp DESC` reproduces the original
	// per-peer / newest-first processing order, so the "first row per remote_ip,
	// preferring one that carries a LocalSubnet" result is unchanged — and more
	// deterministic than before (the old peer loop iterated a Go map in random
	// order). Cross-dialect; no window function required.
	if len(peerIDs) > 0 {
		ids := make([]uint, 0, len(peerIDs))
		for id := range peerIDs {
			ids = append(ids, id)
		}
		var peerVPNs []models.VPNStatus
		d.db.Where("device_id IN ? AND (local_subnet != '' OR remote_subnet != '')", ids).
			Order("device_id, timestamp DESC").Find(&peerVPNs)
		for _, pv := range peerVPNs {
			if pv.RemoteIP == "" {
				continue
			}
			existing, exists := peerTunnelsByRemoteIP[pv.RemoteIP]
			if !exists || (pv.LocalSubnet != "" && existing.LocalSubnet == "") {
				peerTunnelsByRemoteIP[pv.RemoteIP] = pv
			}
		}
	}

	// Collect this device's known IPs for matching
	deviceIPSet := make(map[uint]map[string]bool)
	for _, s := range statuses {
		if _, ok := deviceIPSet[s.DeviceID]; !ok {
			deviceIPSet[s.DeviceID] = make(map[string]bool)
			var dev models.Device
			if err := d.db.Select("ip_address").First(&dev, s.DeviceID).Error; err == nil {
				deviceIPSet[s.DeviceID][dev.IPAddress] = true
			}
		}
	}

	// Cross-fill: for each tunnel missing subnets, find a peer tunnel whose RemoteIP matches our device
	for i := range statuses {
		if statuses[i].LocalSubnet == "" || statuses[i].RemoteSubnet == "" {
			// Try matching by our device's IPs against peer tunnels' RemoteIP
			myIPs := deviceIPSet[statuses[i].DeviceID]
			var peerTunnel *models.VPNStatus
			for ip := range myIPs {
				if pt, ok := peerTunnelsByRemoteIP[ip]; ok {
					peerTunnel = &pt
					break
				}
			}
			// Also try matching by this tunnel's RemoteIP
			if peerTunnel == nil && statuses[i].RemoteIP != "" {
				if pt, ok := peerTunnelsByRemoteIP[statuses[i].RemoteIP]; ok {
					peerTunnel = &pt
				}
			}
			if peerTunnel != nil {
				if statuses[i].LocalSubnet == "" && peerTunnel.LocalSubnet != "" {
					statuses[i].LocalSubnet = peerTunnel.LocalSubnet
				}
				if statuses[i].RemoteSubnet == "" && peerTunnel.RemoteSubnet != "" {
					statuses[i].RemoteSubnet = peerTunnel.RemoteSubnet
				}
				// Surface the resolved peer device id (v0.10.218, bundle G3).
				// Frontend uses this to link the remote_ip cell to the peer's
				// /admin/devices/:id detail page.
				if peerTunnel.DeviceID != 0 && peerTunnel.DeviceID != statuses[i].DeviceID {
					pid := peerTunnel.DeviceID
					statuses[i].RemoteDeviceID = &pid
				}
			}
		}
	}

	// Second-pass peer resolution (v0.10.218, bundle G3). The block above
	// only populates RemoteDeviceID when a subnet cross-fill was needed.
	// Tunnels that already had complete subnet info skipped that path but
	// can still benefit from a peer link in the UI. Re-run the same match
	// logic for RemoteDeviceID only.
	for i := range statuses {
		if statuses[i].RemoteDeviceID != nil {
			continue
		}
		var peerTunnel *models.VPNStatus
		myIPs := deviceIPSet[statuses[i].DeviceID]
		for ip := range myIPs {
			if pt, ok := peerTunnelsByRemoteIP[ip]; ok {
				peerTunnel = &pt
				break
			}
		}
		if peerTunnel == nil && statuses[i].RemoteIP != "" {
			if pt, ok := peerTunnelsByRemoteIP[statuses[i].RemoteIP]; ok {
				peerTunnel = &pt
			}
		}
		if peerTunnel != nil && peerTunnel.DeviceID != 0 && peerTunnel.DeviceID != statuses[i].DeviceID {
			pid := peerTunnel.DeviceID
			statuses[i].RemoteDeviceID = &pid
		}
	}

	// last_up_at enrichment (v0.10.217, bundle D4). For every tunnel in
	// the latest snapshot, look up the most-recent historical timestamp
	// at which the same (device, tunnel_name) reported status='up'. Lets
	// the frontend show "last seen up 2h ago" for tunnels currently down
	// instead of just "down".
	//
	// Single grouped query rather than N per-tunnel queries — for a fleet
	// with 200 tunnels per device the difference is meaningful. Skipped
	// for tunnels that are currently up (LastUpAt would just equal the
	// snapshot timestamp anyway and the UI doesn't render the chip).
	type lastUpRow struct {
		TunnelName string    `gorm:"column:tunnel_name"`
		MaxTs      time.Time `gorm:"column:max_ts"`
	}
	var rows []lastUpRow
	if err := d.db.Model(&models.VPNStatus{}).
		Select("tunnel_name, MAX(timestamp) as max_ts").
		Where("device_id = ? AND status = ?", deviceID, "up").
		Group("tunnel_name").
		Scan(&rows).Error; err == nil {
		byName := make(map[string]time.Time, len(rows))
		for _, r := range rows {
			byName[r.TunnelName] = r.MaxTs
		}
		for i := range statuses {
			if ts, ok := byName[statuses[i].TunnelName]; ok {
				t := ts
				statuses[i].LastUpAt = &t
			}
		}
	}

	return statuses, err
}

func (d *Database) SaveAlert(alert *models.Alert) error {
	return d.db.Create(alert).Error
}

func (d *Database) GetAlerts(limit int, acknowledged *bool) ([]models.Alert, error) {
	var alerts []models.Alert
	query := d.db.Order("timestamp DESC").Limit(limit)
	if acknowledged != nil {
		query = query.Where("acknowledged = ?", *acknowledged)
	}
	err := query.Find(&alerts).Error
	return alerts, err
}

func (d *Database) AcknowledgeAlert(id uint) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Update("acknowledged", true).Error
}

func (d *Database) SaveTrapEvent(trap *models.TrapEvent) error {
	if d.trapBatch != nil {
		d.trapBatch.Add(*trap)
		return nil
	}
	return d.db.Create(trap).Error
}

func (d *Database) SaveTrapEvents(traps []models.TrapEvent) error {
	if len(traps) == 0 {
		return nil
	}
	return d.db.Create(&traps).Error
}

func (d *Database) GetTrapEvents(limit int) ([]models.TrapEvent, error) {
	var traps []models.TrapEvent
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&traps).Error
	return traps, err
}

func (d *Database) SaveUptimeRecord(record *models.UptimeRecord) error {
	return d.db.Create(record).Error
}

func (d *Database) GetUptimeRecords(limit int) ([]models.UptimeRecord, error) {
	var records []models.UptimeRecord
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&records).Error
	return records, err
}

func (d *Database) SaveLoginAttempt(attempt *models.LoginAttempt) error {
	return d.db.Create(attempt).Error
}

func (d *Database) GetLoginAttempts(since time.Time, limit int) ([]models.LoginAttempt, error) {
	var attempts []models.LoginAttempt
	err := d.db.Where("timestamp > ?", since).Order("timestamp DESC").Limit(limit).Find(&attempts).Error
	return attempts, err
}

func (d *Database) SaveConfigRevision(rev *models.DeviceConfigRevision) error {
	tx := d.db.Begin()
	if err := tx.Create(rev).Error; err != nil {
		tx.Rollback()
		return err
	}
	var count int64
	if err := tx.Model(&models.DeviceConfigRevision{}).Where("device_id = ?", rev.DeviceID).Count(&count).Error; err != nil {
		tx.Rollback()
		return err
	}
	if count > 5 {
		deleteCount := count - 5
		var toDelete []uint
		if err := tx.Model(&models.DeviceConfigRevision{}).
			Where("device_id = ?", rev.DeviceID).
			Order("timestamp ASC").
			Limit(int(deleteCount)).
			Pluck("id", &toDelete).Error; err != nil {
			tx.Rollback()
			return err
		}
		if len(toDelete) > 0 {
			if err := tx.Where("device_id = ? AND id IN ?", rev.DeviceID, toDelete).Delete(&models.DeviceConfigRevision{}).Error; err != nil {
				tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit().Error
}

func (d *Database) GetLatestConfigRevision(deviceID uint) (*models.DeviceConfigRevision, error) {
	var rev models.DeviceConfigRevision
	err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&rev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &rev, err
}

func (d *Database) SaveProcessStats(stats *models.ProcessStats) error {
	return d.db.Create(stats).Error
}

func (d *Database) SaveInterfaceErrors(errs []models.InterfaceErrors) error {
	if len(errs) == 0 {
		return nil
	}
	return d.db.Create(&errs).Error
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
	return err
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
			return err
		}
		if affected < int64(batchSize) {
			return nil // last (partial) batch — nothing more to delete
		}
		time.Sleep(100 * time.Millisecond)
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
		{&models.TrapEvent{}, "trap_event", trapDays},
		{&models.LoginAttempt{}, "login_attempt", defaultDays},
		{&models.FlowSample{}, "flow_sample", flowDays},
		{&models.InterfaceAddress{}, "interface_addresses", statusDays},
		{&models.PingResult{}, "ping_result", pingDays},
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

// CleanupConfigRevisions enforces retention on device_config_revisions.
// Simple in v0.10.198+ thanks to the merge-into-latest storage model: the
// `device_config_revisions` table now contains one row per *distinct* config
// state, so there are no IV-drift duplicates to collapse. Just two rules:
//
//  1. Hard-delete rows older than 365 days. Plenty for compliance audit and
//     bounds long-tail storage growth on devices that change frequently.
//  2. Per-device cap: 500 distinct states. Devices that genuinely change 500
//     times in a year are rare; if a deployment has them, raise the cap.
func (d *Database) CleanupConfigRevisions() error {
	const keepDays = 365
	const perDeviceCap = 500

	timeCutoff := time.Now().AddDate(0, 0, -keepDays)

	// Step 1: time-based cleanup is one query across all devices.
	if err := d.db.Where("timestamp < ?", timeCutoff).
		Delete(&models.DeviceConfigRevision{}).Error; err != nil {
		return fmt.Errorf("cleanup config_revisions by age: %w", err)
	}

	// Step 2: per-device cap — only walk devices that actually have > cap rows.
	// Most deployments will have devices well under 500 distinct states, so
	// this loop is empty in the common case.
	type devCount struct {
		DeviceID uint
		Cnt      int64
	}
	var hot []devCount
	if err := d.db.Model(&models.DeviceConfigRevision{}).
		Select("device_id, COUNT(*) as cnt").
		Group("device_id").
		Having("COUNT(*) > ?", perDeviceCap).
		Scan(&hot).Error; err != nil {
		return fmt.Errorf("cleanup config_revisions: count over-cap devices: %w", err)
	}

	for _, dc := range hot {
		// Find the cutoff timestamp: the timestamp of the (perDeviceCap)th
		// most recent row. Anything older than that is dropped.
		var floor models.DeviceConfigRevision
		if err := d.db.Where("device_id = ?", dc.DeviceID).
			Order("timestamp DESC").Offset(perDeviceCap - 1).Limit(1).
			First(&floor).Error; err != nil {
			continue
		}
		if err := d.db.Where("device_id = ? AND timestamp < ?", dc.DeviceID, floor.Timestamp).
			Delete(&models.DeviceConfigRevision{}).Error; err != nil {
			return fmt.Errorf("cleanup config_revisions device %d cap: %w", dc.DeviceID, err)
		}
	}

	return nil
}

// CollapseLegacyConfigRevisionDuplicates is a one-time migration helper for
// deployments that ran v0.10.187 → v0.10.197 (the always-store era). It walks
// each device's history and collapses runs of identical NormalizedChecksum
// rows down to a single representative row per run — the most recent of the
// run keeps the bytes, the older rows of the run are deleted, and the
// representative row's VerifyCount is set to the count of merged rows so the
// audit trail is preserved.
//
// Idempotent. Safe to call multiple times. Returns the number of rows deleted.
func (d *Database) CollapseLegacyConfigRevisionDuplicates() (int64, error) {
	var deviceIDs []uint
	if err := d.db.Model(&models.DeviceConfigRevision{}).
		Distinct("device_id").Pluck("device_id", &deviceIDs).Error; err != nil {
		return 0, fmt.Errorf("list device ids: %w", err)
	}

	var totalDeleted int64
	for _, devID := range deviceIDs {
		var revs []models.DeviceConfigRevision
		if err := d.db.Where("device_id = ?", devID).
			Order("timestamp ASC, id ASC").Find(&revs).Error; err != nil {
			return totalDeleted, fmt.Errorf("device %d: list: %w", devID, err)
		}
		if len(revs) == 0 {
			continue
		}

		// Walk in order. Each run of identical NormalizedChecksum gets
		// collapsed: we update the LAST row in the run to carry the run's
		// VerifyCount and FirstSeenAt, then delete the earlier rows in the run.
		i := 0
		for i < len(revs) {
			j := i + 1
			for j < len(revs) && revs[j].NormalizedChecksum == revs[i].NormalizedChecksum {
				j++
			}
			runLen := j - i
			if runLen > 1 {
				keep := &revs[j-1]
				// Update keep row with the run's metadata.
				updates := map[string]interface{}{
					"first_seen_at":    revs[i].Timestamp,
					"last_verified_at": keep.Timestamp,
					"verify_count":     runLen,
				}
				if err := d.db.Model(&models.DeviceConfigRevision{}).
					Where("id = ?", keep.ID).Updates(updates).Error; err != nil {
					return totalDeleted, fmt.Errorf("device %d collapse update: %w", devID, err)
				}
				// Delete older rows in the run.
				deleteIDs := make([]uint, 0, runLen-1)
				for k := i; k < j-1; k++ {
					deleteIDs = append(deleteIDs, revs[k].ID)
				}
				res := d.db.Where("id IN ?", deleteIDs).Delete(&models.DeviceConfigRevision{})
				if res.Error != nil {
					return totalDeleted, fmt.Errorf("device %d collapse delete: %w", devID, res.Error)
				}
				totalDeleted += res.RowsAffected
			} else {
				// Single-row run — backfill new fields if they're zero (legacy).
				keep := &revs[i]
				if keep.FirstSeenAt.IsZero() || keep.LastVerifiedAt.IsZero() || keep.VerifyCount == 0 {
					updates := map[string]interface{}{}
					if keep.FirstSeenAt.IsZero() {
						updates["first_seen_at"] = keep.Timestamp
					}
					if keep.LastVerifiedAt.IsZero() {
						updates["last_verified_at"] = keep.Timestamp
					}
					if keep.VerifyCount == 0 {
						updates["verify_count"] = 1
					}
					if len(updates) > 0 {
						d.db.Model(&models.DeviceConfigRevision{}).
							Where("id = ?", keep.ID).Updates(updates)
					}
				}
			}
			i = j
		}
	}
	return totalDeleted, nil
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

func (d *Database) Close() error {
	// Flush and stop all batch inserters before closing the DB
	if d.syslogBatch != nil {
		d.syslogBatch.Stop()
	}
	if d.trapBatch != nil {
		d.trapBatch.Stop()
	}
	if d.pingBatch != nil {
		d.pingBatch.Stop()
	}

	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (d *Database) GetAllDevices() ([]models.Device, error) {
	var devices []models.Device
	err := d.db.Preload("Site").Preload("Probe").Find(&devices).Error
	for i := range devices {
		d.DecryptDeviceSecrets(&devices[i])
	}
	return devices, err
}

func (d *Database) GetDevice(id uint) (*models.Device, error) {
	var device models.Device
	err := d.db.Preload("Site").Preload("Probe").First(&device, id).Error
	if err != nil {
		return nil, err
	}
	d.DecryptDeviceSecrets(&device)
	return &device, nil
}

// ResolveDeviceByIP finds a device ID by management IP or interface address.
func (d *Database) ResolveDeviceByIP(ip string) uint {
	// Check management IP first
	var device models.Device
	if err := d.db.Where("ip_address = ?", ip).Select("id").First(&device).Error; err == nil {
		return device.ID
	}
	// Check interface addresses
	var addr models.InterfaceAddress
	if err := d.db.Where("ip_address = ?", ip).Select("device_id").First(&addr).Error; err == nil {
		return addr.DeviceID
	}
	return 0
}

func (d *Database) CreateDevice(device *models.Device) error {
	d.EncryptDeviceSecrets(device)
	err := d.db.Create(device).Error
	// Decrypt back so the caller sees plaintext
	d.DecryptDeviceSecrets(device)
	return err
}

func (d *Database) UpdateDevice(device *models.Device) error {
	return d.db.Save(device).Error
}

// UpdateDeviceStatus performs a targeted update of only status and last_polled fields.
func (d *Database) UpdateDeviceStatus(id uint, status string, lastPolled time.Time) error {
	return d.db.Model(&models.Device{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":      status,
		"last_polled": lastPolled,
	}).Error
}

// UpdateDeviceSSLVPN updates SSL-VPN user/session counts for a device.
func (d *Database) UpdateDeviceSSLVPN(id uint, users, tunnels int) error {
	return d.db.Model(&models.Device{}).Where("id = ?", id).Updates(map[string]interface{}{
		"sslvpn_users":   users,
		"sslvpn_tunnels": tunnels,
	}).Error
}

// MarkStaleProbeDevicesOffline marks probe-assigned devices as "offline" if
// their last_polled timestamp is older than the given threshold, and returns
// the devices that transitioned online -> offline on this call.
//
// It returns the flipped devices (not just a count) so the caller can fire a
// DEVICE_OFFLINE alert + critical email per transition — the same notification
// path that updateDeviceStatus drives for directly-polled devices. The WHERE
// clause already restricts to rows currently `status = 'online'`, so the
// selected set IS the online->offline transition set: a device that is already
// offline is not re-selected, which keeps this to one alert per offline
// episode (recovery is handled by the poller calling CheckDeviceOnline on the
// devices that come back fresh).
//
// Implemented as SELECT-then-UPDATE rather than a bare UPDATE so the caller
// gets the affected rows; the two statements are not wrapped in a transaction
// because a probe device that flips back to online between them simply isn't
// alerted this cycle (the next cycle re-evaluates), which is the desired
// fail-safe — we would rather miss a flap than emit a spurious offline alert.
func (d *Database) MarkStaleProbeDevicesOffline(staleThreshold time.Time) ([]models.Device, error) {
	var stale []models.Device
	if err := d.db.
		Where("probe_id IS NOT NULL AND enabled = ? AND status = ? AND last_polled < ?", true, "online", staleThreshold).
		Find(&stale).Error; err != nil {
		return nil, err
	}
	if len(stale) == 0 {
		return nil, nil
	}
	ids := make([]uint, len(stale))
	for i := range stale {
		ids[i] = stale[i].ID
		stale[i].Status = "offline"
	}
	if err := d.db.Model(&models.Device{}).Where("id IN ?", ids).Update("status", "offline").Error; err != nil {
		return nil, err
	}
	return stale, nil
}

func (d *Database) DeleteDevice(id uint) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		// Delete all related monitoring data
		for _, model := range []interface{}{
			&models.SystemStatus{},
			&models.InterfaceStats{},
			&models.VPNStatus{},
			&models.HAStatus{},
			&models.HardwareSensor{},
			&models.ProcessorStats{},
			&models.Alert{},
			&models.UptimeRecord{},
			&models.TrapEvent{},
			&models.DeviceTunnel{},
			&models.InterfaceAddress{},
		} {
			if err := tx.Where("device_id = ?", id).Delete(model).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("source_device_id = ? OR dest_device_id = ?", id, id).Delete(&models.DeviceConnection{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.Device{}, id).Error
	})
}

func (d *Database) GetAllConnections() ([]models.DeviceConnection, error) {
	var conns []models.DeviceConnection
	err := d.db.Preload("SourceDevice").Preload("DestDevice").Find(&conns).Error
	return conns, err
}

// GetConnectionStatuses returns only id and status for all connections (lightweight).
func (d *Database) GetConnectionStatuses() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := d.db.Model(&models.DeviceConnection{}).Select("id, status").Find(&results).Error
	return results, err
}

// GetDeviceStatuses returns only id and status for all devices (lightweight).
func (d *Database) GetDeviceStatuses() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := d.db.Model(&models.Device{}).Select("id, status").Find(&results).Error
	return results, err
}

// ConnectionEvent represents a unified event from alerts, traps, or syslog.
type ConnectionEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"` // "alert", "trap", "syslog"
	DeviceID  uint      `json:"device_id"`
	Severity  string    `json:"severity"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
}

// GetConnectionEvents returns correlated events (alerts, traps, syslog) for two devices.
func (d *Database) GetConnectionEvents(srcDeviceID, dstDeviceID uint, hours int) ([]ConnectionEvent, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	deviceIDs := []uint{srcDeviceID, dstDeviceID}
	var events []ConnectionEvent

	// Alerts
	var alerts []models.Alert
	d.db.Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(50).Find(&alerts)
	for _, a := range alerts {
		events = append(events, ConnectionEvent{
			Timestamp: a.Timestamp,
			Source:    "alert",
			DeviceID:  a.DeviceID,
			Severity:  a.Severity,
			Type:      a.AlertType,
			Message:   a.Message,
		})
	}

	// Traps
	var traps []models.TrapEvent
	d.db.Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(50).Find(&traps)
	for _, t := range traps {
		events = append(events, ConnectionEvent{
			Timestamp: t.Timestamp,
			Source:    "trap",
			DeviceID:  t.DeviceID,
			Severity:  t.Severity,
			Type:      t.TrapType,
			Message:   t.Message,
		})
	}

	// Syslog (severity <= 4 = warning and above)
	var syslogs []models.SyslogMessage
	d.db.Where("device_id IN ? AND severity <= 4 AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(30).Find(&syslogs)
	for _, s := range syslogs {
		sev := "info"
		if s.Severity <= 2 {
			sev = "critical"
		} else if s.Severity <= 4 {
			sev = "warning"
		}
		events = append(events, ConnectionEvent{
			Timestamp: s.Timestamp,
			Source:    "syslog",
			DeviceID:  s.DeviceID,
			Severity:  sev,
			Type:      "syslog",
			Message:   s.Message,
		})
	}

	// Sort by timestamp descending
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	if len(events) > 100 {
		events = events[:100]
	}

	return events, nil
}

// GetAllLatestVPNStatuses returns the latest VPN tunnel snapshot for every device.
func (d *Database) GetAllLatestVPNStatuses() ([]models.VPNStatus, error) {
	var statuses []models.VPNStatus
	// Subquery: max timestamp per device
	sub := d.db.Model(&models.VPNStatus{}).Select("device_id, MAX(timestamp) as max_ts").Group("device_id")
	err := d.db.Where("(device_id, timestamp) IN (?)", sub).Find(&statuses).Error
	return statuses, err
}

// FindConnectionByDevicePairAndType finds a connection between two devices of a specific type.
func (d *Database) FindConnectionByDevicePairAndType(deviceA, deviceB uint, connType string) (*models.DeviceConnection, error) {
	var conn models.DeviceConnection
	err := d.db.Where(
		"((source_device_id = ? AND dest_device_id = ?) OR (source_device_id = ? AND dest_device_id = ?)) AND connection_type = ?",
		deviceA, deviceB, deviceB, deviceA, connType,
	).First(&conn).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &conn, err
}

// UpsertAutoConnection creates or updates an auto-detected connection.
// Uses device pair + connection_type as the unique key, allowing multiple
// connection types between the same pair (e.g. ipsec + l2vlan).
// Manual connections (AutoDetected=false) are never overwritten.
func (d *Database) UpsertAutoConnection(sourceID, destID uint, status, tunnelNames, name, connType, matchMethod string) error {
	if connType == "" {
		connType = "ipsec"
	}
	if matchMethod == "" {
		matchMethod = "ip_match"
	}

	existing, err := d.FindConnectionByDevicePairAndType(sourceID, destID, connType)
	if err != nil {
		return err
	}

	if existing != nil {
		if !existing.AutoDetected {
			return nil // don't touch manual connections
		}
		// Update existing auto-detected connection
		return d.db.Model(existing).Updates(map[string]interface{}{
			"status":          status,
			"tunnel_names":    tunnelNames,
			"connection_type": connType,
			"match_method":    matchMethod,
			"last_check":      time.Now(),
		}).Error
	}

	// Create new auto-detected connection with normalized direction
	conn := &models.DeviceConnection{
		Name:           name,
		SourceDeviceID: sourceID,
		DestDeviceID:   destID,
		ConnectionType: connType,
		Status:         status,
		AutoDetected:   true,
		TunnelNames:    tunnelNames,
		MatchMethod:    matchMethod,
		LastCheck:      time.Now(),
	}
	return d.db.Create(conn).Error
}

func (d *Database) CreateConnection(conn *models.DeviceConnection) error {
	return d.db.Create(conn).Error
}

func (d *Database) UpdateConnection(conn *models.DeviceConnection) error {
	return d.db.Save(conn).Error
}

func (d *Database) DeleteConnection(id uint) error {
	return d.db.Delete(&models.DeviceConnection{}, id).Error
}

// CleanupStaleAutoConnections removes auto-detected connections with tunnel names
// that should never have been matched (e.g., ssl.root present on every FortiGate).
func (d *Database) CleanupStaleAutoConnections(skipNames []string) int64 {
	if len(skipNames) == 0 {
		return 0
	}
	result := d.db.Where("auto_detected = ? AND tunnel_names IN ?", true, skipNames).
		Delete(&models.DeviceConnection{})
	return result.RowsAffected
}

// CleanupStaleAutoConnectionsBefore deletes auto-detected connections whose
// last_check is older than the given timestamp. Called after each detection
// cycle to remove connections whose interfaces no longer exist.
func (d *Database) CleanupStaleAutoConnectionsBefore(before time.Time) int64 {
	result := d.db.Where("auto_detected = ? AND last_check < ?", true, before).
		Delete(&models.DeviceConnection{})
	return result.RowsAffected
}

func (d *Database) GetAllSettings() ([]models.SystemSetting, error) {
	var settings []models.SystemSetting
	err := d.db.Find(&settings).Error
	return settings, err
}

// UpsertSetting persists a system_settings row, creating it if absent.
//
// v0.10.233: was the exact v0.10.226 bug verbatim — FirstOrCreate then
// copied only Value/Label/Category onto the existing struct before Save,
// dropping IsSecret and Type on update. Currently has zero in-tree callers,
// but the function is exported on the public *Database API and would
// silently corrupt any secret persisted through it. Fixed to mirror the
// canonical pattern used in UpdateSettings (handlers_settings.go:228-241):
// copy every field that matters, including IsSecret.
func (d *Database) UpsertSetting(setting *models.SystemSetting) error {
	existing := models.SystemSetting{Key: setting.Key}
	if err := d.db.FirstOrCreate(&existing, models.SystemSetting{Key: setting.Key}).Error; err != nil {
		return err
	}
	existing.Value = setting.Value
	existing.Label = setting.Label
	existing.Category = setting.Category
	existing.Type = setting.Type
	existing.IsSecret = setting.IsSecret
	return d.db.Save(&existing).Error
}

func (d *Database) GetAdmin() (*models.Admin, error) {
	var admin models.Admin
	err := d.db.First(&admin).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &admin, err
}

func (d *Database) CreateAdmin(admin *models.Admin) error {
	return d.db.Create(admin).Error
}

func (d *Database) UpdateAdmin(admin *models.Admin) error {
	return d.db.Save(admin).Error
}

func (d *Database) InitAdmin(username, password string) error {
	admin, err := d.GetAdmin()
	if err != nil {
		return err
	}
	if admin == nil {
		return d.CreateAdmin(&models.Admin{Username: username, Password: password})
	}
	log.Printf("Admin user already exists, skipping initialization")
	return nil
}

func (d *Database) GetAdminByUsername(username string) (*auth.AdminAuth, error) {
	var admin models.Admin
	err := d.db.Where("username = ?", username).First(&admin).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &auth.AdminAuth{
		ID:           admin.ID,
		Username:     admin.Username,
		Password:     admin.Password,
		TokenVersion: admin.TokenVersion,
	}, nil
}

func (d *Database) UpdateAdminPassword(id uint, password string) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).Update("password", password).Error
}

func (d *Database) GetAdminTokenVersion(id uint) (uint, error) {
	var admin models.Admin
	err := d.db.Select("token_version").First(&admin, id).Error
	if err != nil {
		return 0, err
	}
	return admin.TokenVersion, nil
}

func (d *Database) IncrementAdminTokenVersion(id uint) error {
	return d.db.Model(&models.Admin{}).Where("id = ?", id).
		UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error
}

func (d *Database) GetAllSites() ([]models.Site, error) {
	var sites []models.Site
	err := d.db.Preload("ParentSite").Find(&sites).Error
	return sites, err
}

func (d *Database) GetSite(id uint) (*models.Site, error) {
	var site models.Site
	err := d.db.Preload("ParentSite").Preload("Probes").First(&site, id).Error
	if err != nil {
		return nil, err
	}
	return &site, nil
}

func (d *Database) GetSiteByName(name string) (*models.Site, error) {
	var site models.Site
	err := d.db.Where("name = ?", name).First(&site).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &site, err
}

func (d *Database) CreateSite(site *models.Site) error {
	return d.db.Create(site).Error
}

func (d *Database) UpdateSite(site *models.Site) error {
	return d.db.Save(site).Error
}

func (d *Database) DeleteSite(id uint) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("site_id = ?", id).Delete(&models.Probe{}).Error; err != nil {
			return err
		}
		if err := tx.Where("site_id = ?", id).Delete(&models.Device{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.Site{}, id).Error
	})
}

func (d *Database) GetAllProbes() ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Preload("Site").Find(&probes).Error
	return probes, err
}

func (d *Database) GetProbe(id uint) (*models.Probe, error) {
	var probe models.Probe
	err := d.db.Preload("Site").First(&probe, id).Error
	if err != nil {
		return nil, err
	}
	return &probe, nil
}

func (d *Database) GetProbeByName(name string) (*models.Probe, error) {
	var probe models.Probe
	err := d.db.Where("name = ?", name).First(&probe).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &probe, err
}

func (d *Database) CreateProbe(probe *models.Probe) error {
	return d.db.Create(probe).Error
}

func (d *Database) UpdateProbe(probe *models.Probe) error {
	return d.db.Save(probe).Error
}

func (d *Database) DeleteProbe(id uint) error {
	return d.db.Delete(&models.Probe{}, id).Error
}

func (d *Database) GetProbesBySite(siteID uint) ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Where("site_id = ?", siteID).Find(&probes).Error
	return probes, err
}

func (d *Database) GetProbeByRegistrationKey(key string) (*models.Probe, error) {
	var probe models.Probe
	// AUDIT-017: keys are stored hashed; hash the supplied plaintext to match.
	err := d.db.Where("registration_key = ?", HashProbeKey(key)).First(&probe).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &probe, err
}

func (d *Database) ApproveProbe(probeID uint, approvedBy uint) error {
	now := time.Now()
	if err := d.db.Model(&models.Probe{}).Where("id = ?", probeID).Updates(map[string]interface{}{
		"status":          "approved",
		"approval_status": "approved",
		"approved_at":     now,
		"approved_by":     approvedBy,
	}).Error; err != nil {
		return err
	}
	approval := &models.ProbeApproval{
		ProbeID:     probeID,
		RequestedAt: now,
		ApprovedAt:  &now,
		ApprovedBy:  &approvedBy,
		Status:      "approved",
	}
	return d.db.Create(approval).Error
}

func (d *Database) RejectProbe(probeID uint, reason string) error {
	now := time.Now()
	if err := d.db.Model(&models.Probe{}).Where("id = ?", probeID).Updates(map[string]interface{}{
		"status":          "rejected",
		"approval_status": "rejected",
		"rejected_at":     now,
		"rejected_reason": reason,
	}).Error; err != nil {
		return err
	}
	approval := &models.ProbeApproval{
		ProbeID:        probeID,
		RequestedAt:    now,
		RejectedAt:     &now,
		RejectedReason: reason,
		Status:         "rejected",
	}
	return d.db.Create(approval).Error
}

func (d *Database) GetPendingProbes() ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Where("approval_status = ?", "pending").Find(&probes).Error
	return probes, err
}

func (d *Database) GetApprovedProbes() ([]models.Probe, error) {
	var probes []models.Probe
	err := d.db.Where("approval_status = ?", "approved").Find(&probes).Error
	return probes, err
}

func (d *Database) UpdateProbeHeartbeat(heartbeat *models.ProbeHeartbeat) error {
	var existing models.ProbeHeartbeat
	err := d.db.Where("probe_id = ?", heartbeat.ProbeID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return d.db.Create(heartbeat).Error
	}
	existing.Status = heartbeat.Status
	existing.IPAddress = heartbeat.IPAddress
	existing.Version = heartbeat.Version
	existing.Uptime = heartbeat.Uptime
	existing.Timestamp = heartbeat.Timestamp
	return d.db.Save(&existing).Error
}

func (d *Database) GetProbeHeartbeats(probeID uint) ([]models.ProbeHeartbeat, error) {
	var heartbeats []models.ProbeHeartbeat
	err := d.db.Where("probe_id = ?", probeID).Order("timestamp DESC").Find(&heartbeats).Error
	return heartbeats, err
}

func (d *Database) SavePingResult(result *models.PingResult) error {
	if d.pingBatch != nil {
		d.pingBatch.Add(*result)
		return nil
	}
	return d.db.Create(result).Error
}

func (d *Database) SavePingResults(results []models.PingResult) error {
	if len(results) == 0 {
		return nil
	}
	return d.db.Create(&results).Error
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

func (d *Database) GetPingStatsByTarget(deviceID uint, probeID uint, targetIP string) (*models.PingStats, error) {
	var stats models.PingStats
	err := d.db.Where("device_id = ? AND probe_id = ? AND target_ip = ?", deviceID, probeID, targetIP).First(&stats).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &stats, err
}

func (d *Database) SaveProcessorStats(stats []models.ProcessorStats) error {
	if len(stats) == 0 {
		return nil
	}
	return d.db.Create(&stats).Error
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
	if len(sensors) == 0 {
		return nil
	}
	return d.db.Create(&sensors).Error
}

func (d *Database) SaveHAStatuses(statuses []models.HAStatus) error {
	if len(statuses) == 0 {
		return nil
	}
	return d.db.Create(&statuses).Error
}

func (d *Database) SaveSecurityStats(stats []models.SecurityStats) error {
	if len(stats) == 0 {
		return nil
	}
	return d.db.Create(&stats).Error
}

func (d *Database) SaveSDWANHealth(health []models.SDWANHealth) error {
	if len(health) == 0 {
		return nil
	}
	return d.db.Create(&health).Error
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
	if len(msgs) == 0 {
		return nil
	}
	return d.db.Create(&msgs).Error
}

func (d *Database) GetSyslogMessages(limit int) ([]models.SyslogMessage, error) {
	var messages []models.SyslogMessage
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&messages).Error
	return messages, err
}

func (d *Database) SaveFlowSamples(samples []models.FlowSample) error {
	if len(samples) == 0 {
		return nil
	}
	return d.db.Create(&samples).Error
}

func (d *Database) GetFlowSamples(limit int) ([]models.FlowSample, error) {
	var samples []models.FlowSample
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&samples).Error
	return samples, err
}

// InterfaceChartBucket holds a single time-bucket for interface chart data.
type InterfaceChartBucket struct {
	Bucket     string  `json:"bucket"`
	InBytes    float64 `json:"in_bytes"`
	OutBytes   float64 `json:"out_bytes"`
	InPackets  float64 `json:"in_packets"`
	OutPackets float64 `json:"out_packets"`
	InErrors   float64 `json:"in_errors"`
	OutErrors  float64 `json:"out_errors"`
}

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

// TimeBucket is a generic time-series count bucket
type TimeBucket struct {
	Bucket string `json:"bucket"`
	Count  int64  `json:"count"`
}

// KeyCount is a generic key-value count pair
type KeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// protoNames maps IP protocol numbers to human-readable names.
var protoNames = map[uint8]string{
	0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 8: "EGP",
	17: "UDP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE",
	50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
	88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP", 137: "MPLS-in-IP",
}

// protoName returns the human name for a protocol number, or "Proto N" as fallback.
func protoName(p uint8) string {
	if name, ok := protoNames[p]; ok {
		return name
	}
	return fmt.Sprintf("Proto %d", p)
}

// FlowStatsResult holds aggregated flow statistics
var wellKnownPorts = map[uint16]string{
	22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
	443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 3389: "RDP",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt", 500: "IKE", 4500: "NAT-T",
	1194: "OpenVPN", 51820: "WireGuard",
}

type FlowStatsResult struct {
	TotalFlows       int64              `json:"total_flows"`
	TotalBytes       uint64             `json:"total_bytes"`
	TotalPackets     uint64             `json:"total_packets"`
	BitsPerSecond    float64            `json:"bits_per_second"`
	UniqueSources    int64              `json:"unique_sources"`
	UniqueDests      int64              `json:"unique_dests"`
	ProtocolCount    int64              `json:"protocol_count"`
	BucketSeconds    int                `json:"bucket_seconds"`
	AvgSamplingRate  float64            `json:"avg_sampling_rate"`
	EstimatedBytes   uint64             `json:"estimated_bytes"`
	ByProtocol       []KeyCount         `json:"by_protocol"`
	TopSources       []KeyCount         `json:"top_sources"`
	TopDestinations  []KeyCount         `json:"top_destinations"`
	TopConversations []FlowConversation `json:"top_conversations"`
	BytesOverTime    []TimeBucket       `json:"bytes_over_time"`
	TopPorts         []KeyCount         `json:"top_ports"`
	LocalTraffic     struct {
		Bytes   uint64 `json:"bytes"`
		Packets uint64 `json:"packets"`
		Flows   int64  `json:"flows"`
	} `json:"local_traffic"`
}

// topAddrsByBytes returns top N addresses grouped by addrCol, ordered by total bytes descending.
func topAddrsByBytes(base func() *gorm.DB, addrCol string, limit int) []KeyCount {
	type row struct {
		Addr  string
		Total int64
	}
	var rows []row
	base().Select(addrCol + " as addr, SUM(bytes) as total").Group(addrCol).
		Order("total DESC").Limit(limit).Scan(&rows)
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: r.Addr, Count: r.Total})
	}
	return out
}

// topAddrsByBytesRollup is like topAddrsByBytes but for rollup tables (bytes_sum column).
func topAddrsByBytesRollup(base func() *gorm.DB, addrCol string, limit int) []KeyCount {
	type row struct {
		Addr  string
		Total int64
	}
	var rows []row
	base().Select(addrCol + " as addr, SUM(bytes_sum) as total").Group(addrCol).
		Order("total DESC").Limit(limit).Scan(&rows)
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: r.Addr, Count: r.Total})
	}
	return out
}

// GetFlowStats returns aggregated flow statistics, optionally filtered by device.
// It queries both raw flow_samples (recent) and flow_rollups (older data).
func (d *Database) GetFlowStats(hours int, deviceID uint) (*FlowStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &FlowStatsResult{}

	// Determine which data source to use:
	// - hours <= 1: raw samples only (rollups haven't consumed them yet)
	// - hours > 1: union raw samples + rollups
	useRollups := hours > 1

	// --- Raw flow_samples base ---
	newRawBase := func() *gorm.DB {
		q := d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff)
		if deviceID > 0 {
			q = q.Where("device_id = ?", deviceID)
		}
		return q
	}

	// --- Rollup base (best available interval for the time range) ---
	rollupInterval := "5m"
	if hours > 48 {
		rollupInterval = "1h"
	}
	if hours > 720 { // 30 days
		rollupInterval = "1d"
	}
	newRollupBase := func() *gorm.DB {
		q := d.db.Model(&models.FlowRollup{}).Where("timestamp > ? AND interval_type = ?", cutoff, rollupInterval)
		if deviceID > 0 {
			q = q.Where("device_id = ?", deviceID)
		}
		return q
	}

	// Combined aggregates: count, bytes, unique src/dst from raw samples
	var rawAgg struct {
		TotalFlows    int64
		TotalBytes    uint64
		UniqueSources int64
		UniqueDests   int64
	}
	// Multiply bytes/packets by sampling_rate to estimate actual traffic volume
	if err := newRawBase().Select("COUNT(*) as total_flows, COALESCE(SUM(bytes),0) as total_bytes, " +
		"COUNT(DISTINCT src_addr) as unique_sources, COUNT(DISTINCT dst_addr) as unique_dests").
		Scan(&rawAgg).Error; err != nil {
		return nil, fmt.Errorf("flow stats raw aggregates: %w", err)
	}
	result.TotalFlows = rawAgg.TotalFlows
	result.TotalBytes = rawAgg.TotalBytes
	result.UniqueSources = rawAgg.UniqueSources
	result.UniqueDests = rawAgg.UniqueDests

	// Add rollup aggregates if needed
	if useRollups {
		var rollupAgg struct {
			TotalFlows    int64
			TotalBytes    uint64
			UniqueSources int64
			UniqueDests   int64
		}
		if err := newRollupBase().Select("COALESCE(SUM(flow_count),0) as total_flows, COALESCE(SUM(bytes_sum),0) as total_bytes, " +
			"COUNT(DISTINCT src_addr) as unique_sources, COUNT(DISTINCT dst_addr) as unique_dests").
			Scan(&rollupAgg).Error; err != nil {
			log.Printf("Flow stats rollup aggregates: %v", err)
		} else {
			result.TotalFlows += rollupAgg.TotalFlows
			result.TotalBytes += rollupAgg.TotalBytes
			// For unique counts, the union of distinct sets needs re-counting; this is approximate
			if rollupAgg.UniqueSources > result.UniqueSources {
				result.UniqueSources = rollupAgg.UniqueSources
			}
			if rollupAgg.UniqueDests > result.UniqueDests {
				result.UniqueDests = rollupAgg.UniqueDests
			}
		}
	}

	// Total packets from raw
	var totalPkts struct{ Sum uint64 }
	newRawBase().Select("COALESCE(SUM(packets),0) as sum").Scan(&totalPkts)
	result.TotalPackets = totalPkts.Sum

	// Average sampling rate (0 means no sampling or unknown)
	var avgRate struct{ Rate float64 }
	newRawBase().Select("COALESCE(AVG(CASE WHEN sampling_rate > 0 THEN sampling_rate ELSE NULL END),0) as rate").Scan(&avgRate)
	result.AvgSamplingRate = avgRate.Rate
	if result.AvgSamplingRate > 1 {
		result.EstimatedBytes = uint64(float64(result.TotalBytes) * result.AvgSamplingRate)
	} else {
		result.EstimatedBytes = result.TotalBytes
	}

	// Computed throughput
	if hours > 0 {
		result.BitsPerSecond = float64(result.TotalBytes) * 8 / (float64(hours) * 3600)
	}

	// Local traffic stats (port-0 internal traffic, e.g. IPv6 link-local)
	var localRaw struct {
		Bytes   uint64
		Packets uint64
		Flows   int64
	}
	newRawBase().Where("src_port = 0 AND dst_port = 0").
		Select("COALESCE(SUM(bytes),0) as bytes, COALESCE(SUM(packets),0) as packets, COUNT(*) as flows").
		Scan(&localRaw)
	result.LocalTraffic.Bytes = localRaw.Bytes
	result.LocalTraffic.Packets = localRaw.Packets
	result.LocalTraffic.Flows = localRaw.Flows

	if useRollups {
		var localRollup struct {
			Bytes   uint64
			Packets uint64
			Flows   int64
		}
		newRollupBase().Where("dst_port = 0").
			Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
			Scan(&localRollup)
		result.LocalTraffic.Bytes += localRollup.Bytes
		result.LocalTraffic.Packets += localRollup.Packets
		result.LocalTraffic.Flows += localRollup.Flows
	}

	// Filtered bases that exclude port-0 local traffic for top-N charts
	newFilteredRawBase := func() *gorm.DB {
		return newRawBase().Where("NOT (src_port = 0 AND dst_port = 0)")
	}
	newFilteredRollupBase := func() *gorm.DB {
		return newRollupBase().Where("dst_port != 0")
	}

	// Protocol distribution (from raw; supplement with rollups)
	var protocols []struct {
		Protocol uint8
		Count    int64
	}
	if err := newRawBase().Select("protocol, COUNT(*) as count").Group("protocol").
		Order("count DESC").Limit(10).Scan(&protocols).Error; err != nil {
		log.Printf("Flow stats protocol distribution: %v", err)
	}
	if useRollups {
		var rollupProtos []struct {
			Protocol uint8
			Count    int64
		}
		newRollupBase().Select("protocol, SUM(flow_count) as count").Group("protocol").
			Order("count DESC").Limit(10).Scan(&rollupProtos)
		// Merge rollup protocol counts into raw
		protoMap := make(map[uint8]int64)
		for _, p := range protocols {
			protoMap[p.Protocol] = p.Count
		}
		for _, p := range rollupProtos {
			protoMap[p.Protocol] += p.Count
		}
		protocols = protocols[:0]
		for proto, count := range protoMap {
			protocols = append(protocols, struct {
				Protocol uint8
				Count    int64
			}{proto, count})
		}
		sort.Slice(protocols, func(i, j int) bool { return protocols[i].Count > protocols[j].Count })
		if len(protocols) > 10 {
			protocols = protocols[:10]
		}
	}
	for _, p := range protocols {
		result.ByProtocol = append(result.ByProtocol, KeyCount{Key: protoName(p.Protocol), Count: p.Count})
	}
	result.ProtocolCount = int64(len(protocols))

	// Top sources by bytes (filtered: excludes port-0 local traffic)
	result.TopSources = topAddrsByBytes(newFilteredRawBase, "src_addr", 10)
	if useRollups {
		rollupSrc := topAddrsByBytesRollup(newFilteredRollupBase, "src_addr", 10)
		result.TopSources = mergeKeyCounts(result.TopSources, rollupSrc, 10)
	}

	// Top destinations by bytes (filtered: excludes port-0 local traffic)
	result.TopDestinations = topAddrsByBytes(newFilteredRawBase, "dst_addr", 10)
	if useRollups {
		rollupDst := topAddrsByBytesRollup(newFilteredRollupBase, "dst_addr", 10)
		result.TopDestinations = mergeKeyCounts(result.TopDestinations, rollupDst, 10)
	}

	// Top conversations (filtered: excludes port-0 local traffic)
	var convos []struct {
		SrcAddr  string
		DstAddr  string
		DstPort  uint16
		Protocol uint8
		Bytes    uint64
		Packets  uint64
	}
	if err := newFilteredRawBase().Select("src_addr, dst_addr, dst_port, protocol, SUM(bytes) as bytes, SUM(packets) as packets").
		Group("src_addr, dst_addr, dst_port, protocol").
		Order("bytes DESC").Limit(10).Scan(&convos).Error; err != nil {
		log.Printf("Flow stats top conversations: %v", err)
	}
	for _, c := range convos {
		result.TopConversations = append(result.TopConversations, FlowConversation{
			SrcAddr:  c.SrcAddr,
			DstAddr:  c.DstAddr,
			DstPort:  c.DstPort,
			Protocol: protoName(c.Protocol),
			Bytes:    c.Bytes,
			Packets:  c.Packets,
		})
	}

	// Top destination ports
	var topPorts []struct {
		Port  uint16
		Total int64
	}
	newFilteredRawBase().Select("dst_port as port, SUM(bytes) as total").
		Where("dst_port > 0").Group("dst_port").Order("total DESC").Limit(10).Scan(&topPorts)
	for _, p := range topPorts {
		portName := fmt.Sprintf("%d", p.Port)
		if n, ok := wellKnownPorts[p.Port]; ok {
			portName = n
		}
		result.TopPorts = append(result.TopPorts, KeyCount{Key: portName, Count: p.Total})
	}

	// Adaptive time bucketing for bytes over time
	bucketUnit := "hour"
	result.BucketSeconds = 3600
	if hours <= 6 {
		bucketUnit = "minute"
		result.BucketSeconds = 60
	} else if hours > 168 {
		bucketUnit = "day"
		result.BucketSeconds = 86400
	}
	var timeSeries []struct {
		Bucket string
		Total  int64
	}
	if err := newRawBase().Select(d.dialect.TimeBucket(bucketUnit, "timestamp") + " as bucket, SUM(bytes) as total").
		Group("bucket").Order("bucket ASC").Scan(&timeSeries).Error; err != nil {
		log.Printf("Flow stats bytes over time: %v", err)
	}

	// Merge rollup time series
	if useRollups {
		var rollupTS []struct {
			Bucket string
			Total  int64
		}
		newRollupBase().Select(d.dialect.TimeBucket(bucketUnit, "timestamp") + " as bucket, SUM(bytes_sum) as total").
			Group("bucket").Order("bucket ASC").Scan(&rollupTS)
		timeSeries = mergeTimeSeries(timeSeries, rollupTS)
	}

	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
}

// mergeKeyCounts merges two KeyCount slices by summing counts for matching keys,
// then returns the top N sorted by count descending.
func mergeKeyCounts(a, b []KeyCount, limit int) []KeyCount {
	m := make(map[string]int64, len(a)+len(b))
	for _, kc := range a {
		m[kc.Key] += kc.Count
	}
	for _, kc := range b {
		m[kc.Key] += kc.Count
	}
	merged := make([]KeyCount, 0, len(m))
	for k, c := range m {
		merged = append(merged, KeyCount{Key: k, Count: c})
	}
	// Sort descending by count
	sort.Slice(merged, func(i, j int) bool { return merged[i].Count > merged[j].Count })
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged
}

// mergeTimeSeries merges two time-bucketed series by summing totals for matching buckets.
func mergeTimeSeries(a, b []struct {
	Bucket string
	Total  int64
}) []struct {
	Bucket string
	Total  int64
} {
	m := make(map[string]int64, len(a)+len(b))
	for _, ts := range a {
		m[ts.Bucket] += ts.Total
	}
	for _, ts := range b {
		m[ts.Bucket] += ts.Total
	}
	// Collect and sort by bucket
	result := make([]struct {
		Bucket string
		Total  int64
	}, 0, len(m))
	for k, v := range m {
		result = append(result, struct {
			Bucket string
			Total  int64
		}{k, v})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Bucket < result[j].Bucket })
	return result
}

// rollupRow holds aggregated data during rollup operations.
type rollupRow struct {
	Bucket          string
	DeviceID        uint
	SrcAddr         string
	DstAddr         string
	DstPort         uint16
	Protocol        uint8
	BytesSum        uint64
	PacketsSum      uint64
	FlowCount       int64
	SamplingRateAvg float64
}

// batchInsertRollups inserts rollup rows in batches within the given transaction.
func batchInsertRollups(tx *gorm.DB, rows []rollupRow, intervalType, bucketFmt string) error {
	const batchSize = 500
	for i := 0; i < len(rows); i += batchSize {
		end := i + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := make([]models.FlowRollup, 0, end-i)
		for _, r := range rows[i:end] {
			ts, _ := time.Parse(bucketFmt, r.Bucket)
			batch = append(batch, models.FlowRollup{
				Timestamp:       ts,
				DeviceID:        r.DeviceID,
				IntervalType:    intervalType,
				SrcAddr:         r.SrcAddr,
				DstAddr:         r.DstAddr,
				DstPort:         r.DstPort,
				Protocol:        r.Protocol,
				BytesSum:        r.BytesSum,
				PacketsSum:      r.PacketsSum,
				FlowCount:       r.FlowCount,
				SamplingRateAvg: r.SamplingRateAvg,
			})
		}
		if err := tx.Create(&batch).Error; err != nil {
			return fmt.Errorf("batch insert rollups: %w", err)
		}
	}
	return nil
}

// RunFlowRollupCycle aggregates raw flow samples into rollup buckets for scalability.
// Called every 5 minutes by the poller:
//  1. Raw flows older than 1h → 5m rollups
//  2. 5m rollups older than 48h → 1h rollups
//  3. 1h rollups older than 30d → 1d rollups
func (d *Database) RunFlowRollupCycle() {
	work := false

	// Step 1: raw flows > 1h old → 5m rollups
	cutoff1h := time.Now().Add(-1 * time.Hour)
	if d.aggregateFlowsToRollup(cutoff1h, "5m") {
		work = true
	}

	// Step 2: 5m rollups > 48h old → 1h rollups
	cutoff48h := time.Now().Add(-48 * time.Hour)
	if d.aggregateRollupsUp("5m", "1h", cutoff48h) {
		work = true
	}

	// Step 3: 1h rollups > 30d old → 1d rollups
	cutoff30d := time.Now().Add(-30 * 24 * time.Hour)
	if d.aggregateRollupsUp("1h", "1d", cutoff30d) {
		work = true
	}

	if !work {
		log.Println("Flow rollup: cycle complete (no data to aggregate)")
	}
}

// aggregateFlowsToRollup groups raw FlowSamples older than cutoff into 5-minute rollups.
// Returns true if work was done.
func (d *Database) aggregateFlowsToRollup(cutoff time.Time, intervalType string) bool {
	bucketExpr := d.dialect.TimeBucket("5min", "timestamp")

	// Paginate: process in chunks to limit memory usage
	const pageSize = 50000
	offset := 0
	totalGroups := 0

	for {
		var rows []rollupRow
		if err := d.db.Model(&models.FlowSample{}).
			Where("timestamp < ?", cutoff).
			Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, " +
				"SUM(bytes) as bytes_sum, SUM(packets) as packets_sum, COUNT(*) as flow_count, " +
				"AVG(sampling_rate) as sampling_rate_avg").
			Group("bucket, device_id, src_addr, dst_addr, dst_port, protocol").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Flow rollup: error scanning raw flows: %v", err)
			return totalGroups > 0
		}

		if len(rows) == 0 {
			break
		}

		// Wrap insert+delete in a transaction for atomicity
		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := batchInsertRollups(tx, rows, intervalType, "2006-01-02 15:04"); err != nil {
				return err
			}
			return nil
		}); err != nil {
			log.Printf("Flow rollup: transaction error: %v", err)
			return totalGroups > 0
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false
	}

	// Delete consumed raw rows (outside the insert tx since we've confirmed inserts succeeded)
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.FlowSample{}).Error; err != nil {
		log.Printf("Flow rollup: error deleting consumed raw flows: %v", err)
	}
	log.Printf("Flow rollup: aggregated %d groups from raw flows into %s rollups", totalGroups, intervalType)
	return true
}

// aggregateRollupsUp promotes rollups from srcInterval older than cutoff into dstInterval.
// Uses weighted average for sampling rate. Returns true if work was done.
func (d *Database) aggregateRollupsUp(srcInterval, dstInterval string, cutoff time.Time) bool {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if dstInterval == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	var rows []rollupRow
	if err := d.db.Model(&models.FlowRollup{}).
		Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
		Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, " +
			"SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, SUM(flow_count) as flow_count, " +
			"CASE WHEN SUM(flow_count) > 0 THEN SUM(sampling_rate_avg * flow_count) / SUM(flow_count) ELSE 0 END as sampling_rate_avg").
		Group("bucket, device_id, src_addr, dst_addr, dst_port, protocol").
		Scan(&rows).Error; err != nil {
		log.Printf("Flow rollup: error scanning %s rollups: %v", srcInterval, err)
		return false
	}

	if len(rows) == 0 {
		return false
	}

	// Wrap insert+delete in a transaction for atomicity
	if err := d.db.Transaction(func(tx *gorm.DB) error {
		if err := batchInsertRollups(tx, rows, dstInterval, bucketFmt); err != nil {
			return err
		}
		// Delete consumed source rollups within the same transaction
		if err := tx.Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
			Delete(&models.FlowRollup{}).Error; err != nil {
			return fmt.Errorf("delete consumed %s rollups: %w", srcInterval, err)
		}
		return nil
	}); err != nil {
		log.Printf("Flow rollup: transaction error promoting %s to %s: %v", srcInterval, dstInterval, err)
		return false
	}

	log.Printf("Flow rollup: promoted %d groups from %s to %s rollups", len(rows), srcInterval, dstInterval)
	return true
}

// RunSyslogAggregationCycle aggregates old informational syslog into summaries for scalability.
// Called every 5 minutes by the poller:
//  1. Raw informational (severity 6-7) older than SyslogInfoDays → hourly summaries
//  2. Hourly summaries older than 48h → daily summaries
func (d *Database) RunSyslogAggregationCycle(retention config.RetentionConfig) error {
	infoDays := retention.SyslogInfoDays
	if infoDays <= 0 {
		infoDays = 7 // default: aggregate after 7 days
	}

	work := false
	var lastErr error

	// Step 1: raw informational syslog > infoDays old → hourly summaries
	cutoffInfo := time.Now().AddDate(0, 0, -infoDays)
	if done, err := d.aggregateSyslogToSummary(cutoffInfo, "1h"); err != nil {
		lastErr = err
		log.Printf("Syslog aggregation: step 1 error: %v", err)
	} else if done {
		work = true
	}

	// Step 2: hourly summaries > 48h old → daily summaries
	cutoff48h := time.Now().Add(-48 * time.Hour)
	if done, err := d.promoteSyslogSummaries("1h", "1d", cutoff48h); err != nil {
		lastErr = err
		log.Printf("Syslog aggregation: step 2 error: %v", err)
	} else if done {
		work = true
	}

	if !work && lastErr == nil {
		log.Println("Syslog aggregation: cycle complete (no data to aggregate)")
	}

	return lastErr
}

// syslogSummaryRow holds aggregated data during syslog summary operations.
type syslogSummaryRow struct {
	Bucket         string
	DeviceID       uint
	Severity       int
	Facility       int
	AppName        string
	MessagePattern string
	Count          int64
	SampleMessage  string
}

// aggregateSyslogToSummary groups raw informational syslog older than cutoff into hourly summaries.
// Returns true if work was done, error if fatal.
func (d *Database) aggregateSyslogToSummary(cutoff time.Time, intervalType string) (bool, error) {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if intervalType == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	const pageSize = 10000
	offset := 0
	totalGroups := 0

	for {
		var rows []syslogSummaryRow
		if err := d.db.Model(&models.SyslogMessage{}).
			Where("timestamp < ? AND severity >= 6", cutoff). // only informational (6) and debug (7)
			Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, " +
				"COUNT(*) as count, MIN(message) as sample_message").
			Group("bucket, device_id, severity, facility, app_name").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Syslog aggregation: error scanning raw messages: %v", err)
			return totalGroups > 0, err
		}

		if len(rows) == 0 {
			break
		}

		// Wrap insert+delete in a transaction for atomicity per page
		// Note: This deletes ALL informational messages < cutoff for simplicity.
		// If this page fails, messages will be re-aggregated on next cycle (potential duplicates, but safe).
		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := batchInsertSyslogSummaries(tx, rows, intervalType, bucketFmt); err != nil {
				return err
			}
			// Delete informational messages older than cutoff
			if err := tx.Where("timestamp < ? AND severity >= 6", cutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
				return fmt.Errorf("delete raw syslog after aggregation: %w", err)
			}
			return nil
		}); err != nil {
			log.Printf("Syslog aggregation: transaction error: %v", err)
			return totalGroups > 0, err
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false, nil
	}

	log.Printf("Syslog aggregation: aggregated %d groups from raw syslog into %s summaries", totalGroups, intervalType)
	return true, nil
}

// batchInsertSyslogSummaries inserts syslog summary rows in batches.
func batchInsertSyslogSummaries(tx *gorm.DB, rows []syslogSummaryRow, intervalType, bucketFmt string) error {
	const batchSize = 500
	for i := 0; i < len(rows); i += batchSize {
		end := i + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := make([]models.SyslogSummary, 0, end-i)
		for _, r := range rows[i:end] {
			ts, _ := time.Parse(bucketFmt, r.Bucket)
			batch = append(batch, models.SyslogSummary{
				Timestamp:      ts,
				DeviceID:       r.DeviceID,
				IntervalType:   intervalType,
				Severity:       r.Severity,
				Facility:       r.Facility,
				AppName:        r.AppName,
				MessagePattern: r.MessagePattern,
				Count:          r.Count,
				SampleMessage:  r.SampleMessage,
			})
		}
		if err := tx.Create(&batch).Error; err != nil {
			return fmt.Errorf("batch insert syslog summaries: %w", err)
		}
	}
	return nil
}

// promoteSyslogSummaries promotes summaries from srcInterval older than cutoff into dstInterval.
// Returns true if work was done, error if fatal.
func (d *Database) promoteSyslogSummaries(srcInterval, dstInterval string, cutoff time.Time) (bool, error) {
	bucketUnit := "day"
	bucketFmt := "2006-01-02"
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	const pageSize = 5000
	offset := 0
	totalGroups := 0

	for {
		var rows []syslogSummaryRow
		if err := d.db.Model(&models.SyslogSummary{}).
			Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
			Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, message_pattern, " +
				"SUM(count) as count, MIN(sample_message) as sample_message").
			Group("bucket, device_id, severity, facility, app_name, message_pattern").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Syslog aggregation: error scanning %s summaries: %v", srcInterval, err)
			return totalGroups > 0, err
		}

		if len(rows) == 0 {
			break
		}

		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := batchInsertSyslogSummaries(tx, rows, dstInterval, bucketFmt); err != nil {
				return err
			}
			if err := tx.Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
				Delete(&models.SyslogSummary{}).Error; err != nil {
				return fmt.Errorf("delete consumed %s syslog summaries: %w", srcInterval, err)
			}
			return nil
		}); err != nil {
			log.Printf("Syslog aggregation: transaction error promoting %s to %s: %v", srcInterval, dstInterval, err)
			return totalGroups > 0, err
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false, nil
	}

	log.Printf("Syslog aggregation: promoted %d groups from %s to %s summaries", totalGroups, srcInterval, dstInterval)
	return true, nil
}

// EventStatsResult holds aggregated event statistics (alerts, traps, syslog)
type EventStatsResult struct {
	Total      int64        `json:"total"`
	BySeverity []KeyCount   `json:"by_severity"`
	ByType     []KeyCount   `json:"by_type"`
	OverTime   []TimeBucket `json:"over_time"`
}

// timeSeriesCount queries hourly time-bucketed counts for model since cutoff.
// timeSeriesCount returns per-hour COUNT buckets for the given model
// since cutoff. deviceID = 0 means "all devices" (v0.10.217, bundle D4).
func (d *Database) timeSeriesCount(model interface{}, cutoff time.Time, deviceID uint) []TimeBucket {
	var rows []struct {
		Bucket string
		Count  int64
	}
	q := d.db.Model(model).Where("timestamp > ?", cutoff)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	q.Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, COUNT(*) as count").
		Group("bucket").Order("bucket ASC").Scan(&rows)
	buckets := make([]TimeBucket, 0, len(rows))
	for _, r := range rows {
		buckets = append(buckets, TimeBucket{Bucket: r.Bucket, Count: r.Count})
	}
	return buckets
}

// groupByString queries COUNT grouped by groupCol on model since cutoff.
// deviceID = 0 means "all devices". (v0.10.217, bundle D4)
func (d *Database) groupByString(model interface{}, cutoff time.Time, groupCol string, deviceID uint) []KeyCount {
	var rows []struct {
		Key   string
		Count int64
	}
	qCol := d.dialect.QuoteIdent(groupCol)
	q := d.db.Model(model).Where("timestamp > ?", cutoff)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	q.Select(qCol + " as key, COUNT(*) as count").Group(qCol).Order("count DESC").Scan(&rows)
	counts := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		counts = append(counts, KeyCount{Key: r.Key, Count: r.Count})
	}
	return counts
}

// GetAlertStats returns aggregated alert statistics. deviceID = 0 means
// "all devices" (the existing /admin/alerts page passes 0); a non-zero
// value scopes the stats to a single device for the per-device noise
// view added in v0.10.217 (bundle D4).
func (d *Database) GetAlertStats(hours int, deviceID uint) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	q := d.db.Model(&models.Alert{}).Where("timestamp > ?", cutoff)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	q.Count(&result.Total)
	result.BySeverity = d.groupByString(&models.Alert{}, cutoff, "severity", deviceID)
	result.ByType = d.groupByString(&models.Alert{}, cutoff, "alert_type", deviceID)
	result.OverTime = d.timeSeriesCount(&models.Alert{}, cutoff, deviceID)

	return result, nil
}

// GetTrapStats returns aggregated trap statistics. deviceID semantics
// same as GetAlertStats. Trap rows are matched on `device_id` when set;
// trap events arriving from unknown sources are excluded from a per-
// device filter (they have device_id = 0).
func (d *Database) GetTrapStats(hours int, deviceID uint) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	q := d.db.Model(&models.TrapEvent{}).Where("timestamp > ?", cutoff)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	q.Count(&result.Total)
	result.BySeverity = d.groupByString(&models.TrapEvent{}, cutoff, "severity", deviceID)
	result.ByType = d.groupByString(&models.TrapEvent{}, cutoff, "trap_type", deviceID)
	result.OverTime = d.timeSeriesCount(&models.TrapEvent{}, cutoff, deviceID)

	return result, nil
}

// GetSyslogStats returns aggregated syslog statistics (raw + summaries
// combined). deviceID = 0 means "all devices" (v0.10.217, bundle D4).
func (d *Database) GetSyslogStats(hours int, deviceID uint) (*EventStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &EventStatsResult{}

	// applyDevFilter is a small helper to keep the device_id WHERE
	// clause out of every chain below.
	applyDevFilter := func(q *gorm.DB) *gorm.DB {
		if deviceID != 0 {
			return q.Where("device_id = ?", deviceID)
		}
		return q
	}

	// Total: raw syslog + summaries
	var rawCount int64
	if err := applyDevFilter(d.db.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff)).
		Count(&rawCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count raw syslog: %w", err)
	}
	var summaryCount int64
	if err := applyDevFilter(d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff)).
		Select("COALESCE(SUM(count), 0)").Scan(&summaryCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count syslog summaries: %w", err)
	}
	result.Total = rawCount + summaryCount

	// Syslog severity is numeric, map to human-readable names
	sevNames := map[int]string{0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error", 4: "Warning", 5: "Notice", 6: "Info", 7: "Debug"}
	var bySev []struct {
		Severity int
		Count    int64
	}
	// Get severity counts from raw syslog
	if err := applyDevFilter(d.db.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff)).
		Select("severity, COUNT(*) as count").Group("severity").Scan(&bySev).Error; err != nil {
		return nil, fmt.Errorf("failed to get raw syslog severity counts: %w", err)
	}
	// Get severity counts from summaries
	var summaryBySev []struct {
		Severity int
		Count    int64
	}
	if err := applyDevFilter(d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff)).
		Select("severity, SUM(count) as count").Group("severity").Scan(&summaryBySev).Error; err != nil {
		return nil, fmt.Errorf("failed to get summary severity counts: %w", err)
	}
	// Merge summary counts into bySev
	sevMap := make(map[int]int64)
	for _, s := range bySev {
		sevMap[s.Severity] += s.Count
	}
	for _, s := range summaryBySev {
		sevMap[s.Severity] += s.Count
	}
	for sev, count := range sevMap {
		name := sevNames[sev]
		if name == "" {
			name = fmt.Sprintf("Severity %d", sev)
		}
		result.BySeverity = append(result.BySeverity, KeyCount{Key: name, Count: count})
	}

	// OverTime: combine raw time series with summary counts
	rawTimeSeries := d.timeSeriesCount(&models.SyslogMessage{}, cutoff, deviceID)
	// Get summary time series grouped by hour
	var summaryTimeSeries []struct {
		Bucket string
		Count  int64
	}
	if err := applyDevFilter(d.db.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff)).
		Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, SUM(count) as count").
		Group("bucket").Order("bucket ASC").Scan(&summaryTimeSeries).Error; err != nil {
		return nil, fmt.Errorf("failed to get summary time series: %w", err)
	}
	// Merge summary time series into raw time series
	summaryMap := make(map[string]int64)
	for _, r := range summaryTimeSeries {
		summaryMap[r.Bucket] += r.Count
	}
	for _, r := range rawTimeSeries {
		summaryMap[r.Bucket] += r.Count
	}
	// Sort by bucket for consistent ordering
	buckets := make([]string, 0, len(summaryMap))
	for bucket := range summaryMap {
		buckets = append(buckets, bucket)
	}
	sort.Strings(buckets)
	for _, bucket := range buckets {
		result.OverTime = append(result.OverTime, TimeBucket{Bucket: bucket, Count: summaryMap[bucket]})
	}

	return result, nil
}

// DashboardTimeSeries holds overview metrics over time
type DashboardTimeSeries struct {
	FlowsOverTime   []TimeBucket `json:"flows_over_time"`
	AlertsOverTime  []TimeBucket `json:"alerts_over_time"`
	SyslogOverTime  []TimeBucket `json:"syslog_over_time"`
	TrapsOverTime   []TimeBucket `json:"traps_over_time"`
	DeviceStatusMap []KeyCount   `json:"device_status"`
}

// GetDashboardTimeSeries returns dashboard-level time-series data
func (d *Database) GetDashboardTimeSeries(hours int) (*DashboardTimeSeries, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &DashboardTimeSeries{
		FlowsOverTime:  d.timeSeriesCount(&models.FlowSample{}, cutoff, 0),
		AlertsOverTime: d.timeSeriesCount(&models.Alert{}, cutoff, 0),
		SyslogOverTime: d.timeSeriesCount(&models.SyslogMessage{}, cutoff, 0),
		TrapsOverTime:  d.timeSeriesCount(&models.TrapEvent{}, cutoff, 0),
	}

	// Device status distribution
	var deviceStatus []struct {
		Status string
		Count  int64
	}
	d.db.Model(&models.Device{}).Where("enabled = ?", true).
		Select("status, COUNT(*) as count").Group("status").Scan(&deviceStatus)
	for _, s := range deviceStatus {
		result.DeviceStatusMap = append(result.DeviceStatusMap, KeyCount{Key: s.Status, Count: s.Count})
	}

	return result, nil
}

func (d *Database) GetDevicesByProbe(probeID uint) ([]models.Device, error) {
	var devices []models.Device
	err := d.db.Where("probe_id = ?", probeID).Preload("Site").Find(&devices).Error
	for i := range devices {
		d.DecryptDeviceSecrets(&devices[i])
	}
	return devices, err
}

// VPNChartBucket holds a single time-bucket for VPN tunnel chart data.
type VPNChartBucket struct {
	Bucket     string  `json:"bucket"`
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

	// Use LAG() window function to compute per-sample deltas from cumulative SNMP counters.
	// First row per partition (LAG is NULL) returns NULL and is filtered by the outer WHERE.
	// Counter resets (new value < old value) use the raw value as the delta.
	// AUDIT-043: the named `WINDOW w AS (...)` clause runs on BOTH Postgres
	// (prod) and the modernc SQLite test backend — no dialect gating needed.
	// `vpnchart_window_audit043_test.go` exercises this path on SQLite (the
	// audit flagged it as untested in CI) and pins the delta + reset-clamp math.
	query := fmt.Sprintf(`
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
			WHERE device_id = ? AND tunnel_name = ? AND timestamp > ?
			WINDOW w AS (ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY bucket ORDER BY bucket ASC`, bucketExpr)

	var rows []VPNChartBucket
	err := d.db.Raw(query, deviceID, tunnelName, cutoff).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Phase2Match represents a matched pair of Phase 2 selectors between two devices.
type Phase2Match struct {
	SourceTunnel string `json:"source_tunnel"`
	DestTunnel   string `json:"dest_tunnel"`
	SourcePhase1 string `json:"source_phase1"`
	DestPhase1   string `json:"dest_phase1"`
	LocalSubnet  string `json:"local_subnet"`
	RemoteSubnet string `json:"remote_subnet"`
	SourceStatus string `json:"source_status"`
	DestStatus   string `json:"dest_status"`
	SrcBytesIn   uint64 `json:"src_bytes_in"`
	SrcBytesOut  uint64 `json:"src_bytes_out"`
	DstBytesIn   uint64 `json:"dst_bytes_in"`
	DstBytesOut  uint64 `json:"dst_bytes_out"`
	SrcUptime    uint64 `json:"src_uptime"`
	DstUptime    uint64 `json:"dst_uptime"`
}

// ConnectionDetailResult holds full detail for a connection including matching tunnels.
type ConnectionDetailResult struct {
	Connection      models.DeviceConnection `json:"connection"`
	SourceTunnels   []models.VPNStatus      `json:"source_tunnels"`
	DestTunnels     []models.VPNStatus      `json:"dest_tunnels"`
	TotalBytesIn    uint64                  `json:"total_bytes_in"`
	TotalBytesOut   uint64                  `json:"total_bytes_out"`
	TotalPacketsIn  uint64                  `json:"total_packets_in"`
	TotalPacketsOut uint64                  `json:"total_packets_out"`
	ThroughputIn    float64                 `json:"throughput_in"`
	ThroughputOut   float64                 `json:"throughput_out"`
	HasFlowData     bool                    `json:"has_flow_data"`
	Phase2Matches   []Phase2Match           `json:"phase2_matches"`
}

// collectDeviceIPs returns all known IPs for a device (management + interface addresses).
func (d *Database) collectDeviceIPs(deviceID uint, device *models.Device) map[string]bool {
	ips := make(map[string]bool)
	if device != nil && device.IPAddress != "" {
		ips[device.IPAddress] = true
	}
	var distinctIPs []string
	d.db.Model(&models.InterfaceAddress{}).
		Where("device_id = ?", deviceID).
		Distinct("ip_address").
		Pluck("ip_address", &distinctIPs)
	for _, ip := range distinctIPs {
		ips[ip] = true
	}
	return ips
}

// GetConnectionDetail returns full detail for a connection with matching tunnels from both sides.
func (d *Database) GetConnectionDetail(connID uint) (*ConnectionDetailResult, error) {
	var conn models.DeviceConnection
	if err := d.db.Preload("SourceDevice").Preload("DestDevice").First(&conn, connID).Error; err != nil {
		return nil, err
	}

	result := &ConnectionDetailResult{Connection: conn}

	// Get latest VPN statuses for both devices
	srcTunnels, _ := d.GetLatestVPNStatuses(conn.SourceDeviceID)
	dstTunnels, _ := d.GetLatestVPNStatuses(conn.DestDeviceID)

	// Collect IPs for the dest device (management + interface addresses)
	destIPs := d.collectDeviceIPs(conn.DestDeviceID, conn.DestDevice)

	// Collect IPs for the source device
	srcIPs := d.collectDeviceIPs(conn.SourceDeviceID, conn.SourceDevice)

	// Build a set of known tunnel names from the connection record (auto-discovery)
	knownTunnels := make(map[string]bool)
	if conn.TunnelNames != "" {
		for _, name := range strings.Split(conn.TunnelNames, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				knownTunnels[name] = true
			}
		}
	}

	// Filter source tunnels: remote IP matches dest device OR tunnel name in known list
	for _, t := range srcTunnels {
		if destIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			// Avoid duplicates
			alreadyAdded := false
			for _, existing := range result.SourceTunnels {
				if existing.TunnelName == t.TunnelName && existing.DeviceID == t.DeviceID {
					alreadyAdded = true
					break
				}
			}
			if alreadyAdded {
				continue
			}
			result.SourceTunnels = append(result.SourceTunnels, t)
			result.TotalBytesIn += t.BytesIn
			result.TotalBytesOut += t.BytesOut
			result.TotalPacketsIn += t.PacketsIn
			result.TotalPacketsOut += t.PacketsOut
		}
	}

	// For indirectly matched connections (NAT'd hub-spoke), dest tunnels' remote IPs
	// are likely source's WAN IPs. Add them to srcIPs so dest tunnels can match.
	// This is safe because the VPN detector already confirmed the connection.
	if conn.MatchMethod == "tunnel_indirect" || conn.MatchMethod == "wan_inferred" {
		for _, t := range dstTunnels {
			if t.RemoteIP != "" {
				srcIPs[t.RemoteIP] = true
			}
		}
	}

	// Filter dest tunnels: remote IP matches source device (including inferred WAN IPs),
	// or tunnel name is in the known list from auto-detection
	for _, t := range dstTunnels {
		if srcIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			// Avoid duplicates
			alreadyAdded := false
			for _, existing := range result.DestTunnels {
				if existing.TunnelName == t.TunnelName && existing.DeviceID == t.DeviceID {
					alreadyAdded = true
					break
				}
			}
			if alreadyAdded {
				continue
			}
			result.DestTunnels = append(result.DestTunnels, t)
		}
	}

	// Cross-fill: if one side has empty subnets, infer from the other side (swapped).
	// Hub-side ADVPN tunnels often have empty Phase 2 selectors in SNMP.
	log.Printf("GetConnectionDetail %d: source_tunnels=%d dest_tunnels=%d", connID, len(result.SourceTunnels), len(result.DestTunnels))
	for i, t := range result.SourceTunnels {
		log.Printf("GetConnectionDetail %d: source_tunnel[%d] name=%s local=%s remote=%s", connID, i, t.TunnelName, t.LocalSubnet, t.RemoteSubnet)
	}
	for i, t := range result.DestTunnels {
		log.Printf("GetConnectionDetail %d: dest_tunnel[%d] name=%s local=%s remote=%s", connID, i, t.TunnelName, t.LocalSubnet, t.RemoteSubnet)
	}
	if len(result.SourceTunnels) > 0 && len(result.DestTunnels) > 0 {
		for i := range result.SourceTunnels {
			if result.SourceTunnels[i].LocalSubnet == "" || result.SourceTunnels[i].RemoteSubnet == "" {
				for _, dst := range result.DestTunnels {
					if dst.LocalSubnet != "" && dst.RemoteSubnet != "" {
						if result.SourceTunnels[i].LocalSubnet == "" {
							result.SourceTunnels[i].LocalSubnet = dst.RemoteSubnet
						}
						if result.SourceTunnels[i].RemoteSubnet == "" {
							result.SourceTunnels[i].RemoteSubnet = dst.LocalSubnet
						}
						break
					}
				}
			}
		}
		for i := range result.DestTunnels {
			if result.DestTunnels[i].LocalSubnet == "" || result.DestTunnels[i].RemoteSubnet == "" {
				for _, src := range result.SourceTunnels {
					if src.LocalSubnet != "" && src.RemoteSubnet != "" {
						if result.DestTunnels[i].LocalSubnet == "" {
							result.DestTunnels[i].LocalSubnet = src.RemoteSubnet
						}
						if result.DestTunnels[i].RemoteSubnet == "" {
							result.DestTunnels[i].RemoteSubnet = src.LocalSubnet
						}
						break
					}
				}
			}
		}
	}

	// Cross-fill tunnel uptime: if one side reports 0 uptime, use the paired tunnel's value.
	if len(result.SourceTunnels) > 0 && len(result.DestTunnels) > 0 {
		for i := range result.SourceTunnels {
			if result.SourceTunnels[i].TunnelUptime == 0 {
				for _, dst := range result.DestTunnels {
					if dst.TunnelUptime > 0 {
						result.SourceTunnels[i].TunnelUptime = dst.TunnelUptime
						break
					}
				}
			}
		}
		for i := range result.DestTunnels {
			if result.DestTunnels[i].TunnelUptime == 0 {
				for _, src := range result.SourceTunnels {
					if src.TunnelUptime > 0 {
						result.DestTunnels[i].TunnelUptime = src.TunnelUptime
						break
					}
				}
			}
		}
	}

	// Phase 2 inverse matching: source's local_subnet == dest's remote_subnet (and vice versa)
	for _, src := range result.SourceTunnels {
		if src.LocalSubnet == "" || src.RemoteSubnet == "" {
			continue
		}
		for _, dst := range result.DestTunnels {
			if dst.LocalSubnet == "" || dst.RemoteSubnet == "" {
				continue
			}
			if src.LocalSubnet == dst.RemoteSubnet && src.RemoteSubnet == dst.LocalSubnet {
				result.Phase2Matches = append(result.Phase2Matches, Phase2Match{
					SourceTunnel: src.TunnelName,
					DestTunnel:   dst.TunnelName,
					SourcePhase1: src.Phase1Name,
					DestPhase1:   dst.Phase1Name,
					LocalSubnet:  src.LocalSubnet,
					RemoteSubnet: src.RemoteSubnet,
					SourceStatus: src.Status,
					DestStatus:   dst.Status,
					SrcBytesIn:   src.BytesIn,
					SrcBytesOut:  src.BytesOut,
					DstBytesIn:   dst.BytesIn,
					DstBytesOut:  dst.BytesOut,
					SrcUptime:    src.TunnelUptime,
					DstUptime:    dst.TunnelUptime,
				})
			}
		}
	}

	// Compute live throughput (bytes/sec) from the two most recent VPNStatus samples per source tunnel
	for _, t := range result.SourceTunnels {
		var samples []models.VPNStatus
		d.db.Where("device_id = ? AND tunnel_name = ?", t.DeviceID, t.TunnelName).
			Order("timestamp DESC").Limit(2).Find(&samples)
		if len(samples) == 2 {
			dt := samples[0].Timestamp.Sub(samples[1].Timestamp).Seconds()
			if dt > 0 {
				dIn := float64(samples[0].BytesIn) - float64(samples[1].BytesIn)
				dOut := float64(samples[0].BytesOut) - float64(samples[1].BytesOut)
				// Handle counter resets
				if dIn < 0 {
					dIn = float64(samples[0].BytesIn)
				}
				if dOut < 0 {
					dOut = float64(samples[0].BytesOut)
				}
				result.ThroughputIn += dIn / dt
				result.ThroughputOut += dOut / dt
			}
		}
	}

	// Check if sFlow data exists for either device
	var flowCount int64
	d.db.Model(&models.FlowSample{}).Where("device_id IN ?", []uint{conn.SourceDeviceID, conn.DestDeviceID}).Limit(1).Count(&flowCount)
	result.HasFlowData = flowCount > 0

	return result, nil
}

// getConnectionTunnelNames returns matching tunnel names for a connection's source and dest devices.
func (d *Database) getConnectionTunnelNames(connID uint) (srcDeviceID, dstDeviceID uint, srcTunnelNames, dstTunnelNames []string, err error) {
	var conn models.DeviceConnection
	if err = d.db.Preload("SourceDevice").Preload("DestDevice").First(&conn, connID).Error; err != nil {
		return
	}
	srcDeviceID = conn.SourceDeviceID
	dstDeviceID = conn.DestDeviceID

	srcTunnels, _ := d.GetLatestVPNStatuses(conn.SourceDeviceID)
	dstTunnels, _ := d.GetLatestVPNStatuses(conn.DestDeviceID)

	// Collect IPs for both devices
	destIPs := d.collectDeviceIPs(conn.DestDeviceID, conn.DestDevice)
	srcIPs := d.collectDeviceIPs(conn.SourceDeviceID, conn.SourceDevice)

	// For indirectly matched connections (NAT'd hub-spoke), relax IP matching
	// by adding the peer's tunnel remote IPs — same logic as GetConnectionDetail
	if conn.MatchMethod == "tunnel_indirect" || conn.MatchMethod == "wan_inferred" {
		for _, t := range dstTunnels {
			if t.RemoteIP != "" {
				srcIPs[t.RemoteIP] = true
			}
		}
		for _, t := range srcTunnels {
			if t.RemoteIP != "" {
				destIPs[t.RemoteIP] = true
			}
		}
	}

	// Known tunnel names from auto-discovery
	knownTunnels := make(map[string]bool)
	if conn.TunnelNames != "" {
		for _, name := range strings.Split(conn.TunnelNames, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				knownTunnels[name] = true
			}
		}
	}

	for _, t := range srcTunnels {
		if destIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			srcTunnelNames = append(srcTunnelNames, t.TunnelName)
		}
	}
	for _, t := range dstTunnels {
		if srcIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			dstTunnelNames = append(dstTunnelNames, t.TunnelName)
		}
	}
	return
}

// GetConnectionTraffic returns aggregated VPN chart data for all matching tunnels in a connection.
func (d *Database) GetConnectionTraffic(connID uint, rangeStr string) ([]VPNChartBucket, error) {
	srcDeviceID, dstDeviceID, srcTunnelNames, dstTunnelNames, err := d.getConnectionTunnelNames(connID)
	if err != nil {
		return nil, err
	}

	// Determine time params
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
	default:
		hours = 24
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// Collect all tunnel conditions
	var allNames []string
	var deviceIDs []uint
	for _, n := range srcTunnelNames {
		allNames = append(allNames, n)
	}
	for _, n := range dstTunnelNames {
		allNames = append(allNames, n)
	}
	if len(srcTunnelNames) > 0 {
		deviceIDs = append(deviceIDs, srcDeviceID)
	}
	if len(dstTunnelNames) > 0 {
		deviceIDs = append(deviceIDs, dstDeviceID)
	}

	if len(allNames) == 0 {
		return []VPNChartBucket{}, nil
	}

	// Build explicit placeholders for IN clauses (GORM Raw doesn't reliably expand slices)
	var args []interface{}
	devPH := make([]string, len(deviceIDs))
	for i, id := range deviceIDs {
		devPH[i] = "?"
		args = append(args, id)
	}
	namePH := make([]string, len(allNames))
	for i, n := range allNames {
		namePH[i] = "?"
		args = append(args, n)
	}
	args = append(args, cutoff)

	// Use LAG() window function to compute per-sample deltas from cumulative SNMP counters.
	// First row per partition (LAG is NULL) returns NULL and is filtered by the outer WHERE.
	query := fmt.Sprintf(`
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
			WHERE device_id IN (%s) AND tunnel_name IN (%s) AND timestamp > ?
			WINDOW w AS (PARTITION BY device_id, tunnel_name ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY bucket ORDER BY bucket ASC`,
		bucketExpr, strings.Join(devPH, ","), strings.Join(namePH, ","))

	var rows []VPNChartBucket
	err = d.db.Raw(query, args...).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// FlowConversation represents a top conversation from flow data.
type FlowConversation struct {
	SrcAddr  string `json:"src_addr"`
	DstAddr  string `json:"dst_addr"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
	Bytes    uint64 `json:"bytes"`
	Packets  uint64 `json:"packets"`
}

// ConnectionFlowResult holds sFlow traffic analysis for a connection.
type ConnectionFlowResult struct {
	TotalBytes       uint64             `json:"total_bytes"`
	TotalPackets     uint64             `json:"total_packets"`
	TotalFlows       int64              `json:"total_flows"`
	ByProtocol       []KeyCount         `json:"by_protocol"`
	TopSources       []KeyCount         `json:"top_sources"`
	TopDests         []KeyCount         `json:"top_destinations"`
	TopConversations []FlowConversation `json:"top_conversations"`
	BytesOverTime    []TimeBucket       `json:"bytes_over_time"`
}

// cidrToLikePattern converts a CIDR subnet to a SQL LIKE pattern.
// Works for /8, /16, /24 which cover ~99% of real VPN subnets.
// Returns empty string for invalid, too-broad (e.g. 0.0.0.0/0), or unsupported prefix lengths.
//
// AUDIT-148: the output of this function is fed verbatim into a SQL
// LIKE clause (with the `ESCAPE '\'` modifier at the call site).
// The patterns only ever contain digits, dots, and an intentional
// trailing `%` (the wildcard), so today's input set is safe by
// construction — `net.ParseIP` and `net.ParseCIDR` reject anything
// that isn't a valid IP literal. The defense-in-depth is the ESCAPE
// clause at the call site, not anything in this function.
func cidrToLikePattern(cidr string) string {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" || cidr == "0.0.0.0/0" {
		return ""
	}

	// Handle non-CIDR formats: "10.0.1.0 - 10.0.1.255" or bare IPs
	if !strings.Contains(cidr, "/") {
		// IP range format
		if strings.Contains(cidr, " - ") {
			parts := strings.SplitN(cidr, " - ", 2)
			beginIP := net.ParseIP(strings.TrimSpace(parts[0]))
			if beginIP == nil {
				return ""
			}
			b := beginIP.To4()
			if b == nil {
				return ""
			}
			return fmt.Sprintf("%d.%d.%d.%%", b[0], b[1], b[2])
		}
		// Single IP — exact match
		if net.ParseIP(cidr) != nil {
			return cidr
		}
		return ""
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return ""
	}
	ones, _ := ipNet.Mask.Size()
	switch {
	case ones == 32:
		return fmt.Sprintf("%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3])
	case ones >= 24:
		return fmt.Sprintf("%d.%d.%d.%%", ip4[0], ip4[1], ip4[2])
	case ones >= 16:
		return fmt.Sprintf("%d.%d.%%", ip4[0], ip4[1])
	case ones >= 8:
		return fmt.Sprintf("%d.%%", ip4[0])
	default:
		return ""
	}
}

// GetConnectionFlowStats returns sFlow traffic analysis for a connection.
// Primary strategy: filter flows by VPN subnet pairs (local/remote).
// Fallback: match tunnel interface indices by name (including Phase1Name).
func (d *Database) GetConnectionFlowStats(connID uint, hours int) (*ConnectionFlowResult, error) {
	srcDeviceID, dstDeviceID, srcTunnelNames, dstTunnelNames, err := d.getConnectionTunnelNames(connID)
	if err != nil {
		return nil, err
	}

	var tunnelNames []string
	tunnelNames = append(tunnelNames, srcTunnelNames...)
	tunnelNames = append(tunnelNames, dstTunnelNames...)
	if len(tunnelNames) == 0 {
		return &ConnectionFlowResult{}, nil
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	deviceIDs := []uint{srcDeviceID, dstDeviceID}

	// --- Strategy 1: Subnet-based filtering ---
	// Query VPN statuses for these tunnel names to get (local_subnet, remote_subnet) pairs
	type subnetPair struct {
		LocalSubnet  string
		RemoteSubnet string
	}
	var pairs []subnetPair
	d.db.Raw(`SELECT DISTINCT local_subnet, remote_subnet FROM vpn_status
		WHERE device_id IN ? AND tunnel_name IN ? AND local_subnet != '' AND remote_subnet != ''`,
		deviceIDs, tunnelNames).Scan(&pairs)

	// Convert subnet pairs to LIKE patterns
	var subnetConditions []string
	var subnetArgs []interface{}
	for _, p := range pairs {
		localPattern := cidrToLikePattern(p.LocalSubnet)
		remotePattern := cidrToLikePattern(p.RemoteSubnet)
		if localPattern == "" || remotePattern == "" {
			continue
		}
		// Bidirectional: src in local AND dst in remote, OR vice versa.
		// AUDIT-148: the `ESCAPE '\'` clause makes the LIKE evaluator
		// treat `\%` and `\_` as literal `%` / `_` rather than wildcards.
		// Today's patterns (built by cidrToLikePattern) never contain
		// literal `%` or `_` in user-controlled positions — only an
		// intentional trailing `%` as the "any" wildcard — so this is
		// defense-in-depth. The escape character `\` itself is never
		// emitted by cidrToLikePattern, so no double-escape is needed.
		subnetConditions = append(subnetConditions,
			"(src_addr LIKE ? ESCAPE '\\' AND dst_addr LIKE ? ESCAPE '\\')",
			"(src_addr LIKE ? ESCAPE '\\' AND dst_addr LIKE ? ESCAPE '\\')")
		subnetArgs = append(subnetArgs, localPattern, remotePattern, remotePattern, localPattern)
	}

	result := &ConnectionFlowResult{}

	var newBase func() *gorm.DB

	if len(subnetConditions) > 0 {
		// Use subnet-based filtering
		subnetWhere := strings.Join(subnetConditions, " OR ")
		newBase = func() *gorm.DB {
			return d.db.Model(&models.FlowSample{}).
				Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
				Where(subnetWhere, subnetArgs...)
		}
	} else {
		// --- Strategy 2 (fallback): Interface index matching with Phase1Names ---
		// Collect Phase1Names alongside tunnel names for better interface matching
		var phase1Names []string
		d.db.Raw(`SELECT DISTINCT phase1_name FROM vpn_status
			WHERE device_id IN ? AND tunnel_name IN ? AND phase1_name != ''`,
			deviceIDs, tunnelNames).Pluck("phase1_name", &phase1Names)

		allNames := make([]string, 0, len(tunnelNames)+len(phase1Names))
		allNames = append(allNames, tunnelNames...)
		allNames = append(allNames, phase1Names...)

		var tunnelIfIndices []int
		ifIndexSet := make(map[int]bool)
		var ifaces []models.InterfaceStats
		d.db.Raw(fmt.Sprintf("SELECT DISTINCT device_id, %s FROM interface_stats WHERE device_id IN ? AND (name IN ? OR description IN ? OR alias IN ?)", d.dialect.QuoteIdent("index")),
			deviceIDs, allNames, allNames, allNames).Scan(&ifaces)
		for _, iface := range ifaces {
			ifIndexSet[iface.Index] = true
		}
		for idx := range ifIndexSet {
			tunnelIfIndices = append(tunnelIfIndices, idx)
		}
		if len(tunnelIfIndices) == 0 {
			return &ConnectionFlowResult{}, nil
		}

		newBase = func() *gorm.DB {
			return d.db.Model(&models.FlowSample{}).
				Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
				Where("input_if_index IN ? OR output_if_index IN ?", tunnelIfIndices, tunnelIfIndices)
		}
	}

	// Total counts from raw samples
	newBase().Count(&result.TotalFlows)
	var totalBytes struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(bytes),0) as sum").Scan(&totalBytes)
	result.TotalBytes = totalBytes.Sum
	var totalPackets struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(packets),0) as sum").Scan(&totalPackets)
	result.TotalPackets = totalPackets.Sum

	// Supplement with rollup data for historical periods (subnet strategy only)
	if hours > 1 && len(subnetConditions) > 0 {
		rollupInterval := "5m"
		if hours > 48 {
			rollupInterval = "1h"
		}
		if hours > 720 {
			rollupInterval = "1d"
		}
		subnetWhere := strings.Join(subnetConditions, " OR ")
		rollupBase := func() *gorm.DB {
			return d.db.Model(&models.FlowRollup{}).
				Where("device_id IN ? AND timestamp > ? AND interval_type = ?", deviceIDs, cutoff, rollupInterval).
				Where(subnetWhere, subnetArgs...)
		}
		var rollupAgg struct {
			Flows int64
			Bytes uint64
			Pkts  uint64
		}
		rollupBase().Select("COALESCE(SUM(flow_count),0) as flows, COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as pkts").Scan(&rollupAgg)
		result.TotalFlows += rollupAgg.Flows
		result.TotalBytes += rollupAgg.Bytes
		result.TotalPackets += rollupAgg.Pkts
	}

	// Protocol distribution
	var protocols []struct {
		Protocol uint8
		Count    int64
	}
	newBase().Select("protocol, COUNT(*) as count").Group("protocol").Order("count DESC").Limit(10).Scan(&protocols)
	for _, p := range protocols {
		result.ByProtocol = append(result.ByProtocol, KeyCount{Key: protoName(p.Protocol), Count: p.Count})
	}

	// Top sources / destinations by bytes
	result.TopSources = topAddrsByBytes(newBase, "src_addr", 10)
	result.TopDests = topAddrsByBytes(newBase, "dst_addr", 10)

	// Top conversations
	var convos []struct {
		SrcAddr  string
		DstAddr  string
		SrcPort  uint16
		DstPort  uint16
		Protocol uint8
		Bytes    uint64
		Packets  uint64
	}
	newBase().Select("src_addr, dst_addr, src_port, dst_port, protocol, SUM(bytes) as bytes, SUM(packets) as packets").
		Group("src_addr, dst_addr, src_port, dst_port, protocol").Order("bytes DESC").Limit(10).Scan(&convos)
	for _, c := range convos {
		result.TopConversations = append(result.TopConversations, FlowConversation{
			SrcAddr: c.SrcAddr, DstAddr: c.DstAddr,
			SrcPort: c.SrcPort, DstPort: c.DstPort,
			Protocol: protoName(c.Protocol), Bytes: c.Bytes, Packets: c.Packets,
		})
	}

	// Bytes over time
	var timeSeries []struct {
		Bucket string `json:"bucket"`
		Total  int64  `json:"total"`
	}
	newBase().Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, SUM(bytes) as total").
		Group("bucket").Order("bucket ASC").Scan(&timeSeries)
	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
}

// GetAlertsByDeviceAndHours returns alerts for a specific device within the given hours.
func (d *Database) GetAlertsByDeviceAndHours(deviceID uint, hours int) ([]models.Alert, error) {
	var alerts []models.Alert
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	err := d.db.Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Order("timestamp DESC").Find(&alerts).Error
	return alerts, err
}

// InterfaceTrafficSummary holds aggregated traffic for an interface.
type InterfaceTrafficSummary struct {
	Name       string  `json:"name"`
	Index      int     `json:"index"`
	TotalIn    float64 `json:"total_in"`
	TotalOut   float64 `json:"total_out"`
	TotalBytes float64 `json:"total_bytes"`
}

// GetTopInterfacesByTraffic returns the top N interfaces by total bytes for a device.
func (d *Database) GetTopInterfacesByTraffic(deviceID uint, hours int, limit int) ([]InterfaceTrafficSummary, error) {
	var results []InterfaceTrafficSummary
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	quotedIndex := d.dialect.QuoteIdent("index")
	err := d.db.Model(&models.InterfaceStats{}).
		Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
		Select(fmt.Sprintf("name, %s as %s, SUM(in_bytes) as total_in, SUM(out_bytes) as total_out, SUM(in_bytes)+SUM(out_bytes) as total_bytes",
			quotedIndex, quotedIndex)).
		Group(fmt.Sprintf("name, %s", quotedIndex)).
		Order("total_bytes DESC").
		Limit(limit).
		Scan(&results).Error
	return results, err
}

// GetDevicePollCount returns the number of system_status rows for a device since the given time.
func (d *Database) GetDevicePollCount(deviceID uint, since time.Time) (int64, error) {
	var count int64
	err := d.db.Model(&models.SystemStatus{}).
		Where("device_id = ? AND timestamp > ?", deviceID, since).
		Count(&count).Error
	return count, err
}

// GetDeviceFirstPoll returns the earliest timestamp from system_status for a device.
func (d *Database) GetDeviceFirstPoll(deviceID uint) (time.Time, error) {
	var result struct {
		MinTS *time.Time
	}
	err := d.db.Model(&models.SystemStatus{}).
		Where("device_id = ?", deviceID).
		Select("MIN(timestamp) as min_ts").
		Scan(&result).Error
	if err != nil {
		return time.Time{}, err
	}
	if result.MinTS == nil {
		return time.Time{}, nil
	}
	return *result.MinTS, nil
}

// --- Alert Policy CRUD ---

func (d *Database) EnsureDefaultPolicy() {
	var policy models.AlertPolicy
	d.db.Where("is_default = ?", true).Attrs(models.AlertPolicy{
		Name:            "Default",
		Description:     "Default alert policy — all notifications use global settings",
		IsDefault:       true,
		CooldownMinutes: 5,
	}).FirstOrCreate(&policy)
}

func (d *Database) GetAlertPolicies() ([]models.AlertPolicy, error) {
	var policies []models.AlertPolicy
	err := d.db.Preload("Rules").Order("is_default DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (d *Database) GetAlertPolicy(id uint) (*models.AlertPolicy, error) {
	var policy models.AlertPolicy
	err := d.db.Preload("Rules").First(&policy, id).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (d *Database) GetDefaultAlertPolicy() (*models.AlertPolicy, error) {
	var policy models.AlertPolicy
	err := d.db.Preload("Rules").Where("is_default = ?", true).First(&policy).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (d *Database) CreateAlertPolicy(policy *models.AlertPolicy) error {
	return d.db.Create(policy).Error
}

func (d *Database) UpdateAlertPolicy(policy *models.AlertPolicy) error {
	return d.db.Save(policy).Error
}

func (d *Database) DeleteAlertPolicy(id uint) error {
	// Prevent deleting default policy
	var policy models.AlertPolicy
	if err := d.db.First(&policy, id).Error; err != nil {
		return err
	}
	if policy.IsDefault {
		return fmt.Errorf("cannot delete the default alert policy")
	}
	// Delete associated rules first
	d.db.Where("policy_id = ?", id).Delete(&models.AlertRule{})
	return d.db.Delete(&models.AlertPolicy{}, id).Error
}

func (d *Database) BatchUpsertAlertRules(policyID uint, rules []models.AlertRule) error {
	// Delete existing rules for this policy
	if err := d.db.Where("policy_id = ?", policyID).Delete(&models.AlertRule{}).Error; err != nil {
		return err
	}
	// Insert new rules
	for i := range rules {
		rules[i].ID = 0
		rules[i].PolicyID = policyID
	}
	if len(rules) > 0 {
		return d.db.Create(&rules).Error
	}
	return nil
}

// --- Device Alert Config CRUD ---

func (d *Database) GetDeviceAlertConfig(deviceID uint) (*models.DeviceAlertConfig, error) {
	var cfg models.DeviceAlertConfig
	err := d.db.Where("device_id = ?", deviceID).First(&cfg).Error
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (d *Database) UpsertDeviceAlertConfig(cfg *models.DeviceAlertConfig) error {
	var existing models.DeviceAlertConfig
	err := d.db.Where("device_id = ?", cfg.DeviceID).First(&existing).Error
	if err == nil {
		cfg.ID = existing.ID
		return d.db.Save(cfg).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return d.db.Create(cfg).Error
}

func (d *Database) DeleteDeviceAlertConfig(deviceID uint) error {
	return d.db.Where("device_id = ?", deviceID).Delete(&models.DeviceAlertConfig{}).Error
}

func (d *Database) GetAllDeviceAlertConfigs() ([]models.DeviceAlertConfig, error) {
	var configs []models.DeviceAlertConfig
	err := d.db.Find(&configs).Error
	return configs, err
}

// --- Site Alert Config CRUD ---

func (d *Database) GetSiteAlertConfig(siteID uint) (*models.SiteAlertConfig, error) {
	var cfg models.SiteAlertConfig
	err := d.db.Where("site_id = ?", siteID).First(&cfg).Error
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (d *Database) UpsertSiteAlertConfig(cfg *models.SiteAlertConfig) error {
	var existing models.SiteAlertConfig
	err := d.db.Where("site_id = ?", cfg.SiteID).First(&existing).Error
	if err == nil {
		cfg.ID = existing.ID
		return d.db.Save(cfg).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return d.db.Create(cfg).Error
}

func (d *Database) DeleteSiteAlertConfig(siteID uint) error {
	return d.db.Where("site_id = ?", siteID).Delete(&models.SiteAlertConfig{}).Error
}

func (d *Database) GetAllSiteAlertConfigs() ([]models.SiteAlertConfig, error) {
	var configs []models.SiteAlertConfig
	err := d.db.Find(&configs).Error
	return configs, err
}

// --- Maintenance Window CRUD ---

func (d *Database) GetMaintenanceWindows() ([]models.MaintenanceWindow, error) {
	var windows []models.MaintenanceWindow
	err := d.db.Order("start_time DESC").Find(&windows).Error
	return windows, err
}

func (d *Database) GetActiveMaintenanceWindows() ([]models.MaintenanceWindow, error) {
	var windows []models.MaintenanceWindow
	now := time.Now()
	err := d.db.Where("start_time <= ? AND end_time >= ?", now, now).Find(&windows).Error
	return windows, err
}

func (d *Database) CreateMaintenanceWindow(w *models.MaintenanceWindow) error {
	return d.db.Create(w).Error
}

func (d *Database) UpdateMaintenanceWindow(w *models.MaintenanceWindow) error {
	return d.db.Save(w).Error
}

func (d *Database) DeleteMaintenanceWindow(id uint) error {
	return d.db.Delete(&models.MaintenanceWindow{}, id).Error
}

// --- Enhanced Alert methods ---

func (d *Database) AcknowledgeAlertEnhanced(id uint, notes string) error {
	now := time.Now()
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"acknowledged":    true,
		"acknowledged_at": now,
		"notes":           notes,
	}).Error
}

// SnoozeAlert sets SnoozedUntil to the given timestamp (v0.10.218,
// bundle G2). The handler clamps `until` into a 1h..30d window before
// calling here. Audit fields SnoozedBy / SnoozedReason are recorded for
// post-mortem review.
func (d *Database) SnoozeAlert(id uint, until time.Time, by, reason string) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"snoozed_until":  until,
		"snoozed_by":     by,
		"snoozed_reason": reason,
	}).Error
}

// UnsnoozeAlert clears the snooze window (v0.10.218, bundle G2). Used
// when an operator changes their mind, or programmatically from the
// frontend when a snooze duration has obviously elapsed.
func (d *Database) UnsnoozeAlert(id uint) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"snoozed_until":  nil,
		"snoozed_by":     "",
		"snoozed_reason": "",
	}).Error
}

// AcknowledgeAlertsBulk flips acknowledged=true for all rows whose ID is in ids,
// in a single UPDATE statement. Returns the number of rows actually changed
// (already-acked rows are still in the IN list — the UPDATE just rewrites the
// flag, so RowsAffected reflects the WHERE match count, which may exceed the
// number of *transitions*).
//
// Caller is responsible for capping len(ids); a sensible upper bound (e.g. 500)
// is enforced by the handler so we don't send unbounded SQL parameter lists.
func (d *Database) AcknowledgeAlertsBulk(ids []uint, notes string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	now := time.Now()
	res := d.db.Model(&models.Alert{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"acknowledged":    true,
			"acknowledged_at": now,
			"notes":           notes,
		})
	return res.RowsAffected, res.Error
}

// AlertFilter narrows an alert query for bulk ack-by-filter. Empty / zero
// fields are not added to the WHERE clause. Mirrors the query parameters
// accepted by GetAlerts so the client can ack exactly the rows it sees.
type AlertFilter struct {
	DeviceID     uint   // 0 = any
	AlertType    string // "" = any
	Severity     string // "" = any
	Acknowledged *bool  // nil = any (typically the caller passes false to ack only unacked rows)
}

// AcknowledgeAlertsByFilter flips acknowledged=true for all rows matching the
// filter. Used by the admin UI's "Select all N matching" → "Acknowledge"
// flow when the result set is too large to ship as an ID list. Single
// UPDATE; bounded only by the filter, not by client-side IDs.
//
// Returns RowsAffected. Note that already-acked rows in the match set will
// have their notes rewritten by this call.
func (d *Database) AcknowledgeAlertsByFilter(f AlertFilter, notes string) (int64, error) {
	now := time.Now()
	q := d.db.Model(&models.Alert{})
	if f.DeviceID > 0 {
		q = q.Where("device_id = ?", f.DeviceID)
	}
	if f.AlertType != "" {
		q = q.Where("alert_type = ?", f.AlertType)
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.Acknowledged != nil {
		q = q.Where("acknowledged = ?", *f.Acknowledged)
	}
	res := q.Updates(map[string]interface{}{
		"acknowledged":    true,
		"acknowledged_at": now,
		"notes":           notes,
	})
	return res.RowsAffected, res.Error
}

// SnoozeAlertsBulk sets snoozed_until to `until` (with audit fields
// `by` and `reason`) for every alert whose ID is in `ids`, in a single
// UPDATE. AUDIT-143: the audit complained that bulk-ack had both an
// ID-list form and a filter form, but bulk-snooze only had a single-
// alert form. This brings bulk-snooze to parity.
//
// Caller is responsible for capping len(ids); the handler enforces
// the same 500-row limit that AcknowledgeAlertsBulk uses.
//
// `until` is the snooze-expiry timestamp; the handler clamps the
// `hours` value to [1, 720] before calling here.
func (d *Database) SnoozeAlertsBulk(ids []uint, until time.Time, by, reason string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	res := d.db.Model(&models.Alert{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"snoozed_until":  until,
			"snoozed_by":     by,
			"snoozed_reason": reason,
		})
	return res.RowsAffected, res.Error
}

// SnoozeAlertsByFilter sets snoozed_until on every alert matching
// the filter. AUDIT-143: mirror of AcknowledgeAlertsByFilter for
// the snooze flow. Used by the admin UI's "Select all N matching"
// → "Snooze for 4h" flow.
//
// Same filter semantics as AcknowledgeAlertsByFilter (DeviceID,
// AlertType, Severity, Acknowledged). The Acknowledged filter
// is especially useful here — an operator who wants to snooze
// only the unacked alerts can pass `acknowledged=false` to skip
// already-handled rows.
//
// `until` is the snooze-expiry timestamp; the handler clamps
// the `hours` value to [1, 720] before calling here.
func (d *Database) SnoozeAlertsByFilter(f AlertFilter, until time.Time, by, reason string) (int64, error) {
	q := d.db.Model(&models.Alert{})
	if f.DeviceID > 0 {
		q = q.Where("device_id = ?", f.DeviceID)
	}
	if f.AlertType != "" {
		q = q.Where("alert_type = ?", f.AlertType)
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.Acknowledged != nil {
		q = q.Where("acknowledged = ?", *f.Acknowledged)
	}
	res := q.Updates(map[string]interface{}{
		"snoozed_until":  until,
		"snoozed_by":     by,
		"snoozed_reason": reason,
	})
	return res.RowsAffected, res.Error
}

func (d *Database) UpdateAlertNotes(id uint, notes string) error {
	return d.db.Model(&models.Alert{}).Where("id = ?", id).Update("notes", notes).Error
}

func (d *Database) GetUnacknowledgedAlerts(since time.Time) ([]models.Alert, error) {
	var alerts []models.Alert
	err := d.db.Where("acknowledged = ? AND suppressed = ? AND timestamp > ?", false, false, since).
		Find(&alerts).Error
	return alerts, err
}
