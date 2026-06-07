// Package database is the persistence layer: a thin wrapper over GORM that
// owns the DB connection, schema migration, and all model CRUD/query methods.
// AUDIT-072 split the original 4,800-line database.go into cohesive per-domain
// files (devices.go, alerts.go, flows.go, …); this file keeps the core
// lifecycle — connection setup, advisory locks, and Close.
package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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

// WithContext returns a shallow copy of the Database whose underlying *gorm.DB
// is bound to ctx, so every query/transaction run through the returned handle
// is cancelled when ctx is (AUDIT-032/079). Browser-facing handlers call
// `db := h.db.WithContext(c.Request.Context())` once at the top, then use `db`
// — a client disconnect then cancels the in-flight query and frees the pooled
// connection instead of leaving it checked out (the dashboard-polling
// pool-exhaustion outage). gorm's WithContext yields a reusable session, so the
// single copy safely serves many queries and transactions in one request.
//
// The copy shares the encryption keychain, dialect, and the async batchers (by
// pointer) — the batchers' flush closures captured the original *Database, so
// batched writes always run on the durable background context regardless of any
// per-request copy. Daemons (poller/trap) and probe-ingestion handlers keep
// using the root Database so their writes are never cancelled by a client.
func (d *Database) WithContext(ctx context.Context) *Database {
	cp := *d
	cp.db = d.db.WithContext(ctx)
	return &cp
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

// Connect opens the database, configures the connection pool and encryption
// keychain, and wires the async batchers — but does NOT run migrations or the
// startup setup. The `migrate` / `migrate-status` subcommands use this to get a
// live handle without starting a server or auto-applying anything beyond what
// they explicitly invoke. NewDatabase is the normal daemon entry point.
func Connect(cfg *config.Config) (*Database, error) {
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

	return d, nil
}

// NewDatabase connects, applies any pending migrations (AUDIT-044 versioned
// runner — leader-gated, idempotent baseline), then runs the idempotent
// post-migration startup setup. This is the entry point for the long-running
// daemons (api/poller/trap); they keep auto-applying migrations on startup so a
// forgotten explicit `migrate` step still self-heals.
func NewDatabase(cfg *config.Config) (*Database, error) {
	d, err := Connect(cfg)
	if err != nil {
		return nil, err
	}

	if err := d.RunMigrations(); err != nil {
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
		return fmt.Errorf("close database: get underlying sql.DB: %w", err)
	}
	return sqlDB.Close()
}
