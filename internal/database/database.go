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

	"github.com/jackc/pgx/v5/pgxpool"
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
	// pgxPool is the dedicated *pgxpool.Pool used for high-throughput bulk
	// inserts via the COPY protocol (SaveFlowSamples on the hot path). It is
	// nil on the SQLite test backend (NewDatabaseForTesting) and on any
	// Postgres connection that failed to initialize the pool — both
	// fall back to GORM's per-row Create. PostgreSQL production connects
	// always set this.
	pgxPool *pgxpool.Pool

	// ingest is the syslog ingest meter (syslog_ingest.go). A POINTER on
	// purpose: WithContext shallow-copies the struct for every browser request,
	// so a by-value mutex would fail go vet's copylocks and every copy would
	// carry its own counts. nil-receiver-safe (a Database{} literal is a no-op).
	ingest *syslogIngestMeter

	// M8 encryption key-check verdict, set once by VerifyEncryptionKey at
	// startup and read by EncryptionVerified (health/readiness, daemon
	// fail-fast). encKeyBroken=true means the configured key chain provably
	// cannot decrypt this database's {enc} secrets. Zero value (test harness,
	// check not run) reports verified.
	encKeyBroken bool
	encKeyDetail string
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
	// An empty value must be quoted: a bare `password=` mid-DSN makes the
	// keyword-value parser consume the NEXT `key=value` token as the password
	// and silently drop that key.
	if s == "" {
		return "''"
	}
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

	// AUDIT D4: pin the session time zone to UTC on every pooled connection.
	// Chart bucketing runs date_trunc/to_char server-side and parseBucketToMillis
	// (charts.go) parses the zone-less result AS UTC; without this the x-axis
	// silently shifts by the server's local offset if the PG session TZ isn't UTC.
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s TimeZone=UTC",
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

	// Initialize the pgx pool alongside GORM. pgxpool gives us direct access
	// to the Postgres COPY protocol for bulk inserts (SaveFlowSamples on the
	// sFlow hot path). GORM's own postgres driver uses lib/pq under the hood
	// and doesn't expose CopyFrom, so we maintain a separate pool with the
	// same connection settings. Pool sizing tracks the GORM pool: MaxOpenConns
	// (default 25) with a small floor of 2 so even a 1-conn GORM pool gets
	// parallel COPY capacity.
	if pgxPool, pgxErr := openPGXPool(cfg, maxOpen); pgxErr != nil {
		log.Printf("WARNING: failed to open pgxpool for COPY inserts (%v); SaveFlowSamples will fall back to GORM batch insert (~2x slower on hot path, measured — see docs/OPERATIONS.md)", pgxErr)
	} else {
		d.pgxPool = pgxPool
		log.Printf("Database: pgxpool opened for bulk COPY inserts")
	}

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
	d.ingest = newSyslogIngestMeter(time.Now)

	return d, nil
}

// openPGXPool opens a dedicated *pgxpool.Pool alongside the GORM connection
// for use by SaveFlowSamples' COPY-protocol bulk insert (the audit's
// sFlow-bulk-insert-pgx-copyfrom requirement). The DSN mirrors the GORM one
// (host/port/user/password/dbname/sslmode/statement_timeout). Pool sizing
// tracks the GORM pool's MaxOpenConns with a floor of 2 so even a 1-conn
// GORM pool gets parallel COPY capacity.
//
// Returns an error (and a nil pool) if the connection fails — the caller
// logs a warning and falls back to GORM Create. A failed pgx pool must
// never prevent the GORM connection from succeeding; the GORM path is the
// historical baseline and the pgx path is a performance optimization.
func openPGXPool(cfg *config.Config, maxOpen int) (*pgxpool.Pool, error) {
	pgxCfg, err := pgxpool.ParseConfig(buildPGXDSN(cfg))
	if err != nil {
		return nil, fmt.Errorf("pgxpool parse dsn: %w", err)
	}
	// AUDIT-037: per-connection statement timeout, matching GORM. pgx's
	// config field is in milliseconds.
	if cfg.Database.StatementTimeout > 0 {
		pgxCfg.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", cfg.Database.StatementTimeout.Milliseconds())
	}
	// Pool sizing: match the GORM pool. Floor of 2 so even a 1-conn GORM
	// pool (test lane) gets parallel COPY capacity. Cap at 25 to match the
	// legacy default.
	if maxOpen < 2 {
		maxOpen = 2
	}
	if maxOpen > 25 {
		maxOpen = 25
	}
	pgxCfg.MaxConns = int32(maxOpen)
	pgxCfg.MinConns = 1
	pgxCfg.MaxConnLifetime = 5 * time.Minute
	pgxCfg.MaxConnIdleTime = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), pgxCfg)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.NewWithConfig: %w", err)
	}
	// Verify the pool with a Ping. A connection that opens but can't
	// authenticate is worse than no pool at all (silent fallback to slow path).
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgxpool.Ping: %w", err)
	}
	return pool, nil
}

// buildPGXDSN assembles a libpq key=value DSN from the cfg fields — the SAME
// form (and the same pgQuote escaping) the GORM connection in Connect() uses,
// so an address that works for GORM always works for pgx. The previous
// postgres:// URL form broke on unix-socket hosts: the single-container prod
// deployment sets DB_HOST=/var/run/postgresql, which the URL parser mangled
// into database "run/postgresql:5432/firewall_mon" — the pool failed its ping
// and SaveFlowSamples silently ran on the ~2x slower GORM fallback since the
// pool was introduced.
func buildPGXDSN(cfg *config.Config) string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port,
		pgQuote(cfg.Database.User), pgQuote(cfg.Database.Password),
		pgQuote(cfg.Database.Name), cfg.Database.SSLMode)
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

	// M8: verify the configured ENCRYPTION_KEY can still decrypt this
	// database's secrets, and cache the verdict (EncryptionVerified). Run in
	// EVERY process — before the startup-setup lock below, which only one wins
	// — because each binary reads secrets and must know the key is good. This
	// only logs/records; poller & trap-receiver fail-fast on the verdict, the
	// API surfaces it on /health. The canary write (first run) is idempotent.
	if err := d.VerifyEncryptionKey(); err != nil {
		log.Printf("Encryption key verification: %v", err)
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

	// Ensure the Default event rule profile exists (v48) BEFORE the rule
	// seeder so seeds get stamped with its ID (migration v48 also creates it
	// on upgrades; this covers fresh installs and is idempotent).
	d.EnsureDefaultEventProfile()

	// Seed the default event rules once (v35): the legacy syslog sev0-2 behavior
	// now ships as rules, so this must run before syslog ingestion serves.
	d.EnsureDefaultRules()

	// Backfill empty vendor → fortigate (the in-code default per
	// internal/models/models.go) and audit the fleet's vendor distribution.
	// Any device whose vendor lacks a rich normalizer in internal/configdiff
	// will silently false-alert on every config backup, because byte-equality
	// hashing makes random-IV ENC ciphertext look like a real change. The
	// audit log makes that visible without mutating the data.
	d.auditDeviceVendors()

	// Repair stored normalized checksums after a normalizer change, so adding or
	// tightening one does not fire a phantom CONFIG_CHANGE per device on the
	// first backup after upgrade. Idempotent, and gated by the same startup lock
	// acquired above so exactly one process does the work.
	d.backfillNormalizedChecksums()

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
// poller-process cron ticks (runMonitoringCycle, rollup, cleanup) so two
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
// Pair every call with `defer release()`. If the caller crashes between
// acquire and release, the lock is dropped at session close (5 min
// `SetConnMaxLifetime` boundary or sooner) — a minor availability hit
// (one cron tick skipped) but not stuck forever.
//
// H9 of the 2026-07-01 audit: advisory locks are SESSION-scoped, so the
// acquire and release MUST run on the same backend. The pre-fix code
// issued both through gorm's connection pool, so during a busy poll
// cycle the unlock routinely landed on a DIFFERENT connection —
// pg_advisory_unlock on a non-owning session returns false with only a
// WARNING (no SQL error), so the failed release was invisible, the lock
// leaked on an idle pooled conn for up to ConnMaxLifetime (5 min), and
// the next tick's probe concluded "another poller holds the work lock"
// and skipped the ENTIRE cycle — in a single-poller deployment. Now the
// lock is taken on a dedicated PINNED *sql.Conn (the pattern
// AcquireAPISingletonLock / acquireMigrationLock already use) and the
// returned release func unlocks on that same conn, then closes it.
//
// SQLite (tests) returns acquired=true + a no-op release — single-process there.
func (d *Database) TryAcquirePollerWorkLock() (release func(), acquired bool) {
	if !d.dialect.IsPostgres() {
		return func() {}, true
	}
	sqlDB, err := d.db.DB()
	if err != nil {
		// Probe failure: bias toward DOING the work over skipping it.
		// A duplicate poll cycle is recoverable; a missed one is not.
		log.Printf("Poller work lock probe failed (%v); proceeding with work anyway.", err)
		return func() {}, true
	}
	ctx := context.Background()
	conn, err := sqlDB.Conn(ctx) // pins one backend out of the pool
	if err != nil {
		log.Printf("Poller work lock probe failed (%v); proceeding with work anyway.", err)
		return func() {}, true
	}
	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", pollerWorkLockKey).Scan(&got); err != nil {
		conn.Close()
		log.Printf("Poller work lock probe failed (%v); proceeding with work anyway.", err)
		return func() {}, true
	}
	if !got {
		conn.Close() // held by another session — don't leak the pinned conn
		return func() {}, false
	}
	return func() {
		var released bool
		if err := conn.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", pollerWorkLockKey).Scan(&released); err != nil {
			log.Printf("Poller work lock release failed (%v); will auto-release on connection close.", err)
		} else if !released {
			// Cannot happen on the pinned conn, but pg_advisory_unlock
			// reports non-ownership via its return value (not an error) —
			// surface it instead of silently ignoring it like the pre-fix code.
			log.Printf("Poller work lock release returned false (lock not held by this session)")
		}
		conn.Close() // returns the (now-unlocked) connection to the pool
	}, true
}

// apiSingletonLockKey is the advisory-lock key the API process holds for its
// ENTIRE lifetime to enforce singleton operation (AUDIT-040). cmd/api keeps four
// state stores in process memory — the IRC bots (one nick per server), the
// login-lockout counters, the rate-limit buckets, and the uptime baseline — so a
// second cmd/api against the same DB double-runs them (nick collision, ~2× the
// lockout/rate-limit thresholds, divergent uptime). Distinct from
// startupMigrationLockKey / pollerWorkLockKey / migrationLockKey. Value is the
// ASCII of "FWMNAPIS" so it's visible in pg_locks.
const apiSingletonLockKey int64 = 0x46574d4e41504953

// AcquireAPISingletonLock takes a NON-blocking, session-scoped Postgres advisory
// lock on a dedicated PINNED connection (so the matching unlock runs on the SAME
// backend — gorm's pool would otherwise route the unlock to a different
// connection, making it a no-op; same pattern as acquireMigrationLock). Unlike
// the migration lock this is a LIFETIME hold: the API keeps it until graceful
// shutdown calls the returned release func.
//
//   - acquired=true + a real release func (unlock + close the pinned conn) when
//     this process owns the singleton lock (it is the primary).
//   - acquired=false + a no-op release when another session already holds it
//     (the pinned conn is closed before returning so it isn't leaked).
//   - err only on a connection/probe infrastructure failure.
//
// AUDIT-183: release is ALWAYS a callable func, on every path including
// errors. main.go registers `defer releaseSingleton()` with whatever this
// returns, and its lockErr branch deliberately proceeds as primary — a nil
// release there panicked at graceful shutdown after any transient DB error
// during the startup probe.
//
// SQLite (tests / single-process) returns acquired=true + a no-op release — the
// guard is inert because there is exactly one process. A second call on the same
// *Database pins a DIFFERENT pooled connection (a different PG session), so it
// genuinely contends — that's how the integration test simulates two processes.
func (d *Database) AcquireAPISingletonLock() (release func(), acquired bool, err error) {
	if !d.dialect.IsPostgres() {
		return func() {}, true, nil
	}
	sqlDB, err := d.db.DB()
	if err != nil {
		return func() {}, false, err
	}
	ctx := context.Background()
	conn, err := sqlDB.Conn(ctx) // pins one backend out of the pool
	if err != nil {
		return func() {}, false, err
	}
	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", apiSingletonLockKey).Scan(&got); err != nil {
		conn.Close()
		return func() {}, false, err
	}
	if !got {
		conn.Close() // held by another session — don't leak the pinned conn
		return func() {}, false, nil
	}
	return func() {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", apiSingletonLockKey); err != nil {
			log.Printf("api: singleton advisory unlock failed (%v); it releases on connection close", err)
		}
		conn.Close() // returns the (now-unlocked) connection to the pool
	}, true, nil
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
	// Land the ingest meter's unflushed buckets (≤ 60 s of counts) while the
	// connection is still open. Reached only on graceful shutdown (deferred
	// Close); a log.Fatalf exit loses that window, which is acceptable for a
	// rate estimate.
	if err := d.flushSyslogIngest(true); err != nil {
		log.Printf("syslog ingest meter: final flush failed: %v", err)
	}

	// Close the pgx pool first so any in-flight COPY is drained before
	// the underlying socket closes.
	if d.pgxPool != nil {
		d.pgxPool.Close()
		d.pgxPool = nil
	}

	sqlDB, err := d.db.DB()
	if err != nil {
		return fmt.Errorf("close database: get underlying sql.DB: %w", err)
	}
	return sqlDB.Close()
}
