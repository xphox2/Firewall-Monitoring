package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/models"
)

// AppVersion is the build version stamped into each schema_migrations row.
// Set by the binary's main (cmd/api) from its ServerVersion const; empty for
// the poller/trap daemons and tests, which is harmless.
var AppVersion string

// migrationLockKey is the Postgres advisory-lock key the runner holds while
// applying migrations, so the three racing processes (api/poller/trap) and any
// explicit `migrate` subcommand serialize. It MUST differ from
// startupMigrationLockKey (a never-released try-lock — a blocking acquire on the
// same key would deadlock) and pollerWorkLockKey. "FWMNMIGR".
const migrationLockKey int64 = 0x46574d4e4d494752

// createSchemaMigrationsDDL creates the bookkeeping table. Written as raw DDL
// (valid on both Postgres and SQLite) so it exists before the runner queries
// applied versions — it must NOT depend on any migration having run.
const createSchemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version BIGINT PRIMARY KEY,
	name TEXT,
	app_version TEXT,
	applied_at TIMESTAMP
)`

// migration is one ordered, recorded schema change. run MUST be idempotent: the
// runner skips a migration once its row is recorded, but a crash between run()
// and the INSERT means run() can re-execute, so it has to tolerate re-running.
type migration struct {
	version int
	name    string
	run     func(d *Database) error
}

// registeredMigrations is the append-only, strictly-increasing list of
// migrations. RULES: never edit or renumber a released entry; append the next
// integer; keep run() idempotent (prefer AutoMigrate / AddColumn /
// CREATE ... IF NOT EXISTS).
//
// v1 "baseline" reuses the proven AutoMigrate+shims (migrateBaseline). It is
// idempotent, so on an existing deployment it no-ops and is simply recorded;
// on a fresh install it builds the whole schema.
var registeredMigrations = []migration{
	{version: 1, name: "baseline", run: (*Database).migrateBaseline},
	{version: 2, name: "partition_high_volume", run: (*Database).migratePartitionHighVolume},
	{version: 3, name: "unify_ping_stats_by_device_target", run: (*Database).migrateUnifyPingStats},
	{version: 4, name: "probe_decommissioned_at", run: (*Database).migrateProbeDecommissionedAt},
	{version: 5, name: "config_revision_attribution", run: (*Database).migrateConfigRevisionAttribution},
	{version: 6, name: "device_ssh_host_key", run: (*Database).migrateDeviceSSHHostKey},
	{version: 7, name: "flow_samples_sampling_rate_scale", run: (*Database).migrateFlowSamplesSamplingRateScale},
	{version: 8, name: "flow_agent_drops_table", run: (*Database).migrateFlowAgentDropsTable},
	{version: 9, name: "flow_samples_widen_int_columns", run: (*Database).migrateFlowSamplesWidenIntColumns},
	{version: 10, name: "flow_samples_add_drops_column", run: (*Database).migrateFlowSamplesAddDropsColumn},
	{version: 11, name: "flow_classification_columns", run: (*Database).migrateFlowClassificationColumns},
	{version: 12, name: "flow_geoip_columns", run: (*Database).migrateFlowGeoIPColumns},
	{version: 13, name: "flow_detections_table", run: (*Database).migrateFlowDetectionsTable},
	{version: 14, name: "threat_intel_and_flow_threat_flag", run: (*Database).migrateThreatIntelAndFlowThreatFlag},
	{version: 15, name: "flow_bgp_columns", run: (*Database).migrateFlowBGPColumns},
	{version: 16, name: "flow_if_counters_table", run: (*Database).migrateFlowIfCountersTable},
	{version: 17, name: "threat_intel_cidr_column_rename", run: (*Database).migrateThreatIntelCIDRColumnRename},
	{version: 18, name: "flow_if_counters_add_direction", run: (*Database).migrateFlowIfCountersAddDirection},
	{version: 19, name: "admin_must_change_password", run: (*Database).migrateAdminMustChangePassword},
	{version: 20, name: "admin_roles", run: (*Database).migrateAdminRoles},
	{version: 21, name: "api_tokens", run: (*Database).migrateAPITokens},
	{version: 22, name: "admin_totp", run: (*Database).migrateAdminTOTP},
	{version: 23, name: "alert_rule_clear_threshold", run: (*Database).migrateAlertRuleClearThreshold},
	{version: 24, name: "alert_rule_zscore_mode", run: (*Database).migrateAlertRuleZScoreMode},
	{version: 25, name: "alert_policy_incident_channels", run: (*Database).migrateAlertPolicyIncidentChannels},
	{version: 26, name: "alert_policy_escalation_steps", run: (*Database).migrateAlertPolicyEscalationSteps},
	{version: 27, name: "incidents", run: (*Database).migrateIncidents},
	{version: 28, name: "admin_profile", run: (*Database).migrateAdminProfile},
	{version: 29, name: "flow_ingest_columns", run: (*Database).migrateFlowIngestColumns},
	{version: 30, name: "flow_rollup_firewall_event", run: (*Database).migrateFlowRollupFirewallEvent},
	{version: 31, name: "threat_feed_status_table", run: (*Database).migrateThreatFeedStatusTable},
	{version: 32, name: "alert_flow_enrichment", run: (*Database).migrateAlertFlowEnrichment},
	{version: 33, name: "feed_toggle_and_flow_suppress", run: (*Database).migrateFeedToggleAndFlowSuppress},
	{version: 34, name: "flow_scope_local", run: (*Database).migrateFlowScopeLocal},
}

// RunMigrations applies every registered migration not yet recorded in
// schema_migrations, in order, recording and logging each (AUDIT-044). It
// serializes across processes via a blocking advisory lock and is safe to run
// concurrently with a service's startup auto-migrate (same lock, idempotent).
func (d *Database) RunMigrations() error {
	return d.runMigrationList(registeredMigrations)
}

// runMigrationList is the testable core of RunMigrations (a test injects a
// custom list).
func (d *Database) runMigrationList(list []migration) error {
	unlock, err := d.acquireMigrationLock()
	if err != nil {
		return fmt.Errorf("migrate: acquire lock: %w", err)
	}
	defer unlock()

	if err := d.db.Exec(createSchemaMigrationsDDL).Error; err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	var rows []models.SchemaMigration
	if err := d.db.Find(&rows).Error; err != nil {
		return fmt.Errorf("migrate: load applied versions: %w", err)
	}
	for _, r := range rows {
		applied[r.Version] = true
	}

	for _, m := range list {
		if applied[m.version] {
			continue
		}
		log.Printf("migrate: applying v%d %q", m.version, m.name)
		if err := m.run(d); err != nil {
			return fmt.Errorf("migrate: v%d %q failed: %w", m.version, m.name, err)
		}
		rec := models.SchemaMigration{
			Version:    m.version,
			Name:       m.name,
			AppVersion: AppVersion,
			AppliedAt:  time.Now().UTC(),
		}
		if err := d.db.Create(&rec).Error; err != nil {
			return fmt.Errorf("migrate: record v%d: %w", m.version, err)
		}
		log.Printf("migrate: applied v%d %q", m.version, m.name)
	}
	return nil
}

// acquireMigrationLock takes a blocking Postgres advisory lock on a dedicated
// pooled connection (so the matching unlock runs on the SAME backend — gorm's
// pool would otherwise route the unlock to a different connection, making it a
// no-op). Returns a release func. On SQLite (tests) it's a no-op.
func (d *Database) acquireMigrationLock() (func(), error) {
	if !d.dialect.IsPostgres() {
		return func() {}, nil
	}
	sqlDB, err := d.db.DB()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	// AUDIT-037 sets a per-connection statement_timeout (default 30s) on every
	// pooled connection. pg_advisory_lock() blocks until a concurrent migrator
	// releases the lock, which can exceed 30s when another process is mid-way
	// through a heavy migration on a large DB — the timeout then cancels the
	// wait (SQLSTATE 57014) and the starting process fails to boot ("migrate:
	// acquire lock: canceling statement due to statement timeout"), crash-looping
	// the API/trap-receiver while the poller holds the lock. Lift the timeout on
	// THIS dedicated lock connection so the blocking acquire can wait as long as
	// needed. Only this connection is affected; the migrations themselves run on
	// other pooled connections and keep their timeout.
	if _, err := conn.ExecContext(ctx, "SET statement_timeout = 0"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("lift statement_timeout on migration-lock connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		conn.Close()
		return nil, err
	}
	return func() {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey); err != nil {
			log.Printf("migrate: advisory unlock failed (%v); it releases on connection close", err)
		}
		conn.Close() // returns the connection to the pool (lock already released)
	}, nil
}

// PrintMigrationStatus logs the applied migrations and any pending registered
// versions. Used by the `migrate` and `migrate-status` subcommands. It does not
// create the table or apply anything; if schema_migrations is absent it reports
// nothing applied.
func (d *Database) PrintMigrationStatus() {
	var rows []models.SchemaMigration
	if err := d.db.Find(&rows).Error; err != nil {
		log.Printf("migrate-status: schema_migrations not readable (no migrations applied yet?): %v", err)
	}
	applied := map[int]bool{}
	for _, r := range rows {
		applied[r.Version] = true
		log.Printf("migrate-status: applied  v%d %q (app %s, at %s)", r.Version, r.Name, r.AppVersion, r.AppliedAt.Format(time.RFC3339))
	}
	pending := 0
	for _, m := range registeredMigrations {
		if !applied[m.version] {
			pending++
			log.Printf("migrate-status: PENDING  v%d %q", m.version, m.name)
		}
	}
	if pending == 0 {
		log.Printf("migrate-status: up to date (%d migration(s) applied)", len(rows))
	}
}
