//go:build !production

package database

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"firewall-mon/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testModels is every model the SQLite test harness AutoMigrates. A package
// var (not a function local) so the device-purge coverage test can reflect
// over it alongside baselineModels — a device-keyed table missing here would
// make the purge test fail with "no such table" instead of a real gap.
var testModels = []interface{}{
	&models.Probe{},
	&models.ProbeApproval{},
	&models.ProbeHeartbeat{},
	&models.ProbeCommand{},
	&models.IPSecTunnel{},
	&models.Device{},
	// Baseline has device_tunnels; the harness lacked it until the purge job
	// needed every device-keyed table present.
	&models.DeviceTunnel{},
	&models.Site{},
	&models.SystemStatus{},
	&models.ServerMetric{},
	&models.InterfaceStats{},
	&models.VPNStatus{},
	&models.HAStatus{},
	// LC-20: the remaining per-poll status tables, now covered by
	// CleanupOldData's entries slice (vpn_status/ha_status are above).
	&models.SecurityStats{},
	&models.SDWANHealth{},
	&models.LicenseInfo{},
	&models.HardwareSensor{},
	&models.ProcessorStats{},
	&models.DiskUsage{},
	&models.LoadAverage{},
	&models.TopologyEntry{},
	&models.TopologyNeighbor{},
	&models.DeviceConfigRevision{},
	&models.TrapEvent{},
	&models.SyslogMessage{},
	&models.FlowSample{},
	&models.FlowRollup{},
	&models.FlowSummary{},
	&models.FlowSummaryTop{},
	&models.FlowSummaryBucket{},
	&models.AgentDrops{},
	&models.FlowDetection{},
	&models.ThreatIntel{},
	&models.ThreatFeedStatus{},
	&models.FlowInterfaceCounter{},
	&models.DeniedEvent{},
	&models.Alert{},
	&models.AlertPolicy{},
	&models.AlertRule{},
	&models.DeviceAlertConfig{},
	&models.SiteAlertConfig{},
	&models.MaintenanceWindow{},
	&models.PingResult{},
	&models.PingStats{},
	// AUDIT-029: the four tables that the cleanup regression
	// tests exercise. They were previously missing from
	// this list, which made the test discover the missing
	// AutoMigrate as a "no such table" failure rather than
	// the actual audit-029 row-preservation failure.
	&models.InterfaceErrors{},
	&models.ProcessStats{},
	&models.InterfaceAddress{},
	&models.DeviceConnection{},
	&models.LoginAttempt{},
	&models.AuditLog{},
	&models.IRCMessageLog{},
	&models.SyslogSummary{},
	&models.UptimeRecord{},
	&models.ProcessedBatch{},
	&models.SystemSetting{},
	&models.Admin{},
	&models.ApiToken{},
	&models.AdminRecoveryCode{},
	// v70: passkeys.
	&models.WebAuthnCredential{},
	// v83: TOTP replay guard.
	&models.UsedTOTPCode{},
	&models.Incident{},
	// v0.11.46: flow-source silencing table.
	&models.FlowSourceSuppression{},
	// Event-rule engine (v35+): rules.
	&models.EventRule{},
	// Event Rule Profiles (v48): profile + sparse toggle matrix.
	&models.EventRuleProfile{},
	&models.EventRuleProfileToggle{},
	// v59: syslog ingest meter buckets.
	&models.SyslogIngestHourly{},
	// v65: device purge jobs.
	&models.DevicePurgeJob{},
	// v72: normalized event tables (plain tables here; partitioned on PG).
	&models.NetEvent{},
	&models.SecEvent{},
	&models.NetEventRollup{},
	&models.FwRule{},
	&models.DeviceFieldObserved{},
	// v73: the normalized-event backfill job queue.
	&models.NormalizeBackfillJob{},
	// v75: the raw archive's manifest.
	&models.ArchiveChunk{},
	&models.ArchiveObject{},
	&models.ArchiveMonth{},
	&models.ArchiveIDMark{},
	// v77: intervals the archive gate was released or the stream disabled.
	&models.ArchiveGateEvent{},
	// v78: archive restores to staging tables.
	&models.ArchiveRestoreJob{},
	&models.ArchiveRestoreObject{},
}

// The schema template.
//
// Every test used to build the schema from scratch: AutoMigrate over 80
// models. That costs 15ms without the race detector and **356ms with it** —
// the pure-Go SQLite parser is instrumented by the race detector, so every
// statement costs 23x more. The package has 766 tests, so that was **4.5
// minutes of the race suite's wall clock spent re-creating an identical
// schema** — which is why `go test -race ./internal/database/` needed
// 4m37s and overflowed a 5-minute timeout on a busy machine. It looked
// like a deadlock; the goroutine dump showed the parser, not a lock.
//
// The schema is now built ONCE, into a template file, and each test gets a
// COPY. The copy is file I/O, so the per-test cost is a few milliseconds
// of copying instead of 356ms of parsing.
//
// The copy is a FILE rather than `:memory:` so the schema arrives without
// being parsed at all. The pool is still pinned to ONE connection, so the
// concurrent paths behave exactly as they did: the goroutines queue on the
// pool instead of running in parallel.
var (
	schemaOnce sync.Once
	schemaPath string
	schemaErr  error
)

// buildTestSchema creates the harness's schema on db.
//
// It is factored out so the template and a direct migration build the
// IDENTICAL schema: the template is only a faster way to get there, not a
// different database.
func buildTestSchema(fatal func(...interface{}), db *gorm.DB) {
	for _, m := range testModels {
		if err := db.AutoMigrate(m); err != nil {
			fatal("NewDatabaseForTesting: AutoMigrate:", err)
		}
	}

	// Device names are unique among ACTIVE devices only (migration v63). The
	// harness runs AutoMigrate, never registeredMigrations, so the partial
	// unique index is applied here so unit tests exercise the real constraint.
	// The DROP guards against a unique idx_devices_name from an older model
	// tag; the current tag declares a plain index, which is left in place.
	var uniqueName int64
	db.Raw(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_devices_name' AND sql LIKE 'CREATE UNIQUE%'`).Scan(&uniqueName)
	if uniqueName > 0 {
		if err := db.Exec(`DROP INDEX IF EXISTS idx_devices_name`).Error; err != nil {
			fatal("NewDatabaseForTesting: drop unique idx_devices_name:", err)
		}
		if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_devices_name ON devices (name)`).Error; err != nil {
			fatal("NewDatabaseForTesting: create idx_devices_name:", err)
		}
	}
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_name_active ON devices (name) WHERE retired_at IS NULL`).Error; err != nil {
		fatal("NewDatabaseForTesting: create idx_devices_name_active:", err)
	}
}

// schemaTemplate builds the schema ONCE and returns the path of a SQLite
// file holding it.
func schemaTemplate() (string, error) {
	schemaOnce.Do(func() {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
		if err != nil {
			schemaErr = fmt.Errorf("open the schema template database: %w", err)
			return
		}
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			sqlDB.SetMaxOpenConns(1)
		}
		buildTestSchema(func(args ...interface{}) {
			schemaErr = fmt.Errorf("%v", args...)
		}, db)
		if schemaErr != nil {
			return
		}
		dir, err := os.MkdirTemp("", "fwmon-schema-")
		if err != nil {
			schemaErr = fmt.Errorf("create the schema template directory: %w", err)
			return
		}
		path := filepath.Join(dir, "schema.db")
		// VACUUM INTO writes a compacted copy of the database to a file.
		if err := db.Exec("VACUUM INTO ?", path).Error; err != nil {
			schemaErr = fmt.Errorf("write the schema template: %w", err)
			return
		}
		schemaPath = path
	})
	return schemaPath, schemaErr
}

// copyFile copies a file. The schema template is a couple of hundred
// kilobytes, so a whole-file copy is cheaper than a streamed one and lets
// the page cache do the work.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// NewDatabaseForTesting creates a SQLite Database for use in tests.
// The returned Database has no batch inserters (trapBatch etc. are nil) since
// handlers use db.Gorm().Create() directly for single-record writes.
//
// The schema comes from a template that is built once per process and copied
// per test: re-migrating 80 models costs 356ms under the race detector, and
// this package has 766 tests.
func NewDatabaseForTesting(t interface {
	Helper()
	Fatal(...interface{})
	// TempDir gives each test its own directory, so the copy is removed
	// when the test ends.
	TempDir() string
}) *Database {
	t.Helper()
	template, err := schemaTemplate()
	if err != nil {
		t.Fatal("NewDatabaseForTesting: build the schema template:", err)
	}
	path := filepath.Join(t.TempDir(), "fwmon-test.db")
	if err := copyFile(template, path); err != nil {
		t.Fatal("NewDatabaseForTesting: copy the schema template:", err)
	}
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal("NewDatabaseForTesting: open SQLite:", err)
	}

	// Pin the pool to ONE connection. The pool is pinned so the concurrent
	// paths stay under test: the goroutines queue on the pool instead of
	// running in parallel, so the scheduling and the merge ordering are
	// still exercised. It also keeps a single SQLite connection, so the
	// database has one writer and one reader.
	if sqlDB, dbErr := db.DB(); dbErr == nil {
		sqlDB.SetMaxOpenConns(1)
	}

	// The ingest meter is real here: SaveSyslogMessages must count on the test
	// backend exactly as it does in production, and the meter is the only
	// producer of syslog_ingest_hourly.
	return &Database{db: db, keylessPassthrough: true, dialect: sqliteDialect{}, ingest: newSyslogIngestMeter(time.Now), connSkips: newAutoConnSkipLog(), archiveHold: &archiveHoldState{}}
}

// SetEncryptionKeyForTesting installs the key chain derived from secret so
// that tests outside this package (e.g. the API handlers) can assert real
// encrypted-at-rest behavior ({enc2} prefix in stored rows) instead of the
// plaintext passthrough a keyless test Database gives. Test-only — this file
// is build-tagged !production alongside NewDatabaseForTesting.
func (d *Database) SetEncryptionKeyForTesting(secret string) {
	d.encKeys = newKeyChain(secret, nil)
}

// RequireEncryptionKeyForTesting turns off the harness's keyless plaintext
// passthrough, so a keyless test Database behaves like a production one: an
// EncryptField with no key is an error (D-12) instead of an identity no-op.
func (d *Database) RequireEncryptionKeyForTesting() {
	d.keylessPassthrough = false
}

// SetArchiveRestoreBatchForTesting sets the restore load batch size (lines
// per transaction) and the hook run inside every load transaction before its
// progress update (an error rolls the batch back), until the test ends — for
// the restore worker's tests in another package.
func SetArchiveRestoreBatchForTesting(t interface{ Cleanup(func()) }, size int, hook func(obj *models.ArchiveRestoreObject, cursor int64) error) {
	os, oh := archiveRestoreBatchSize, archiveRestoreTxHook
	archiveRestoreBatchSize, archiveRestoreTxHook = size, hook
	t.Cleanup(func() { archiveRestoreBatchSize, archiveRestoreTxHook = os, oh })
}

// EnableArchiveGateCacheForTesting gives d the retention gate's switch cache
// the production constructor installs (NewDatabaseForTesting leaves it nil:
// every gate call reads the switches and records nothing), so tests in other
// packages can exercise ArchiveGateReadHealth.
func (d *Database) EnableArchiveGateCacheForTesting() {
	d.archiveGateCache = &archiveGateCacheState{}
}
