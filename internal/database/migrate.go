package database

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// baselineModels is every model the baseline migration AutoMigrates. A package
// var (not a function local) so the device-purge coverage test can reflect
// over it: every struct here with a device-keyed column must have an entry in
// devicePurgeTables (purge.go), or a purge would leave that table's rows behind.
var baselineModels = []interface{}{
	&models.SystemStatus{},
	&models.ServerMetric{},
	&models.InterfaceStats{},
	&models.VPNStatus{},
	&models.HAStatus{},
	&models.HardwareSensor{},
	&models.ProcessorStats{},
	&models.DiskUsage{},
	&models.LoadAverage{},
	&models.TopologyEntry{},
	&models.TopologyNeighbor{},
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
	&models.ProbeCommand{},
	&models.IPSecTunnel{},
	&models.PingResult{},
	&models.PingStats{},
	&models.SyslogMessage{},
	&models.SyslogSummary{},
	&models.FlowSample{},
	&models.FlowRollup{},
	&models.FlowSummary{},
	&models.FlowSummaryTop{},
	&models.FlowSummaryBucket{},
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
	&models.ThreatFeedStatus{},
	&models.FlowInterfaceCounter{},
	&models.DeniedEvent{},
	&models.EventRuleProfile{},
	&models.EventRuleProfileToggle{},
	&models.SyslogIngestHourly{},
	// v65: device purge jobs.
	&models.DevicePurgeJob{},
	// v72: normalized event tables. On a fresh install v1 creates the two
	// partitioned ones plain and v2 converts them (the denied_events path);
	// on an existing install v72 does both. The three small ones are plain.
	&models.NetEvent{},
	&models.SecEvent{},
	&models.NetEventRollup{},
	&models.FwRule{},
	&models.DeviceFieldObserved{},
	// v73: the normalized-event backfill job queue (S-5).
	&models.NormalizeBackfillJob{},
	// v75: the raw archive's manifest (chunks, objects, months, id marks).
	&models.ArchiveChunk{},
	&models.ArchiveObject{},
	&models.ArchiveMonth{},
	&models.ArchiveIDMark{},
	// v77: intervals the archive gate was released or the stream disabled.
	&models.ArchiveGateEvent{},
}

// migrateBaseline is the v1 "baseline" migration (AUDIT-044): it brings an empty
// database up to the full current schema and is idempotent, so on an existing
// (already-AutoMigrated) deployment every step is a no-op and the migration
// runner simply records v1 as applied. It is invoked via the registry in
// migrations.go — do not call it directly; call RunMigrations.
func (d *Database) migrateBaseline() error {
	// Migrate each model individually so one failure doesn't block others.
	// GORM may attempt table recreation which may fail with "already exists" on upgrades.
	for _, model := range baselineModels {
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
	{"denied_events", "timestamp"},
	// v72: the normalized event tables (Phase 1, S-3). net_events is the one
	// DAILY-partitioned table (dailyPartitionTables); sec_events is monthly
	// like the rest.
	{"net_events", "ts"},
	{"sec_events", "ts"},
}

// dailyPartitionTables are the partitionTables entries whose leaves are one
// DAY wide instead of one month: net_events, whose retention (30 days by
// default) is shorter than a month, so a monthly leaf could never be dropped
// whole and the table would be row-deleted instead. A side set rather than a
// partitionDef field so the existing two-field literals above stay as they are.
// Daily tables are created with a LOOKBACK (partitionLookbackDays) as well as
// the lead, so a backfill of the retention window lands in real leaves and not
// in the DEFAULT partition.
var dailyPartitionTables = map[string]bool{
	"net_events": true,
}

// daily reports whether the table's leaves are one day wide.
func (p partitionDef) daily() bool { return dailyPartitionTables[p.tableName] }

// partitionLeadMonths / partitionLeadDays are how far ahead EnsurePartitions
// creates leaves: six months for the monthly tables (unchanged), seven days
// for the daily ones (a week of missed cron passes before rows fall into the
// DEFAULT partition).
const (
	partitionLeadMonths = 6
	partitionLeadDays   = 7
)

// defaultNetEventLookbackDays is the daily-table lookback when no
// configuration reached the Database (the SQLite harness; a Connect without
// retention config). Equals the RETENTION_NET_EVENT_DAYS default.
const defaultNetEventLookbackDays = 30

// partitionLookbackDays is how many days BEFORE today a daily table gets
// leaves for: net_events gets its retention window (RETENTION_NET_EVENT_DAYS,
// recorded on the Database by Connect), so the S-5 backfill of that window
// never lands in the DEFAULT partition — where retention could not drop it.
// Monthly tables keep no lookback (0): their rows are live ingest only.
func (d *Database) partitionLookbackDays(def partitionDef) int {
	if !def.daily() {
		return 0
	}
	if d.netEventRetentionDays > 0 {
		return d.netEventRetentionDays
	}
	return defaultNetEventLookbackDays
}

// partitionWindow is one leaf to ensure: its name and half-open [start, end)
// range, both UTC-anchored.
type partitionWindow struct {
	name       string
	start, end time.Time
}

// partitionWindows lists the leaves a table must have at `now`: for a monthly
// table the current month plus partitionLeadMonths ahead (named
// <table>_YYYYMM, exactly as before); for a daily table lookbackDays before
// today through partitionLeadDays after it (named <table>_YYYYMMDD). Bounds
// are UTC midnights: the partition key is timestamptz and the DSN pins the
// session to UTC, so a leaf's range is the same instant range everywhere.
func partitionWindows(def partitionDef, now time.Time, lookbackDays int) []partitionWindow {
	now = now.UTC()
	if def.daily() {
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		out := make([]partitionWindow, 0, lookbackDays+partitionLeadDays+1)
		for i := -lookbackDays; i <= partitionLeadDays; i++ {
			start := today.AddDate(0, 0, i)
			out = append(out, partitionWindow{
				name:  fmt.Sprintf("%s_%s", def.tableName, start.Format("20060102")),
				start: start,
				end:   start.AddDate(0, 0, 1),
			})
		}
		return out
	}
	out := make([]partitionWindow, 0, partitionLeadMonths+1)
	for i := 0; i <= partitionLeadMonths; i++ {
		year, month, _ := now.Date()
		month += time.Month(i)
		for month > 12 {
			month -= 12
			year++
		}
		start := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
		out = append(out, partitionWindow{
			name:  fmt.Sprintf("%s_%d%02d", def.tableName, year, month),
			start: start,
			end:   start.AddDate(0, 1, 0),
		})
	}
	return out
}

// partitionModels maps each partitioned table to its GORM model so the
// per-partition index list can be DERIVED from the model's `gorm:"index:..."`
// tags (LC-19, 2026-07-04 audit). The previous hand-maintained list in
// EnsurePartitions was a second copy of what the tags already declare, and it
// had drifted: the AUDIT-034 flow_samples src/dst indexes (plus the probe_id
// and syslog_summaries interval/severity indexes) were silently absent from
// every partition on a fresh Postgres install, because
// convertEmptyTableToPartitioned recreates the parent with
// `INCLUDING DEFAULTS` only (dropping the AutoMigrate-created indexes with the
// _prepart table) and nothing ever re-created the tag indexes. The drift guard
// in partition_index_lc19_test.go cross-checks this map against
// partitionTables and the model tags so the lists can't diverge again.
var partitionModels = map[string]interface{}{
	"interface_stats":  &models.InterfaceStats{},
	"system_status":    &models.SystemStatus{},
	"syslog_messages":  &models.SyslogMessage{},
	"syslog_summaries": &models.SyslogSummary{},
	"trap_events":      &models.TrapEvent{},
	"flow_samples":     &models.FlowSample{},
	"denied_events":    &models.DeniedEvent{},
	"net_events":       &models.NetEvent{},
	"sec_events":       &models.SecEvent{},
}

// partitionIndex is one per-partition index to (re)create: the physical name
// is idx_<partitionName>_<suffix>, over cols (unquoted column names).
type partitionIndex struct {
	suffix string
	cols   []string
}

// partitionSchemaCache backs schema.Parse in partitionIndexPlan (each model is
// parsed once per process).
var partitionSchemaCache sync.Map

// partitionIndexPlan computes the index set every monthly partition of a table
// must carry: the two baseline indexes every partitioned table gets —
// (device_id, <partition column>) and (<partition column>) — plus every index
// declared by `gorm:"index:..."` tags on the table's model (the single source
// of truth; see partitionModels). Redundant candidates are dropped: an index
// whose column list is a leading prefix of another planned index (e.g. the
// models' standalone device_id index, which the (device_id, timestamp)
// baseline already serves on a btree) adds nothing. Unique and expression
// indexes are excluded — none of the partitioned models declare any, and a
// per-partition unique index couldn't enforce global uniqueness anyway.
func partitionIndexPlan(def partitionDef) ([]partitionIndex, error) {
	model, ok := partitionModels[def.tableName]
	if !ok {
		return nil, fmt.Errorf("partition index plan: no model registered for table %q (add it to partitionModels)", def.tableName)
	}
	sch, err := schema.Parse(model, &partitionSchemaCache, schema.NamingStrategy{IdentifierMaxLength: 64})
	if err != nil {
		return nil, fmt.Errorf("partition index plan: parse model for %q: %w", def.tableName, err)
	}

	candidates := [][]string{
		{"device_id", def.column},
		{def.column},
	}
	for _, idx := range sch.ParseIndexes() {
		if idx.Class == "UNIQUE" {
			continue
		}
		cols := make([]string, 0, len(idx.Fields))
		expr := false
		for _, f := range idx.Fields {
			if f.Expression != "" {
				expr = true
				break
			}
			cols = append(cols, f.DBName)
		}
		if expr || len(cols) == 0 {
			continue
		}
		candidates = append(candidates, cols)
	}

	var plan []partitionIndex
	for i, c := range candidates {
		covered := false
		for j, o := range candidates {
			if i == j || !isColPrefix(c, o) {
				continue
			}
			// c is a prefix of (or equal to) o: keep only the longer index;
			// for exact duplicates keep the earlier candidate.
			if len(c) < len(o) || j < i {
				covered = true
				break
			}
		}
		if !covered {
			plan = append(plan, partitionIndex{suffix: partitionIndexSuffix(c), cols: c})
		}
	}
	return plan, nil
}

// isColPrefix reports whether a is a leading prefix of b (or equal to it).
func isColPrefix(a, b []string) bool {
	if len(a) > len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parentPartitionedIndexColumns returns the ordered column list of every
// NON-UNIQUE partitioned index (pg_class relkind 'I') declared on the given
// partitioned parent table. PostgreSQL cascades a parent-level index to every
// existing and future leaf automatically, so any per-leaf index over the same
// (or a covered) column list would be a second, physically identical btree.
// Postgres-only by construction — callers reach here only for partitioned
// parents, which exist only on the PG backend.
func (d *Database) parentPartitionedIndexColumns(tableName string) ([][]string, error) {
	var rows []struct {
		IndexName string
		Cols      string
	}
	// indexprs IS NULL excludes expression indexes (their indkey carries 0
	// attnums that would join to nothing); indisunique=false matches the plan's
	// own scope — partitionIndexPlan never emits unique indexes.
	//
	// Review hardening (AUDIT-174): indpred IS NULL — a PARTIAL parent index
	// does NOT fully cover a plan entry and must never suppress the full
	// per-leaf index; ord <= indnkeyatts — INCLUDE columns are payload, not
	// key columns, and must not widen the claimed coverage; indisvalid —
	// an invalid index serves no queries and covers nothing.
	if err := d.db.Raw(`
		SELECT i.relname AS index_name,
		       string_agg(a.attname, ',' ORDER BY k.ord) AS cols
		FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid
		JOIN pg_class t ON t.oid = x.indrelid
		JOIN LATERAL unnest(x.indkey) WITH ORDINALITY AS k(attnum, ord) ON k.ord <= x.indnkeyatts
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
		WHERE t.relname = ?
		  AND i.relkind = 'I'
		  AND NOT x.indisunique
		  AND x.indexprs IS NULL
		  AND x.indpred IS NULL
		  AND x.indisvalid
		GROUP BY i.relname`, tableName).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([][]string, 0, len(rows))
	for _, r := range rows {
		if r.Cols == "" {
			continue
		}
		out = append(out, strings.Split(r.Cols, ","))
	}
	return out, nil
}

// planEntriesNotCoveredByParent filters a per-leaf index plan against the
// parent's partitioned indexes (AUDIT-174): an entry whose column list is
// equal to, or a leading prefix of, a parent index's columns is dropped —
// the cascaded parent index already serves it on every leaf, and creating it
// again under the plan's own name would build a second physically identical
// btree per leaf (double write amplification and disk on the volume-dominant
// tables, forever). The returned skipped list carries the dropped entries'
// suffixes for one summary log line. The plan itself stays complete
// (partitionIndexPlan is untouched — the LC-19 drift guard keeps pinning it);
// only its application is filtered.
func planEntriesNotCoveredByParent(plan []partitionIndex, parentIndexCols [][]string) (kept []partitionIndex, skipped []string) {
	for _, p := range plan {
		covered := false
		for _, cols := range parentIndexCols {
			if isColPrefix(p.cols, cols) {
				covered = true
				break
			}
		}
		if covered {
			skipped = append(skipped, p.suffix)
			continue
		}
		kept = append(kept, p)
	}
	return kept, skipped
}

// dropParentCoveredLeafIndexes removes the plan-named per-leaf indexes that a
// covering parent partitioned index makes redundant (AUDIT-174 review fix).
// Fresh installs created between v0.11.183 (v54 shipped) and v0.11.213 built
// both btrees on every leaf; stopping NEW duplicates alone would leave those
// installs carrying the write-amplification twins for the leaves' whole
// lifetime. Scope is deliberately surgical: only children of the named parent,
// only the exact plan-derived names (idx_<child>_<suffix>), and only for
// suffixes the catalog probe proved covered. Failures log and continue — a
// leftover duplicate is recoverable on the next boot.
func (d *Database) dropParentCoveredLeafIndexes(parent string, skippedSuffixes []string) {
	var children []string
	if err := d.db.Raw(`
		SELECT c.relname FROM pg_inherits h
		JOIN pg_class c ON c.oid = h.inhrelid
		JOIN pg_class p ON p.oid = h.inhparent
		WHERE p.relname = ?`, parent).Scan(&children).Error; err != nil {
		log.Printf("AUDIT-174: child enumeration for %s failed: %v (duplicate-index cleanup skipped this boot)", parent, err)
		return
	}
	candidates := make([]string, 0, len(children)*len(skippedSuffixes))
	for _, child := range children {
		for _, suffix := range skippedSuffixes {
			candidates = append(candidates, fmt.Sprintf("idx_%s_%s", child, suffix))
		}
	}
	if len(candidates) == 0 {
		return
	}
	// Drop only names that actually exist as indexes, so the common case (no
	// duplicates — this prod) costs one catalog probe and zero DDL. The
	// pg_inherits exclusion matters on upgrade-path installs partitioned
	// BEFORE v54: there the parent CREATE INDEX *attached* the pre-existing
	// plan-named leaf index instead of cascading a twin — that index IS the
	// cascade child (no duplicate exists), PG refuses to drop it, and without
	// this filter every boot would log a "will retry" that can never succeed.
	var existing []string
	if err := d.db.Raw(`SELECT relname FROM pg_class WHERE relname IN ? AND relkind = 'i'
		AND NOT EXISTS (SELECT 1 FROM pg_inherits h WHERE h.inhrelid = pg_class.oid)`,
		candidates).Scan(&existing).Error; err != nil {
		log.Printf("AUDIT-174: duplicate-index existence probe for %s failed: %v (cleanup skipped this boot)", parent, err)
		return
	}
	for _, idx := range existing {
		if err := d.db.Exec("DROP INDEX IF EXISTS " + idx).Error; err != nil {
			log.Printf("AUDIT-174: drop duplicate leaf index %s: %v (will retry next boot)", idx, err)
			continue
		}
		log.Printf("AUDIT-174: dropped duplicate leaf index %s (covered by a parent partitioned index)", idx)
	}
}

// partitionIndexSuffix maps an index's column list to the per-partition name
// suffix (idx_<partition>_<suffix>). The first three cases pin the names the
// pre-LC-19 hard-coded list already created, so `CREATE INDEX IF NOT EXISTS`
// no-ops on existing deployments instead of building duplicate indexes under
// new names.
func partitionIndexSuffix(cols []string) string {
	switch strings.Join(cols, ",") {
	case "device_id,timestamp":
		return "device_ts"
	case "timestamp":
		return "timestamp"
	case "device_id,index,timestamp":
		return "device_idx_ts"
	default:
		return strings.Join(cols, "_")
	}
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

// execCronDDL is execMaintenanceDDL for DDL issued by the daily retention pass,
// which since v0.11.256 runs concurrently with the monitoring cycle and flow
// detection instead of shutting them out. A partition CREATE or DROP takes
// ACCESS EXCLUSIVE on the parent, and while it queues behind a reader every
// insert on that parent queues behind IT — so here the wait is bounded by
// cronDDLLockTimeout and a timeout surfaces as 55P03 for the caller to handle.
// Startup DDL keeps execMaintenanceDDL: nothing else is running yet, and a
// startup that gave up on a lock would be worse than one that waited.
func (d *Database) execCronDDL(sql string, args ...interface{}) error {
	if !d.dialect.IsPostgres() {
		return d.db.Exec(sql, args...).Error
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
			return fmt.Errorf("lift statement_timeout: %w", err)
		}
		// SET takes no bind parameters, hence the rendered literal; the value is
		// a package duration, never input.
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", cronDDLLockTimeout.Milliseconds())).Error; err != nil {
			return fmt.Errorf("set lock_timeout: %w", err)
		}
		return tx.Exec(sql, args...).Error
	})
}

// EnsurePartitions creates monthly range partitions for high-volume tables on PostgreSQL.
// Partitions are created for the current month + 6 months ahead.
// This is safe for existing servers - it only creates new partitions, never modifies existing data.
// Startup variant; the retention cron calls EnsurePartitionsForCron.
func (d *Database) EnsurePartitions() error {
	return d.ensurePartitions(d.execMaintenanceDDL, 0)
}

// EnsurePartitionsForCron is EnsurePartitions for the daily retention pass: the
// monthly CREATE TABLE ... PARTITION OF (ACCESS EXCLUSIVE on the parent and its
// DEFAULT partition) goes through execCronDDL so it cannot stall ingest behind a
// reader. A lock-timed-out CREATE is logged and retried the next day; with a
// six-month lead and a DEFAULT partition that costs nothing. Only that statement
// changes: the DEFAULT-partition CREATE ... IF NOT EXISTS returns before locking
// when it exists, and CREATE INDEX takes SHARE, which never queues behind a
// reader — under a lock_timeout its daily no-op would instead fail behind any
// long COPY.
//
// Since v72 the daily tables (net_events) add one CREATE ... PARTITION OF per
// day to this pass — one ACCESS EXCLUSIVE acquisition on the parent (and its
// DEFAULT child) per day, bounded by cronDDLLockTimeout like the monthly ones;
// a timed-out day is retried the next pass, and the seven-day lead means
// ingest never waits on it. The same bound covers the locked move-and-attach
// transaction ensureLeaf uses when the DEFAULT child already holds the day's
// rows (lockTimeout below; 0 = wait, the startup variant).
func (d *Database) EnsurePartitionsForCron() error {
	return d.ensurePartitions(d.execCronDDL, cronDDLLockTimeout)
}

func (d *Database) ensurePartitions(createPartition func(sql string, args ...interface{}) error, lockTimeout time.Duration) error {
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

	// AUDIT D2: ensure a DEFAULT partition per parent so a row whose timestamp
	// falls outside the current±6-month window — backward clock skew, or a batch
	// received just after 00:00 on the 1st carrying prev-month rows — lands in the
	// default instead of failing the whole insert/COPY with "no partition of
	// relation found for row". Idempotent; the cleanup cron already skips the
	// default's unparseable bound and parent-level retention still trims its rows
	// — except, for one pass, rows older than the floor of a lock-timed-out
	// partition DROP (see dropPartitionsOlderThan).
	// Also covers freshly-converted parents that predate the v51 migration.
	for _, def := range partitioned {
		if err := d.execMaintenanceDDL(fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s_default PARTITION OF %s DEFAULT`, def.tableName, def.tableName)); err != nil {
			log.Printf("Default partition warning for %s: %v", def.tableName, err)
		}
	}

	// LC-19: compute each table's per-partition index plan once — derived from
	// the model's gorm index tags (partitionIndexPlan), not a second hard-coded
	// list that can drift from the model.
	indexPlans := make(map[string][]partitionIndex, len(partitioned))
	for _, def := range partitioned {
		plan, err := partitionIndexPlan(def)
		if err != nil {
			return fmt.Errorf("partition index plan for %s: %w", def.tableName, err)
		}
		indexPlans[def.tableName] = plan
	}

	// AUDIT-174: drop plan entries a parent-level PARTITIONED index already
	// serves. v54 (idx_syslog_sev_ts on syslog_messages (severity, timestamp))
	// and v57 (idx_trap_events_timestamp on trap_events (timestamp)) create
	// their indexes on the PARENT, and PostgreSQL cascades a parent index to
	// every new leaf automatically — so on a fresh install each monthly leaf
	// got the cascaded index AND the plan's identically-columned one under a
	// different name (`IF NOT EXISTS` matches by name only). This is resolved
	// from the catalog on every run rather than a hard-coded exclusion list,
	// which would be exactly the LC-19 drift the derived plan exists to
	// prevent. On a probe failure the FULL plan is kept: a redundant index is
	// recoverable, a missing one is a silent per-query regression.
	for _, def := range partitioned {
		parentIdx, err := d.parentPartitionedIndexColumns(def.tableName)
		if err != nil {
			log.Printf("Parent index probe warning for %s: %v (keeping the full per-leaf index plan)", def.tableName, err)
			continue
		}
		kept, skipped := planEntriesNotCoveredByParent(indexPlans[def.tableName], parentIdx)
		if len(skipped) > 0 {
			log.Printf("Partition indexes for %s: skipping per-leaf %s — covered by a parent partitioned index that cascades to every leaf (AUDIT-174)",
				def.tableName, strings.Join(skipped, ", "))
			// Review fix: fresh installs created on v0.11.183..v0.11.213
			// (published images) already built BOTH btrees on every leaf —
			// this deployment's prod never did (verified against the live
			// catalog), but the fleet did. Drop the plan-named twins the
			// covering parent index makes redundant; exact names only,
			// only for suffixes the catalog probe proved covered.
			d.dropParentCoveredLeafIndexes(def.tableName, skipped)
		}
		indexPlans[def.tableName] = kept
	}

	// The DEFAULT child (v51 / created above) is a leaf like any monthly
	// partition and takes the same plan. It was created bare (pkey only) —
	// the index loop below only ever named the <table>_YYYYMM leaves — so
	// every backdated row that lands there was read by full scan: retention's
	// timestamp-bounded DELETE and the device purge's (device_id, timestamp)
	// batch subquery both seq-scanned + sorted the default on every batch.
	for _, def := range partitioned {
		d.ensureLeafIndexes(def.tableName+"_default", indexPlans[def.tableName])
	}

	// Create the leaves each table needs: current month + 6 ahead for the
	// monthly tables, lookback..today+7 days for the daily ones
	// (partitionWindows).
	now := time.Now()
	for _, def := range partitioned {
		for _, w := range partitionWindows(def, now, d.partitionLookbackDays(def)) {
			// Render the RANGE bounds with an EXPLICIT UTC offset (not a bare date) so
			// the literal is interpreted identically regardless of the PG session
			// TimeZone. The partition key is timestamptz, and a bare-date literal is
			// anchored in the session TZ at CREATE time — so once D4 pins the session
			// to UTC, an explicit +00 keeps every new partition aligned with the
			// existing UTC-created ones (no boundary overlap/gap). parsePartition-
			// UpperBound already accepts this rendering.
			startStr := w.start.Format("2006-01-02 15:04:05-07:00")
			endStr := w.end.Format("2006-01-02 15:04:05-07:00")

			partitionName := w.name
			if err := d.ensureLeaf(def, w, startStr, endStr, createPartition, lockTimeout); err != nil {
				log.Printf("Partition creation warning for %s: %v", partitionName, err)
				continue
			}

			// Ensure the per-partition indexes exist. LC-19: the list is derived
			// from the model's gorm index tags (see partitionIndexPlan) — the
			// previous hard-coded list here had drifted and dropped the AUDIT-034
			// flow_samples src/dst indexes on fresh installs. This runs for
			// pre-existing partitions too (IF NOT EXISTS makes it a cheap no-op
			// when the index is present), so a partition created while an index
			// was missing from the old list is backfilled on the next startup.
			d.ensureLeafIndexes(partitionName, indexPlans[def.tableName])
		}
	}

	return nil
}

// ensureLeaf makes w's leaf an attached child of def's parent, creating it
// when absent. The plain path is unchanged — one CREATE TABLE ... PARTITION OF
// through createPartition (lock-bounded on the cron). The other path exists
// because a leaf can be needed for a range the DEFAULT child already holds
// rows for: a poller down for longer than the lead, or ingest before the first
// EnsurePartitions, puts a day's rows in <table>_default, and from then on
// `CREATE TABLE ... PARTITION OF ... FOR VALUES` fails every pass with
// "updated partition constraint for default partition would be violated by
// some row" — the leaf never appears, every later row of that day lands in
// the default too, and partition-drop retention never reaches any of them.
// Reproduced on PostgreSQL 16 (TestNormalizedTables_PG/MissingLeafWith
// DefaultRows). So when the default holds rows in [start, end):
//
//  1. create the leaf as a STANDALONE table shaped like the parent (LIKE ...
//     INCLUDING DEFAULTS, which carries the id sequence default) — invisible
//     to readers until attached, so a crash leaves nothing half-visible;
//  2. move the rows out of the default in bounded batches, each one
//     DELETE ... RETURNING feeding an INSERT in a single transaction under the
//     retention pass's lock / statement timeouts (moveDefaultRowsIntoLeaf);
//  3. ATTACH PARTITION through createPartition (ACCESS EXCLUSIVE on the
//     now-near-empty default, SHARE UPDATE EXCLUSIVE on the parent, lock-
//     bounded on the cron). Postgres builds the parent's partitioned
//     indexes — the PK — on the leaf at attach; the plan indexes follow from
//     the caller as for any leaf.
//
// Idempotent across a crash at any point: an existing but unattached leaf is
// recognised and the move + attach resume; a moved row is never duplicated
// (the DELETE and INSERT share a transaction) and never lost (the standalone
// table keeps it). Rows are unreadable through the parent only between their
// move and the attach — they were strays in the default to begin with.
func (d *Database) ensureLeaf(def partitionDef, w partitionWindow, startStr, endStr string,
	createPartition func(sql string, args ...interface{}) error, lockTimeout time.Duration) error {
	var attached bool
	if err := d.db.Raw(`SELECT EXISTS (SELECT 1 FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE c.relname = ?)`,
		w.name).Scan(&attached).Error; err != nil {
		return fmt.Errorf("attached probe: %w", err)
	}
	if attached {
		return nil
	}
	var exists bool
	if err := d.db.Raw(`SELECT to_regclass(?) IS NOT NULL`, w.name).Scan(&exists).Error; err != nil {
		return fmt.Errorf("exists probe: %w", err)
	}
	def_ := def.tableName + "_default"
	var strays bool
	if err := d.db.Raw(fmt.Sprintf(`SELECT to_regclass(?) IS NOT NULL AND EXISTS (SELECT 1 FROM %s WHERE %s >= ? AND %s < ?)`,
		def_, def.column, def.column), def_, w.start, w.end).Scan(&strays).Error; err != nil {
		// The default child is created above in every pass; a probe error here
		// means the relation is missing or unreadable — fall through to the
		// plain CREATE, which reports the real problem.
		strays = false
	}
	if !exists && !strays {
		if err := createPartition(fmt.Sprintf(`
					CREATE TABLE %s PARTITION OF %s
					FOR VALUES FROM ('%s') TO ('%s')`, w.name, def.tableName, startStr, endStr)); err != nil {
			return err
		}
		log.Printf("Created partition: %s", w.name)
		return nil
	}
	// The raw archive must not count or verify this table while rows sit in
	// the standalone leaf (invisible through the parent): the leaf's
	// existence holds it, and this epoch catches a move that starts and ends
	// inside one of its counts (archive_gate.go). Bumped before anything
	// moves; a failure stops the move.
	if err := d.bumpArchiveLeafMoveEpoch(def.tableName); err != nil {
		return fmt.Errorf("record the leaf move for the archive: %w", err)
	}
	if !exists {
		log.Printf("WARNING: %s already holds rows for [%s, %s); creating %s as a standalone table, moving them, then attaching it",
			def_, startStr, endStr, w.name)
		if err := d.execMaintenanceDDL(fmt.Sprintf(`CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS)`, w.name, def.tableName)); err != nil {
			return fmt.Errorf("create standalone leaf: %w", err)
		}
	} else {
		log.Printf("WARNING: %s exists but is not attached to %s (an interrupted earlier pass); resuming the move from %s and the attach",
			w.name, def.tableName, def_)
		// A leaf left unattached across a schema migration no longer matches
		// the default's shape; INSERT ... SELECT * then fails on a column
		// mismatch. Say so plainly before it does: the operator rescues the
		// leaf's rows and drops it (or ALTERs it to match).
		var leafCols, defCols int
		d.db.Raw(`SELECT COUNT(*) FROM pg_attribute WHERE attrelid = to_regclass(?) AND attnum > 0 AND NOT attisdropped`, w.name).Scan(&leafCols)
		d.db.Raw(`SELECT COUNT(*) FROM pg_attribute WHERE attrelid = to_regclass(?) AND attnum > 0 AND NOT attisdropped`, def_).Scan(&defCols)
		if leafCols != defCols {
			log.Printf("WARNING: unattached %s has %d columns but %s has %d — the table changed shape while the leaf sat unattached; the move below will fail until %s is dropped (after rescuing its rows) or altered to match",
				w.name, leafCols, def_, defCols, w.name)
		}
	}
	// Give the leaf everything ATTACH would otherwise have to build or verify
	// under the lock: the range CHECK (so the attach skips scanning the leaf),
	// the parent's partitioned indexes incl. the PK (so it attaches them
	// instead of building them). No contention — the leaf is still standalone.
	// Done before the move so the PK also rejects a duplicate id early.
	if err := d.prepareLeafForAttach(def, w, startStr, endStr); err != nil {
		return fmt.Errorf("prepare %s for attach: %w", w.name, err)
	}
	var moved, remainder int64
	for attempt := 1; ; attempt++ {
		// Bulk of the move: unlocked, batched, while ingest keeps writing the
		// day's rows into the default.
		n, err := d.moveDefaultRowsIntoLeaf(def_, w.name, def.column, w.start, w.end)
		moved += n
		if err != nil {
			return fmt.Errorf("move rows from %s: %w", def_, err)
		}
		if leafAttachHook != nil {
			leafAttachHook(w.name, attempt) // test seam: rows for this day arrive now
		}
		// Final step, ONE transaction: lock the default (ACCESS EXCLUSIVE,
		// bounded by lockTimeout on the cron), move the remainder that arrived
		// since the batched pass and attach. Separate statements here were the
		// bug: a row committed into the default between the last batch and the
		// ATTACH failed the attach ("default partition would be violated")
		// every pass until the day was over, while the moved rows sat
		// invisible in the standalone leaf. The remainder must be SMALL for
		// the lock hold to be a scan of the default: when a backlog replay has
		// stuffed more than leafAttachRemainderCap rows into the range since
		// the batched pass, the transaction rolls back before moving anything
		// and the loop goes round again unlocked, a bounded number of times.
		remainder, err = d.attachLeafLocked(def, w, startStr, endStr, lockTimeout)
		if errors.Is(err, errLeafRemainderTooLarge) {
			if attempt >= leafAttachMaxAttempts {
				return fmt.Errorf("attach: the default kept receiving more than %d rows for [%s, %s) between the batched move and the lock on %d attempts (%d row(s) moved so far, kept in the standalone leaf; retried next pass)",
					leafAttachRemainderCap, startStr, endStr, attempt, moved)
			}
			log.Printf("Partition %s: more than %d rows arrived in %s for [%s, %s) since the batched move; moving them unlocked first (attempt %d/%d)",
				w.name, leafAttachRemainderCap, def_, startStr, endStr, attempt, leafAttachMaxAttempts)
			continue
		}
		if err != nil {
			return fmt.Errorf("attach (%d row(s) moved out of %s and kept in the standalone leaf; retried next pass): %w", moved, def_, err)
		}
		break
	}
	log.Printf("Created partition: %s (attached after moving %d+%d row(s) out of %s)", w.name, moved, remainder, def_)
	return nil
}

// leafAttachHook, when non-nil, runs on every attempt between the batched move
// and the locked attach — where concurrent ingest rows can land in the default
// child — with the attempt number, so a test can inject rows and count rounds.
var leafAttachHook func(leaf string, attempt int)

// errLeafRemainderTooLarge is attachLeafLocked's refusal to move more than
// leafAttachRemainderCap rows under the default's ACCESS EXCLUSIVE lock.
var errLeafRemainderTooLarge = errors.New("remainder in the default exceeds the locked-move cap")

var (
	// leafAttachRemainderCap is the most rows attachLeafLocked moves while
	// holding the default's lock; a day's worth from a backlog replay is far
	// above it and goes through the unlocked batched move instead.
	leafAttachRemainderCap = 50000
	// leafAttachMaxAttempts bounds the move → locked-attach loop per pass.
	leafAttachMaxAttempts = 5
)

// defaultMoveStmt is the DELETE ... RETURNING → INSERT that moves rows of
// [start, end) from the DEFAULT child into the leaf; with limit > 0 one batch
// of that many rows, otherwise every matching row.
func defaultMoveStmt(defaultChild, leaf, column string, limit bool) string {
	sel := fmt.Sprintf(`SELECT id FROM %s WHERE %s >= ? AND %s < ?`, defaultChild, column, column)
	if limit {
		sel += fmt.Sprintf(` ORDER BY %s LIMIT ?`, column)
	}
	return fmt.Sprintf(`WITH moved AS (DELETE FROM %s WHERE id IN (%s) RETURNING *) INSERT INTO %s SELECT * FROM moved`,
		defaultChild, sel, leaf)
}

// moveDefaultRowsIntoLeaf moves the rows of [start, end) from the DEFAULT child
// into an unattached leaf, cleanupDeleteBatchSize rows per transaction, each
// batch a DELETE ... RETURNING feeding the INSERT so a row is either in one
// table or the other at every commit. Lock / statement timeouts match the
// retention pass's batched deletes. Returns the rows moved.
func (d *Database) moveDefaultRowsIntoLeaf(defaultChild, leaf, column string, start, end time.Time) (int64, error) {
	stmt := defaultMoveStmt(defaultChild, leaf, column, true)
	var total int64
	for {
		var n int64
		err := d.db.Transaction(func(tx *gorm.DB) error {
			if e := tx.Exec("SET LOCAL lock_timeout = '5s'").Error; e != nil {
				return e
			}
			if e := tx.Exec("SET LOCAL statement_timeout = '120s'").Error; e != nil {
				return e
			}
			res := tx.Exec(stmt, start, end, cleanupDeleteBatchSize)
			n = res.RowsAffected
			return res.Error
		})
		if err != nil {
			return total, err
		}
		total += n
		if n < int64(cleanupDeleteBatchSize) {
			return total, nil
		}
		time.Sleep(batchDeleteInterSleep)
	}
}

// prepareLeafForAttach adds to the standalone leaf what ATTACH PARTITION would
// otherwise do under its locks: a CHECK constraint equal to the partition
// bound (Postgres then skips the leaf scan that proves every row fits) and a
// matching index for each of the parent's partitioned indexes — the PK (id,
// column) and any v54/v57-style parent index — which the attach then adopts
// instead of building. Idempotent: every step probes the catalog first, so a
// pass resumed after a crash adds only what is missing.
func (d *Database) prepareLeafForAttach(def partitionDef, w partitionWindow, startStr, endStr string) error {
	check := w.name + "_range"
	var hasCheck bool
	if err := d.db.Raw(`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = ? AND conrelid = to_regclass(?))`,
		check, w.name).Scan(&hasCheck).Error; err != nil {
		return fmt.Errorf("check probe: %w", err)
	}
	if !hasCheck {
		if err := d.execMaintenanceDDL(fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s CHECK (%s IS NOT NULL AND %s >= '%s' AND %s < '%s')`,
			w.name, check, def.column, def.column, startStr, def.column, endStr)); err != nil {
			return fmt.Errorf("add range check: %w", err)
		}
	}
	var hasPK bool
	if err := d.db.Raw(`SELECT EXISTS (SELECT 1 FROM pg_index WHERE indrelid = to_regclass(?) AND indisprimary)`, w.name).
		Scan(&hasPK).Error; err != nil {
		return fmt.Errorf("pk probe: %w", err)
	}
	if !hasPK {
		if err := d.execMaintenanceDDL(fmt.Sprintf(`ALTER TABLE %s ADD PRIMARY KEY (id, %s)`, w.name, def.column)); err != nil {
			return fmt.Errorf("add primary key: %w", err)
		}
	}
	// The parent's other partitioned indexes, rendered by the catalog as
	// "CREATE [UNIQUE] INDEX <name> ON ONLY <parent> USING ..." — re-aimed at
	// the leaf under a leaf-prefixed name.
	var defs []struct {
		Name string
		Def  string
	}
	if err := d.db.Raw(`SELECT i.relname AS name, pg_get_indexdef(i.oid) AS def
		FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid
		WHERE x.indrelid = to_regclass(?) AND NOT x.indisprimary`, def.tableName).Scan(&defs).Error; err != nil {
		return fmt.Errorf("parent index probe: %w", err)
	}
	for _, ix := range defs {
		stmt := parentIndexDefForLeaf(ix.Def, ix.Name, w.name)
		if stmt == "" {
			log.Printf("Partition %s: cannot re-aim parent index %s at the leaf (%q); ATTACH will build it", w.name, ix.Name, ix.Def)
			continue
		}
		if err := d.execMaintenanceDDL(stmt); err != nil {
			return fmt.Errorf("create %s on leaf: %w", ix.Name, err)
		}
	}
	return nil
}

// parentIndexDefForLeaf rewrites a partitioned index's pg_get_indexdef output
// ("CREATE [UNIQUE] INDEX name ON ONLY [schema.]parent USING ...") into the
// equivalent "CREATE [UNIQUE] INDEX IF NOT EXISTS <leaf>_<name> ON <leaf>
// USING ..." for a standalone leaf; "" when the text is not that shape.
func parentIndexDefForLeaf(indexDef, indexName, leaf string) string {
	const marker = " ON ONLY "
	i := strings.Index(indexDef, marker)
	using := strings.Index(indexDef, " USING ")
	if i < 0 || using < i {
		return ""
	}
	head := indexDef[:i] // CREATE [UNIQUE] INDEX name
	head = strings.TrimSuffix(head, " "+indexName)
	if !strings.HasPrefix(head, "CREATE ") || !strings.HasSuffix(head, "INDEX") {
		return ""
	}
	return fmt.Sprintf("%s IF NOT EXISTS %s_%s ON %s%s", head, leaf, indexName, leaf, indexDef[using:])
}

// attachLeafLocked is the final step of absorbing a day from the DEFAULT child,
// in ONE transaction: lock the default (ACCESS EXCLUSIVE, so no row can be
// routed into it meanwhile), move whatever arrived since the batched pass,
// attach the prepared leaf, drop its now-redundant range CHECK. lockTimeout
// bounds the lock wait (0 = wait, startup). Returns the rows moved here.
func (d *Database) attachLeafLocked(def partitionDef, w partitionWindow, startStr, endStr string, lockTimeout time.Duration) (int64, error) {
	def_ := def.tableName + "_default"
	var remainder int64
	err := d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
			return fmt.Errorf("lift statement_timeout: %w", err)
		}
		if lockTimeout > 0 {
			// Rendered literal, never input: a package duration (see execCronDDL).
			if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", lockTimeout.Milliseconds())).Error; err != nil {
				return fmt.Errorf("set lock_timeout: %w", err)
			}
		}
		if err := tx.Exec(fmt.Sprintf(`LOCK TABLE %s IN ACCESS EXCLUSIVE MODE`, def_)).Error; err != nil {
			return fmt.Errorf("lock %s: %w", def_, err)
		}
		// Bounded probe (stops at cap+1): a remainder above the cap is not
		// moved under this lock — roll back and let the caller drain it
		// unlocked first.
		var pending int64
		if err := tx.Raw(fmt.Sprintf(`SELECT COUNT(*) FROM (SELECT 1 FROM %s WHERE %s >= ? AND %s < ? LIMIT ?) s`,
			def_, def.column, def.column), w.start, w.end, leafAttachRemainderCap+1).Scan(&pending).Error; err != nil {
			return fmt.Errorf("count remainder: %w", err)
		}
		if pending > int64(leafAttachRemainderCap) {
			return errLeafRemainderTooLarge
		}
		res := tx.Exec(defaultMoveStmt(def_, w.name, def.column, false), w.start, w.end)
		if res.Error != nil {
			return fmt.Errorf("move remainder: %w", res.Error)
		}
		remainder = res.RowsAffected
		if err := tx.Exec(fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s FOR VALUES FROM ('%s') TO ('%s')`,
			def.tableName, w.name, startStr, endStr)).Error; err != nil {
			return err
		}
		return tx.Exec(fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s_range`, w.name, w.name)).Error
	})
	return remainder, err
}

// ensureLeafIndexes creates the plan's indexes on one leaf partition as
// idx_<leaf>_<suffix>. IF NOT EXISTS makes it a no-op when the index is
// present and a backfill when the leaf was created while an index was missing
// from the plan. Column names are quoted — interface_stats has an "index"
// column, which is a reserved word. Errors are logged, never returned: a
// missing leaf index is a per-query slowdown, not a reason to fail startup.
func (d *Database) ensureLeafIndexes(leaf string, plan []partitionIndex) {
	for _, idx := range plan {
		quoted := make([]string, len(idx.cols))
		for i, c := range idx.cols {
			quoted[i] = `"` + c + `"`
		}
		createIdxSQL := fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s (%s)",
			leaf, idx.suffix, leaf, strings.Join(quoted, ", "))
		if err := d.execMaintenanceDDL(createIdxSQL); err != nil {
			log.Printf("Index creation warning on %s: %v", leaf, err)
		}
	}
}

// migratePartitionDefaultPartitions is the v51 migration (AUDIT D2): create a
// DEFAULT partition for each already-partitioned high-volume parent so a row
// whose timestamp falls outside the current±6-month window lands in the default
// rather than failing the entire insert/COPY with "no partition of relation
// found for row" (which, for flow_samples, fails the whole pgx COPY batch and
// the collector re-queues it forever). Idempotent (IF NOT EXISTS); PG-only
// (recorded as a no-op on the SQLite test backend). Plain (unconverted) tables
// are skipped — EnsurePartitions adds their default once they are converted.
// Runs before EnsurePartitions on boot, so a fresh install has the default
// before any traffic.
func (d *Database) migratePartitionDefaultPartitions() error {
	if !d.dialect.IsPostgres() {
		return nil
	}
	for _, def := range partitionTables {
		var isPartitioned bool
		if err := d.db.Raw(`
			SELECT EXISTS (
				SELECT 1 FROM pg_partitioned_table pt
				JOIN pg_class c ON c.oid = pt.partrelid
				WHERE c.relname = ?
			)`, def.tableName).Scan(&isPartitioned).Error; err != nil {
			log.Printf("v51 default-partition probe warning for %s: %v", def.tableName, err)
			continue
		}
		if !isPartitioned {
			continue
		}
		if err := d.execMaintenanceDDL(fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s_default PARTITION OF %s DEFAULT`, def.tableName, def.tableName)); err != nil {
			// Log-and-continue (not fatal), matching EnsurePartitions — which runs
			// immediately after on the same boot and idempotently retries the same
			// CREATE. A fatal error here would crash-loop the process over a
			// non-critical partition-hygiene step.
			log.Printf("v51 create default partition warning for %s: %v", def.tableName, err)
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
	// Partitioned, ~44k rows/day, and a 2-day retention window — so it churns
	// harder than several tables already on this list, yet was never tuned.
	"denied_events",
	// Measured on production while tracing the dashboard's cost: these are among
	// the largest relations in the database and none of them was being tuned.
	// flow_rollups in particular is the SECOND biggest table there (49.7M rows /
	// 9.4 GB) and is written continuously by the 5-minute rollup ladder.
	"flow_rollups",
	"flow_detections",
	"hardware_sensors",
	"security_stats",
	"disk_usage",
	// v72 normalized event tables: net_events is the traffic class of syslog
	// re-typed (the same volume as the dominant syslog_messages stream, in
	// daily leaves), net_event_rollups is upserted every hour and rewritten
	// once per day, sec_events is small but partitioned like the rest.
	"net_events",
	"sec_events",
	"net_event_rollups",
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
		// Storage parameters do NOT propagate from a partitioned parent to its
		// children, and Postgres rejects them on the parent outright ("specify
		// storage parameters for its leaf partitions instead"). Applying them to
		// the parent and logging the failure therefore meant the aggressive
		// settings SILENTLY stopped applying the moment a table was partitioned —
		// every leaf ran at the 20% default scale factor instead of 1%.
		//
		// That is load-bearing, not cosmetic. A monthly partition only stays near
		// its live size because rows deleted by retention free pages that later
		// inserts into that same still-open partition reuse. Vacuum has to keep up
		// for that to happen; at a 20% scale factor on a multi-GB partition it does
		// not, and the partition grows toward its full ingest size instead.
		for _, target := range d.autovacuumTargets(table) {
			// A leaf that already carries both parameter sets needs nothing: an
			// ALTER TABLE SET takes SHARE UPDATE EXCLUSIVE on the leaf and
			// rewrites its pg_class row, and with the v72 daily leaves there
			// are ~40 of them per boot — the catalog read is the cheaper no-op.
			if d.autovacuumConfigured(target) {
				continue
			}
			sql := fmt.Sprintf(`
			ALTER TABLE %s SET (
				autovacuum_vacuum_scale_factor = 0.01,
				autovacuum_analyze_scale_factor = 0.05,
				autovacuum_vacuum_cost_delay = 10,
				autovacuum_vacuum_cost_limit = 2000
			)`, target)
			if err := d.execMaintenanceDDL(sql); err != nil {
				// Log but don't fail - table might not exist yet on this deployment
				log.Printf("Autovacuum config warning for %s: %v", target, err)
				continue
			}

			// INSERT-driven autovacuum, issued as a SEPARATE statement.
			//
			// The settings above only govern vacuums triggered by dead tuples. An
			// append-only telemetry table produces almost none, so on production
			// syslog_messages the vacuum that maintains the VISIBILITY MAP was
			// instead governed by the global autovacuum_vacuum_insert_scale_factor
			// of 0.2 — roughly 19M inserts on a 99M-row table, against an ingest of
			// ~4.5M rows/day. The last day of rows therefore never had its
			// visibility map set, and every index-only scan over the recent window
			// degraded into millions of random heap fetches: the dashboard's 24h
			// GROUP BY measured 10s with 4,299,238 heap fetches. These two settings
			// are what stop that.
			//
			// Separate from the ALTER above on purpose. ALTER TABLE is atomic and
			// these two reloptions are PostgreSQL 13+, so folding them into one
			// statement would mean an older server rejects the whole thing and
			// silently loses the four aggressive settings it applies today —
			// leaving the table worse off than before while only logging a warning.
			// Split, an old server simply keeps what it has and skips these.
			insertSQL := fmt.Sprintf(`
			ALTER TABLE %s SET (
				autovacuum_vacuum_insert_scale_factor = 0.005,
				autovacuum_vacuum_insert_threshold = 100000
			)`, target)
			// Logged BEFORE the insert-params attempt, not after: the four
			// settings above are already applied at this point, so skipping this
			// line when only the PG13+ parameters are rejected would report a
			// total failure on every boot of an older server.
			log.Printf("Configured autovacuum for %s", target)
			if err := d.execMaintenanceDDL(insertSQL); err != nil {
				log.Printf("Autovacuum insert-threshold config warning for %s (PostgreSQL 13+ only): %v", target, err)
				continue
			}
		}
	}

	return nil
}

// autovacuumConfigured reports whether rel's reloptions already carry the
// settings ConfigureAutovacuum applies — both statements' worth, so a
// pre-PG13 server (where the insert parameters are rejected) keeps retrying
// them exactly as before. False on any probe error, which re-applies.
func (d *Database) autovacuumConfigured(rel string) bool {
	var opts string
	if err := d.db.Raw(`SELECT COALESCE(array_to_string(reloptions, ','), '') FROM pg_class WHERE oid = to_regclass(?)`, rel).
		Scan(&opts).Error; err != nil {
		return false
	}
	return strings.Contains(opts, "autovacuum_vacuum_scale_factor=0.01") &&
		strings.Contains(opts, "autovacuum_vacuum_insert_threshold=100000")
}

// autovacuumTargets resolves a configured table name to the relations that can
// actually carry storage parameters: the leaf partitions when it is partitioned,
// otherwise the table itself. A partitioned parent accepts no reloptions, so
// addressing it is always a no-op.
//
// Returns the table unchanged on any error — the caller's per-target ALTER is
// already failure-tolerant, so a probe failure degrades to today's behaviour
// rather than skipping the table entirely.
func (d *Database) autovacuumTargets(table string) []string {
	var isPartitioned bool
	if err := d.db.Raw(`SELECT EXISTS (
		SELECT 1 FROM pg_partitioned_table pt
		JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = ?)`, table).Scan(&isPartitioned).Error; err != nil {
		return []string{table}
	}
	if !isPartitioned {
		return []string{table}
	}
	var leaves []string
	if err := d.db.Raw(`
		SELECT c.relname
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class parent ON parent.oid = i.inhparent
		WHERE parent.relname = ?`, table).Scan(&leaves).Error; err != nil || len(leaves) == 0 {
		return []string{table}
	}
	return leaves
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

// migrateDeviceRetiredAt (v60) adds Device.retired_at (+ its index): the
// soft-delete marker behind retire/restore (v0.11.239). Same shape as v4 —
// AutoMigrate only adds what's missing, so it is idempotent, and fresh installs
// already have the column from the baseline run against the current model.
func (d *Database) migrateDeviceRetiredAt() error {
	return d.db.AutoMigrate(&models.Device{})
}

// orphanDeviceSourceTables are the small, device_id-indexed tables the v61
// migration scans for device ids that no longer resolve. The partitioned
// telemetry parents (interface_stats, system_status, ...) are deliberately NOT
// scanned: a DISTINCT over millions of rows has no place in a startup migration,
// and any device that ever produced telemetry also has alerts or uptime rows.
var orphanDeviceSourceTables = []string{
	"alerts", "device_config_revisions", "device_alert_configs", "uptime_records", "vpn_status",
}

// migrateMaterializeOrphanedDevices (v61) recreates, as RETIRED rows, the
// devices that were removed by the pre-v0.11.239 DeleteDevice: that path
// deleted only the devices row and left every child table keyed by a
// device_id that no longer resolves (prod 2026-09-06: device 4 with 1.28M
// interface_stats, 552 alerts, 43 config revisions rendering as "DEV-4" with a
// dead link). Recreating the row under its ORIGINAL id reattaches the history
// with zero child-row rewrites; the device can then be restored or purged like
// any other retired device.
//
// Name and IP are recovered from the newest DEVICE_OFFLINE/online alert
// message ("Device <name> (<ip>) is offline" / "... is back online"), anchored
// on the LAST "(ip)" group before the suffix because names may contain
// parentheses. Fallback: "Removed device #<id>" / 0.0.0.0, also used when the
// recovered name collides with an existing device (names are unique). The
// `device_id > 0` guard is mandatory: site digest alerts and cross-device flow
// detections carry device_id 0 and must never materialize a "device 0".
//
// Idempotent by construction (only ids absent from devices are inserted). On
// Postgres the id sequence is bumped past the highest id afterwards so an
// orphan above the sequence cannot make a later CreateDevice fail with 23505.
//
// The whole migration — orphan scans, identity recovery, inserts and the
// sequence bump — runs in ONE transaction with `SET LOCAL statement_timeout =
// 0` on Postgres, the ensureInterfaceAddrUniqueIndex / v54 / v34 pattern:
// AUDIT-037's per-connection 30s statement_timeout applies to every pooled
// connection, and a DISTINCT + `NOT IN (SELECT id FROM devices)` anti-join over
// a prod-sized alerts or uptime_records table can exceed it and be canceled
// mid-migration. The transaction also makes the insert set atomic: a partial
// materialization can never be recorded as applied.
func (d *Database) migrateMaterializeOrphanedDevices() error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if d.dialect.IsPostgres() {
			if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
				return fmt.Errorf("lift statement_timeout: %w", err)
			}
		}
		return d.materializeOrphanedDevices(tx)
	})
}

// materializeOrphanedDevices is the body of migration v61, run on the
// transaction migrateMaterializeOrphanedDevices opens.
func (d *Database) materializeOrphanedDevices(tx *gorm.DB) error {
	orphans := map[uint]struct{}{}
	for _, table := range orphanDeviceSourceTables {
		if !tx.Migrator().HasTable(table) {
			continue
		}
		var ids []uint
		if err := tx.Table(table).Distinct("device_id").
			Where("device_id > 0 AND device_id NOT IN (SELECT id FROM devices)").
			Pluck("device_id", &ids).Error; err != nil {
			return fmt.Errorf("scan %s for orphaned device ids: %w", table, err)
		}
		for _, id := range ids {
			orphans[id] = struct{}{}
		}
	}
	if len(orphans) == 0 {
		return nil
	}
	sorted := make([]uint, 0, len(orphans))
	for id := range orphans {
		sorted = append(sorted, id)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	now := time.Now().UTC()
	inserted := 0
	for _, id := range sorted {
		name, ip := recoverOrphanedDeviceIdentity(tx, id)
		fallback := fmt.Sprintf("Removed device #%d", id)
		if name == "" {
			name, ip = fallback, "0.0.0.0"
		} else {
			// Name uniqueness here is checked against EVERY device, not only
			// the active ones: on an upgraded install this ran under the old
			// global unique index (v63 relaxes it to active devices only),
			// and a materialized retired row must not shadow a live name. On
			// a fresh install there is no name uniqueness at all between v1
			// (the non-unique idx_devices_name from the model tag) and v63,
			// which is harmless: a fresh database has no orphans to recover.
			var clash int64
			if err := tx.Model(&models.Device{}).Where("name = ?", name).Count(&clash).Error; err != nil {
				return fmt.Errorf("materialize device %d: name check: %w", id, err)
			}
			if clash > 0 {
				log.Printf("migrate v61: device %d recovered name %q is already in use; using %q", id, name, fallback)
				name, ip = fallback, "0.0.0.0"
			}
		}
		// Explicit id + every defaulted column spelled out, via raw SQL so the
		// insert is unambiguous on both backends (GORM Create treats id 0 and
		// zero-valued defaults specially). last_polled stays NULL: the device
		// was never polled by this row.
		if err := tx.Exec(`INSERT INTO devices (id, name, ip_address, snmp_port, snmp_version, enabled, public_visible, vendor,
			wan_speed_mbps, sslvpn_users, sslvpn_tunnels, ssh_port, ssh_poll_enabled, ssh_poll_interval, api_port, api_insecure_tls,
			created_at, updated_at, status, retired_at)
			VALUES (?, ?, ?, 161, '2c', ?, ?, 'fortigate', 1000, 0, 0, 22, ?, 900, 443, ?, ?, ?, 'offline', ?)`,
			id, name, ip, false, false, false, false, now, now, now).Error; err != nil {
			return fmt.Errorf("materialize device %d: insert: %w", id, err)
		}
		inserted++
		log.Printf("migrate v61: materialized retired device %d %q (%s) from orphaned history", id, name, ip)
	}

	if inserted > 0 && d.dialect.IsPostgres() {
		var seq string
		if err := tx.Raw(`SELECT COALESCE(pg_get_serial_sequence('devices', 'id'), '')`).Scan(&seq).Error; err != nil {
			return fmt.Errorf("materialize devices: resolve id sequence: %w", err)
		}
		if seq != "" {
			if err := tx.Exec(fmt.Sprintf(
				`SELECT setval('%s', GREATEST((SELECT COALESCE(MAX(id), 1) FROM devices), (SELECT last_value FROM %s)))`,
				seq, seq)).Error; err != nil {
				return fmt.Errorf("materialize devices: bump id sequence %s: %w", seq, err)
			}
		}
	}
	return nil
}

// recoverOrphanedDeviceIdentity returns the (name, ip) parsed from the newest
// device-status alert for id, or ("", "") when no message has the expected
// shape. See migrateMaterializeOrphanedDevices; tx is the migration's
// transaction.
func recoverOrphanedDeviceIdentity(tx *gorm.DB, id uint) (string, string) {
	var msgs []string
	if err := tx.Model(&models.Alert{}).
		Where("device_id = ? AND message LIKE ? AND (message LIKE ? OR message LIKE ?)", id, "Device %", "% is offline", "% is back online").
		Order("timestamp DESC").Limit(1).Pluck("message", &msgs).Error; err != nil || len(msgs) == 0 {
		return "", ""
	}
	return parseDeviceStatusMessage(msgs[0])
}

// parseDeviceStatusMessage extracts (name, ip) from "Device <name> (<ip>) is
// offline" / "Device <name> (<ip>) is back online", anchoring on the LAST
// "(ip)" group so a name containing parentheses parses correctly. Returns
// ("", "") for anything else (including an unparsable ip).
func parseDeviceStatusMessage(msg string) (string, string) {
	body, ok := strings.CutPrefix(msg, "Device ")
	if !ok {
		return "", ""
	}
	if b, found := strings.CutSuffix(body, " is offline"); found {
		body = b
	} else if b, found := strings.CutSuffix(body, " is back online"); found {
		body = b
	} else {
		return "", ""
	}
	if !strings.HasSuffix(body, ")") {
		return "", ""
	}
	open := strings.LastIndex(body, " (")
	if open <= 0 {
		return "", ""
	}
	name := strings.TrimSpace(body[:open])
	ip := body[open+2 : len(body)-1]
	if name == "" || net.ParseIP(ip) == nil {
		return "", ""
	}
	return name, ip
}

// migrateCloseAlertsForRetiredDevices (v62) closes the open alert and incident
// rows of EVERY retired device, exactly as RetireDevice does at retire time
// (closeAlertsForRetiredDevice, note "Auto-resolved: device retired").
//
// Why: v61 recreated deleted devices as retired rows but left their alert rows
// as they were, and on production the recovered device carried an open,
// unacknowledged DEVICE_OFFLINE raised inside the 24h GetUnacknowledgedAlerts
// window — CheckEscalations kept re-notifying it. v61 has already been
// recorded as applied there, so the fix has to be a new migration rather than
// a change inside v61's loop. Sweeping every retired device (not only the
// v61-materialized ones) also covers any row a future code path retires
// without the alert step.
//
// Idempotent by construction: the helper's UPDATEs only match unacknowledged
// or unresolved rows, so a rerun finds nothing. One transaction with
// `SET LOCAL statement_timeout = 0` on Postgres, the v61 pattern: the alert
// UPDATEs are indexed on device_id but a prod-sized alerts table can still
// exceed AUDIT-037's per-connection 30s statement_timeout.
func (d *Database) migrateCloseAlertsForRetiredDevices() error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if d.dialect.IsPostgres() {
			if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
				return fmt.Errorf("lift statement_timeout: %w", err)
			}
		}
		var ids []uint
		if err := tx.Model(&models.Device{}).Where("retired_at IS NOT NULL").Order("id").
			Pluck("id", &ids).Error; err != nil {
			return fmt.Errorf("list retired devices: %w", err)
		}
		now := time.Now().UTC()
		for _, id := range ids {
			if err := closeAlertsForRetiredDevice(tx, id, "Auto-resolved: device retired", now); err != nil {
				return fmt.Errorf("migrate v62: %w", err)
			}
		}
		if len(ids) > 0 {
			log.Printf("migrate v62: closed open alerts and incidents for %d retired device(s)", len(ids))
		}
		return nil
	})
}

// migrateDeviceNameUniqueAmongActive (v63) relaxes device-name uniqueness
// from "every row" to "active rows only" so a replacement device can reuse a
// retired device's name while the retired row keeps its history under its
// own id (v0.11.241). The model tag went from uniqueIndex to index, so
// AutoMigrate now declares the plain lookup index idx_devices_name; this
// migration converges an upgraded install (whose idx_devices_name is the OLD
// global unique index) onto the same shape: drop it, recreate it non-unique,
// and add the partial unique index idx_devices_name_active on
// (name) WHERE retired_at IS NULL. SQLite supports partial indexes, so the
// DDL is identical on both dialects and every statement is IF (NOT) EXISTS,
// which makes a rerun a no-op.
//
// Pre-flight: if two ACTIVE devices already share a name (impossible under
// the old index, but a hand-edited database is not) the migration returns an
// error naming them instead of half-applying — the partial unique index could
// not be built and the global one would already be gone. One transaction with
// `SET LOCAL statement_timeout = 0` on Postgres, the v61/v62 pattern, so the
// index build on a large devices table is never cancelled mid-swap.
func (d *Database) migrateDeviceNameUniqueAmongActive() error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if d.dialect.IsPostgres() {
			if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
				return fmt.Errorf("lift statement_timeout: %w", err)
			}
		}
		var dups []struct {
			Name string
			N    int64
		}
		if err := tx.Raw(`SELECT name, count(*) AS n FROM devices WHERE retired_at IS NULL GROUP BY name HAVING count(*) > 1 ORDER BY name`).
			Scan(&dups).Error; err != nil {
			return fmt.Errorf("migrate v63: scan active duplicate names: %w", err)
		}
		if len(dups) > 0 {
			parts := make([]string, 0, len(dups))
			for _, dup := range dups {
				parts = append(parts, fmt.Sprintf("%q (%d active rows)", dup.Name, dup.N))
			}
			return fmt.Errorf("migrate v63: active devices share a name, retire or rename them first: %s", strings.Join(parts, ", "))
		}
		if err := tx.Exec(`DROP INDEX IF EXISTS idx_devices_name`).Error; err != nil {
			return fmt.Errorf("migrate v63: drop global unique name index: %w", err)
		}
		if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_devices_name ON devices (name)`).Error; err != nil {
			return fmt.Errorf("migrate v63: create name lookup index: %w", err)
		}
		if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_name_active ON devices (name) WHERE retired_at IS NULL`).Error; err != nil {
			return fmt.Errorf("migrate v63: create active-name unique index: %w", err)
		}
		return nil
	})
}

// migrateDeviceUUID (v64) adds Device.uuid (+ its unique index) and backfills
// every existing row with a fresh UUID (v0.11.242). AutoMigrate adds the
// column as NULL on an upgraded install, and rows inserted by v61's raw INSERT
// (which does not name the column) are NULL on a fresh install too — the
// unique index tolerates NULLs on both dialects, so the ADD COLUMN itself
// cannot fail, and the backfill then removes them. An empty string is treated
// the same as NULL so a row created by any pre-hook path is covered as well.
//
// The backfill is a raw UPDATE per row rather than a GORM Update so
// updated_at is left alone (the device did not change; it merely gained an
// identity). Idempotent: a rerun selects nothing. One transaction with
// `SET LOCAL statement_timeout = 0` on Postgres, the v61/v62/v63 pattern —
// the table is tiny, but the migration must never be the one that trips
// AUDIT-037's per-connection statement timeout.
func (d *Database) migrateDeviceUUID() error {
	if err := d.db.AutoMigrate(&models.Device{}); err != nil {
		return fmt.Errorf("migrate v64: add uuid column: %w", err)
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		if d.dialect.IsPostgres() {
			if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
				return fmt.Errorf("lift statement_timeout: %w", err)
			}
		}
		var ids []uint
		if err := tx.Model(&models.Device{}).Where("uuid IS NULL OR uuid = ''").Order("id").
			Pluck("id", &ids).Error; err != nil {
			return fmt.Errorf("migrate v64: list devices without a uuid: %w", err)
		}
		for _, id := range ids {
			if err := tx.Exec(`UPDATE devices SET uuid = ? WHERE id = ?`, uuid.NewString(), id).Error; err != nil {
				return fmt.Errorf("migrate v64: backfill uuid for device %d: %w", id, err)
			}
		}
		if len(ids) > 0 {
			log.Printf("migrate v64: backfilled uuid for %d device(s)", len(ids))
		}
		return nil
	})
}

// migrateDeviceSSHHostKey (v6) adds Device.ssh_host_key — the pinned SSH
// host-key fingerprint used for change detection. Additive nullable column;
// AutoMigrate adds only what's missing, so this is idempotent and safe on a
// populated database.
func (d *Database) migrateDeviceSSHHostKey() error {
	return d.db.AutoMigrate(&models.Device{})
}

// migrateDeviceAPICredentials (v49) adds Device.api_token (encrypted vendor
// REST credential for config automation) and Device.api_port (mgmt HTTPS port,
// default 443). Additive nullable columns; AutoMigrate adds only what's
// missing, so this is idempotent and safe on a populated database.
func (d *Database) migrateDeviceAPICredentials() error {
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
// A review found the server had been storing frame_length verbatim, so every
// dashboard chart / top-N list under-reported real traffic by 1:N.
//
// Idempotency: the WHERE clause selects only rows that haven't been migrated
// yet (sampling_rate > 1 AND packets = 1). New inserts already write
// Packets = sampling_rate (the parser change now lives in the collector's
// sFlow parser; the server's own copy was removed in v0.11.228),
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
	// AUDIT D1: route through execMaintenanceDDL, which lifts the per-connection
	// 30s statement_timeout (AUDIT-037) for the duration of the DDL. On a
	// populated flow_samples the first-time ALTER COLUMN ... TYPE is a full table
	// rewrite; without the lift it would be cancelled at 30s and crash-loop boot.
	// (Latent today — prod is past v9 and fresh installs get correct types from
	// AutoMigrate so this is a no-op — but cheap to harden.)
	if err := d.execMaintenanceDDL(stmt); err != nil {
		return fmt.Errorf("migrate v9 flow_samples widen int columns: %w", err)
	}
	log.Printf("migrate v9 flow_samples widen: src_port/dst_port -> integer, sequence_number/sampling_rate/input_if_index/output_if_index -> bigint")
	return nil
}

// migrateSystemStatusSource (v52, AUDIT AL-M2) adds the `source` column to
// system_status so the alert engine can tell which collector writer produced a
// row (SNMP full poll vs SSH-perf freshness row) and trust a 0 session_count as
// "idle" (allowing SESSIONS_HIGH to auto-resolve) only from an authoritative
// SNMP row. Adding a column with a constant default is metadata-only on
// PostgreSQL 11+ (no table rewrite), fast even on a partitioned system_status;
// routed through execMaintenanceDDL so the lifted statement_timeout covers the
// ADD propagating across all partitions.
func (d *Database) migrateSystemStatusSource() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.SystemStatus{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE system_status ADD COLUMN IF NOT EXISTS source varchar(16) NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate v52 add system_status.source: %w", err)
	}
	log.Printf("migrate v52 system_status.source: ensured column exists (varchar(16) not null default '')")
	return nil
}

// migrateServerMetrics (v53) creates the server_metrics table on existing
// databases. The baseline AutoMigrate covers fresh installs only.
func (d *Database) migrateServerMetrics() error {
	return d.db.AutoMigrate(&models.ServerMetric{})
}

// migrateDevicePurgeJobs (v65) creates device_purge_jobs, the queue/progress
// table of the permanent device purge worker (v0.11.243). AutoMigrate is
// idempotent, so a fresh install (baseline already built it) is a no-op.
func (d *Database) migrateDevicePurgeJobs() error {
	return d.db.AutoMigrate(&models.DevicePurgeJob{})
}

// migrateNormalizeBackfillJobs (v73) creates normalize_backfill_jobs, the
// queue/progress table of the one-time normalized-event backfill (Phase 1,
// S-5; v0.11.297). Same shape as v65: a small AutoMigrate, idempotent.
func (d *Database) migrateNormalizeBackfillJobs() error {
	return d.db.AutoMigrate(&models.NormalizeBackfillJob{})
}

// migrateArchiveManifestTables (v75) creates the raw archive's manifest:
// archive_chunks, archive_objects, archive_months and archive_id_marks (archive
// plan PR 3). New, small tables only — nothing touches syslog_messages or the
// flow tables, so there is no lock to wait for. AutoMigrate is idempotent: a
// fresh install (the baseline already built them) is a no-op.
func (d *Database) migrateArchiveManifestTables() error {
	return d.db.AutoMigrate(&models.ArchiveChunk{}, &models.ArchiveObject{}, &models.ArchiveMonth{}, &models.ArchiveIDMark{})
}

// migrateArchiveChunkRetryCounters (v76) adds archive_chunks.mismatches and
// verify_failures (archive plan PR 4 review): the worker re-exports a chunk
// only after a mismatch, at most models.ArchiveMaxMismatches times, and
// retries a transient verification failure with backoff. Two NOT NULL
// DEFAULT 0 columns on a small table (metadata-only on PostgreSQL ≥ 11);
// AutoMigrate is idempotent.
func (d *Database) migrateArchiveChunkRetryCounters() error {
	return d.db.AutoMigrate(&models.ArchiveChunk{})
}

// migrateArchiveGateEvents (v77) creates archive_gate_events (archive plan PR
// 7 review): the intervals a stream's raw deletes did not wait for the
// archive (an override, or archiving disabled), so a month whose archiving
// overlaps one is sealed partial. The overrides made before it (0.11.304+)
// are rebuilt from their audit rows (backfillArchiveGateOverrides). Disabled
// periods before it cannot be rebuilt; the seal treats them conservatively
// (worker/seal.go, "unrecorded"). AutoMigrate and the backfill are idempotent.
func (d *Database) migrateArchiveGateEvents() error {
	if err := d.db.AutoMigrate(&models.ArchiveGateEvent{}); err != nil {
		return err
	}
	return d.db.Transaction(backfillArchiveGateOverrides)
}

// archiveOverrideAuditRe parses an archive_gate_override audit target, as the
// CLI and the API write it: "stream=<s> until=<RFC 3339> reason=..." or
// "stream=<s> re-engaged reason=...".
var archiveOverrideAuditRe = regexp.MustCompile(`^stream=(syslog|flows) (?:until=(\S+)|re-engaged)(?: |$)`)

// backfillArchiveGateOverrides rebuilds the override intervals from the
// archive_gate_override audit rows written before archive_gate_events
// existed: a release at t until u is [t, u); a later release or re-engage of
// the same stream at t' ends it at t' if earlier. Only rows older than the
// first recorded override event are used, and an interval already present
// (same stream and start) is not added again, so a re-run adds nothing.
func backfillArchiveGateOverrides(tx *gorm.DB) error {
	q := tx.Model(&models.AuditLog{}).Where("action = ?", "archive_gate_override")
	var first []models.ArchiveGateEvent
	if err := tx.Where("kind = ?", models.ArchiveGateEventOverride).Order("created_at").Limit(1).Find(&first).Error; err != nil {
		return err
	}
	if len(first) > 0 {
		q = q.Where("created_at < ?", first[0].CreatedAt)
	}
	var rows []models.AuditLog
	if err := q.Order("created_at, id").Find(&rows).Error; err != nil {
		return fmt.Errorf("archive gate events: read the override audit rows: %w", err)
	}
	var evs []*models.ArchiveGateEvent
	open := map[string]*models.ArchiveGateEvent{}
	for _, r := range rows {
		m := archiveOverrideAuditRe.FindStringSubmatch(r.Target)
		if m == nil {
			log.Printf("archive gate events: audit row %d (%q) is not an override target; skipped", r.ID, r.Target)
			continue
		}
		at := r.CreatedAt.UTC()
		if e := open[m[1]]; e != nil && e.To.After(at) {
			t := at
			e.To = &t
		}
		delete(open, m[1])
		if m[2] == "" {
			continue
		}
		until, err := time.Parse(time.RFC3339, m[2])
		if err != nil || !until.After(at) {
			continue
		}
		u := until.UTC()
		e := &models.ArchiveGateEvent{Stream: m[1], Kind: models.ArchiveGateEventOverride, From: at, To: &u}
		evs = append(evs, e)
		open[m[1]] = e
	}
	added := 0
	for _, e := range evs {
		var n int64
		if err := tx.Model(&models.ArchiveGateEvent{}).Where("stream = ? AND kind = ? AND from_ts = ?", e.Stream, e.Kind, e.From).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		if err := tx.Create(e).Error; err != nil {
			return fmt.Errorf("archive gate events: record a past override of %s: %w", e.Stream, err)
		}
		added++
	}
	if added > 0 {
		log.Printf("archive gate events: rebuilt %d past override interval(s) from the audit log", added)
	}
	return nil
}

// v74's lock bounds. Package vars so the PostgreSQL test can shrink them.
var (
	// syslogFormatLockTimeout bounds each attempt as a WHOLE: it is both the
	// lock_timeout and the statement_timeout of the ALTER. lock_timeout alone
	// applies per lock wait, and on a partitioned table the ALTER holds ACCESS
	// EXCLUSIVE on the parent while it waits for each leaf in turn, so readers
	// on several leaves could stall every insert for (leaves+1) x the timeout.
	// The statement_timeout caps the whole statement, which is safe because
	// the ALTER itself is metadata-only (milliseconds once it has its locks).
	syslogFormatLockTimeout = 2 * time.Second
	// syslogFormatLockRetries / syslogFormatRetrySleep: ~3.5 min of attempts
	// before the migration fails (and the process exits to be restarted).
	syslogFormatLockRetries = 30
	syslogFormatRetrySleep  = 5 * time.Second
)

// migrateSyslogFormatColumn (v74) adds syslog_messages.format, the stored
// collector format hint (models.SyslogMessage.StoredFormat).
//
// It must be metadata-only: on production syslog_messages is a ~161 GB plain
// heap under constant ingest. ADD COLUMN of a nullable column with no default
// never rewrites the table (PostgreSQL 11+; it only adds a pg_attribute row,
// existing tuples read NULL), on a plain heap and on a partitioned parent,
// which propagates the column to every leaf the same way. No default, no NOT
// NULL, no index. The one cost is the ACCESS EXCLUSIVE lock, held for
// milliseconds but QUEUED behind any running reader — and every insert queues
// behind the waiting ALTER (on a partitioned table it also holds the parent
// while it waits for each leaf). So each attempt runs under a short
// lock_timeout AND statement_timeout of the same bound, and a lock timeout,
// statement timeout or deadlock is retried after a pause: ingest stalls at
// most about syslogFormatLockTimeout per attempt, whatever the number of
// leaves. Long readers are not cancelled by the queued lock (an
// anti-wraparound autovacuum, a pg_dump, an idle-in-transaction psql), so the
// operator pre-flight in MIGRATING.md checks for them first. The catalog is read first so a
// fresh install (the baseline AutoMigrate already created the column) takes no
// lock at all.
//
// Failing is correct when the lock never comes: the model writes the column
// on every insert, so a binary must not run against a table without it.
func (d *Database) migrateSyslogFormatColumn() error {
	if !d.dialect.IsPostgres() {
		// SQLite test backend: ADD COLUMN IF NOT EXISTS is not SQLite syntax.
		if d.db.Migrator().HasColumn(&models.SyslogMessage{}, "format") {
			return nil
		}
		return d.db.Migrator().AddColumn(&models.SyslogMessage{}, "StoredFormat")
	}
	var exists bool
	if err := d.db.Raw(`SELECT EXISTS (SELECT 1 FROM pg_attribute
		WHERE attrelid = to_regclass('syslog_messages') AND attname = 'format' AND NOT attisdropped)`).Scan(&exists).Error; err != nil {
		return fmt.Errorf("migrate v74: probe syslog_messages.format: %w", err)
	}
	if exists {
		log.Printf("migrate v74 syslog_messages.format: column already present")
		return nil
	}
	const ddl = `ALTER TABLE syslog_messages ADD COLUMN IF NOT EXISTS format smallint`
	for attempt := 1; ; attempt++ {
		err := d.db.Transaction(func(tx *gorm.DB) error {
			// Rendered literals, never input: a package duration (see execCronDDL).
			ms := syslogFormatLockTimeout.Milliseconds()
			if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", ms)).Error; err != nil {
				return fmt.Errorf("set lock_timeout: %w", err)
			}
			if err := tx.Exec(fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms)).Error; err != nil {
				return fmt.Errorf("set statement_timeout: %w", err)
			}
			return tx.Exec(ddl).Error
		})
		if err == nil {
			log.Printf("migrate v74 syslog_messages.format: added (smallint, nullable, no default — metadata only)")
			return nil
		}
		if !(lockRetryable(err) || sqlState(err) == "57014") || attempt >= syslogFormatLockRetries {
			return fmt.Errorf("migrate v74 add syslog_messages.format (attempt %d/%d): %w", attempt, syslogFormatLockRetries, err)
		}
		log.Printf("migrate v74 syslog_messages.format: locks not granted within %s (attempt %d/%d, SQLSTATE %s); retrying in %s",
			syslogFormatLockTimeout, attempt, syslogFormatLockRetries, sqlState(err), syslogFormatRetrySleep)
		time.Sleep(syslogFormatRetrySleep)
	}
}

// migrateFlowSummaries (v66) creates the three flow-summary tables. They are
// deliberately NOT partitioned: the whole point is that they are small — under
// a million rows for six months of history against 118M in flow_rollups — so
// partitioning would add machinery without pruning anything worth pruning.
func (d *Database) migrateFlowSummaries() error {
	return d.db.AutoMigrate(&models.FlowSummary{}, &models.FlowSummaryTop{}, &models.FlowSummaryBucket{})
}

// migrateSyslogSeverityIndex (v54) creates the (severity, timestamp) composite
// that per-severity retention deletes need.
//
// It is an explicit migration rather than a model tag because a tag would do
// NOTHING on an existing database: tags are only applied by migrateBaseline's
// AutoMigrate loop, and runMigrationList skips any version already recorded, so
// v1 never runs again. EnsurePartitions is no help either — it returns early for
// a plain table, which is what syslog_messages is here. The tag is kept as well,
// so fresh installs get the index from the baseline.
//
// The timeout is lifted deliberately. AutoMigrate would have run this on an
// ordinary pooled connection carrying the DSN's 30s statement_timeout AND
// swallowed the resulting abort as a warning while still recording the migration
// as applied — a silent no-op. This runs its own transaction so the lift is
// explicit and a failure is a real error.
func (d *Database) migrateSyslogSeverityIndex() error {
	const create = `CREATE INDEX IF NOT EXISTS idx_syslog_sev_ts ON syslog_messages (severity, "timestamp")`
	// Superseded by the composite, which covers it as a leading prefix. Dropped
	// AFTER the create so no query is ever left without an index to use.
	const dropOld = `DROP INDEX IF EXISTS idx_syslog_severity`

	if !d.dialect.IsPostgres() {
		// SET LOCAL is Postgres-only syntax and registered migrations also run
		// against SQLite in tests.
		if err := d.db.Exec(create).Error; err != nil {
			return fmt.Errorf("create idx_syslog_sev_ts: %w", err)
		}
		return d.db.Exec(dropOld).Error
	}

	d.logSyslogIndexScale()

	stop := make(chan struct{})
	d.watchIndexBuild("syslog_messages", stop)
	// Closed even when the DDL errors, so a failed build never leaks the poller.
	defer close(stop)

	return d.db.Transaction(func(tx *gorm.DB) error {
		// Lift the 30s timeout: this build takes minutes on a large table.
		if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
			return err
		}
		// The server default (64MB) forces an external merge sort that spills to
		// disk on a table this size. SET LOCAL reverts on commit.
		if err := tx.Exec("SET LOCAL maintenance_work_mem = '1GB'").Error; err != nil {
			return err
		}
		if err := tx.Exec(create).Error; err != nil {
			return fmt.Errorf("create idx_syslog_sev_ts: %w", err)
		}
		return tx.Exec(dropOld).Error
	})
}

// migrateDropRedundantSyslogDeviceIndex (v56) drops idx_syslog_messages_device_id.
//
// It is a strict leading prefix of idx_syslog_device_ts (device_id, timestamp),
// so the composite serves every device_id lookup the single-column index could
// — dropping it removes no capability, it only moves those lookups onto an index
// that is already there and already maintained.
//
// Measured on production: 881 MB for 14 scans across the whole life of the
// database, against a composite that answered the same shape 126 times. The
// device-filtered syslog page is the real consumer and it needs the composite,
// not this: its plan takes both predicates as an Index Cond and satisfies
// ORDER BY timestamp DESC from the backward scan, turning 16.2M matching rows
// into a 50-row walk. That plan is unaffected here.
//
// Removing the model tag alone would do nothing on an existing database — tags
// are only applied by migrateBaseline's AutoMigrate loop, and AutoMigrate
// creates indexes but never drops ones that disappear from a struct. Hence the
// explicit migration. partitionIndexPlan (migrate.go:266-318) already applied
// this same prefix-coverage rule, so a partitioned deployment never had the
// index and this is a no-op there.
func (d *Database) migrateDropRedundantSyslogDeviceIndex() error {
	const drop = `DROP INDEX IF EXISTS idx_syslog_messages_device_id`
	if !d.dialect.IsPostgres() {
		return d.db.Exec(drop).Error
	}
	// Dropping an index takes a brief ACCESS EXCLUSIVE lock. It is metadata-only
	// — no table rewrite, no scan — so it returns in milliseconds even on a
	// 72 GB table, unlike the build in v54 that needed the timeout lifted.
	if err := d.execMaintenanceDDL(drop); err != nil {
		return fmt.Errorf("migrate v56 drop idx_syslog_messages_device_id: %w", err)
	}
	log.Printf("migrate v56: dropped idx_syslog_messages_device_id (redundant leading prefix of idx_syslog_device_ts)")
	return nil
}

// migrateTrapEventsTimestampIndex (v57) gives trap_events a standalone
// timestamp index.
//
// The table had only idx_trap_device_ts (device_id, timestamp), which leads on
// device_id and so cannot serve the fleet-wide `SELECT MAX(timestamp)` the
// system-health composite runs to decide whether the trap receiver is up — that
// was a full scan of the table for one boolean badge. SyslogMessage, FlowSample
// and PingResult all declare a standalone timestamp index; trap_events was
// simply missed.
//
// Like v54 this needs to be an explicit migration as well as a model tag: tags
// are only applied by migrateBaseline's AutoMigrate loop, which never runs again
// on an existing database. The tag is kept so fresh installs get it from the
// baseline.
//
// Shape-aware by construction: on a fresh install trap_events is a partitioned
// parent and on production it is a plain heap, and CREATE INDEX on a partitioned
// parent cascades to the leaves (PG11+), so one statement covers both. It is
// also NOT a leading prefix of idx_trap_device_ts, so partitionIndexPlan's
// prefix-coverage rule keeps it.
//
// No timeout lift here, unlike v54: trap_events is a small table (production:
// ~200k rows / 61 MB) and this build returns in well under the 30s
// statement_timeout. If that ever stops being true the v54 shape is the model.
func (d *Database) migrateTrapEventsTimestampIndex() error {
	const create = `CREATE INDEX IF NOT EXISTS idx_trap_events_timestamp ON trap_events ("timestamp")`
	if !d.dialect.IsPostgres() {
		return d.db.Exec(create).Error
	}
	if err := d.execMaintenanceDDL(create); err != nil {
		return fmt.Errorf("migrate v57 create idx_trap_events_timestamp: %w", err)
	}
	log.Printf("migrate v57: ensured idx_trap_events_timestamp on trap_events")
	return nil
}

// migrateVPNStatusTimestampIndex (v67) adds a timestamp-leading index to
// vpn_status. GetAllLatestVPNStatuses — run every poller telemetry cycle, by
// VPN and overlay auto-detection, and by the VPN map page — filters the whole
// fleet on `timestamp >= now − 27h`, and with only (device_id) and
// (device_id, timestamp) to choose from, production ran it as a parallel
// sequential scan of all 841k rows to keep 12k: 81 ms, 12 times a minute,
// 3.8M tuples read per minute (measured 2026-09-26).
//
// The model tag carries the same index so fresh installs build it from the
// baseline; this migration is what reaches existing databases, where the
// baseline never runs again.
//
// Plain CREATE INDEX, as v57: vpn_status is 215 MB on production and builds in
// seconds. The build holds a SHARE lock, so the poller's vpn_status inserts
// wait for those seconds. vpn_status is never partitioned.
func (d *Database) migrateVPNStatusTimestampIndex() error {
	const create = `CREATE INDEX IF NOT EXISTS idx_vpn_status_timestamp ON vpn_status ("timestamp")`
	if !d.dialect.IsPostgres() {
		return d.db.Exec(create).Error
	}
	if err := d.execMaintenanceDDL(create); err != nil {
		return fmt.Errorf("migrate v67 create idx_vpn_status_timestamp: %w", err)
	}
	log.Printf("migrate v67: ensured idx_vpn_status_timestamp on vpn_status")
	return nil
}

// flowSummaryServiceSinceKey records when flows began recording a service
// port. Rollups from before it carry service_port 0 and summary buckets from
// before it have no service dimension, so a window reaching back past it shows
// Top services from the boundary on only (see serviceSinceBoundary). Absent
// means every row has one — a fresh install, or history reclassified since.
// Internal state: never user-editable.
const flowSummaryServiceSinceKey = "flow_summary_service_since"

// migrateFlowServicePortClassRev (v68) adds service_port and class_rev to
// flow_samples and flow_rollups, and — only when flow history already exists —
// stamps flowSummaryServiceSinceKey.
//
// ADD COLUMN with a constant default is a catalog-only change on PostgreSQL
// 11+, so neither 140M-row table is rewritten; the brief ACCESS EXCLUSIVE lock
// is taken while the poller (which runs the rollup ladder) is stopped by the
// container recreate. On a fresh install flow_samples is partitioned and the
// parent's ADD COLUMN reaches every partition.
func (d *Database) migrateFlowServicePortClassRev() error {
	if !d.dialect.IsPostgres() {
		if err := d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
			return err
		}
	} else {
		stmts := []string{
			`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS service_port integer NOT NULL DEFAULT 0`,
			`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS class_rev integer NOT NULL DEFAULT 0`,
			`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS service_port integer NOT NULL DEFAULT 0`,
			`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS class_rev integer NOT NULL DEFAULT 0`,
		}
		for _, s := range stmts {
			if err := d.execMaintenanceDDL(s); err != nil {
				return fmt.Errorf("migrate v68 flow service_port/class_rev: %w", err)
			}
		}
	}
	return d.markFlowSummaryServiceSince(time.Now())
}

// markFlowSummaryServiceSince stamps the service boundary when any flow
// history predates the column — a flow sample, rollup or summary top — and no
// boundary is recorded. Probing the source tables, not only the summary: an
// install upgrading across v66 and v68 at once has empty summary tables yet a
// year of rollups the summary backfill will later summarise without a service
// dimension. Idempotent: a re-run never moves an existing boundary.
func (d *Database) markFlowSummaryServiceSince(now time.Time) error {
	var existing int64
	if err := d.db.Model(&models.SystemSetting{}).Where("\"key\" = ?", flowSummaryServiceSinceKey).Count(&existing).Error; err != nil {
		return fmt.Errorf("migrate v68 read %s: %w", flowSummaryServiceSinceKey, err)
	}
	if existing > 0 {
		return nil
	}
	hasHistory := false
	for _, table := range []string{"flow_rollups", "flow_samples", "flow_summary_tops"} {
		var ids []uint
		if err := d.db.Table(table).Select("id").Limit(1).Pluck("id", &ids).Error; err != nil {
			return fmt.Errorf("migrate v68 probe %s: %w", table, err)
		}
		if len(ids) > 0 {
			hasHistory = true
			break
		}
	}
	if !hasHistory {
		return nil // fresh install: every row it writes carries a service port
	}
	if err := d.db.Create(&models.SystemSetting{
		Key: flowSummaryServiceSinceKey, Value: now.UTC().Format(time.RFC3339), Category: "system",
	}).Error; err != nil {
		return fmt.Errorf("migrate v68 write %s: %w", flowSummaryServiceSinceKey, err)
	}
	log.Printf("migrate v68: flows before %s carry no service port until history is reclassified", now.UTC().Format(time.RFC3339))
	return nil
}

// logSyslogIndexScale states up front why the wait is long, so the progress
// lines that follow have context.
func (d *Database) logSyslogIndexScale() {
	var info struct {
		Rows int64
		Size string
	}
	err := d.db.Raw(`
		SELECT COALESCE(GREATEST(c.reltuples, 0), 0)::bigint AS rows,
		       pg_size_pretty(pg_relation_size(c.oid))       AS size
		FROM pg_class c WHERE c.relname = 'syslog_messages'`).Scan(&info).Error
	if err != nil {
		return
	}
	log.Printf("index build syslog_messages: creating idx_syslog_sev_ts over ~%d rows (%s heap); "+
		"writes to this table are blocked until it completes", info.Rows, info.Size)
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

// migrateAlertFlowEnrichment (v32) supports the alerts overhaul: it links flow
// detections to the alert that represents them (single-feed de-dup) and stores
// ASN organization names on flow samples.
//   - flow_detections.alert_id (+ partial index WHERE alert_id IS NULL, matching
//     the hot "show only non-alerting detections" filter). flow_detections is not
//     partitioned, so a plain ALTER + CREATE INDEX suffices.
//   - flow_samples.src_asn_org / dst_asn_org. flow_samples is monthly RANGE-
//     partitioned; Postgres propagates ADD COLUMN to every partition automatically,
//     so execMaintenanceDDL on the parent is enough.
//
// AutoMigrate covers the SQLite (test) path; both are idempotent.
func (d *Database) migrateAlertFlowEnrichment() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowDetection{}, &models.FlowSample{})
	}
	stmts := []string{
		`ALTER TABLE flow_detections ADD COLUMN IF NOT EXISTS alert_id bigint`,
		`CREATE INDEX IF NOT EXISTS idx_flowdet_alert ON flow_detections (alert_id) WHERE alert_id IS NULL`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS src_asn_org text`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS dst_asn_org text`,
	}
	for _, s := range stmts {
		if err := d.execMaintenanceDDL(s); err != nil {
			return fmt.Errorf("migrate v32 alert_flow_enrichment: %w", err)
		}
	}
	log.Printf("migrate v32: ensured flow_detections.alert_id (+partial idx) and flow_samples.src/dst_asn_org")
	return nil
}

// migrateThreatFeedStatusTable (v31) creates the threat_feed_status table that
// records per-source feed outcomes for the admin Threat Intelligence page.
// AutoMigrate is idempotent and cross-dialect; the table is tiny (one row per
// feed source).
func (d *Database) migrateThreatFeedStatusTable() error {
	return d.db.AutoMigrate(&models.ThreatFeedStatus{})
}

// migrateEventRules (v35) creates the event_rules table backing the unified,
// vendor-aware alert/suppress rule engine. New table → plain AutoMigrate is
// sufficient and idempotent on both dialects. Seed defaults are inserted at
// runtime by EnsureDefaultRules (idempotent via SeedVersion), NOT here, so an
// operator who deletes a seed doesn't have it resurrected by a re-run.
func (d *Database) migrateEventRules() error {
	return d.db.AutoMigrate(&models.EventRule{})
}

// migrateAlertSiteScope (v36) adds alerts.site_id so a site-scoped, device-less
// alert (the SFLOW_SECURITY_DIGEST storm rollup, DeviceID 0) can name its site in
// the UI. Nullable column + index; PG uses ADD COLUMN IF NOT EXISTS routed through
// execMaintenanceDDL (statement_timeout safety), sqlite uses AutoMigrate.
func (d *Database) migrateAlertSiteScope() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.Alert{})
	}
	for _, s := range []string{
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS site_id bigint`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_site_id ON alerts (site_id)`,
	} {
		if err := d.execMaintenanceDDL(s); err != nil {
			return fmt.Errorf("migrate v36 alert_site_scope: %w", err)
		}
	}
	log.Printf("migrate v36: ensured alerts.site_id (+idx)")
	return nil
}

// migrateFeedToggleAndFlowSuppress (v33) backs the alert-taming + feed-control
// feature: a per-source suppression table, a per-feed enable flag, a persisted
// alert source, per-policy/per-site storm-threshold overrides, and seeds the
// Default policy's SFLOW_SECURITY / SFLOW_SECURITY_DIGEST cadence rules (needed
// because the seeded policy CooldownMinutes:5 otherwise shadows the type default).
func (d *Database) migrateFeedToggleAndFlowSuppress() error {
	if err := d.db.AutoMigrate(&models.FlowSourceSuppression{}); err != nil {
		return fmt.Errorf("migrate v33 flow_source_suppressions: %w", err)
	}
	if !d.dialect.IsPostgres() {
		if err := d.db.AutoMigrate(&models.ThreatFeedStatus{}, &models.Alert{}, &models.AlertRule{}, &models.SiteAlertConfig{}); err != nil {
			return fmt.Errorf("migrate v33 columns (sqlite): %w", err)
		}
	} else {
		for _, s := range []string{
			`ALTER TABLE threat_feed_status ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true`,
			`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source_addr varchar(45)`,
			`ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS storm_sources integer`,
			`ALTER TABLE site_alert_configs ADD COLUMN IF NOT EXISTS storm_sources integer`,
		} {
			if err := d.execMaintenanceDDL(s); err != nil {
				return fmt.Errorf("migrate v33 columns: %w", err)
			}
		}
	}
	d.seedSFlowSecurityRules()
	log.Printf("migrate v33: flow_source_suppressions + threat_feed_status.enabled + alerts.source_addr + storm_sources overrides + seeded SFLOW security cadence rules")
	return nil
}

// seedSFlowSecurityRules ensures the Default policy carries the two 6h-cadence
// security rules. Idempotent (FirstOrCreate on the unique (policy_id, alert_type)
// index); safe to call from the v33 migration and EnsureDefaultPolicy. No-op if
// there is no Default policy yet.
func (d *Database) seedSFlowSecurityRules() {
	var policy models.AlertPolicy
	if err := d.db.Where("is_default = ?", true).First(&policy).Error; err != nil {
		return
	}
	cd := 360
	for _, at := range []models.AlertType{models.AlertTypeSFlowSecurity, models.AlertTypeSFlowSecurityDigest} {
		rule := models.AlertRule{PolicyID: policy.ID, AlertType: at}
		d.db.Where(models.AlertRule{PolicyID: policy.ID, AlertType: at}).
			Attrs(models.AlertRule{Enabled: true, CooldownMinutes: &cd}).
			FirstOrCreate(&rule)
	}
}

// migrateFlowScopeLocal (v34) adds the scope_local boolean to flow_samples and
// flow_rollups and backfills it for existing history. scope_local flags
// link-local / multicast / broadcast / loopback / unspecified noise (see
// classify.ScopeLocal) so the Flows page can exclude it from top-talker charts
// WITHOUT hiding portless routed protocols (ESP/GRE/ICMP/OSPF) — the defect of
// the old `src_port = 0 AND dst_port = 0` filter this replaces.
//
// DDL: PG16 ADD COLUMN ... NOT NULL DEFAULT false is metadata-only (non-volatile
// default), instant even on the monthly-partitioned flow_samples; routed through
// execMaintenanceDDL so the 30s statement_timeout can't abort it (AUDIT-037).
// SQLite (dev/test) uses AutoMigrate.
//
// Backfill runs on canonical net.IP.String() output (lowercase, zero-compressed),
// so the prefix predicate is EXACT — unlike a naive LIKE, `^fe[89ab][0-9a-f]:`
// matches fe80–febf (link-local) but not the 3-hex-group global "fe8::1". It is
// batched by id-window and idempotent (guarded on `scope_local = <false>`), so a
// mid-pass crash simply resumes; the migration advisory lock serializes
// concurrent binaries. flow_samples is backfilled before flow_rollups.
//
// Bounded residue: during a rolling deploy an old binary can insert scope-local
// rows (default false) AFTER the backfill passed their id range — those stay
// visible as noise until the next deploy, acceptable for a cosmetic chart filter.
func (d *Database) migrateFlowScopeLocal() error {
	if !d.dialect.IsPostgres() {
		if err := d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{}); err != nil {
			return fmt.Errorf("migrate v34 scope_local (sqlite): %w", err)
		}
	} else {
		for _, s := range []string{
			`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS scope_local boolean NOT NULL DEFAULT false`,
			`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS scope_local boolean NOT NULL DEFAULT false`,
		} {
			if err := d.execMaintenanceDDL(s); err != nil {
				return fmt.Errorf("migrate v34 add scope_local column: %w", err)
			}
		}
	}
	predicate := fmt.Sprintf("(%s) OR (%s)",
		d.scopeLocalColumnPredicate("src_addr"), d.scopeLocalColumnPredicate("dst_addr"))
	if err := d.backfillScopeLocalTable("flow_samples", predicate); err != nil {
		return err
	}
	if err := d.backfillScopeLocalTable("flow_rollups", predicate); err != nil {
		return err
	}
	log.Printf("migrate v34 flow_scope_local: columns ensured + backfilled")
	return nil
}

// scopeLocalColumnPredicate returns a dialect-specific SQL boolean expression
// that is TRUE when the address in `col` is scope-local. It mirrors
// classify.isScopeLocal exactly for canonical net.IP.String() values:
//   - fe80::/10 link-local  → first group fe80–febf
//   - ff00::/8 multicast     → IPv6 first byte 0xff (4-hex first group ffxx:)
//   - 224.0.0.0/4 multicast  → 224.–239.
//   - 169.254.0.0/16, 127.0.0.0/8, 255.255.255.255, 0.0.0.0, ::, ::1
//
// `col` is always a compile-time literal ("src_addr"/"dst_addr"), never user
// input. Postgres uses POSIX `~`; SQLite (dev/test) uses GLOB char classes.
func (d *Database) scopeLocalColumnPredicate(col string) string {
	if d.dialect.IsPostgres() {
		return fmt.Sprintf(
			"%[1]s ~ '^fe[89ab][0-9a-f]:' OR %[1]s ~ '^ff[0-9a-f][0-9a-f]:' OR "+
				"%[1]s ~ '^2(2[4-9]|3[0-9])\\.' OR %[1]s LIKE '169.254.%%' OR "+
				"%[1]s LIKE '127.%%' OR %[1]s IN ('255.255.255.255','0.0.0.0','::','::1')",
			col)
	}
	return fmt.Sprintf(
		"%[1]s GLOB 'fe[89ab][0-9a-f]:*' OR %[1]s GLOB 'ff[0-9a-f][0-9a-f]:*' OR "+
			"%[1]s GLOB '22[4-9].*' OR %[1]s GLOB '23[0-9].*' OR %[1]s LIKE '169.254.%%' OR "+
			"%[1]s LIKE '127.%%' OR %[1]s IN ('255.255.255.255','0.0.0.0','::','::1')",
		col)
}

// backfillScopeLocalTable sets scope_local = true for every already-stored row
// matching `predicate`, in id-windows so no single statement locks the whole
// table. Each window lifts statement_timeout (PG) inside its own short
// transaction, matching execMaintenanceDDL's posture while still exposing
// RowsAffected for progress logging.
func (d *Database) backfillScopeLocalTable(table, predicate string) error {
	var bounds struct {
		MinID int64
		MaxID int64
	}
	if err := d.db.Raw(
		fmt.Sprintf("SELECT COALESCE(MIN(id),0) AS min_id, COALESCE(MAX(id),0) AS max_id FROM %s", table),
	).Scan(&bounds).Error; err != nil {
		return fmt.Errorf("scope_local backfill bounds for %s: %w", table, err)
	}
	if bounds.MaxID == 0 {
		return nil
	}
	falseLit := "false"
	if !d.dialect.IsPostgres() {
		falseLit = "0"
	}
	const window = 100000
	updateSQL := fmt.Sprintf(
		"UPDATE %s SET scope_local = true WHERE id >= ? AND id < ? AND scope_local = %s AND (%s)",
		table, falseLit, predicate)
	var total int64
	for start := bounds.MinID; start <= bounds.MaxID; start += window {
		end := start + window
		var affected int64
		err := d.db.Transaction(func(tx *gorm.DB) error {
			if d.dialect.IsPostgres() {
				if e := tx.Exec("SET LOCAL statement_timeout = 0").Error; e != nil {
					return e
				}
			}
			res := tx.Exec(updateSQL, start, end)
			affected = res.RowsAffected
			return res.Error
		})
		if err != nil {
			return fmt.Errorf("scope_local backfill %s [%d,%d): %w", table, start, end, err)
		}
		total += affected
	}
	if total > 0 {
		log.Printf("migrate v34: backfilled scope_local on %d %s rows", total, table)
	}
	return nil
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

// migrateAlertRuleClearThreshold (v23, F14 hysteresis) adds the recovery-band
// column. Additive with default 0 = legacy recover-at-threshold behavior.
func (d *Database) migrateAlertRuleClearThreshold() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.AlertRule{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS clear_threshold double precision NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("migrate v23 add alert_rules.clear_threshold: %w", err)
	}
	log.Printf("migrate v23 alert_rule_clear_threshold: column ensured")
	return nil
}

// migrateAlertRuleZScoreMode (v24, F17 adaptive baselining) adds the firing
// mode + deviation multiplier. Defaults keep every existing rule static.
func (d *Database) migrateAlertRuleZScoreMode() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.AlertRule{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'static'`); err != nil {
		return fmt.Errorf("migrate v24 add alert_rules.mode: %w", err)
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS z_score_k double precision NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("migrate v24 add alert_rules.z_score_k: %w", err)
	}
	log.Printf("migrate v24 alert_rule_zscore_mode: columns ensured")
	return nil
}

// migrateAlertPolicyIncidentChannels (v25, T2-5) adds the PagerDuty/Opsgenie/
// Teams routing flags to alert policies. Additive, default off.
func (d *Database) migrateAlertPolicyIncidentChannels() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.AlertPolicy{})
	}
	for _, col := range []string{"notify_pager_duty", "notify_opsgenie", "notify_teams"} {
		if err := d.execMaintenanceDDL(`ALTER TABLE alert_policies ADD COLUMN IF NOT EXISTS ` + col + ` boolean NOT NULL DEFAULT false`); err != nil {
			return fmt.Errorf("migrate v25 add alert_policies.%s: %w", col, err)
		}
	}
	log.Printf("migrate v25 alert_policy_incident_channels: columns ensured")
	return nil
}

// migrateAlertPolicyEscalationSteps (v26, F19) adds the JSON steps column.
// Empty default = legacy escalation behavior everywhere.
func (d *Database) migrateAlertPolicyEscalationSteps() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.AlertPolicy{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE alert_policies ADD COLUMN IF NOT EXISTS escalation_steps text NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate v26 add alert_policies.escalation_steps: %w", err)
	}
	log.Printf("migrate v26 alert_policy_escalation_steps: column ensured")
	return nil
}

// migrateIncidents (v27, F12) creates the incidents table and the grouping FK
// column on alerts. Both additive; alerts is NOT one of the partitioned
// tables, so plain DDL is safe.
func (d *Database) migrateIncidents() error {
	if err := d.db.AutoMigrate(&models.Incident{}); err != nil {
		return fmt.Errorf("migrate v27 incidents table: %w", err)
	}
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.Alert{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS incident_id bigint`); err != nil {
		return fmt.Errorf("migrate v27 add alerts.incident_id: %w", err)
	}
	if err := d.execMaintenanceDDL(`CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts (incident_id)`); err != nil {
		return fmt.Errorf("migrate v27 index alerts.incident_id: %w", err)
	}
	log.Printf("migrate v27 incidents: table + alerts.incident_id ensured")
	return nil
}

// migrateAdminProfile (v28, profile page + MFA onboarding wizard) adds the
// self-service profile columns. All additive with empty/NULL defaults —
// upgrading changes nothing until a user edits their profile or declines the
// MFA prompt.
func (d *Database) migrateAdminProfile() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.Admin{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS email text NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate v28 add admins.email: %w", err)
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS full_name text NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate v28 add admins.full_name: %w", err)
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS mfa_prompt_dismissed_at timestamptz`); err != nil {
		return fmt.Errorf("migrate v28 add admins.mfa_prompt_dismissed_at: %w", err)
	}
	log.Printf("migrate v28 admin_profile: ensured admins email/full_name/mfa_prompt_dismissed_at columns")
	return nil
}

// migrateAdminDashboardPrefs (v37) adds the admins.dashboard_prefs column that
// stores each user's customizable system-health dashboard layout (JSON). Additive
// with an empty default so existing accounts fall back to the default layout.
func (d *Database) migrateAdminDashboardPrefs() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.Admin{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS dashboard_prefs text NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate v37 add admins.dashboard_prefs: %w", err)
	}
	log.Printf("migrate v37 admin_dashboard_prefs: ensured admins.dashboard_prefs column")
	return nil
}

// migrateAddDiskAndLoad (v38) creates the disk_usage and load_average
// time-series tables (SNMP-collected filesystem usage and system load average).
// New tables only, so plain AutoMigrate matches the v31/v35 new-table precedent.
func (d *Database) migrateAddDiskAndLoad() error {
	return d.db.AutoMigrate(&models.DiskUsage{}, &models.LoadAverage{})
}

// migrateProbeCommandsAndSchemaVersion (v39) creates the probe_commands table
// (the server→collector command channel, relay schema v4) and adds
// probes.schema_version — the negotiated wire version persisted at register,
// which the heartbeat handler gates pending_commands delivery on. New table +
// additive int column with a zero default, so plain AutoMigrate matches the
// v31/v35/v38 precedent on both dialects (probes is small and unpartitioned).
func (d *Database) migrateProbeCommandsAndSchemaVersion() error {
	return d.db.AutoMigrate(&models.Probe{}, &models.ProbeCommand{})
}

// migrateIPSecTunnels (v40) creates the ipsec_tunnels table backing the
// cross-vendor IPSec provisioning wizard. New table, plain AutoMigrate (small,
// unpartitioned) — same precedent as v39.
func (d *Database) migrateIPSecTunnels() error {
	return d.db.AutoMigrate(&models.IPSecTunnel{})
}

// migrateIPSecTunnelDeployState (v50) adds ipsec_tunnels.deploy_json — the
// per-deploy record (per-end apply command IDs + body-less remove-steps snapshot
// + rollback command IDs; NO secrets) that makes deploy status tunnel-scoped and
// rollback snapshot-driven. Additive text column, plain AutoMigrate (small,
// unpartitioned), idempotent — same precedent as v40.
func (d *Database) migrateIPSecTunnelDeployState() error {
	return d.db.AutoMigrate(&models.IPSecTunnel{})
}

// migrateIPSecTunnelPreflightState (v58) adds ipsec_tunnels.preflight_json — the
// per-preflight record (per-end preflight command IDs) that makes preflight status
// tunnel-scoped, so two tunnels sharing a hub device don't cross-contaminate
// preflight reports (AUDIT-258). Additive text column, plain AutoMigrate (small,
// unpartitioned), idempotent — same precedent as v50 (deploy_json).
func (d *Database) migrateIPSecTunnelPreflightState() error {
	return d.db.AutoMigrate(&models.IPSecTunnel{})
}

// migrateEventRuleDampenJSON (v41) adds event_rules.dampen_json — the per-source
// dampening params blob backing the unified alerting-via-Event-Rules program.
// Additive text column, plain AutoMigrate (event_rules is small, unpartitioned).
func (d *Database) migrateEventRuleDampenJSON() error {
	return d.db.AutoMigrate(&models.EventRule{})
}

// migrateEventRuleExpiryAndSilences (v44) adds EventRule.expires_at (temporary
// rules) and migrates any still-active per-IP Silence-Source rows into equivalent
// temporary flow_security suppress Event Rules — the unified suppression hub
// replaces the standalone FlowSourceSuppression table. Idempotent: a rule whose
// name already exists is skipped, so an insert-then-crash-before-version-stamp
// re-run can't duplicate.
func (d *Database) migrateEventRuleExpiryAndSilences() error {
	if err := d.db.AutoMigrate(&models.EventRule{}); err != nil {
		return fmt.Errorf("migrate v44 event_rules expires_at: %w", err)
	}
	var sups []models.FlowSourceSuppression
	if err := d.db.Where("suppressed_until > ?", time.Now()).Find(&sups).Error; err != nil {
		return fmt.Errorf("migrate v44 load active silences: %w", err)
	}
	for _, s := range sups {
		name := "Silenced " + s.SrcAddr
		var count int64
		if err := d.db.Model(&models.EventRule{}).Where("name = ?", name).Count(&count).Error; err != nil {
			return fmt.Errorf("migrate v44 dedup check: %w", err)
		}
		if count > 0 {
			continue // already migrated (idempotent)
		}
		reason := s.SuppressedReason
		if reason == "" {
			reason = "migrated from Silence Source"
		}
		until := s.SuppressedUntil
		rule := models.EventRule{
			Name:        name,
			Description: reason,
			Enabled:     true,
			Priority:    50,
			Source:      "flow_security",
			MatchJSON:   fmt.Sprintf(`{"op":"eq","field":"source_ip","value":%q}`, s.SrcAddr),
			Action:      "suppress",
			ExpiresAt:   &until,
			SeedVersion: 0,
		}
		if err := d.db.Create(&rule).Error; err != nil {
			return fmt.Errorf("migrate v44 create temp rule for %s: %w", s.SrcAddr, err)
		}
	}
	return nil
}

// migrateActivatedSeedDescriptions (v42, Phase 4a) refreshes the descriptions of
// the metric + trap built-in rules on installs that took the earlier "Preview —
// not driving alerts yet" copy: those rules now DRIVE alerting, so the preview
// caveat is misleading. Matches by the shipped seed name; idempotent (re-running
// re-sets the same text). Only the description column is touched — never an
// operator-edited match/threshold/severity.
func (d *Database) migrateActivatedSeedDescriptions() error {
	updates := map[string]string{
		"CPU high":             "Threshold alert when device CPU usage is high. Inherits the Settings → Alerts / policy threshold unless you set one here.",
		"Memory high":          "Threshold alert when device memory usage is high. Inherits the Settings → Alerts / policy threshold unless you set one here.",
		"Disk high":            "Threshold alert when device disk usage is high. Inherits the Settings → Alerts / policy threshold unless you set one here.",
		"Session count high":   "Threshold alert when device session count is high. Inherits the Settings → Alerts / policy threshold unless you set one here.",
		"HA member down":       "HA cluster member down (SNMP trap).",
		"HA heartbeat failure": "HA cluster heartbeat lost (SNMP trap).",
		"HA failover":          "HA cluster failover/switch (SNMP trap).",
		"Link down (trap)":     "Interface link down reported by SNMP trap.",
	}
	for name, desc := range updates {
		if err := d.db.Model(&models.EventRule{}).
			Where("name = ? AND seed_version > 0", name).
			Update("description", desc).Error; err != nil {
			return fmt.Errorf("migrate v42 refresh %q: %w", name, err)
		}
	}
	return nil
}

// migrateSpikeRuleInheritSettings (v43, Phase 4b) activates the "Traffic spike"
// rule non-regressively. (a) Clears the baked dampen params to '{}' so the rule
// INHERITS the operator's live spike SystemSettings — but ONLY when the value is
// still the exact shipped default, so an operator who tuned k/min-duration in the
// rule keeps their value. (b) Refreshes the now-stale "Preview" description.
// seed_version>0 guards operator-created rules; idempotent.
func (d *Database) migrateSpikeRuleInheritSettings() error {
	if err := d.db.Model(&models.EventRule{}).
		Where("name = ? AND seed_version > 0 AND dampen_json = ?",
			"Traffic spike", `{"stddev_k":3,"min_duration_minutes":15}`).
		Update("dampen_json", "{}").Error; err != nil {
		return fmt.Errorf("migrate v43 clear spike dampen: %w", err)
	}
	if err := d.db.Model(&models.EventRule{}).
		Where("name = ? AND seed_version > 0", "Traffic spike").
		Update("description", "Alert on a sustained traffic spike vs the interface's seasonal baseline. Inherits the Settings → Alerts spike sensitivity unless you set values here.").Error; err != nil {
		return fmt.Errorf("migrate v43 refresh spike description: %w", err)
	}
	// (c) The old poller path NEVER closed a fired spike row (its resolve inserted a
	// separate resolved row). Close any lingering OPEN TRAFFIC_SPIKE rows once here
	// so the pre-4b orphans clear immediately — the new detector re-opens a fresh
	// row on the next spike. Idempotent (matches only resolved_at IS NULL).
	now := time.Now()
	if err := d.db.Model(&models.Alert{}).
		Where("alert_type = ? AND resolved_at IS NULL", models.AlertTypeTrafficSpike).
		Updates(map[string]interface{}{"resolved_at": now, "acknowledged": true, "acknowledged_at": now}).Error; err != nil {
		return fmt.Errorf("migrate v43 close orphan spike alerts: %w", err)
	}
	return nil
}

// migrateFlowIngestColumns (v29, Tranche 3 NetFlow v5/v9 + IPFIX) adds every
// column the multi-protocol flow ingest needs in ONE migration — flow_samples
// is monthly RANGE-partitioned on prod-shaped installs, so column adds are a
// thing we want to do exactly once. All additive with constant defaults:
// metadata-only on PG11+ (no table rewrite), the ALTER propagates to all
// monthly children on the partitioned-parent case, and the populated
// plain-table prod case (skipped by the v2 partition conversion) takes the
// same statement. Column rationale: flow_start/flow_end because NetFlow records are interval aggregates
// (up to 30-min active timeouts) not instants; firewall_event because
// denied-flow visibility is the headline NetFlow win (zero-byte rows are
// legal); flow_end_reason for future flow stitching (2 = active timeout);
// post-NAT tuple for pre/post-NAT correlation; the rest are cheap now and
// unpayable later. No new indexes: flow_source is a 4-value column and every
// filtered query also carries the indexed timestamp/device predicates —
// revisit only if a source-first hot path appears.
func (d *Database) migrateFlowIngestColumns() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowSample{}, &models.FlowRollup{})
	}
	stmts := []string{
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS flow_source smallint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS flow_start timestamptz`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS flow_end timestamptz`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS firewall_event smallint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS flow_end_reason smallint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS post_nat_src_addr varchar(45)`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS post_nat_dst_addr varchar(45)`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS post_nat_src_port integer NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS post_nat_dst_port integer NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS icmp_type_code integer NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS tos smallint NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS src_vlan integer NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS dst_vlan integer NOT NULL DEFAULT 0`,
		`ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS app_name varchar(64)`,
		`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS flow_source smallint NOT NULL DEFAULT 0`,
	}
	for _, s := range stmts {
		if err := d.execMaintenanceDDL(s); err != nil {
			return fmt.Errorf("migrate v29 flow ingest columns (%s): %w", s, err)
		}
	}
	log.Printf("migrate v29 flow_ingest_columns: ensured flow_samples multi-protocol columns + flow_rollups.flow_source")
	return nil
}

// migrateFlowRollupFirewallEvent (v30) adds firewall_event to flow_rollups so
// the rollup cycle can carry the IE 233 event label (denied=3 above all) as a
// group key instead of erasing denied-flow visibility one hour after ingest —
// v29 justified the flow_samples column as "the headline NetFlow win" and the
// rollup ladder then deleted it. Additive with constant default (metadata-only
// on PG11+), exactly like the v29 flow_rollups.flow_source add. flow_rollups
// is not partitioned, so plain DDL is safe.
func (d *Database) migrateFlowRollupFirewallEvent() error {
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.FlowRollup{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS firewall_event smallint NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("migrate v30 add flow_rollups.firewall_event: %w", err)
	}
	log.Printf("migrate v30 flow_rollup_firewall_event: column ensured")
	return nil
}

// migrateL2TopologyTables (v45) creates the topology_entries (ARP/FDB) and
// topology_neighbors (LLDP/CDP) state tables for the port-to-port connection
// map (relay schema v5). New tables only, so plain AutoMigrate matches the
// v38 new-table precedent.
func (d *Database) migrateL2TopologyTables() error {
	return d.db.AutoMigrate(&models.TopologyEntry{}, &models.TopologyNeighbor{})
}

// migrateConnectionPortFields (v46) adds the port-level endpoint columns to
// device_connections (source/dest ifIndex+ifName, vlan_ids) for L2-inferred
// links, and PURGES the old subnet-guess auto connections: the map now only
// draws links backed by L2 evidence ("hide unconfirmed" — the subnet_match
// detector produced a fake mesh and was removed with this migration). Manual
// connections (auto_detected = false) are never touched.
func (d *Database) migrateConnectionPortFields() error {
	if err := d.db.AutoMigrate(&models.DeviceConnection{}); err != nil {
		return fmt.Errorf("migrate v46 add connection port fields: %w", err)
	}
	res := d.db.Where("auto_detected = ? AND match_method = ?", true, "subnet_match").
		Delete(&models.DeviceConnection{})
	if res.Error != nil {
		return fmt.Errorf("migrate v46 purge subnet_match connections: %w", res.Error)
	}
	log.Printf("migrate v46 connection_port_fields: columns ensured, purged %d subnet_match auto connection(s)", res.RowsAffected)
	return nil
}

// migrateDeniedEventsTable (v47) ensures the denied_events projection table
// (Tranche 4 Phase 2 deny detectors) exists and — on Postgres — is a monthly
// RANGE-partitioned parent.
//
// Two install paths, distinguished by whether the table already exists:
//   - FRESH install: v1 baseline created denied_events (it's in the baseline
//     model list) and v2 (migratePartitionHighVolume) already converted it to
//     a partitioned parent (it's in partitionTables). By the time v47 runs the
//     table exists and is partitioned — so v47 must NOT AutoMigrate it again
//     (GORM would try to alter `timestamp`, which is now in the composite PK,
//     and Postgres rejects that: SQLSTATE 42P16). v47 no-ops.
//   - EXISTING prod: v1/v2 ran long ago WITHOUT denied_events, so the table
//     does not exist yet. v47 creates it empty and converts it, replicating
//     what v2 does for a fresh install. RunMigrations runs before
//     EnsurePartitions at boot, so the monthly child partitions get created the
//     same startup.
func (d *Database) migrateDeniedEventsTable() error {
	if !d.dialect.IsPostgres() {
		// SQLite test backend: a plain table (partitioning is a Postgres-only
		// concept). Safe to AutoMigrate every run.
		return d.db.AutoMigrate(&models.DeniedEvent{})
	}
	var exists bool
	if err := d.db.Raw(`SELECT to_regclass('denied_events') IS NOT NULL`).Scan(&exists).Error; err != nil {
		return fmt.Errorf("migrate v47 table-exists probe: %w", err)
	}
	if exists {
		// Fresh install: v1 + v2 already built and partitioned it. Re-running
		// AutoMigrate on the partitioned table would fail on the PK'd timestamp
		// column, so leave it alone.
		return nil
	}
	// Existing prod: create the empty table, then convert to partitioned so it
	// matches a fresh install. Newly created ⇒ provably empty.
	if err := d.db.AutoMigrate(&models.DeniedEvent{}); err != nil {
		return fmt.Errorf("migrate v47 denied_events AutoMigrate: %w", err)
	}
	if err := d.convertEmptyTableToPartitioned("denied_events", "timestamp"); err != nil {
		return fmt.Errorf("migrate v47 convert denied_events to partitioned: %w", err)
	}
	log.Printf("migrate v47 denied_events_table: created + converted to monthly RANGE-partitioned parent on timestamp")
	return nil
}

// migrateEventRuleProfiles (v48) introduces Event Rule Profiles — the
// Default > Site > Device chain of per-alert-type toggles + rule layers — and
// FAITHFULLY migrates the retired AlertRule.Enabled semantics into it.
//
// Fidelity invariant this is derived from: pre-v48 the SINGLE policy resolved
// by device→site→default is TOTAL authority for per-type enablement (no
// AlertRule blending across policies; EventRule.PolicyID pins channels only).
// The toggle chain instead FALLS THROUGH on a missing row, so every migrated
// profile must be DENSE over D (the set of types any referenced policy
// disables): explicit On rows are what stop a lower layer's Off from leaking
// through a layer that today shadows it. That includes the DEFAULT profile —
// a device explicitly pinned to the default policy shadows its site's
// disables today, so the pin is mirrored (EventProfileID → Default profile)
// and the Default profile's explicit On rows must win at the device layer.
// Types outside D stay sparse everywhere, preserving the "new alert type ⇒
// Inherit ⇒ ON fleet-wide" contract.
//
// Idempotent throughout: AutoMigrate/IF NOT EXISTS DDL, FirstOrCreate
// profiles+toggles, and assignment mirroring guarded on event_profile_id IS
// NULL (a crash-and-rerun never clobbers state a completed step wrote).
// When no referenced policy disables anything (D empty — the common install)
// the migration creates only the Default profile and provably changes no
// firing behavior.
func (d *Database) migrateEventRuleProfiles() error {
	// (a) New tables + columns. Errors propagate (fresh tables must exist);
	// column adds use the IF NOT EXISTS / AutoMigrate idempotent patterns.
	if err := d.db.AutoMigrate(&models.EventRuleProfile{}, &models.EventRuleProfileToggle{}); err != nil {
		return fmt.Errorf("migrate v48 profile tables: %w", err)
	}
	if !d.dialect.IsPostgres() {
		if err := d.db.AutoMigrate(&models.EventRule{}, &models.DeviceAlertConfig{}, &models.SiteAlertConfig{}); err != nil {
			return fmt.Errorf("migrate v48 columns (sqlite): %w", err)
		}
	} else {
		for _, s := range []string{
			`ALTER TABLE event_rules ADD COLUMN IF NOT EXISTS profile_id bigint NOT NULL DEFAULT 0`,
			`CREATE INDEX IF NOT EXISTS idx_event_rules_profile_id ON event_rules (profile_id)`,
			`ALTER TABLE device_alert_configs ADD COLUMN IF NOT EXISTS event_profile_id bigint`,
			`CREATE INDEX IF NOT EXISTS idx_device_alert_configs_event_profile_id ON device_alert_configs (event_profile_id)`,
			`ALTER TABLE site_alert_configs ADD COLUMN IF NOT EXISTS event_profile_id bigint`,
			`CREATE INDEX IF NOT EXISTS idx_site_alert_configs_event_profile_id ON site_alert_configs (event_profile_id)`,
		} {
			if err := d.execMaintenanceDDL(s); err != nil {
				return fmt.Errorf("migrate v48 columns: %w", err)
			}
		}
	}

	// (b) Default profile — needed here for the backfill; EnsureDefaultEventProfile
	// also runs at every startup for fresh installs.
	d.EnsureDefaultEventProfile()
	defProfile, err := d.GetDefaultEventRuleProfile()
	if err != nil {
		return fmt.Errorf("migrate v48 load default profile: %w", err)
	}

	// (c) Every pre-existing rule belongs to the Default layer. profile_id=0
	// stays a pinned Default sentinel in the engine, so rows an old binary
	// writes mid-rolling-restart still evaluate; this backfill just makes the
	// stored state explicit.
	if err := d.db.Exec(`UPDATE event_rules SET profile_id = ? WHERE profile_id = 0 OR profile_id IS NULL`, defProfile.ID).Error; err != nil {
		return fmt.Errorf("migrate v48 backfill event_rules.profile_id: %w", err)
	}

	// (d) AlertRule.Enabled=false fidelity migration.
	var defaultPolicy models.AlertPolicy
	hasDefaultPolicy := d.db.Where("is_default = ?", true).First(&defaultPolicy).Error == nil

	// referenced = default policy ∪ policies pinned by any device/site config.
	// Dangling pins are skipped exactly like resolvedPolicyIDLocked falls
	// through them at fire time.
	var policies []models.AlertPolicy
	if err := d.db.Find(&policies).Error; err != nil {
		return fmt.Errorf("migrate v48 load policies: %w", err)
	}
	policyByID := map[uint]models.AlertPolicy{}
	for _, p := range policies {
		policyByID[p.ID] = p
	}
	referenced := map[uint]bool{}
	if hasDefaultPolicy {
		referenced[defaultPolicy.ID] = true
	}
	var devCfgs []models.DeviceAlertConfig
	var siteCfgs []models.SiteAlertConfig
	if err := d.db.Find(&devCfgs).Error; err != nil {
		return fmt.Errorf("migrate v48 load device configs: %w", err)
	}
	if err := d.db.Find(&siteCfgs).Error; err != nil {
		return fmt.Errorf("migrate v48 load site configs: %w", err)
	}
	for _, c := range devCfgs {
		if c.PolicyID != nil {
			if _, ok := policyByID[*c.PolicyID]; ok {
				referenced[*c.PolicyID] = true
			}
		}
	}
	for _, c := range siteCfgs {
		if c.PolicyID != nil {
			if _, ok := policyByID[*c.PolicyID]; ok {
				referenced[*c.PolicyID] = true
			}
		}
	}

	// D = types disabled in ANY referenced policy — read straight from
	// alert_rules so UI-unrendered types are included (the old hardcoded JS
	// list drifted; the DB is the only honest source).
	disabledByPolicy := map[uint]map[models.AlertType]bool{}
	dSet := map[models.AlertType]bool{}
	var disabledRules []models.AlertRule
	if err := d.db.Where("enabled = ?", false).Find(&disabledRules).Error; err != nil {
		return fmt.Errorf("migrate v48 load disabled alert rules: %w", err)
	}
	for _, r := range disabledRules {
		if !referenced[r.PolicyID] {
			continue // policy assigned nowhere ⇒ its disables were already inert
		}
		if disabledByPolicy[r.PolicyID] == nil {
			disabledByPolicy[r.PolicyID] = map[models.AlertType]bool{}
		}
		disabledByPolicy[r.PolicyID][r.AlertType] = true
		dSet[r.AlertType] = true
	}
	if len(dSet) == 0 {
		log.Printf("migrate v48 event_rule_profiles: tables + Default profile ready; no referenced policy disables any type — no toggles migrated (inert)")
		return nil
	}

	ensureToggle := func(profileID uint, at models.AlertType, enabled bool) error {
		var tg models.EventRuleProfileToggle
		return d.db.Where(models.EventRuleProfileToggle{ProfileID: profileID, AlertType: at}).
			Attrs(models.EventRuleProfileToggle{Enabled: enabled}).
			FirstOrCreate(&tg).Error
	}

	// Dense-over-D rows for the Default profile (explicit On rows matter when
	// a device/site pin points at Default — see the header comment).
	for at := range dSet {
		enabled := !(hasDefaultPolicy && disabledByPolicy[defaultPolicy.ID][at])
		if err := ensureToggle(defProfile.ID, at, enabled); err != nil {
			return fmt.Errorf("migrate v48 default toggles: %w", err)
		}
	}

	// One profile per non-default referenced policy (INCLUDING clean ones —
	// a clean pinned policy must still shadow a lower layer's Off rows),
	// dense over D.
	profileForPolicy := map[uint]uint{}
	if hasDefaultPolicy {
		profileForPolicy[defaultPolicy.ID] = defProfile.ID
	}
	// Iterate policies in ID order (not map order) and claim names through a
	// deterministic candidate ladder — so a crash-and-rerun recomputes the
	// SAME name per policy (FirstOrCreate then reuses), and two adversarially
	// named policies can never silently merge into one profile.
	orderedPids := make([]uint, 0, len(referenced))
	for pid := range referenced {
		if hasDefaultPolicy && pid == defaultPolicy.ID {
			continue
		}
		orderedPids = append(orderedPids, pid)
	}
	sort.Slice(orderedPids, func(i, j int) bool { return orderedPids[i] < orderedPids[j] })
	claimed := map[string]bool{defProfile.Name: true}
	for _, pid := range orderedPids {
		p := policyByID[pid]
		name := p.Name
		if claimed[name] {
			name = p.Name + " (event profile)"
		}
		if claimed[name] {
			name = fmt.Sprintf("%s #%d", p.Name, p.ID) // policy IDs are unique — always free
		}
		claimed[name] = true
		var prof models.EventRuleProfile
		if err := d.db.Where(models.EventRuleProfile{Name: name}).
			Attrs(models.EventRuleProfile{Description: "Migrated from notification profile \"" + p.Name + "\" (v48): carries its per-type enable/disable state."}).
			FirstOrCreate(&prof).Error; err != nil {
			return fmt.Errorf("migrate v48 profile for policy %q: %w", p.Name, err)
		}
		profileForPolicy[pid] = prof.ID
		for at := range dSet {
			if err := ensureToggle(prof.ID, at, !disabledByPolicy[pid][at]); err != nil {
				return fmt.Errorf("migrate v48 toggles for policy %q: %w", p.Name, err)
			}
		}
	}

	// Mirror assignments (default-policy pins included — that pin is what
	// shadows a site's disables today). IS NULL guard = idempotent and never
	// clobbers a post-migration operator change.
	for pid, profID := range profileForPolicy {
		if err := d.db.Exec(`UPDATE device_alert_configs SET event_profile_id = ? WHERE policy_id = ? AND event_profile_id IS NULL`, profID, pid).Error; err != nil {
			return fmt.Errorf("migrate v48 mirror device assignments: %w", err)
		}
		if err := d.db.Exec(`UPDATE site_alert_configs SET event_profile_id = ? WHERE policy_id = ? AND event_profile_id IS NULL`, profID, pid).Error; err != nil {
			return fmt.Errorf("migrate v48 mirror site assignments: %w", err)
		}
	}

	log.Printf("migrate v48 event_rule_profiles: migrated %d disabled type(s) across %d referenced policy(ies) into dense profile toggles; assignments mirrored", len(dSet), len(referenced))
	return nil
}

// migrateProbeAgentVersion (v55) adds probes.agent_version.
//
// The server previously knew only the negotiated schema_version, which tracks
// the wire format rather than the binary — so there was no way to answer "which
// collector build is this?". Anything version-dependent had to infer it: the
// IPSec telemetry gate matches on the TEXT of a failure the collector returns,
// and diagnosing a stale collector meant hunting for side effects in unrelated
// telemetry.
//
// Nullable with no default: empty means a collector too old to report it, which
// is itself the answer, and backfilling a guess would destroy that distinction.
func (d *Database) migrateProbeAgentVersion() error {
	// SQLite (the test backend) does not support ADD COLUMN IF NOT EXISTS and
	// already has the column from the baseline AutoMigrate, so it takes the
	// AutoMigrate path — which adds the column only if missing. Same shape as
	// v52/v53.
	if !d.dialect.IsPostgres() {
		return d.db.AutoMigrate(&models.Probe{})
	}
	if err := d.execMaintenanceDDL(`ALTER TABLE probes ADD COLUMN IF NOT EXISTS agent_version VARCHAR(32)`); err != nil {
		return fmt.Errorf("migrate v55 add probes.agent_version: %w", err)
	}
	log.Printf("migrate v55 probes.agent_version: ensured column exists (varchar(32), nullable)")
	return nil
}

// migrateSyslogIngestHourly (v59) creates the syslog_ingest_hourly table (one
// row per hour × severity of accepted syslog ingest, written by the ingest
// meter) and adds server_metrics.data_disk_total_bytes, the volume size the
// Retention page's projection verdict is measured against.
//
// Idempotency: AutoMigrate adds only what is missing. Fresh installs get both
// from the baseline allModels loop, so this is a recorded no-op there (same
// shape as migrateFlowAgentDropsTable). Not a partitioned table — ≤ 192 rows a
// day — so it is deliberately absent from partitionTables/partitionModels.
func (d *Database) migrateSyslogIngestHourly() error {
	if err := d.db.AutoMigrate(&models.SyslogIngestHourly{}); err != nil {
		return err
	}
	return d.db.AutoMigrate(&models.ServerMetric{})
}

// migrateDeleteConnectionsToRetiredDevices (v69) removes device_connections
// rows whose source or destination device is retired or no longer exists.
// RetireDevice already deletes a device's connections, but before v0.11.268
// the poller's VPN detector re-created them every cycle from the provisioned
// tunnel table (which keeps retired endpoints), leaving a "? <-> peer" row the
// list showed and the map could not draw. The poller no longer offers such a
// pair; this clears the rows it already wrote. Restoring a device re-derives
// its auto-detected connections on the next poller cycle, as before.
func (d *Database) migrateDeleteConnectionsToRetiredDevices() error {
	res := d.db.Where(
		"source_device_id NOT IN (SELECT id FROM devices WHERE retired_at IS NULL) OR dest_device_id NOT IN (SELECT id FROM devices WHERE retired_at IS NULL)").
		Delete(&models.DeviceConnection{})
	if res.Error != nil {
		return fmt.Errorf("migrate v69: delete connections to retired devices: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		log.Printf("migrate v69: deleted %d connection(s) to retired or missing devices", res.RowsAffected)
	}
	return nil
}

// passkeysPostgresDDL is migration v70 on Postgres. Every statement is
// idempotent (IF NOT EXISTS), so a run interrupted half-way — migrations are
// not transactional and a failure is fatal at startup — completes on the next
// boot. The webauthn_credentials.admin_id foreign key (ON DELETE CASCADE) is
// only a backstop: DeleteAdmin deletes the rows explicitly.
var passkeysPostgresDDL = []string{
	`ALTER TABLE admins ADD COLUMN IF NOT EXISTS webauthn_user_handle bytea`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_webauthn_user_handle ON admins (webauthn_user_handle)`,
	`ALTER TABLE admins ADD COLUMN IF NOT EXISTS passkey_notice_seen_at timestamptz`,
	`ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS method text`,
	`CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id bigserial PRIMARY KEY,
		admin_id bigint NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
		credential_id bytea NOT NULL,
		public_key bytea NOT NULL,
		attestation_type text NOT NULL DEFAULT '',
		aaguid bytea,
		sign_count bigint NOT NULL DEFAULT 0,
		backup_eligible boolean NOT NULL DEFAULT false,
		backup_state boolean NOT NULL DEFAULT false,
		transports text NOT NULL DEFAULT '',
		name text NOT NULL DEFAULT '',
		created_at timestamptz,
		last_used_at timestamptz
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials (credential_id)`,
	`CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_admin_id ON webauthn_credentials (admin_id)`,
}

// migratePasskeys (v70, passkey login) adds the WebAuthn user handle and the
// new-passkey notice timestamp to admins, the method column to
// login_attempts, and the webauthn_credentials table. All additive and NULL /
// empty by default: nothing changes for an existing account until it
// registers a passkey, and the feature itself ships disabled.
func (d *Database) migratePasskeys() error {
	if !d.dialect.IsPostgres() {
		if err := d.db.AutoMigrate(&models.Admin{}, &models.LoginAttempt{}, &models.WebAuthnCredential{}); err != nil {
			return fmt.Errorf("migrate v70 passkeys: %w", err)
		}
		return nil
	}
	for _, stmt := range passkeysPostgresDDL {
		if err := d.execMaintenanceDDL(stmt); err != nil {
			return fmt.Errorf("migrate v70 passkeys: %w", err)
		}
	}
	log.Printf("migrate v70 passkeys: ensured admins.webauthn_user_handle/passkey_notice_seen_at, login_attempts.method, webauthn_credentials")
	return nil
}

// migrateVendorBackfillFinal (v71) is the last empty-vendor → "fortigate"
// backfill. Until 0.11.289 auditDeviceVendors ran the same UPDATE at every
// startup, which is what kept "" meaning FortiGate on every read path. From
// 0.11.290 an empty or unknown vendor is "generic" everywhere (models.Device
// default, handlers.deviceVendor, deny.ProjectVendor, snmp.resolveVendor), so
// the rows that relied on the old mapping are set once, here, to the value the
// startup code would have given them — no device changes behaviour on upgrade.
// On Postgres the column default is then flipped to 'generic' (metadata only;
// the model tag already says so for fresh installs). Idempotent: the UPDATE
// matches nothing the second time and SET DEFAULT is a no-op.
func (d *Database) migrateVendorBackfillFinal() error {
	res := d.db.Exec("UPDATE devices SET vendor = 'fortigate' WHERE vendor = '' OR vendor IS NULL")
	if res.Error != nil {
		return fmt.Errorf("migrate v71 vendor_backfill_final: backfill: %w", res.Error)
	}
	log.Printf("migrate v71 vendor_backfill_final: set %d device(s) with empty vendor → 'fortigate' (last time; empty now means 'generic')", res.RowsAffected)
	if !d.dialect.IsPostgres() {
		// SQLite cannot ALTER a column default; the test schema is created
		// from the model tag, which already carries default:generic.
		return nil
	}
	if err := d.execMaintenanceDDL("ALTER TABLE devices ALTER COLUMN vendor SET DEFAULT 'generic'"); err != nil {
		return fmt.Errorf("migrate v71 vendor_backfill_final: column default: %w", err)
	}
	return nil
}
