package database

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// migrateBaseline is the v1 "baseline" migration (AUDIT-044): it brings an empty
// database up to the full current schema and is idempotent, so on an existing
// (already-AutoMigrated) deployment every step is a no-op and the migration
// runner simply records v1 as applied. It is invoked via the registry in
// migrations.go — do not call it directly; call RunMigrations.
func (d *Database) migrateBaseline() error {
	allModels := []interface{}{
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
	{"denied_events", "timestamp"},
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

	// AUDIT D2: ensure a DEFAULT partition per parent so a row whose timestamp
	// falls outside the current±6-month window — backward clock skew, or a batch
	// received just after 00:00 on the 1st carrying prev-month rows — lands in the
	// default instead of failing the whole insert/COPY with "no partition of
	// relation found for row". Idempotent; the cleanup cron already skips the
	// default's unparseable bound and parent-level retention still trims its rows.
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

		// Render the RANGE bounds with an EXPLICIT UTC offset (not a bare date) so
		// the literal is interpreted identically regardless of the PG session
		// TimeZone. The partition key is timestamptz, and a bare-date literal is
		// anchored in the session TZ at CREATE time — so once D4 pins the session
		// to UTC, an explicit +00 keeps every new monthly partition aligned with
		// the existing UTC-created ones (no boundary overlap/gap). parsePartition-
		// UpperBound already accepts this rendering.
		startStr := partitionStart.Format("2006-01-02 15:04:05-07:00")
		endStr := partitionEnd.Format("2006-01-02 15:04:05-07:00")

		for _, def := range partitioned {
			partitionName := fmt.Sprintf("%s_%d%02d", def.tableName, year, month)
			// Check if partition already exists
			var count int
			d.db.Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename = ?", partitionName).Scan(&count)
			if count == 0 {
				// Create the partition
				sql := fmt.Sprintf(`
					CREATE TABLE %s PARTITION OF %s
					FOR VALUES FROM ('%s') TO ('%s')`,
					partitionName, def.tableName, startStr, endStr)
				if err := d.execMaintenanceDDL(sql); err != nil {
					log.Printf("Partition creation warning for %s: %v", partitionName, err)
					continue
				}
				log.Printf("Created partition: %s", partitionName)
			}

			// Ensure the per-partition indexes exist. LC-19: the list is derived
			// from the model's gorm index tags (see partitionIndexPlan) — the
			// previous hard-coded list here had drifted and dropped the AUDIT-034
			// flow_samples src/dst indexes on fresh installs. This runs for
			// pre-existing partitions too (IF NOT EXISTS makes it a cheap no-op
			// when the index is present), so a partition created while an index
			// was missing from the old list is backfilled on the next startup.
			// Column names are quoted — interface_stats has an "index" column,
			// which is a reserved word.
			for _, idx := range indexPlans[def.tableName] {
				quoted := make([]string, len(idx.cols))
				for i, c := range idx.cols {
					quoted[i] = `"` + c + `"`
				}
				createIdxSQL := fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s (%s)",
					partitionName, idx.suffix, partitionName, strings.Join(quoted, ", "))
				if err := d.execMaintenanceDDL(createIdxSQL); err != nil {
					log.Printf("Index creation warning on %s: %v", partitionName, err)
				}
			}
		}
	}

	return nil
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
			if err := d.execMaintenanceDDL(insertSQL); err != nil {
				log.Printf("Autovacuum insert-threshold config warning for %s (PostgreSQL 13+ only): %v", target, err)
				continue
			}
			log.Printf("Configured autovacuum for %s", target)
		}
	}

	return nil
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
// same statement. Column rationale: docs/flow-protocol-research-2026-07-03.md
// §2.1 — flow_start/flow_end because NetFlow records are interval aggregates
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
