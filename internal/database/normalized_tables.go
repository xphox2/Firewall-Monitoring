package database

import (
	"fmt"
	"log"

	"firewall-mon/internal/models"
)

// migrateNormalizedEventTables (v72) creates the vendor-neutral event tables
// of roadmap §1.2 (Phase 1, S-3): net_events (daily RANGE partitions on ts),
// sec_events (monthly), and the three plain tables net_event_rollups,
// fw_rules and device_field_observed.
//
// The two partitioned parents take the denied_events (v47) route — AutoMigrate
// the model, then convertEmptyTableToPartitioned — rather than a hand-written
// CREATE TABLE ... PARTITION BY: the model is then the only definition of the
// 55 columns the COPY writer binds by name, and the SQLite lane AutoMigrates
// the same model, so the two backends cannot drift. What v47 lacked was
// idempotency across a crash between its two steps (a plain table left behind
// read as "exists, skip"); ensurePartitionedTable closes that: a plain, EMPTY
// table is converted on the next run. A fresh install never reaches the
// conversion here — v1 creates the plain tables from baselineModels and v2
// converts them, exactly as for denied_events.
//
// EnsurePartitions creates the leaves after migrations (startup) and daily
// (retention cron): net_events gets RETENTION_NET_EVENT_DAYS of lookback plus
// seven days of lead, sec_events the usual current month plus six. Rollback:
// revert the release; the five tables stay (empty, harmless) and
// `DROP TABLE net_events, sec_events, net_event_rollups, fw_rules,
// device_field_observed` is the manual reverse.
func (d *Database) migrateNormalizedEventTables() error {
	small := []interface{}{&models.NetEventRollup{}, &models.FwRule{}, &models.DeviceFieldObserved{}}
	if !d.dialect.IsPostgres() {
		// SQLite test backend: plain tables (partitioning is a Postgres-only
		// concept). Safe to AutoMigrate every run.
		return d.db.AutoMigrate(append([]interface{}{&models.NetEvent{}, &models.SecEvent{}}, small...)...)
	}
	for _, t := range []struct {
		model interface{}
		def   partitionDef
	}{
		{&models.NetEvent{}, partitionDef{"net_events", "ts"}},
		{&models.SecEvent{}, partitionDef{"sec_events", "ts"}},
	} {
		if err := d.ensurePartitionedTable(t.model, t.def); err != nil {
			return fmt.Errorf("migrate v72 %s: %w", t.def.tableName, err)
		}
	}
	if err := d.db.AutoMigrate(small...); err != nil {
		return fmt.Errorf("migrate v72 small tables: %w", err)
	}
	return nil
}

// ensurePartitionedTable brings def's table to "RANGE-partitioned parent on
// def.column with the model's columns", idempotently, on Postgres:
//
//   - already a partitioned parent: nothing to do (the re-run case);
//   - absent: AutoMigrate the model (an empty plain table, by construction)
//     and convert it;
//   - present as a plain table and EMPTY: convert it (an earlier run that
//     stopped between the two steps);
//   - present as a plain table WITH rows: left alone with a warning, the same
//     rule v2 applies — a populated rewrite is a maintenance-window job
//     (docs/partition-migration.md), not a startup one.
func (d *Database) ensurePartitionedTable(model interface{}, def partitionDef) error {
	partitioned, err := d.isPartitionedParent(def.tableName)
	if err != nil {
		return err
	}
	if partitioned {
		return nil
	}
	var exists bool
	if err := d.db.Raw(`SELECT to_regclass(?) IS NOT NULL`, def.tableName).Scan(&exists).Error; err != nil {
		return fmt.Errorf("table-exists probe: %w", err)
	}
	if !exists {
		if err := d.db.AutoMigrate(model); err != nil {
			return fmt.Errorf("AutoMigrate: %w", err)
		}
	} else {
		var hasRows bool
		if err := d.db.Raw(fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s LIMIT 1)", def.tableName)).Scan(&hasRows).Error; err != nil {
			return fmt.Errorf("row probe: %w", err)
		}
		if hasRows {
			log.Printf("WARNING: AUDIT-028 partition migration: %q has existing rows; NOT auto-converting (a populated-table copy is too heavy at startup). Convert it in a maintenance window per docs/partition-migration.md. Until then the table stays plain and cleanup uses batched DELETE.", def.tableName)
			return nil
		}
	}
	if err := d.convertEmptyTableToPartitioned(def.tableName, def.column); err != nil {
		return fmt.Errorf("convert to partitioned: %w", err)
	}
	log.Printf("migrate v72 normalized_event_tables: %s is a RANGE-partitioned parent on %s", def.tableName, def.column)
	return nil
}

// isPartitionedParent reports whether table is a RANGE/LIST-partitioned
// parent (has a pg_partitioned_table row). Postgres-only callers.
func (d *Database) isPartitionedParent(table string) (bool, error) {
	var isPartitioned bool
	err := d.db.Raw(`SELECT EXISTS (
		SELECT 1 FROM pg_partitioned_table pt
		JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = ?)`, table).Scan(&isPartitioned).Error
	if err != nil {
		return false, fmt.Errorf("partition probe %s: %w", table, err)
	}
	return isPartitioned, nil
}
