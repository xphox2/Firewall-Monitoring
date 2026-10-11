package database

// migrateDropUnusedNetEventIndexes is migration v80, kept as an inert no-op so
// already-applied installs (their schema_migrations has v80 recorded) are
// unaffected. v80 dropped the (rule_key, ts), (src_ip, ts) and (dst_ip, ts)
// indexes from every net_events leaf because their one reader had moved to
// net_event_rollups. The admin Events page (Phase 2, PR 1) is that reader
// again, so migration v82 re-adds the indexes (net_event_index_readd.go) and
// the model tags declare them once more. The v80 drop machinery — the daily
// re-sweep and the retired-suffix/parent catalog probes — was removed with the
// indexes it dropped, because leaving the sweep in place would undo v82 on
// every retention pass.
func (d *Database) migrateDropUnusedNetEventIndexes() error {
	return nil
}
