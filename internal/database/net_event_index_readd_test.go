package database

import "testing"

// TestMigrateReaddNetEventIndexes_SQLite: on the SQLite lane net_events is a
// plain table carrying the GORM-named indexes of the model. The re-added tags
// (migration v82's rationale) make AutoMigrate build the (rule_key, ts),
// (src_ip, ts) and (dst_ip, ts) indexes; v82 itself is a no-op there, and the
// now-inert v80 no longer drops them.
func TestMigrateReaddNetEventIndexes_SQLite(t *testing.T) {
	d := NewDatabaseForTesting(t)
	for _, name := range []string{"idx_net_events_rule_ts", "idx_net_events_src_ts", "idx_net_events_dst_ts"} {
		if !d.db.Migrator().HasIndex("net_events", name) {
			t.Errorf("%s missing after AutoMigrate with the re-added tags", name)
		}
	}
	// v80 is inert; v82 is a no-op on SQLite — both idempotent and neither drops
	// the indexes the tags now declare.
	for run := 1; run <= 2; run++ {
		if err := d.migrateDropUnusedNetEventIndexes(); err != nil {
			t.Fatalf("v80 (inert) run %d: %v", run, err)
		}
		if err := d.migrateReaddNetEventIndexes(); err != nil {
			t.Fatalf("v82 run %d: %v", run, err)
		}
		for _, name := range []string{"idx_net_events_rule_ts", "idx_net_events_src_ts", "idx_net_events_dst_ts"} {
			if !d.db.Migrator().HasIndex("net_events", name) {
				t.Errorf("run %d: %s missing", run, name)
			}
		}
	}
}
