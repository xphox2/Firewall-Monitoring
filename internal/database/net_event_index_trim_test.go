package database

import (
	"testing"
)

// TestMigrateDropUnusedNetEventIndexes_SQLite: on the SQLite lane net_events
// is a plain table carrying the GORM-named indexes of the model; v80 drops
// the (rule_key, ts), (src_ip, ts) and (dst_ip, ts) ones a pre-v80 schema
// has, keeps (ts) and (device_id, ts), and is a no-op when run again.
func TestMigrateDropUnusedNetEventIndexes_SQLite(t *testing.T) {
	d := NewDatabaseForTesting(t)
	// The pre-v80 schema: what AutoMigrate built from the old index tags.
	for _, q := range []string{
		`CREATE INDEX IF NOT EXISTS idx_net_events_rule_ts ON net_events (rule_key, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_net_events_src_ts ON net_events (src_ip, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_net_events_dst_ts ON net_events (dst_ip, ts)`,
	} {
		if err := d.db.Exec(q).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for run := 1; run <= 2; run++ {
		if err := d.migrateDropUnusedNetEventIndexes(); err != nil {
			t.Fatalf("v80 run %d: %v", run, err)
		}
		for _, name := range netEventsRetiredParentIndexes {
			if d.db.Migrator().HasIndex("net_events", name) {
				t.Errorf("run %d: %s still present", run, name)
			}
		}
		for _, name := range []string{"idx_net_events_ts", "idx_net_events_device_ts"} {
			if !d.db.Migrator().HasIndex("net_events", name) {
				t.Errorf("run %d: %s was dropped; v80 must keep it", run, name)
			}
		}
	}
}
