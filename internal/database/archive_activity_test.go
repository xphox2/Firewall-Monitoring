package database

import "testing"

// TestMigrateV79_Idempotent (SQLite): the archive status card's partial
// indexes are created, and a re-run changes nothing.
func TestMigrateV79_Idempotent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	for i := 0; i < 2; i++ {
		if err := d.migrateArchiveChunkStatusIndexes(); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	for _, name := range []string{"idx_archive_chunk_open", "idx_archive_chunk_recent"} {
		var sql string
		if err := d.db.Raw("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", name).Scan(&sql).Error; err != nil || sql == "" {
			t.Fatalf("index %s: %q %v", name, sql, err)
		}
	}
}
