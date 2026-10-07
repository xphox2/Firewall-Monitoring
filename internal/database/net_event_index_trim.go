package database

import (
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
)

// netEventsRetiredIndexSuffixes are the per-leaf indexes v72 planned on every
// net_events leaf (idx_<leaf>_<suffix>) that migration v80 drops: no query
// reads net_events by rule, source or destination. Measured on production
// (pg_stat_user_indexes, 30 daily leaves, ~1.5 days of statistics): zero
// scans on all three, 15 GB + 5.7 GB + 5.9 GB, while (ts) had 86 711 scans
// and (device_id, ts) 7.
var netEventsRetiredIndexSuffixes = []string{"rule_key_ts", "src_ip_ts", "dst_ip_ts"}

// netEventsRetiredParentIndexes are the same three indexes as GORM names them
// on the model's table: present on the SQLite lane, on a PostgreSQL install
// whose net_events stayed a plain table (populated before v72 could convert
// it), and as partitioned indexes should one ever have been built on the
// parent (dropping a partitioned index drops its attached leaf indexes too).
var netEventsRetiredParentIndexes = []string{"idx_net_events_rule_ts", "idx_net_events_src_ts", "idx_net_events_dst_ts"}

// v80's lock bounds. Package vars so the PostgreSQL test can shrink them.
var (
	// netEventIndexDropLockTimeout bounds each DROP as a whole (lock_timeout
	// and statement_timeout): DROP INDEX takes ACCESS EXCLUSIVE on the leaf,
	// and while it waits for a reader every insert into that leaf (today's)
	// waits behind it. The drop itself is a catalog change plus unlinking the
	// index's files at commit — milliseconds once the lock is granted.
	netEventIndexDropLockTimeout = 2 * time.Second
	// netEventIndexDropRounds / netEventIndexDropRetrySleep: every index whose
	// lock was not granted is tried again in the next round, up to about
	// 1.5 minutes in all.
	netEventIndexDropRounds     = 12
	netEventIndexDropRetrySleep = 5 * time.Second
)

// migrateDropUnusedNetEventIndexes (v80) drops the (rule_key, ts),
// (src_ip, ts) and (dst_ip, ts) indexes of net_events — the model no longer
// declares them, so partitionIndexPlan stops building them on new leaves —
// from every leaf that has them (the daily leaves, the DEFAULT child, and a
// leaf still standalone in the middle of ensureLeaf's move), and the GORM
// indexes of the same columns on the table itself.
//
// One DROP INDEX per transaction, each under netEventIndexDropLockTimeout, so
// a leaf's ACCESS EXCLUSIVE lock is held for one index at a time and never
// queued for longer than the bound; a lock (55P03), statement-timeout (57014)
// or deadlock (40P01) failure is retried in the next round. DROP INDEX
// CONCURRENTLY would avoid the lock but cannot run in a transaction, so it
// could not carry the bounds. An index still held after the last round is
// left with a WARNING rather than failing the startup: a daily leaf's indexes
// go with the leaf when retention drops it, and the manual statement is in
// MIGRATING.md. Idempotent: only existing indexes are named, and a re-run
// finds none.
func (d *Database) migrateDropUnusedNetEventIndexes() error {
	if !d.dialect.IsPostgres() {
		// SQLite test backend: a plain table with the GORM-named indexes.
		for _, name := range netEventsRetiredParentIndexes {
			if err := d.db.Exec("DROP INDEX IF EXISTS " + name).Error; err != nil {
				return fmt.Errorf("migrate v80: drop %s: %w", name, err)
			}
		}
		return nil
	}
	pending, err := d.netEventsRetiredIndexes()
	if err != nil {
		return fmt.Errorf("migrate v80: list the indexes to drop: %w", err)
	}
	if len(pending) == 0 {
		log.Printf("migrate v80 drop unused net_events indexes: none present")
		return nil
	}
	total := len(pending)
	start := time.Now()
	var longest time.Duration
	for round := 1; ; round++ {
		var held []string
		for _, name := range pending {
			t0 := time.Now()
			err := d.dropIndexBounded(name)
			if dt := time.Since(t0); err == nil && dt > longest {
				longest = dt
			}
			if err == nil {
				continue
			}
			if !(lockRetryable(err) || sqlState(err) == "57014") {
				return fmt.Errorf("migrate v80: drop %s: %w", name, err)
			}
			held = append(held, name)
		}
		if len(held) == 0 {
			log.Printf("migrate v80 drop unused net_events indexes: dropped %d in %s (longest single drop %s)",
				total, time.Since(start).Round(time.Millisecond), longest.Round(time.Millisecond))
			return nil
		}
		if round >= netEventIndexDropRounds {
			log.Printf("WARNING: migrate v80 drop unused net_events indexes: %d of %d not dropped after %d rounds (locks not granted within %s): %s — a daily leaf's go with it at retention; drop the rest by hand (MIGRATING.md, migration v80)",
				len(held), total, round, netEventIndexDropLockTimeout, strings.Join(held, ", "))
			return nil
		}
		log.Printf("migrate v80 drop unused net_events indexes: %d lock(s) not granted within %s (round %d/%d); retrying in %s",
			len(held), netEventIndexDropLockTimeout, round, netEventIndexDropRounds, netEventIndexDropRetrySleep)
		time.Sleep(netEventIndexDropRetrySleep)
		pending = held
	}
}

// netEventsRetiredIndexes lists the existing indexes v80 drops, the table's
// own first (a partitioned one takes its attached leaf indexes with it).
// Leaf indexes are matched by their exact plan names on net_events_default
// and net_events_YYYYMMDD — attached or not, so a leaf standing alone during
// ensureLeaf's move is included — and an index attached to a partitioned
// parent index is left to that index's drop (PostgreSQL refuses it alone).
func (d *Database) netEventsRetiredIndexes() ([]string, error) {
	var names []string
	err := d.db.Raw(`
		SELECT i.relname
		FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid
		JOIN pg_class t ON t.oid = x.indrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE n.nspname = current_schema()
		  AND (
		        (t.relname = 'net_events' AND i.relname IN ?)
		     OR (t.relname ~ '^net_events_(default|[0-9]{8})$'
		         AND i.relname IN (SELECT 'idx_' || t.relname || '_' || s FROM unnest(?::text[]) AS s))
		      )
		  AND NOT EXISTS (SELECT 1 FROM pg_inherits h WHERE h.inhrelid = i.oid)
		ORDER BY (t.relname = 'net_events') DESC, t.relname, i.relname`,
		netEventsRetiredParentIndexes, "{"+strings.Join(netEventsRetiredIndexSuffixes, ",")+"}").Scan(&names).Error
	return names, err
}

// dropIndexBounded drops one index in its own transaction under the v80
// bounds. name comes from the catalog query above (identifiers this package
// built), quoted all the same.
func (d *Database) dropIndexBounded(name string) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		// Rendered literals, never input: a package duration (see execCronDDL).
		ms := netEventIndexDropLockTimeout.Milliseconds()
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", ms)).Error; err != nil {
			return fmt.Errorf("set lock_timeout: %w", err)
		}
		if err := tx.Exec(fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms)).Error; err != nil {
			return fmt.Errorf("set statement_timeout: %w", err)
		}
		return tx.Exec(`DROP INDEX IF EXISTS "` + strings.ReplaceAll(name, `"`, `""`) + `"`).Error
	})
}
