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
	// lock was not granted is tried again in the next round.
	netEventIndexDropRounds     = 12
	netEventIndexDropRetrySleep = 5 * time.Second
	// netEventIndexDropDeadline caps v80 as a whole. The api, the poller and
	// the trap daemon wait on the migration lock meanwhile, so ingest is down
	// for as long as v80 runs: with every leaf held (a pg_dump across the
	// restart) the rounds alone would be ~117 indexes x 2 s x 12 rounds,
	// about 47 minutes. No drop starts after the deadline, so v80 ends at
	// most one lock timeout past it.
	netEventIndexDropDeadline = 90 * time.Second
	// netEventIndexCronDeadline caps the daily re-sweep from the retention
	// pass (one round, no retry sleep): it picks up what v80 left without
	// holding the pass up.
	netEventIndexCronDeadline = 15 * time.Second
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
// or deadlock (40P01) failure is retried in the next round, within
// netEventIndexDropDeadline overall. DROP INDEX CONCURRENTLY would avoid the
// lock but cannot run in a transaction, so it could not carry the bounds. An
// index still held at the last round or the deadline is left with a WARNING
// rather than failing the startup: the retention pass sweeps again every day
// (sweepRetiredNetEventIndexes), and a daily leaf's indexes go with the leaf.
// Idempotent: only existing indexes are named, and a re-run finds none.
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
	if err := d.dropRetiredNetEventIndexes("migrate v80", netEventIndexDropDeadline, netEventIndexDropRounds); err != nil {
		return fmt.Errorf("migrate v80: %w", err)
	}
	return nil
}

// sweepRetiredNetEventIndexes is v80's drop again, from the daily retention
// pass: one round under netEventIndexCronDeadline, so an index v80 left
// behind (a lock it was never granted — the DEFAULT child's is never dropped
// by retention) goes on a later day without manual SQL. A failure is logged,
// never returned: a leftover index costs space, not correctness. PostgreSQL
// only; finds nothing (one catalog read) once the indexes are gone.
func (d *Database) sweepRetiredNetEventIndexes() {
	if !d.dialect.IsPostgres() {
		return
	}
	if err := d.dropRetiredNetEventIndexes("cleanup: retired net_events index sweep", netEventIndexCronDeadline, 1); err != nil {
		log.Printf("cleanup: retired net_events index sweep: %v (retried next pass)", err)
	}
}

// dropRetiredNetEventIndexes drops the existing retired indexes in rounds
// (see migrateDropUnusedNetEventIndexes): no DROP starts once deadline has
// passed since the call, and at most rounds rounds run. Indexes still held
// then are logged with a WARNING and left; only a non-lock error is returned.
func (d *Database) dropRetiredNetEventIndexes(label string, deadline time.Duration, rounds int) error {
	pending, err := d.netEventsRetiredIndexes()
	if err != nil {
		return fmt.Errorf("list the indexes to drop: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}
	total := len(pending)
	start := time.Now()
	var longest time.Duration
	for round := 1; ; round++ {
		var held []string
		for k, name := range pending {
			if time.Since(start) >= deadline {
				held = append(held, pending[k:]...)
				break
			}
			t0 := time.Now()
			err := d.dropIndexBounded(name)
			if dt := time.Since(t0); err == nil && dt > longest {
				longest = dt
			}
			if err == nil {
				continue
			}
			if !(lockRetryable(err) || sqlState(err) == "57014") {
				return fmt.Errorf("drop %s: %w", name, err)
			}
			held = append(held, name)
		}
		if len(held) == 0 {
			log.Printf("%s: dropped %d unused net_events index(es) in %s (longest single drop %s)",
				label, total, time.Since(start).Round(time.Millisecond), longest.Round(time.Millisecond))
			return nil
		}
		if round >= rounds || time.Since(start)+netEventIndexDropRetrySleep >= deadline {
			log.Printf("WARNING: %s: %d of %d unused net_events index(es) not dropped after %d round(s) in %s (locks not granted within %s; deadline %s): %s — the daily retention pass tries again, and a daily leaf's go with it (MIGRATING.md, migration v80)",
				label, len(held), total, round, time.Since(start).Round(time.Millisecond), netEventIndexDropLockTimeout, deadline, namesForLog(held))
			return nil
		}
		log.Printf("%s: %d lock(s) on unused net_events indexes not granted within %s (round %d/%d); retrying in %s",
			label, len(held), netEventIndexDropLockTimeout, round, rounds, netEventIndexDropRetrySleep)
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

// namesForLog lists up to ten index names and counts the rest, so a WARNING
// with every leaf held stays one readable line.
func namesForLog(names []string) string {
	const max = 10
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:max], ", "), len(names)-max)
}
