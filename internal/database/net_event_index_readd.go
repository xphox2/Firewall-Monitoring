package database

import (
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
)

// netEventsReaddedLeafIndexes are the three per-leaf net_events indexes
// migration v82 (re-)creates: each endpoint/rule column paired with ts, so a
// filter on the column still prunes the daily partitions via ts. The leaf
// suffix is the column list joined (partitionIndexSuffix), e.g. the
// (rule_key, ts) index is idx_<leaf>_rule_key_ts. v72 planned these from the
// model tags; v80 dropped them (their one reader had moved to
// net_event_rollups); the admin Events page (Phase 2, PR 1) reads them again,
// which is what makes the write amplification worth paying.
var netEventsReaddedLeafIndexes = []struct {
	suffix string
	cols   []string
}{
	{"rule_key_ts", []string{"rule_key", "ts"}},
	{"src_ip_ts", []string{"src_ip", "ts"}},
	{"dst_ip_ts", []string{"dst_ip", "ts"}},
}

// netEventsReaddedParentIndexes are the same three indexes under the names GORM
// gives them on the model's plain table — present on the SQLite lane, and on a
// PostgreSQL install whose net_events stayed a plain table (populated before
// v72 could convert it). The parent name is the GORM tag name, which differs
// from the leaf suffix (rule_ts vs rule_key_ts).
var netEventsReaddedParentIndexes = []struct {
	name string
	cols []string
}{
	{"idx_net_events_rule_ts", []string{"rule_key", "ts"}},
	{"idx_net_events_src_ts", []string{"src_ip", "ts"}},
	{"idx_net_events_dst_ts", []string{"dst_ip", "ts"}},
}

// v82's lock bounds. Package vars so the PostgreSQL test can shrink them.
var (
	// netEventIndexBuildLockTimeout bounds each CREATE INDEX's wait for the
	// leaf's SHARE lock. A non-concurrent CREATE INDEX only queues behind a
	// concurrent WRITER (INSERT/COPY/UPDATE/DELETE), and at startup there are
	// none — the api, the poller and the trap daemon all wait on the migration
	// lock while v82 runs. The bound is defence in depth: a build that somehow
	// queues behind a writer gives up instead of stalling live traffic, and the
	// partition pass backfills it on a later day (see migrateReaddNetEventIndexes).
	netEventIndexBuildLockTimeout = 2 * time.Second
	// netEventIndexBuildRounds / netEventIndexBuildRetrySleep: every index whose
	// lock was not granted is tried again in the next round.
	netEventIndexBuildRounds     = 12
	netEventIndexBuildRetrySleep = 5 * time.Second
	// netEventIndexBuildDeadline caps v82's migration phase. Unlike v80's drops
	// (milliseconds each), one CREATE INDEX on a 5M-row daily leaf takes
	// minutes, so no per-statement timeout applies — statement_timeout is lifted
	// for the build. The deadline instead stops v82 from STARTING new builds
	// past it, so the api/poller/trap wait on the migration lock at most one
	// build past the deadline; the rest are built by EnsurePartitions later in
	// the same boot and on every daily pass.
	netEventIndexBuildDeadline = 90 * time.Second
)

// migrateReaddNetEventIndexes (v82) re-creates the (rule_key, ts), (src_ip, ts)
// and (dst_ip, ts) indexes on every existing net_events relation that should
// carry them: the daily leaves, the DEFAULT child, a leaf still standalone in
// the middle of ensureLeaf's move, and the plain table itself if net_events was
// never converted. The model tags now declare the indexes again, so the
// partition pass (EnsurePartitions → ensureLeafIndexes, CREATE INDEX IF NOT
// EXISTS) builds them on FUTURE leaves and backfills any leaf v82 left — which
// is what makes v82 safe to interrupt and to leave work for a later pass.
//
// One CREATE INDEX per transaction, each under netEventIndexBuildLockTimeout
// and a lifted statement_timeout, so a leaf's SHARE lock is held for one index
// at a time and never queued for longer than the bound; a lock (55P03) or
// deadlock (40P01) failure is retried in the next round, within
// netEventIndexBuildDeadline overall. An index still unbuilt at the last round
// or the deadline is left with a WARNING rather than failing the startup.
// Idempotent: CREATE INDEX IF NOT EXISTS, and a re-run finds no missing index.
func (d *Database) migrateReaddNetEventIndexes() error {
	if !d.dialect.IsPostgres() {
		// SQLite test backend: a plain table carrying the GORM-named indexes of
		// the model, which the baseline AutoMigrate rebuilds from the re-added
		// tags. Nothing for v82 to do here.
		return nil
	}
	if err := d.buildNetEventIndexes("migrate v82", netEventIndexBuildDeadline, netEventIndexBuildRounds); err != nil {
		return fmt.Errorf("migrate v82: %w", err)
	}
	return nil
}

// netEventIndexTarget is one index v82 must ensure: the relation it is built on
// and its name. cols are the ordered, unquoted column names.
type netEventIndexTarget struct {
	relation string
	name     string
	cols     []string
}

// netEventIndexTargets lists every net_events index v82 must build: the plain
// parent's three GORM-named indexes when net_events is a plain table, otherwise
// the three per-leaf indexes on every leaf — the DEFAULT child, the attached
// daily leaves, and a leaf left standalone mid-move (all relkind 'r', matched by
// their names). A partitioned parent (relkind 'p') is deliberately not targeted:
// EnsurePartitions builds its leaves' indexes from the tags, and v82 must not
// create a parent-level partitioned index that would cascade a duplicate onto
// every leaf.
func (d *Database) netEventIndexTargets() ([]netEventIndexTarget, error) {
	var plainParent bool
	if err := d.db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = current_schema() AND c.relname = 'net_events' AND c.relkind = 'r'
		)`).Scan(&plainParent).Error; err != nil {
		return nil, fmt.Errorf("probe plain net_events: %w", err)
	}
	if plainParent {
		targets := make([]netEventIndexTarget, 0, len(netEventsReaddedParentIndexes))
		for _, ix := range netEventsReaddedParentIndexes {
			targets = append(targets, netEventIndexTarget{relation: "net_events", name: ix.name, cols: ix.cols})
		}
		return targets, nil
	}

	var leaves []string
	if err := d.db.Raw(`
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema()
		  AND c.relkind = 'r'
		  AND c.relname ~ '^net_events_(default|[0-9]{8})$'
		ORDER BY c.relname`).Scan(&leaves).Error; err != nil {
		return nil, fmt.Errorf("list net_events leaves: %w", err)
	}
	targets := make([]netEventIndexTarget, 0, len(leaves)*len(netEventsReaddedLeafIndexes))
	for _, leaf := range leaves {
		for _, ix := range netEventsReaddedLeafIndexes {
			targets = append(targets, netEventIndexTarget{relation: leaf, name: "idx_" + leaf + "_" + ix.suffix, cols: ix.cols})
		}
	}
	return targets, nil
}

// buildNetEventIndexes creates the missing net_events indexes in rounds (see
// migrateReaddNetEventIndexes): no CREATE starts once deadline has passed since
// the call, and at most rounds rounds run. Indexes still missing then are logged
// with a WARNING and left — the partition pass backfills them. Only a non-lock
// error is returned.
func (d *Database) buildNetEventIndexes(label string, deadline time.Duration, rounds int) error {
	targets, err := d.netEventIndexTargets()
	if err != nil {
		return fmt.Errorf("list the indexes to build: %w", err)
	}
	pending, err := d.missingNetEventIndexes(targets)
	if err != nil {
		return fmt.Errorf("probe existing indexes: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}
	total := len(pending)
	start := time.Now()
	var built int
	for round := 1; ; round++ {
		var held []netEventIndexTarget
		for i, tgt := range pending {
			if time.Since(start) >= deadline {
				held = append(held, pending[i:]...)
				break
			}
			if err := d.createIndexBounded(tgt); err != nil {
				if isRelationNameConflict(err) {
					// A sibling process's ensureLeafIndexes (a concurrent
					// EnsurePartitionsForCron during a rolling deploy) created the
					// index between our probe and CREATE — treat it as built.
					built++
					continue
				}
				if !lockRetryable(err) {
					return fmt.Errorf("create %s on %s: %w", tgt.name, tgt.relation, err)
				}
				held = append(held, tgt)
				continue
			}
			built++
		}
		if len(held) == 0 {
			log.Printf("%s: built %d net_events index(es) in %s", label, built, time.Since(start).Round(time.Millisecond))
			return nil
		}
		if round >= rounds || time.Since(start)+netEventIndexBuildRetrySleep >= deadline {
			log.Printf("WARNING: %s: %d of %d net_events index(es) not built after %d round(s) in %s (locks not granted within %s; deadline %s): %s — the partition pass backfills them (EnsurePartitions → ensureLeafIndexes, IF NOT EXISTS)",
				label, len(held), total, round, time.Since(start).Round(time.Millisecond), netEventIndexBuildLockTimeout, deadline, netEventIndexTargetsForLog(held))
			return nil
		}
		log.Printf("%s: %d lock(s) on net_events index builds not granted within %s (round %d/%d); retrying in %s",
			label, len(held), netEventIndexBuildLockTimeout, round, rounds, netEventIndexBuildRetrySleep)
		time.Sleep(netEventIndexBuildRetrySleep)
		pending = held
	}
}

// missingNetEventIndexes filters targets to those whose index does not exist
// yet, so the common re-run costs one catalog probe and no DDL (CREATE INDEX IF
// NOT EXISTS is the backstop; this probe makes the log line honest).
func (d *Database) missingNetEventIndexes(targets []netEventIndexTarget) ([]netEventIndexTarget, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.name
	}
	var existing []string
	if err := d.db.Raw(`
		SELECT i.relname
		FROM pg_class i
		JOIN pg_namespace n ON n.oid = i.relnamespace
		WHERE n.nspname = current_schema() AND i.relkind = 'i' AND i.relname IN ?`, names).Scan(&existing).Error; err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(existing))
	for _, n := range existing {
		have[n] = true
	}
	out := make([]netEventIndexTarget, 0, len(targets))
	for _, t := range targets {
		if !have[t.name] {
			out = append(out, t)
		}
	}
	return out, nil
}

// createIndexBounded creates one index in its own transaction under the v82
// bounds. name and relation come from the catalog query above (identifiers this
// package built), quoted all the same.
func (d *Database) createIndexBounded(tgt netEventIndexTarget) error {
	quoted := make([]string, len(tgt.cols))
	for i, c := range tgt.cols {
		quoted[i] = `"` + c + `"`
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		// Rendered literals, never input: a package duration (see execCronDDL).
		ms := netEventIndexBuildLockTimeout.Milliseconds()
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", ms)).Error; err != nil {
			return fmt.Errorf("set lock_timeout: %w", err)
		}
		// A 5M-row leaf build takes minutes — far past the DSN's 30s
		// statement_timeout, which would abort the build (57014) partway and
		// discard it. Lift it: the deadline above bounds how many builds v82
		// starts, not how long one runs.
		if err := tx.Exec("SET LOCAL statement_timeout = 0").Error; err != nil {
			return fmt.Errorf("lift statement_timeout: %w", err)
		}
		return tx.Exec(fmt.Sprintf(`CREATE INDEX IF NOT EXISTS "%s" ON %s (%s)`,
			strings.ReplaceAll(tgt.name, `"`, `""`), tgt.relation, strings.Join(quoted, ", "))).Error
	})
}

// netEventIndexTargetsForLog lists up to ten index names and counts the rest, so
// a WARNING with every leaf held stays one readable line.
func netEventIndexTargetsForLog(targets []netEventIndexTarget) string {
	const max = 10
	if len(targets) <= max {
		names := make([]string, len(targets))
		for i, t := range targets {
			names[i] = t.name
		}
		return strings.Join(names, ", ")
	}
	names := make([]string, max)
	for i := 0; i < max; i++ {
		names[i] = targets[i].name
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names, ", "), len(targets)-max)
}
