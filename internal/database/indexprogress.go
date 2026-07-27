package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/logging"
)

// Watching a long index build.
//
// There is no progress infrastructure in this codebase — no job table, no push
// channel — and a CREATE INDEX over 68M rows takes long enough that silence is
// indistinguishable from a hang. Postgres exposes the answer in
// pg_stat_progress_create_index (PG 12+); this polls it on its OWN connection,
// because the connection issuing the DDL is blocked inside it for the duration.
//
// Deliberately generic: any future index build gets the same visibility for
// free, which is the only thing that makes this worth more than a single log
// line at the end.

// indexProgressInterval is how often progress is logged. Long enough not to spam
// a multi-minute build, short enough that an operator can tell it is alive.
const indexProgressInterval = 10 * time.Second

type indexProgressRow struct {
	Phase           string
	BlocksTotal     int64
	BlocksDone      int64
	TuplesTotal     int64
	TuplesDone      int64
	PartitionsTotal int64
	PartitionsDone  int64
}

// watchIndexBuild logs the progress of index builds on `table` until stop is
// closed. It returns immediately; the caller closes stop when the DDL returns.
//
// Postgres-only, and silent by design when the view reports nothing: a build
// that finishes inside the first interval simply produces no progress lines
// rather than a confusing empty report.
func (d *Database) watchIndexBuild(table string, stop <-chan struct{}) {
	if !d.dialect.IsPostgres() {
		return
	}
	logging.SafeGo("index-build-progress", func() {
		ticker := time.NewTicker(indexProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				d.logIndexProgress(table)
			}
		}
	})
}

func (d *Database) logIndexProgress(table string) {
	// Scoped to this table: an unrelated build elsewhere would otherwise be
	// indistinguishable from the one being waited on.
	const q = `
		SELECT p.phase,
		       COALESCE(p.blocks_total, 0)     AS blocks_total,
		       COALESCE(p.blocks_done, 0)      AS blocks_done,
		       COALESCE(p.tuples_total, 0)     AS tuples_total,
		       COALESCE(p.tuples_done, 0)      AS tuples_done,
		       COALESCE(p.partitions_total, 0) AS partitions_total,
		       COALESCE(p.partitions_done, 0)  AS partitions_done
		FROM pg_stat_progress_create_index p
		JOIN pg_class c ON c.oid = p.relid
		WHERE c.relname = ?`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var rows []indexProgressRow
	if err := d.db.WithContext(ctx).Raw(q, table).Scan(&rows).Error; err != nil {
		log.Printf("index build %s: progress unavailable (%v)", table, err)
		return
	}
	for _, r := range rows {
		// Report the phase alongside the percentage, always. The counters reset
		// between phases, so a bare percentage that goes backwards reads as a
		// fault when it is actually normal progress.
		log.Printf("index build %s: %s%s%s", table, r.Phase,
			pctSuffix(" — blocks", r.BlocksDone, r.BlocksTotal),
			pctSuffix(" — tuples", r.TuplesDone, r.TuplesTotal))
	}
}

// pctSuffix renders "label X/Y (N%)", or nothing when the phase does not
// populate that counter — most phases populate only one of them.
func pctSuffix(label string, done, total int64) string {
	if total <= 0 {
		return ""
	}
	return fmt.Sprintf("%s %d/%d (%.1f%%)", label, done, total,
		float64(done)/float64(total)*100)
}
