package database

import (
	"fmt"
	"log"

	"gorm.io/gorm"
)

// batchInsertWithFallback inserts rows as one multi-row INSERT and, when that
// statement fails, degrades to per-row inserts — logging and skipping the rows
// that individually fail instead of rejecting the whole batch.
//
// M26 of the 2026-07-01 audit: the M4/M5 batch rewrites turned resilient
// per-row save loops into all-or-nothing statements. On partitioned prod
// Postgres a single row whose timestamp falls outside the existing partition
// range (clock-skewed collector, or a spillover replay after its month's
// partition was dropped — there is no DEFAULT partition) failed the ENTIRE
// insert; the handler then returned 500, the collector buffered the batch as
// retryable, and its drain requeued the poison item forever — ingestion of
// that metric type stopped entirely. The fallback restores the pre-rewrite
// semantics (bad rows logged and skipped, the rest saved) while keeping the
// batch statement as the fast path. An error is returned only when EVERY row
// fails, which indicates a systemic problem worth a retryable 500.
//
// Safe to retry per-row after a batch failure: gorm is not configured with
// CreateBatchSize, so Create(&rows) is one atomic statement — a failure
// inserts nothing.
func batchInsertWithFallback[T any](db *gorm.DB, kind string, rows []T) error {
	_, err := batchInsertWithFallbackSaved(db, kind, rows)
	return err
}

// batchInsertWithFallbackSaved is batchInsertWithFallback that also returns the
// rows that actually landed — the whole input on the fast path, and on the
// per-row fallback only the rows whose Create succeeded. A caller that meters
// what was written (the syslog ingest meter) must count from this, not from
// its input: a nil error here means "at least one row saved", not "all".
func batchInsertWithFallbackSaved[T any](db *gorm.DB, kind string, rows []T) ([]T, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	batchErr := db.Create(&rows).Error
	if batchErr == nil {
		return rows, nil
	}
	log.Printf("%s: batch insert of %d rows failed (%v); retrying per-row (M26 fallback)", kind, len(rows), batchErr)
	saved := make([]T, 0, len(rows))
	var lastErr error
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			lastErr = err
			log.Printf("%s: dropping unsalvageable row %d/%d: %v", kind, i+1, len(rows), err)
			continue
		}
		saved = append(saved, rows[i])
	}
	failed := len(rows) - len(saved)
	if failed == len(rows) {
		return nil, fmt.Errorf("%s: batch and all %d per-row inserts failed: %w", kind, len(rows), lastErr)
	}
	if failed > 0 {
		log.Printf("%s: per-row fallback saved %d/%d rows (%d dropped)", kind, len(saved), len(rows), failed)
	}
	return saved, nil
}
