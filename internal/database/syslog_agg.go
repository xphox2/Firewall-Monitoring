package database

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/logfields"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// syslogAggWindow is the width of one aggregation time window — the slice of
// raw history one transaction summarises and deletes (AUDIT-204). A package
// var (not a const) so tests can shrink it to exercise the multi-window path.
// Defaults to one hour, matching the summary bucket, so a bucket never
// straddles two windows in production.
var syslogAggWindow = time.Hour

// RunSyslogAggregationCycle aggregates old informational syslog into summaries
// for scalability. Called every 5 minutes by the poller:
//  1. Raw severity 6-7 past that severity's OWN retention window → hourly summaries
//  2. Hourly summaries older than 48h → daily summaries (severity-agnostic)
//
// Because this runs every 5 minutes while cleanup runs every 24 hours, this
// path is the effective owner of severities 6-7 — cleanup only ever mops up what
// aggregation missed. That is why the per-severity window has to be honoured
// HERE and not just in cleanup.
func (d *Database) RunSyslogAggregationCycle(retention config.RetentionConfig) error {
	work := false
	var lastErr error

	// Step 1: raw aggregated-severity syslog past ITS OWN window → hourly summaries.
	//
	// One pass per severity, each with its own cutoff, watermark and
	// transaction. Severity partitions the rows disjointly, so no row can be
	// claimed by two passes and each pass keeps the same summarise-then-delete
	// atomicity the single pass had.
	sevDays := d.SyslogRetentionDays(retention)
	for sev := aggregatedSeverityFloor; sev < SyslogSeverityCount; sev++ {
		// 0 means keep forever, so this severity is never summarised OR deleted
		// and simply stays raw. Skipping the pass is the correct reading rather
		// than summarise-but-do-not-delete: every reader unions raw and summary
		// counts, so keeping both would double-count.
		if sevDays[sev] <= 0 {
			continue
		}
		cutoff := time.Now().AddDate(0, 0, -sevDays[sev])
		if done, err := d.aggregateSyslogToSummary(cutoff, sev, "1h"); err != nil {
			lastErr = err
			log.Printf("Syslog aggregation: step 1 error (severity %d): %v", sev, err)
		} else if done {
			work = true
		}
	}

	// Step 2: hourly summaries > 48h old → daily summaries
	cutoff48h := time.Now().Add(-48 * time.Hour)
	if done, err := d.promoteSyslogSummaries("1h", "1d", cutoff48h); err != nil {
		lastErr = err
		log.Printf("Syslog aggregation: step 2 error: %v", err)
	} else if done {
		work = true
	}

	if !work && lastErr == nil {
		log.Println("Syslog aggregation: cycle complete (no data to aggregate)")
	}

	return lastErr
}

// syslogSummaryRow holds aggregated data during syslog summary operations.
type syslogSummaryRow struct {
	Bucket         string
	DeviceID       uint
	Severity       int
	Facility       int
	AppName        string
	MessagePattern string
	Count          int64
	SampleMessage  string
}

// aggregateSyslogToSummary groups raw syslog of ONE severity older than cutoff
// into hourly summaries, deleting exactly what it summarised, one bounded time
// window at a time (AUDIT-204 — see window_agg.go for why LIMIT/OFFSET paging
// could never clear a real backlog under statement_timeout, and why lifting
// the timeout was rejected). Each window's SELECT and DELETE carry
// `timestamp >= ? AND timestamp < ? AND severity = ? AND id <= ?`, served by
// idx_syslog_sev_ts; each window's insert+delete commit in their OWN
// transaction, so a failure mid-backlog keeps every earlier window's progress.
// Returns true if work was done, error if fatal.
//
// Correctness shape retained from the H1+H2/M2 fixes (do not regress):
//   - MAX(id) watermark: every read and delete is scoped to `id <= watermark`,
//     so raw messages that arrive mid-pass (ingestion runs concurrently in
//     cmd/api, and a collector backlog replay carries OLD timestamps) are
//     never deleted un-summarized — they wait for the next cycle.
//   - A window's raw-row DELETE shares its transaction with that window's
//     summary INSERT: no summaries are ever committed for rows that survive,
//     and no rows are ever deleted un-summarised.
//
// The paged version's ORDER BY over the group key is gone with the paging: it
// existed only so LIMIT/OFFSET pages neither overlapped nor skipped groups,
// and each window now consumes its whole group set in one statement.
func (d *Database) aggregateSyslogToSummary(cutoff time.Time, severity int, intervalType string) (bool, error) {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if intervalType == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	// Cheap "is there anything to do" probe, served by (severity, timestamp).
	// Replaces the old `watermark == 0` early-exit, which is no longer
	// available now that the watermark is unfiltered (see below). The probe,
	// watermark and window-start reads run outside any transaction: READ
	// COMMITTED gives each statement a fresh snapshot either way, and only the
	// watermark's upper-bound property (not cross-statement consistency)
	// carries the correctness.
	var probe []int64
	if err := d.db.Model(&models.SyslogMessage{}).
		Where("timestamp < ? AND severity = ?", cutoff, severity).
		Select("1").Limit(1).
		Scan(&probe).Error; err != nil {
		err = fmt.Errorf("work probe: %w", err)
		log.Printf("Syslog aggregation: %v (will retry next cycle)", err)
		return false, err
	}
	if len(probe) == 0 {
		return false, nil
	}

	// The watermark is deliberately UNFILTERED. It exists only as an upper
	// bound excluding rows that arrive mid-pass, so ANY bound >= every id in
	// the target set is correct — and the SELECT and DELETE below both still
	// carry the full predicates, so the set they act on is unchanged.
	//
	// Filtering it was a severe performance trap. PostgreSQL rewrites
	// MAX(id) into a backward walk of the primary key that stops at the
	// first row passing the filter, and prices it by expected-rows-until-
	// first-match. Under `severity = ? AND timestamp < ?` the newest ids all
	// fail the timestamp test, so the walk crossed most of the table while
	// the planner still estimated single-digit cost. Measured on a 92M-row
	// production table it exceeded 120s against a 30s statement_timeout — so
	// every 5-minute cycle aborted and retried forever and NOTHING was ever
	// aggregated. Unfiltered, the same rewrite stops on the first tuple:
	// 0.5ms.
	//
	// An index on (severity, timestamp, id) does NOT fix this: for a
	// high-share severity the planner prices the pkey walk at ~6 and keeps
	// choosing it, so the index would appear to work on the small severities
	// and still fail on the one that carries the volume.
	var watermark int64
	if err := d.db.Model(&models.SyslogMessage{}).
		Select("COALESCE(MAX(id), 0)").
		Scan(&watermark).Error; err != nil {
		err = fmt.Errorf("watermark: %w", err)
		log.Printf("Syslog aggregation: %v (will retry next cycle)", err)
		return false, err
	}
	if watermark == 0 {
		return false, nil
	}

	// Window-walk start: the oldest eligible row. With severity pinned, this
	// is idx_syslog_sev_ts's first tuple for that severity — the same
	// first-tuple stop that makes the unfiltered watermark cheap, not the
	// filtered-MAX planner trap (the oldest rows pass the residual
	// timestamp/id predicates immediately).
	start, ok, err := oldestEligibleTimestamp(d.db.Model(&models.SyslogMessage{}).
		Where("severity = ? AND timestamp < ? AND id <= ?", severity, cutoff, watermark))
	if err != nil {
		err = fmt.Errorf("window start: %w", err)
		log.Printf("Syslog aggregation: %v (will retry next cycle)", err)
		return false, err
	}
	if !ok {
		return false, nil
	}

	window := syslogAggWindow
	if bucketUnit == "day" && window < 24*time.Hour {
		window = 24 * time.Hour // never split a day bucket across windows
	}

	const groupKey = "bucket, device_id, severity, facility, app_name"
	totalGroups, err := walkAggregationWindows(d.db, window, start, cutoff,
		func(tx *gorm.DB, winStart, winEnd time.Time) (int, error) {
			var rows []syslogSummaryRow
			if err := tx.Model(&models.SyslogMessage{}).
				Where("timestamp >= ? AND timestamp < ? AND severity = ? AND id <= ?", winStart, winEnd, severity, watermark).
				Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, " +
					"COUNT(*) as count, MIN(message) as sample_message").
				Group(groupKey).
				Scan(&rows).Error; err != nil {
				return 0, fmt.Errorf("scan raw messages: %w", err)
			}
			if len(rows) == 0 {
				return 0, nil
			}
			if err := batchInsertSyslogSummaries(tx, rows, intervalType, bucketFmt); err != nil {
				return 0, err
			}
			// Delete exactly this window's summarised rows (same predicates and
			// watermark scope), in the same transaction as the inserts.
			if err := tx.Where("timestamp >= ? AND timestamp < ? AND severity = ? AND id <= ?", winStart, winEnd, severity, watermark).
				Delete(&models.SyslogMessage{}).Error; err != nil {
				return 0, fmt.Errorf("delete consumed raw messages: %w", err)
			}
			return len(rows), nil
		})
	if err != nil {
		log.Printf("Syslog aggregation: %v (window rolled back; %d groups from earlier windows kept, will resume next cycle)", err, totalGroups)
		return totalGroups > 0, err
	}

	if totalGroups == 0 {
		return false, nil
	}
	log.Printf("Syslog aggregation: aggregated %d groups from raw syslog into %s summaries", totalGroups, intervalType)
	return true, nil
}

// batchInsertSyslogSummaries inserts syslog summary rows in batches.
func batchInsertSyslogSummaries(tx *gorm.DB, rows []syslogSummaryRow, intervalType, bucketFmt string) error {
	const batchSize = 500
	for i := 0; i < len(rows); i += batchSize {
		end := i + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := make([]models.SyslogSummary, 0, end-i)
		for _, r := range rows[i:end] {
			// AUDIT-203: a bucket/layout mismatch must fail the transaction, not
			// silently commit a year-0001 summary in the same tx that deletes the
			// raw rows — retention would then reap the mis-dated summary and the
			// history would vanish with no log. The caller's tx rolls back, so
			// the raw rows are preserved for the next cycle.
			ts, err := time.Parse(bucketFmt, r.Bucket)
			if err != nil {
				return fmt.Errorf("parse bucket %q with layout %q: %w", r.Bucket, bucketFmt, err)
			}
			batch = append(batch, models.SyslogSummary{
				Timestamp:    ts,
				DeviceID:     r.DeviceID,
				IntervalType: intervalType,
				Severity:     r.Severity,
				Facility:     r.Facility,
				AppName:      r.AppName,
				// M2 fix: message_pattern was never populated (always empty). SQL
				// GROUP BY can't run the Go normalizer, so derive one approximate
				// template per group from the sample (MIN(message)) at insert time.
				MessagePattern: logfields.Normalize(r.SampleMessage),
				Count:          r.Count,
				SampleMessage:  r.SampleMessage,
			})
		}
		if err := tx.Create(&batch).Error; err != nil {
			return fmt.Errorf("batch insert syslog summaries: %w", err)
		}
	}
	return nil
}

// syslogPromotePageSize bounds how many distinct groups promoteSyslogSummaries
// reads per page. A package var (not a const) so tests can shrink it to
// exercise the multi-page path. Defaults to 5000.
var syslogPromotePageSize = 5000

// promoteSyslogSummaries promotes summaries from srcInterval older than cutoff into dstInterval.
// Returns true if work was done, error if fatal.
//
// H3 of the 2026-07-01 audit: the pre-fix code ran an UNSCOPED
// `interval_type = src AND timestamp < cutoff` delete inside EACH page's
// transaction, so the moment page 1 committed it destroyed every
// still-un-promoted source group — any groups beyond the first page were
// silently lost, and the raw syslog behind them was already gone (this is the
// same bug fixed in aggregateSyslogToSummary as M2 of 2026-06-23; the promote
// step had been missed). Now it uses the shared correctness shape: MAX(id)
// watermark for an immutable source set, deterministic ORDER BY pagination,
// and one transaction wrapping every page insert plus a single watermark-scoped
// delete at the end.
func (d *Database) promoteSyslogSummaries(srcInterval, dstInterval string, cutoff time.Time) (bool, error) {
	bucketUnit := "day"
	bucketFmt := "2006-01-02"
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	pageSize := syslogPromotePageSize
	totalGroups := 0

	err := d.db.Transaction(func(tx *gorm.DB) error {
		// Same shape, and the same trap, as aggregateSyslogToSummary's watermark:
		// probe for work under the real predicates, then take an UNFILTERED
		// upper bound. Harmless on a small syslog_summaries, but it becomes the
		// identical pathological pkey walk once summaries accumulate, so it is
		// fixed here rather than left to be rediscovered.
		var probe []int64
		if err := tx.Model(&models.SyslogSummary{}).
			Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
			Select("1").Limit(1).
			Scan(&probe).Error; err != nil {
			return fmt.Errorf("%s work probe: %w", srcInterval, err)
		}
		if len(probe) == 0 {
			return nil
		}

		// Rows inserted below carry dstInterval and ids above this bound, so the
		// final delete — which keeps `interval_type = srcInterval` — can never
		// reach them.
		var watermark int64
		if err := tx.Model(&models.SyslogSummary{}).
			Select("COALESCE(MAX(id), 0)").
			Scan(&watermark).Error; err != nil {
			return fmt.Errorf("%s watermark: %w", srcInterval, err)
		}
		if watermark == 0 {
			return nil
		}

		const groupKey = "bucket, device_id, severity, facility, app_name, message_pattern"
		offset := 0
		for {
			var rows []syslogSummaryRow
			if err := tx.Model(&models.SyslogSummary{}).
				Where("interval_type = ? AND timestamp < ? AND id <= ?", srcInterval, cutoff, watermark).
				Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, message_pattern, " +
					"SUM(count) as count, MIN(sample_message) as sample_message").
				Group(groupKey).
				Order(groupKey).
				Limit(pageSize).Offset(offset).
				Scan(&rows).Error; err != nil {
				return fmt.Errorf("scan %s summaries: %w", srcInterval, err)
			}
			if len(rows) == 0 {
				break
			}
			if err := batchInsertSyslogSummaries(tx, rows, dstInterval, bucketFmt); err != nil {
				return fmt.Errorf("promote %s→%s summaries: insert: %w", srcInterval, dstInterval, err)
			}
			totalGroups += len(rows)
			if len(rows) < pageSize {
				break
			}
			offset += pageSize
		}

		if totalGroups == 0 {
			return nil
		}

		// Single delete of exactly the promoted source rows, after ALL pages,
		// in the same transaction. The dstInterval rows inserted above have a
		// different interval_type (and ids above the watermark), so they can
		// never match this delete.
		if err := tx.Where("interval_type = ? AND timestamp < ? AND id <= ?", srcInterval, cutoff, watermark).
			Delete(&models.SyslogSummary{}).Error; err != nil {
			return fmt.Errorf("delete consumed %s syslog summaries: %w", srcInterval, err)
		}
		return nil
	})
	if err != nil {
		log.Printf("Syslog aggregation: promote %s→%s: %v (rolled back, will retry next cycle)", srcInterval, dstInterval, err)
		return false, err
	}

	if totalGroups == 0 {
		return false, nil
	}
	log.Printf("Syslog aggregation: promoted %d groups from %s to %s summaries", totalGroups, srcInterval, dstInterval)
	return true, nil
}
