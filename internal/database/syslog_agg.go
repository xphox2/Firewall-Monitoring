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

// syslogAggPageSize bounds how many distinct groups aggregateSyslogToSummary
// reads per page. A package var (not a const) so tests can shrink it to exercise
// the multi-page path. Defaults to 10000.
var syslogAggPageSize = 10000

// RunSyslogAggregationCycle aggregates old informational syslog into summaries for scalability.
// Called every 5 minutes by the poller:
//  1. Raw informational (severity 6-7) older than SyslogInfoDays → hourly summaries
//  2. Hourly summaries older than 48h → daily summaries
func (d *Database) RunSyslogAggregationCycle(retention config.RetentionConfig) error {
	infoDays := retention.SyslogInfoDays
	if infoDays <= 0 {
		infoDays = 7 // default: aggregate after 7 days
	}

	work := false
	var lastErr error

	// Step 1: raw informational syslog > infoDays old → hourly summaries
	cutoffInfo := time.Now().AddDate(0, 0, -infoDays)
	if done, err := d.aggregateSyslogToSummary(cutoffInfo, "1h"); err != nil {
		lastErr = err
		log.Printf("Syslog aggregation: step 1 error: %v", err)
	} else if done {
		work = true
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

// aggregateSyslogToSummary groups raw informational syslog older than cutoff into hourly summaries.
// Returns true if work was done, error if fatal.
func (d *Database) aggregateSyslogToSummary(cutoff time.Time, intervalType string) (bool, error) {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if intervalType == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	pageSize := syslogAggPageSize
	totalGroups := 0

	// Correctness shape shared with the flow rollups (H1+H2 of the 2026-07-01
	// audit, extending the M2 fix of 2026-06-23):
	//   - MAX(id) watermark: reads and the final delete are scoped to
	//     `id <= watermark`, so raw messages that arrive mid-pass (ingestion
	//     runs concurrently in cmd/api, and a collector backlog replay carries
	//     OLD timestamps) are never deleted un-summarized — they wait for the
	//     next cycle.
	//   - Deterministic ORDER BY over the full group key so LIMIT/OFFSET pages
	//     neither overlap nor skip groups.
	//   - Inserts + delete in ONE transaction: a mid-pass failure rolls back
	//     completely instead of leaving summaries the next cycle double-counts.
	err := d.db.Transaction(func(tx *gorm.DB) error {
		var watermark int64
		if err := tx.Model(&models.SyslogMessage{}).
			Where("timestamp < ? AND severity >= 6", cutoff).
			Select("COALESCE(MAX(id), 0)").
			Scan(&watermark).Error; err != nil {
			return fmt.Errorf("watermark: %w", err)
		}
		if watermark == 0 {
			return nil
		}

		const groupKey = "bucket, device_id, severity, facility, app_name"
		offset := 0
		for {
			var rows []syslogSummaryRow
			if err := tx.Model(&models.SyslogMessage{}).
				Where("timestamp < ? AND severity >= 6 AND id <= ?", cutoff, watermark). // only informational (6) and debug (7)
				Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, " +
					"COUNT(*) as count, MIN(message) as sample_message").
				Group(groupKey).
				Order(groupKey).
				Limit(pageSize).Offset(offset).
				Scan(&rows).Error; err != nil {
				return fmt.Errorf("scan raw messages: %w", err)
			}
			if len(rows) == 0 {
				break
			}
			if err := batchInsertSyslogSummaries(tx, rows, intervalType, bucketFmt); err != nil {
				return err
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

		// Delete exactly the rows that were summarized (same watermark scope),
		// in the same transaction as the inserts.
		if err := tx.Where("timestamp < ? AND severity >= 6 AND id <= ?", cutoff, watermark).
			Delete(&models.SyslogMessage{}).Error; err != nil {
			return fmt.Errorf("delete consumed raw messages: %w", err)
		}
		return nil
	})
	if err != nil {
		log.Printf("Syslog aggregation: %v (rolled back, will retry next cycle)", err)
		return false, err
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
			ts, _ := time.Parse(bucketFmt, r.Bucket)
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
		var watermark int64
		if err := tx.Model(&models.SyslogSummary{}).
			Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
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
