package database

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/config"
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
	offset := 0
	totalGroups := 0

	for {
		var rows []syslogSummaryRow
		if err := d.db.Model(&models.SyslogMessage{}).
			Where("timestamp < ? AND severity >= 6", cutoff). // only informational (6) and debug (7)
			Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, " +
				"COUNT(*) as count, MIN(message) as sample_message").
			Group("bucket, device_id, severity, facility, app_name").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Syslog aggregation: error scanning raw messages: %v", err)
			return totalGroups > 0, err
		}

		if len(rows) == 0 {
			break
		}

		// Insert this page's summaries only. The raw rows are deleted ONCE after
		// the whole loop (below), not here. The pre-fix code deleted ALL matching
		// rows inside this per-page transaction, so the moment page 1 committed it
		// wiped every still-un-summarized group — any distinct groups beyond the
		// first page were silently dropped without ever being counted (M2 of the
		// 2026-06-23 audit). Reading over the still-intact syslog_messages keeps
		// the OFFSET pagination correct, exactly like aggregateFlowsToRollup.
		if err := d.db.Transaction(func(tx *gorm.DB) error {
			return batchInsertSyslogSummaries(tx, rows, intervalType, bucketFmt)
		}); err != nil {
			log.Printf("Syslog aggregation: transaction error: %v", err)
			return totalGroups > 0, err
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false, nil
	}

	// Delete the consumed raw informational messages once, after every group has
	// been summarized (mirrors aggregateFlowsToRollup's post-loop delete).
	if err := d.db.Where("timestamp < ? AND severity >= 6", cutoff).Delete(&models.SyslogMessage{}).Error; err != nil {
		log.Printf("Syslog aggregation: error deleting consumed raw messages: %v", err)
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
				Timestamp:      ts,
				DeviceID:       r.DeviceID,
				IntervalType:   intervalType,
				Severity:       r.Severity,
				Facility:       r.Facility,
				AppName:        r.AppName,
				MessagePattern: r.MessagePattern,
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

// promoteSyslogSummaries promotes summaries from srcInterval older than cutoff into dstInterval.
// Returns true if work was done, error if fatal.
func (d *Database) promoteSyslogSummaries(srcInterval, dstInterval string, cutoff time.Time) (bool, error) {
	bucketUnit := "day"
	bucketFmt := "2006-01-02"
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	const pageSize = 5000
	offset := 0
	totalGroups := 0

	for {
		var rows []syslogSummaryRow
		if err := d.db.Model(&models.SyslogSummary{}).
			Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
			Select(bucketExpr + " as bucket, device_id, severity, facility, app_name, message_pattern, " +
				"SUM(count) as count, MIN(sample_message) as sample_message").
			Group("bucket, device_id, severity, facility, app_name, message_pattern").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Syslog aggregation: error scanning %s summaries: %v", srcInterval, err)
			return totalGroups > 0, err
		}

		if len(rows) == 0 {
			break
		}

		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := batchInsertSyslogSummaries(tx, rows, dstInterval, bucketFmt); err != nil {
				return fmt.Errorf("syslog aggregation: promote %s→%s summaries: insert: %w", srcInterval, dstInterval, err)
			}
			if err := tx.Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
				Delete(&models.SyslogSummary{}).Error; err != nil {
				return fmt.Errorf("delete consumed %s syslog summaries: %w", srcInterval, err)
			}
			return nil
		}); err != nil {
			log.Printf("Syslog aggregation: transaction error promoting %s to %s: %v", srcInterval, dstInterval, err)
			return totalGroups > 0, err
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false, nil
	}

	log.Printf("Syslog aggregation: promoted %d groups from %s to %s summaries", totalGroups, srcInterval, dstInterval)
	return true, nil
}
