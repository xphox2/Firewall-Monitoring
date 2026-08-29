package database

import (
	"errors"
	"fmt"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

func (d *Database) GetLatestConfigRevision(deviceID uint) (*models.DeviceConfigRevision, error) {
	var rev models.DeviceConfigRevision
	err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&rev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &rev, err
}

// CleanupConfigRevisions enforces retention on device_config_revisions.
// Simple in v0.10.198+ thanks to the merge-into-latest storage model: the
// `device_config_revisions` table now contains one row per *distinct* config
// state, so there are no IV-drift duplicates to collapse. Just two rules:
//
//  1. Hard-delete rows older than 365 days. Plenty for compliance audit and
//     bounds long-tail storage growth on devices that change frequently.
//  2. Per-device cap: 500 distinct states. Devices that genuinely change 500
//     times in a year are rare; if a deployment has them, raise the cap.
func (d *Database) CleanupConfigRevisions() error {
	const keepDays = 365
	const perDeviceCap = 500

	timeCutoff := time.Now().AddDate(0, 0, -keepDays)

	// Step 1: time-based cleanup is one query across all devices.
	if err := d.db.Where("timestamp < ?", timeCutoff).
		Delete(&models.DeviceConfigRevision{}).Error; err != nil {
		return fmt.Errorf("cleanup config_revisions by age: %w", err)
	}

	// Step 2: per-device cap — only walk devices that actually have > cap rows.
	// Most deployments will have devices well under 500 distinct states, so
	// this loop is empty in the common case.
	type devCount struct {
		DeviceID uint
		Cnt      int64
	}
	var hot []devCount
	if err := d.db.Model(&models.DeviceConfigRevision{}).
		Select("device_id, COUNT(*) as cnt").
		Group("device_id").
		Having("COUNT(*) > ?", perDeviceCap).
		Scan(&hot).Error; err != nil {
		return fmt.Errorf("cleanup config_revisions: count over-cap devices: %w", err)
	}

	for _, dc := range hot {
		// Find the cutoff timestamp: the timestamp of the (perDeviceCap)th
		// most recent row. Anything older than that is dropped.
		var floor models.DeviceConfigRevision
		if err := d.db.Where("device_id = ?", dc.DeviceID).
			Order("timestamp DESC").Offset(perDeviceCap - 1).Limit(1).
			First(&floor).Error; err != nil {
			continue
		}
		if err := d.db.Where("device_id = ? AND timestamp < ?", dc.DeviceID, floor.Timestamp).
			Delete(&models.DeviceConfigRevision{}).Error; err != nil {
			return fmt.Errorf("cleanup config_revisions device %d cap: %w", dc.DeviceID, err)
		}
	}

	return nil
}

// CollapseLegacyConfigRevisionDuplicates is a one-time migration helper for
// deployments that ran v0.10.187 → v0.10.197 (the always-store era). It walks
// each device's history and collapses runs of identical NormalizedChecksum
// rows down to a single representative row per run — the most recent of the
// run keeps the bytes, the older rows of the run are deleted, and the
// representative row's VerifyCount is set to the count of merged rows so the
// audit trail is preserved.
//
// Idempotent. Safe to call multiple times. Returns the number of rows deleted.
func (d *Database) CollapseLegacyConfigRevisionDuplicates() (int64, error) {
	var deviceIDs []uint
	if err := d.db.Model(&models.DeviceConfigRevision{}).
		Distinct("device_id").Pluck("device_id", &deviceIDs).Error; err != nil {
		return 0, fmt.Errorf("list device ids: %w", err)
	}

	var totalDeleted int64
	for _, devID := range deviceIDs {
		var revs []models.DeviceConfigRevision
		if err := d.db.Where("device_id = ?", devID).
			Order("timestamp ASC, id ASC").Find(&revs).Error; err != nil {
			return totalDeleted, fmt.Errorf("device %d: list: %w", devID, err)
		}
		if len(revs) == 0 {
			continue
		}

		// Walk in order. Each run of identical NormalizedChecksum gets
		// collapsed: we update the LAST row in the run to carry the run's
		// VerifyCount and FirstSeenAt, then delete the earlier rows in the run.
		i := 0
		for i < len(revs) {
			j := i + 1
			for j < len(revs) && revs[j].NormalizedChecksum == revs[i].NormalizedChecksum {
				j++
			}
			runLen := j - i
			if runLen > 1 {
				keep := &revs[j-1]
				// Update keep row with the run's metadata.
				updates := map[string]interface{}{
					"first_seen_at":    revs[i].Timestamp,
					"last_verified_at": keep.Timestamp,
					"verify_count":     runLen,
				}
				if err := d.db.Model(&models.DeviceConfigRevision{}).
					Where("id = ?", keep.ID).Updates(updates).Error; err != nil {
					return totalDeleted, fmt.Errorf("device %d collapse update: %w", devID, err)
				}
				// Delete older rows in the run.
				deleteIDs := make([]uint, 0, runLen-1)
				for k := i; k < j-1; k++ {
					deleteIDs = append(deleteIDs, revs[k].ID)
				}
				res := d.db.Where("id IN ?", deleteIDs).Delete(&models.DeviceConfigRevision{})
				if res.Error != nil {
					return totalDeleted, fmt.Errorf("device %d collapse delete: %w", devID, res.Error)
				}
				totalDeleted += res.RowsAffected
			} else {
				// Single-row run — backfill new fields if they're zero (legacy).
				keep := &revs[i]
				if keep.FirstSeenAt.IsZero() || keep.LastVerifiedAt.IsZero() || keep.VerifyCount == 0 {
					updates := map[string]interface{}{}
					if keep.FirstSeenAt.IsZero() {
						updates["first_seen_at"] = keep.Timestamp
					}
					if keep.LastVerifiedAt.IsZero() {
						updates["last_verified_at"] = keep.Timestamp
					}
					if keep.VerifyCount == 0 {
						updates["verify_count"] = 1
					}
					if len(updates) > 0 {
						d.db.Model(&models.DeviceConfigRevision{}).
							Where("id = ?", keep.ID).Updates(updates)
					}
				}
			}
			i = j
		}
	}
	return totalDeleted, nil
}
