package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The raw archive's month seal state (archive plan PR 7, §3.1) on
// archive_months: one row per (stream, month), open → sealing → sealed, or
// seal_failed with the reason. The archive worker (internal/archive/worker)
// decides whether a month can be sealed, writes its _MONTH.json and only then
// records it sealed; these are the short statements it runs, under its
// advisory lock. A sealed row is never changed again: every write here leaves
// it alone, and the worker refuses any object write into a sealed month's
// folder (ArchiveMonthSealed).

// ArchiveChunkMonths lists the months ("YYYY-MM") table has chunks in,
// ascending.
func (d *Database) ArchiveChunkMonths(ctx context.Context, table string) ([]string, error) {
	var ms []string
	err := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).Where("table_name = ?", table).
		Distinct("month").Order("month").Pluck("month", &ms).Error
	return ms, err
}

// ArchiveSealedMonths returns the sealed months of stream.
func (d *Database) ArchiveSealedMonths(ctx context.Context, stream string) (map[string]bool, error) {
	var ms []string
	if err := d.db.WithContext(ctx).Model(&models.ArchiveMonth{}).Where("stream = ? AND status = ?", stream, models.ArchiveMonthSealed).
		Pluck("month", &ms).Error; err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ms))
	for _, m := range ms {
		out[m] = true
	}
	return out, nil
}

// ArchiveMonthState returns stream's row for month, or nil when it has none.
func (d *Database) ArchiveMonthState(ctx context.Context, stream, month string) (*models.ArchiveMonth, error) {
	var ms []models.ArchiveMonth
	if err := d.db.WithContext(ctx).Where("stream = ? AND month = ?", stream, month).Limit(1).Find(&ms).Error; err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return nil, nil
	}
	return &ms[0], nil
}

// ArchiveMonthSealed reports whether stream's month is sealed: its folder
// takes no further write.
func (d *Database) ArchiveMonthSealed(ctx context.Context, stream, month string) (bool, error) {
	var n int64
	err := d.db.WithContext(ctx).Model(&models.ArchiveMonth{}).
		Where("stream = ? AND month = ? AND status = ?", stream, month, models.ArchiveMonthSealed).Count(&n).Error
	return n > 0, err
}

// ArchiveMonthChunks returns table's chunks of month in seq order and the
// chunk just before the first of them (nil when there is none: the month
// holds the table's first chunk, or no chunk at all).
func (d *Database) ArchiveMonthChunks(ctx context.Context, table, month string) ([]models.ArchiveChunk, *models.ArchiveChunk, error) {
	var cs []models.ArchiveChunk
	if err := d.db.WithContext(ctx).Where("table_name = ? AND month = ?", table, month).Order("seq").Find(&cs).Error; err != nil {
		return nil, nil, err
	}
	if len(cs) == 0 {
		return nil, nil, nil
	}
	var prev []models.ArchiveChunk
	if err := d.db.WithContext(ctx).Where("table_name = ? AND seq < ?", table, cs[0].Seq).Order("seq DESC").Limit(1).Find(&prev).Error; err != nil {
		return nil, nil, err
	}
	if len(prev) == 0 {
		return cs, nil, nil
	}
	return cs, &prev[0], nil
}

// archiveMonthObjectBatch bounds the chunk ids of one IN list (a month of
// hourly flow chunks is up to 744).
const archiveMonthObjectBatch = 400

// ArchiveMonthObjects returns the objects of the chunks ids that are not
// superseded, by chunk id, each in id order.
func (d *Database) ArchiveMonthObjects(ctx context.Context, ids []uint) (map[uint][]models.ArchiveObject, error) {
	out := make(map[uint][]models.ArchiveObject, len(ids))
	for lo := 0; lo < len(ids); lo += archiveMonthObjectBatch {
		hi := min(lo+archiveMonthObjectBatch, len(ids))
		var objs []models.ArchiveObject
		if err := d.db.WithContext(ctx).Where("chunk_id IN ? AND status <> ?", ids[lo:hi], models.ArchiveObjectSuperseded).
			Order("id").Find(&objs).Error; err != nil {
			return nil, err
		}
		for _, o := range objs {
			out[o.ChunkID] = append(out[o.ChunkID], o)
		}
	}
	return out, nil
}

// archiveMonthRow returns stream's row for month, creating it open.
func archiveMonthRow(tx *gorm.DB, stream, month string) (*models.ArchiveMonth, error) {
	m := models.ArchiveMonth{Stream: stream, Month: month, Status: models.ArchiveMonthOpen}
	if err := tx.Where("stream = ? AND month = ?", stream, month).FirstOrCreate(&m).Error; err != nil {
		return nil, fmt.Errorf("archive: month %s of %s: %w", month, stream, err)
	}
	return &m, nil
}

// ErrArchiveMonthSealed: a write to the state of a month that is already
// sealed (it is never changed again).
var ErrArchiveMonthSealed = errors.New("archive: the month is sealed")

// RefuseArchiveMonth records that stream's month could not be sealed now:
// status seal_failed with msg (the worker tries again on a later pass). A
// sealed month is left as it is.
func (d *Database) RefuseArchiveMonth(ctx context.Context, stream, month, msg string, at time.Time) error {
	if len(msg) > archiveErrorMax {
		msg = msg[:archiveErrorMax]
	}
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		m, err := archiveMonthRow(tx, stream, month)
		if err != nil {
			return err
		}
		if m.Status == models.ArchiveMonthSealed {
			return nil
		}
		return tx.Model(&models.ArchiveMonth{}).Where("id = ? AND status <> ?", m.ID, models.ArchiveMonthSealed).
			Updates(map[string]interface{}{"status": models.ArchiveMonthSealFailed, "error": msg, "updated_at": at}).Error
	})
}

// BeginArchiveMonthSeal records what the worker is about to write as
// stream's month manifest (m: totals, ids, digest, manifest key and hash) and
// moves the month to sealing. ErrArchiveMonthSealed when it is sealed
// already. m.ID and m.Status are set from the stored row.
func (d *Database) BeginArchiveMonthSeal(ctx context.Context, m *models.ArchiveMonth, at time.Time) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		row, err := archiveMonthRow(tx, m.Stream, m.Month)
		if err != nil {
			return err
		}
		if row.Status == models.ArchiveMonthSealed {
			return ErrArchiveMonthSealed
		}
		res := tx.Model(&models.ArchiveMonth{}).Where("id = ? AND status <> ?", row.ID, models.ArchiveMonthSealed).Updates(map[string]interface{}{
			"status": models.ArchiveMonthSealing, "partial": m.Partial, "partial_note": m.PartialNote,
			"first_id": m.FirstID, "last_id": m.LastID, "boundary_late_by_ms": m.BoundaryLateByMs,
			"chunk_count": m.ChunkCount, "row_count": m.RowCount, "object_bytes": m.ObjectBytes,
			"month_digest": m.MonthDigest, "manifest_key": m.ManifestKey, "manifest_sha256": m.ManifestSha256,
			"error": "", "updated_at": at,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrArchiveMonthSealed
		}
		m.ID, m.Status = row.ID, models.ArchiveMonthSealing
		return nil
	})
}

// MarkArchiveMonthSealed moves m from sealing to sealed: the worker has
// written its _MONTH.json and read it back. From here on nothing is written
// into the month's folder.
func (d *Database) MarkArchiveMonthSealed(ctx context.Context, m *models.ArchiveMonth, at time.Time) error {
	res := d.db.WithContext(ctx).Model(&models.ArchiveMonth{}).
		Where("id = ? AND status = ? AND manifest_sha256 = ?", m.ID, models.ArchiveMonthSealing, m.ManifestSha256).
		Updates(map[string]interface{}{"status": models.ArchiveMonthSealed, "sealed_at": at, "error": "", "updated_at": at})
	if res.Error != nil {
		return fmt.Errorf("archive: seal month %s of %s: %w", m.Month, m.Stream, res.Error)
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("archive: month %s of %s is no longer sealing with manifest %s", m.Month, m.Stream, m.ManifestSha256)
	}
	m.Status, m.SealedAt = models.ArchiveMonthSealed, &at
	return nil
}

// ParkArchiveChunk moves c to needs_attention with msg: the worker found
// something no retry can fix (a write into a sealed month).
func (d *Database) ParkArchiveChunk(ctx context.Context, c *models.ArchiveChunk, msg string, at time.Time) error {
	if len(msg) > archiveErrorMax {
		msg = msg[:archiveErrorMax]
	}
	return casChunk(d.db.WithContext(ctx), c, map[string]interface{}{"status": models.ArchiveChunkNeedsAttention, "error": msg, "updated_at": at})
}

// archiveChunkMonthSealed reports whether c's month is sealed for every
// stream c's table is exported to.
func (d *Database) archiveChunkMonthSealed(ctx context.Context, c *models.ArchiveChunk) (bool, error) {
	streams := export.StreamsOf(c.SourceTable)
	if len(streams) == 0 {
		return false, nil
	}
	var n int64
	if err := d.db.WithContext(ctx).Model(&models.ArchiveMonth{}).
		Where("stream IN ? AND month = ? AND status = ?", streams, c.Month, models.ArchiveMonthSealed).Count(&n).Error; err != nil {
		return false, err
	}
	return n == int64(len(streams)), nil
}

// archiveSealedTableMonths returns the months sealed for every stream table
// is exported to.
func (d *Database) archiveSealedTableMonths(ctx context.Context, table string) (map[string]bool, error) {
	streams := export.StreamsOf(table)
	var rows []struct {
		Month string
		N     int64
	}
	if err := d.db.WithContext(ctx).Model(&models.ArchiveMonth{}).Select("month, count(*) AS n").
		Where("stream IN ? AND status = ?", streams, models.ArchiveMonthSealed).Group("month").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range rows {
		if r.N == int64(len(streams)) {
			out[r.Month] = true
		}
	}
	return out, nil
}
