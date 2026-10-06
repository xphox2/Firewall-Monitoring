package database

import (
	"context"
	"time"

	"firewall-mon/internal/models"
)

// Reads behind the archive status card's progress view: how much of each
// table's planned work is left, what was verified lately and how fast, the
// chunks waiting on a retry, and what the bucket holds per stream and month.
// Every one reads only the manifest tables (archive_chunks, archive_objects:
// a row per syslog day per device, two per flow hour), never a source table.

// ArchiveBacklog is a table's planned chunks that are not verified yet.
type ArchiveBacklog struct {
	// Chunks: not verified (pending, exporting, uploading, verifying,
	// failed, needs_attention).
	Chunks int64
	// IDSpan: the sum of their id ranges (id_hi − id_lo), an upper bound of
	// their rows (ids a rollback or a purge skipped are counted).
	IDSpan int64
	// OldestPeriod: the earliest period_start among them (nil: none).
	OldestPeriod *time.Time
}

// ArchiveBacklogs returns the backlog of every table that has one.
func (d *Database) ArchiveBacklogs(ctx context.Context) (map[string]ArchiveBacklog, error) {
	var rows []struct {
		TableName string
		N         int64
		Span      int64
	}
	if err := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).
		Select("table_name, count(*) AS n, COALESCE(sum(id_hi - id_lo), 0) AS span").
		Where("status <> ?", models.ArchiveChunkVerified).Group("table_name").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]ArchiveBacklog, len(rows))
	for _, r := range rows {
		b := ArchiveBacklog{Chunks: r.N, IDSpan: r.Span}
		// The oldest period separately: min() of a timestamp comes back as
		// text on SQLite.
		var first []time.Time
		if err := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).Where("table_name = ? AND status <> ?", r.TableName, models.ArchiveChunkVerified).
			Order("period_start").Limit(1).Pluck("period_start", &first).Error; err != nil {
			return nil, err
		}
		if len(first) == 1 {
			t := first[0].UTC()
			b.OldestPeriod = &t
		}
		out[r.TableName] = b
	}
	return out, nil
}

// ArchiveChunkSummary is a chunk with the totals of its live objects.
type ArchiveChunkSummary struct {
	Chunk       models.ArchiveChunk
	Objects     int64
	ObjectBytes int64
	RawBytes    int64
}

// RecentArchiveChunks returns the newest verified chunks (of table, or of
// every table when it is ""), newest first, with their verified objects'
// totals.
func (d *Database) RecentArchiveChunks(ctx context.Context, table string, limit int) ([]ArchiveChunkSummary, error) {
	q := d.db.WithContext(ctx).Where("status = ? AND verified_at IS NOT NULL", models.ArchiveChunkVerified)
	if table != "" {
		q = q.Where("table_name = ?", table)
	}
	var cs []models.ArchiveChunk
	if err := q.Order("verified_at DESC, id DESC").Limit(limit).Find(&cs).Error; err != nil {
		return nil, err
	}
	return d.summarizeArchiveChunks(ctx, cs, models.ArchiveObjectVerified)
}

// ArchiveChunksWithStatus returns up to limit chunks in status, oldest period
// first, with their objects' totals (objects of any status but superseded).
func (d *Database) ArchiveChunksWithStatus(ctx context.Context, status string, limit int) ([]ArchiveChunkSummary, error) {
	var cs []models.ArchiveChunk
	if err := d.db.WithContext(ctx).Where("status = ?", status).Order("period_start, table_name").Limit(limit).Find(&cs).Error; err != nil {
		return nil, err
	}
	return d.summarizeArchiveChunks(ctx, cs, "")
}

// summarizeArchiveChunks adds the totals of each chunk's objects in status
// ("" = every object not superseded).
func (d *Database) summarizeArchiveChunks(ctx context.Context, cs []models.ArchiveChunk, status string) ([]ArchiveChunkSummary, error) {
	out := make([]ArchiveChunkSummary, len(cs))
	if len(cs) == 0 {
		return out, nil
	}
	ids := make([]uint, len(cs))
	for i, c := range cs {
		ids[i] = c.ID
		out[i].Chunk = c
	}
	q := d.db.WithContext(ctx).Model(&models.ArchiveObject{}).
		Select("chunk_id, count(*) AS n, COALESCE(sum(object_bytes), 0) AS ob, COALESCE(sum(raw_bytes), 0) AS rb").
		Where("chunk_id IN ?", ids)
	if status != "" {
		q = q.Where("status = ?", status)
	} else {
		q = q.Where("status <> ?", models.ArchiveObjectSuperseded)
	}
	var sums []struct {
		ChunkID uint
		N       int64
		Ob      int64
		Rb      int64
	}
	if err := q.Group("chunk_id").Scan(&sums).Error; err != nil {
		return nil, err
	}
	by := make(map[uint]int, len(cs))
	for i, c := range cs {
		by[c.ID] = i
	}
	for _, s := range sums {
		if i, ok := by[s.ChunkID]; ok {
			out[i].Objects, out[i].ObjectBytes, out[i].RawBytes = s.N, s.Ob, s.Rb
		}
	}
	return out, nil
}

// ArchiveMonthTotal is what the bucket holds, verified, for one stream's
// month folder.
type ArchiveMonthTotal struct {
	Stream      string
	Month       string
	Objects     int64
	Rows        int64 `gorm:"column:row_total"`
	ObjectBytes int64
	RawBytes    int64
}

// ArchiveVerifiedTotals returns the verified objects' totals per stream and
// month (the chunk's ingest month: its folder).
func (d *Database) ArchiveVerifiedTotals(ctx context.Context) ([]ArchiveMonthTotal, error) {
	var out []ArchiveMonthTotal
	err := d.db.WithContext(ctx).Table("archive_objects AS o").
		Select("o.stream AS stream, c.month AS month, count(*) AS objects, COALESCE(sum(o.row_count), 0) AS row_total, "+
			"COALESCE(sum(o.object_bytes), 0) AS object_bytes, COALESCE(sum(o.raw_bytes), 0) AS raw_bytes").
		Joins("JOIN archive_chunks AS c ON c.id = o.chunk_id").
		Where("o.status = ?", models.ArchiveObjectVerified).
		Group("o.stream, c.month").Order("o.stream, c.month").Scan(&out).Error
	return out, err
}
