package database

import (
	"context"
	"fmt"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Reads behind the archive status card's progress view: how much of each
// table's planned work is left, what was verified lately and how fast, the
// chunks waiting on a retry, and what the bucket holds per stream and month.
// Every one reads only the manifest tables (archive_chunks, archive_objects:
// a row per syslog day per device, two per flow hour), never a source table,
// and each one's cost is bounded by what it returns, not by the archive's
// age: the card asks every 15 s, and an archive five years old holds ~90 000
// chunks and ~270 000 objects. The open and the recently verified chunks are
// read through partial indexes (migration v79, archiveChunkIndexes); the
// totals only for the months not sealed yet (a sealed month's totals are on
// its archive_months row).

// The partial indexes' predicates. The queries below use the same literal
// text, so PostgreSQL proves the index applies whatever plan it builds.
const (
	archiveOpenChunks     = "status NOT IN ('verified', 'superseded')"
	archiveVerifiedChunks = "status = 'verified'"
)

// archiveChunkIndexes are migration v79's indexes on archive_chunks.
var archiveChunkIndexes = []string{
	// The open chunks of a table by period: the backlog and its oldest
	// period (a handful of rows however old the archive).
	"CREATE INDEX IF NOT EXISTS idx_archive_chunk_open ON archive_chunks (table_name, period_start) WHERE " + archiveOpenChunks,
	// A table's newest verified chunks, in the order the card lists them.
	"CREATE INDEX IF NOT EXISTS idx_archive_chunk_recent ON archive_chunks (table_name, verified_at, id) WHERE " + archiveVerifiedChunks,
}

// ArchiveBacklog is a table's planned chunks that are not verified yet.
type ArchiveBacklog struct {
	// Chunks: not verified (pending, exporting, uploading, verifying,
	// failed, needs_attention; not superseded, which NextArchiveChunk
	// never works either).
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
	if err := archiveBacklogQuery(d.db.WithContext(ctx)).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]ArchiveBacklog, len(rows))
	for _, r := range rows {
		b := ArchiveBacklog{Chunks: r.N, IDSpan: r.Span}
		// The oldest period separately: min() of a timestamp comes back as
		// text on SQLite.
		var first []time.Time
		if err := archiveOldestOpenQuery(d.db.WithContext(ctx), r.TableName).Pluck("period_start", &first).Error; err != nil {
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

// archiveBacklogQuery and archiveOldestOpenQuery are ArchiveBacklogs'
// statements (the plan test EXPLAINs them): both read idx_archive_chunk_open.
func archiveBacklogQuery(tx *gorm.DB) *gorm.DB {
	return tx.Model(&models.ArchiveChunk{}).Select("table_name, count(*) AS n, COALESCE(sum(id_hi - id_lo), 0) AS span").
		Where(archiveOpenChunks).Group("table_name")
}

func archiveOldestOpenQuery(tx *gorm.DB, table string) *gorm.DB {
	return tx.Model(&models.ArchiveChunk{}).Where("table_name = ? AND "+archiveOpenChunks, table).Order("period_start").Limit(1)
}

// ArchiveChunkSummary is a chunk with the totals of its live objects.
type ArchiveChunkSummary struct {
	Chunk       models.ArchiveChunk
	Objects     int64
	ObjectBytes int64
	RawBytes    int64
}

// RecentArchiveChunks returns table's newest verified chunks, newest first,
// with their verified objects' totals: a backward walk of
// idx_archive_chunk_recent, limit rows long.
func (d *Database) RecentArchiveChunks(ctx context.Context, table string, limit int) ([]ArchiveChunkSummary, error) {
	var cs []models.ArchiveChunk
	if err := archiveRecentQuery(d.db.WithContext(ctx), table, limit).Find(&cs).Error; err != nil {
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

// archiveRecentQuery is RecentArchiveChunks' statement (the plan test
// EXPLAINs it).
func archiveRecentQuery(tx *gorm.DB, table string, limit int) *gorm.DB {
	return tx.Model(&models.ArchiveChunk{}).Where(archiveVerifiedChunks+" AND table_name = ? AND verified_at IS NOT NULL", table).
		Order("verified_at DESC, id DESC").Limit(limit)
}

// ArchiveMonthTotal is what the bucket holds, verified, for one stream's
// month folder.
type ArchiveMonthTotal struct {
	Month       string
	Rows        int64 `gorm:"column:row_total"`
	ObjectBytes int64
}

// ArchiveVerifiedTotals returns stream's verified objects' rows and bytes
// for each of months (the chunks' ingest month — the UTC month of their
// period start — is the folder); table is the stream's source table. The
// caller asks only for the months not sealed (a sealed month's totals are on
// its archive_months row), so the read covers a month or two, each in two
// index range reads: the month's chunk ids by period
// (idx_archive_chunk_period), then the objects of that id range
// (archive_objects.chunk_id; one table's chunks of a month were planned
// together, so the range is narrow, and chunks of other months in it are
// left out here). Joined on the month instead, PostgreSQL prefers to scan
// every object the archive ever wrote; an IN list of a month's 720 hourly
// chunks costs an index descent each.
func (d *Database) ArchiveVerifiedTotals(ctx context.Context, table, stream string, months []string) ([]ArchiveMonthTotal, error) {
	out := []ArchiveMonthTotal{}
	for _, m := range months {
		from, err := time.Parse("2006-01", m)
		if err != nil {
			return nil, fmt.Errorf("archive totals: month %q: %w", m, err)
		}
		var ids []uint
		if err := archiveMonthChunksQuery(d.db.WithContext(ctx), table, from).Pluck("id", &ids).Error; err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			continue
		}
		in := make(map[uint]bool, len(ids))
		lo, hi := ids[0], ids[0]
		for _, id := range ids {
			in[id] = true
			lo, hi = min(lo, id), max(hi, id)
		}
		var per []struct {
			ChunkID     uint
			Rows        int64 `gorm:"column:row_total"`
			ObjectBytes int64
		}
		if err := archiveTotalsQuery(d.db.WithContext(ctx), stream, lo, hi).Scan(&per).Error; err != nil {
			return nil, err
		}
		var tot ArchiveMonthTotal
		for _, p := range per {
			if in[p.ChunkID] { // the range may hold another month's chunks
				tot.Rows, tot.ObjectBytes = tot.Rows+p.Rows, tot.ObjectBytes+p.ObjectBytes
			}
		}
		tot.Month = m
		out = append(out, tot)
	}
	return out, nil
}

// archiveMonthChunksQuery and archiveTotalsQuery are ArchiveVerifiedTotals'
// statements (the plan test EXPLAINs them).
func archiveMonthChunksQuery(tx *gorm.DB, table string, month time.Time) *gorm.DB {
	return tx.Model(&models.ArchiveChunk{}).Where("table_name = ? AND period_start >= ? AND period_start < ?", table, month, month.AddDate(0, 1, 0))
}

func archiveTotalsQuery(tx *gorm.DB, stream string, lo, hi uint) *gorm.DB {
	return tx.Model(&models.ArchiveObject{}).
		Select("chunk_id, COALESCE(sum(row_count), 0) AS row_total, COALESCE(sum(object_bytes), 0) AS object_bytes").
		Where("chunk_id BETWEEN ? AND ? AND stream = ? AND status = ?", lo, hi, stream, models.ArchiveObjectVerified).
		Group("chunk_id")
}
