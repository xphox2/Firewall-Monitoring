package models

import "time"

// The raw archive's manifest tables (migration v75, archive plan PR 3). A
// chunk is an id range (id_lo, id_hi] of one source table, cut at a UTC day
// (syslog_messages, flow_if_counters) or hour (flow_samples) boundary; it is
// exported to one or more objects (archive_objects), and the objects of one
// stream and UTC month are sealed into archive_months. archive_id_marks are the
// per-boundary max(id) marks the flow tables are cut by (they have no ingest
// column the cut could binary-search). Nothing writes these tables
// automatically yet: the archive worker is a later release.

// Archive chunk statuses (ArchiveChunk.Status).
const (
	ArchiveChunkPending    = "pending"
	ArchiveChunkExporting  = "exporting"
	ArchiveChunkUploading  = "uploading"
	ArchiveChunkVerifying  = "verifying"
	ArchiveChunkVerified   = "verified"
	ArchiveChunkFailed     = "failed"
	ArchiveChunkSuperseded = "superseded"
)

// ArchiveChunk is one contiguous id range of a source table. Chunks of a table
// are gapless: chunk[seq].IDLo == chunk[seq-1].IDHi, and the first has IDLo 0.
// An empty period is still a chunk (IDLo == IDHi), so a seal can tell "no rows"
// from "missing".
type ArchiveChunk struct {
	ID uint `json:"id" gorm:"primaryKey"`
	// SourceTable is syslog_messages, flow_samples or flow_if_counters.
	SourceTable string `json:"table_name" gorm:"column:table_name;size:32;not null;uniqueIndex:idx_archive_chunk_seq,priority:1;uniqueIndex:idx_archive_chunk_period,priority:1"`
	Seq         int64  `json:"seq" gorm:"not null;uniqueIndex:idx_archive_chunk_seq,priority:2"`
	IDLo        int64  `json:"id_lo" gorm:"column:id_lo;not null"`
	IDHi        int64  `json:"id_hi" gorm:"column:id_hi;not null"`
	// PeriodStart / PeriodEnd: the UTC day or hour [start, end) the chunk was
	// cut for — by created_at for syslog, by the id mark taken at PeriodEnd for
	// the flow tables.
	PeriodStart time.Time `json:"period_start" gorm:"not null;uniqueIndex:idx_archive_chunk_period,priority:2"`
	PeriodEnd   time.Time `json:"period_end" gorm:"not null"`
	// Month is the ingest month "YYYY-MM" of PeriodStart: the month folder the
	// chunk's objects belong to.
	Month string `json:"month" gorm:"size:7;not null;index"`
	// MarkLateByMs: how long after PeriodEnd the closing id mark was taken
	// (flow tables only; NULL for syslog). Rows that arrived in that time are
	// in this chunk.
	MarkLateByMs *int64 `json:"mark_late_by_ms"`
	// CutAt is the instant the cut was fixed (the mark's taken_at, or the end
	// of the syslog search; database clock on PostgreSQL).
	CutAt time.Time `json:"cut_at"`
	// GuardXmax is the xmax of a snapshot taken once the cut has settled
	// (CutAt + statement_timeout + margin): no export until every transaction
	// id below it has finished (any of them may hold rows in the range). NULL
	// until then, and off PostgreSQL.
	GuardXmax *int64 `json:"guard_xmax"`
	Status    string `json:"status" gorm:"size:16;not null;default:pending;index"`
	// RowCount and the message-time bounds/histogram are filled by the export.
	RowCount int64      `json:"row_count"`
	MinTs    *time.Time `json:"min_ts"`
	MaxTs    *time.Time `json:"max_ts"`
	// MsgDayHistogram is {"YYYY-MM-DD": rows} by message (sample) UTC day, so a
	// restore of a message day finds the chunks that hold it.
	MsgDayHistogram *string    `json:"msg_day_histogram" gorm:"type:jsonb"`
	Attempts        int        `json:"attempts"`
	Error           string     `json:"error" gorm:"type:text"`
	RunnerID        string     `json:"runner_id"`
	StartedAt       *time.Time `json:"started_at"`
	VerifiedAt      *time.Time `json:"verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (ArchiveChunk) TableName() string { return "archive_chunks" }

// ArchiveObject is one exported object of a chunk: per device for syslog, per
// stream (sflow / netflow) for flow_samples, one for flow_if_counters.
// A re-export of the same chunk whose content changed (a device purge between
// attempts) marks the old row superseded and adds a new one.
type ArchiveObject struct {
	ID      uint   `json:"id" gorm:"primaryKey"`
	ChunkID uint   `json:"chunk_id" gorm:"not null;index"`
	Stream  string `json:"stream" gorm:"size:16;not null"`
	// DeviceID: the syslog object's device; NULL for flow and counter objects
	// (they hold every device). Not a row owner: the object outlives a purge.
	DeviceID      *uint  `json:"device_id"`
	ObjectKey     string `json:"object_key" gorm:"type:text;not null"`
	SchemaVersion int    `json:"schema_version" gorm:"not null"`
	Compression   string `json:"compression" gorm:"size:8;not null"`
	RowCount      int64  `json:"row_count"`
	RawBytes      int64  `json:"raw_bytes"`
	ObjectBytes   int64  `json:"object_bytes"`
	// Sha256Content is over the uncompressed NDJSON (stable across gzip
	// implementations: idempotency and the month digest use it);
	// Sha256Object over the stored bytes.
	Sha256Content   string     `json:"sha256_content" gorm:"size:64"`
	Sha256Object    string     `json:"sha256_object" gorm:"size:64"`
	PartCount       int        `json:"part_count"`
	ETag            string     `json:"etag" gorm:"column:etag"`
	VersionID       string     `json:"version_id"`
	MinID           int64      `json:"min_id"`
	MaxID           int64      `json:"max_id"`
	MinTs           *time.Time `json:"min_ts"`
	MaxTs           *time.Time `json:"max_ts"`
	MsgDayHistogram *string    `json:"msg_day_histogram" gorm:"type:jsonb"`
	LockUntil       *time.Time `json:"lock_until"`
	Status          string     `json:"status" gorm:"size:16;not null;default:pending"`
	VerifiedAt      *time.Time `json:"verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (ArchiveObject) TableName() string { return "archive_objects" }

// ArchiveMonth is the seal state of one stream's month folder.
type ArchiveMonth struct {
	ID     uint   `json:"id" gorm:"primaryKey"`
	Stream string `json:"stream" gorm:"size:16;not null;uniqueIndex:idx_archive_month,priority:1"`
	Month  string `json:"month" gorm:"size:7;not null;uniqueIndex:idx_archive_month,priority:2"`
	// Status: open → sealing → sealed, or seal_failed.
	Status      string `json:"status" gorm:"size:16;not null;default:open"`
	Partial     bool   `json:"partial" gorm:"not null;default:false"`
	PartialNote string `json:"partial_note" gorm:"type:text"`
	FirstID     *int64 `json:"first_id"`
	LastID      *int64 `json:"last_id"`
	// BoundaryLateByMs: how late the mark closing the month was taken (flow
	// streams).
	BoundaryLateByMs *int64     `json:"boundary_late_by_ms"`
	ChunkCount       int64      `json:"chunk_count"`
	RowCount         int64      `json:"row_count"`
	ObjectBytes      int64      `json:"object_bytes"`
	MonthDigest      string     `json:"month_digest" gorm:"size:64"`
	ManifestKey      string     `json:"manifest_key" gorm:"type:text"`
	ManifestSha256   string     `json:"manifest_sha256" gorm:"size:64"`
	SealedAt         *time.Time `json:"sealed_at"`
	Error            string     `json:"error" gorm:"type:text"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

func (ArchiveMonth) TableName() string { return "archive_months" }

// ArchiveIDMark records max(id) of a source table at one UTC cut boundary,
// taken on the first archive tick at or after it (TakenAt, database clock). The
// flow tables' chunk for [b-1 period, b) ends at the mark of b.
type ArchiveIDMark struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	SourceTable string    `json:"table_name" gorm:"column:table_name;size:32;not null;uniqueIndex:idx_archive_id_mark,priority:1"`
	BoundaryTs  time.Time `json:"boundary_ts" gorm:"not null;uniqueIndex:idx_archive_id_mark,priority:2"`
	MaxID       int64     `json:"max_id" gorm:"not null"`
	TakenAt     time.Time `json:"taken_at" gorm:"not null"`
}

func (ArchiveIDMark) TableName() string { return "archive_id_marks" }
