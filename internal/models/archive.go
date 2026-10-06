package models

import "time"

// The raw archive's manifest tables (migration v75, archive plan PR 3). A
// chunk is an id range (id_lo, id_hi] of one source table, cut at a UTC day
// (syslog_messages, flow_if_counters) or hour (flow_samples) boundary; it is
// exported to one or more objects (archive_objects), and the objects of one
// stream and UTC month are sealed into archive_months. archive_id_marks are the
// per-boundary max(id) marks the flow tables are cut by (they have no ingest
// column the cut could binary-search). The archive worker
// (internal/archive/worker, poller) writes them while a stream is enabled.

// Archive chunk statuses (ArchiveChunk.Status).
const (
	ArchiveChunkPending    = "pending"
	ArchiveChunkExporting  = "exporting"
	ArchiveChunkUploading  = "uploading"
	ArchiveChunkVerifying  = "verifying"
	ArchiveChunkVerified   = "verified"
	ArchiveChunkFailed     = "failed"
	ArchiveChunkSuperseded = "superseded"
	// ArchiveChunkNeedsAttention: the chunk's read-back or count did not match
	// ArchiveMaxMismatches times in a row; the worker no longer retries it on
	// its own (each re-export writes another Object Lock-retained copy).
	ArchiveChunkNeedsAttention = "needs_attention"
)

// ArchiveMaxMismatches is how many exports of one chunk may end in a
// mismatch (read-back content or count check) before it needs attention.
const ArchiveMaxMismatches = 3

// Archive object statuses (ArchiveObject.Status): recorded after the export
// (pending), uploaded with the service's ETag / version (uploaded), read back
// and counted with the rest of its chunk (verified), or replaced by a later
// export of the same chunk (superseded — never verified, kept as history).
const (
	ArchiveObjectPending    = "pending"
	ArchiveObjectUploaded   = "uploaded"
	ArchiveObjectVerified   = "verified"
	ArchiveObjectSuperseded = "superseded"
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
	MsgDayHistogram *string `json:"msg_day_histogram" gorm:"type:jsonb"`
	Attempts        int     `json:"attempts"`
	// Mismatches: exports whose read-back content or count check did not
	// match (each one led to a re-export). VerifyFailures: consecutive
	// verifications that failed for a transient reason (the service or the
	// database), retried with backoff without re-exporting. Migration v76.
	Mismatches     int        `json:"mismatches" gorm:"not null;default:0"`
	VerifyFailures int        `json:"verify_failures" gorm:"not null;default:0"`
	Error          string     `json:"error" gorm:"type:text"`
	RunnerID       string     `json:"runner_id"`
	StartedAt      *time.Time `json:"started_at"`
	VerifiedAt     *time.Time `json:"verified_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
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

// Archive month statuses (ArchiveMonth.Status): open until the worker first
// looks at the month, sealing while its _MONTH.json is written and read back,
// sealed for good (nothing is written into the folder again), or
// seal_failed — not sealable yet, the error says why; retried every pass.
const (
	ArchiveMonthOpen       = "open"
	ArchiveMonthSealing    = "sealing"
	ArchiveMonthSealed     = "sealed"
	ArchiveMonthSealFailed = "seal_failed"
)

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

// Archive gate event kinds (ArchiveGateEvent.Kind).
const (
	ArchiveGateEventOverride = "override"
	ArchiveGateEventDisabled = "disabled"
)

// ArchiveGateEvent is an interval during which a gate stream's raw deletes
// did not wait for the archive (migration v77): an operator override, or the
// stream's archiving disabled while archive_chunks had chunks of it. Rows
// deleted then may never have reached the archive and are missing from both
// sides of the count check, so a month whose archiving overlaps one is sealed
// partial with the interval listed. To is nil while it lasts.
type ArchiveGateEvent struct {
	ID uint `json:"id" gorm:"primaryKey"`
	// Stream is the gate stream: syslog or flows.
	Stream    string     `json:"stream" gorm:"size:16;not null;index"`
	Kind      string     `json:"kind" gorm:"size:16;not null"`
	From      time.Time  `json:"from" gorm:"column:from_ts;not null"`
	To        *time.Time `json:"to" gorm:"column:to_ts"`
	CreatedAt time.Time  `json:"created_at"`
}

func (ArchiveGateEvent) TableName() string { return "archive_gate_events" }

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

// Restore job statuses (ArchiveRestoreJob.Status). pending → running ⇄
// (cancelling) → done | failed | cancelled; a syslog job with Renormalize
// passes through loaded (rows staged, waiting for the normalized-event
// backfill queue to take its job). failed and cancelled keep their per-object
// cursors and can be resumed (→ pending). dropped: the staging table is gone
// (by request or after ExpiresAt).
const (
	ArchiveRestorePending    = "pending"
	ArchiveRestoreRunning    = "running"
	ArchiveRestoreCancelling = "cancelling"
	ArchiveRestoreLoaded     = "loaded"
	ArchiveRestoreDone       = "done"
	ArchiveRestoreFailed     = "failed"
	ArchiveRestoreCancelled  = "cancelled"
	ArchiveRestoreDropped    = "dropped"
)

// ArchiveRestoreJob restores the archived rows of one stream whose message
// (sample) UTC day lies in [FromDay, ToDay] into a staging table of its own,
// StagingTable (restore_<id>_<source table>: the source table's columns, the
// original ids as primary key). Rows are never written back into
// syslog_messages / flow_samples / flow_if_counters (operator decision: restore
// to staging only). Migration v78. The poller's restore worker
// (internal/archive/worker/restore.go) downloads each selected object,
// verifies it (stored bytes, decompressed bytes, rows, id range) and loads it
// in short batches, each committing its rows with the object's cursor.
type ArchiveRestoreJob struct {
	ID          uint   `json:"id" gorm:"primaryKey"`
	RequestedBy string `json:"requested_by"`
	// Stream is syslog, sflow, netflow or sflow-counters; SourceTable its
	// table (the staging table's shape).
	Stream      string `json:"stream" gorm:"size:16;not null"`
	SourceTable string `json:"source_table" gorm:"size:32;not null"`
	// FromDay / ToDay: the message-time UTC days restored, YYYY-MM-DD, inclusive.
	FromDay string `json:"from_day" gorm:"size:10;not null"`
	ToDay   string `json:"to_day" gorm:"size:10;not null"`
	// DeviceID restricts the rows restored to one device; nil = every device.
	// A filter, not a row owner.
	DeviceID *uint `json:"device_id"`
	// FromBucket: the objects are selected from the bucket's sealed months
	// (_MONTH.json) instead of the database manifest (a database that lost
	// it); selected by the worker on its first run.
	FromBucket bool `json:"from_bucket" gorm:"not null;default:false"`
	// Renormalize (syslog only): once staged, queue a normalized-event
	// backfill over the staging table; Replace makes it rewrite the
	// net_events / sec_events rows those raw rows already have.
	Renormalize    bool   `json:"renormalize" gorm:"not null;default:false"`
	Replace        bool   `json:"replace" gorm:"not null;default:false"`
	RateRowsPerSec int    `json:"rate_rows_per_sec"`
	StagingTable   string `json:"staging_table" gorm:"size:64"`
	Status         string `json:"status" gorm:"size:16;not null;default:pending;index"`
	// RunnerID is the owner token of the worker run that claimed the job;
	// every progress write is guarded on it.
	RunnerID string `json:"runner_id"`
	// SelectedAt: when the objects were selected (at creation from the
	// database manifest; on the first run from the bucket).
	SelectedAt   *time.Time `json:"selected_at"`
	ObjectsTotal int        `json:"objects_total"`
	ObjectsDone  int        `json:"objects_done"`
	// RowsEstimate: the rows of the requested days in the selected objects
	// (their message-day histograms; for flows every device's). RowsScanned:
	// lines read from verified objects; RowsLoaded: rows written to the
	// staging table (the requested days and device).
	RowsEstimate    int64 `json:"rows_estimate"`
	RowsScanned     int64 `json:"rows_scanned"`
	RowsLoaded      int64 `json:"rows_loaded"`
	BytesDownloaded int64 `json:"bytes_downloaded"`
	// BackfillJobID: the normalized-event backfill queued over the staging
	// table (Renormalize).
	BackfillJobID *uint `json:"backfill_job_id"`
	// ExpiresAt: the staging table is dropped by the worker after it (a
	// running job's never).
	ExpiresAt time.Time `json:"expires_at"`
	// Note: what the restore could not cover (rows of those days ingested
	// after the archive's verified end, months not sealed in the bucket).
	Note       string     `json:"note" gorm:"type:text"`
	Error      string     `json:"error" gorm:"type:text"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	DroppedAt  *time.Time `json:"dropped_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (ArchiveRestoreJob) TableName() string { return "archive_restore_jobs" }

// Restore object statuses (ArchiveRestoreObject.Status).
const (
	ArchiveRestoreObjectPending = "pending"
	ArchiveRestoreObjectDone    = "done"
)

// ArchiveRestoreObject is one archived object a restore job reads: what the
// manifest (or _MONTH.json) recorded about it — key and version, both hashes,
// sizes, rows and its chunk's id range, the bounds the download is verified
// against — and the job's progress through it: CursorID is the id of the last
// line whose batch committed (lines at or below it are never loaded again).
type ArchiveRestoreObject struct {
	ID            uint   `json:"id" gorm:"primaryKey"`
	JobID         uint   `json:"job_id" gorm:"not null;index"`
	ChunkSeq      int64  `json:"chunk_seq"`
	ChunkIDLo     int64  `json:"chunk_id_lo"`
	ChunkIDHi     int64  `json:"chunk_id_hi"`
	ObjectKey     string `json:"object_key" gorm:"type:text;not null"`
	VersionID     string `json:"version_id"`
	SchemaVersion int    `json:"schema_version"`
	Compression   string `json:"compression" gorm:"size:8"`
	RowCount      int64  `json:"row_count"`
	RawBytes      int64  `json:"raw_bytes"`
	ObjectBytes   int64  `json:"object_bytes"`
	Sha256Content string `json:"sha256_content" gorm:"size:64"`
	Sha256Object  string `json:"sha256_object" gorm:"size:64"`
	ETag          string `json:"etag" gorm:"column:etag"`
	PartCount     int    `json:"part_count"`
	MinID         int64  `json:"min_id"`
	MaxID         int64  `json:"max_id"`
	// DayRows: rows of the requested days in the object (its histogram).
	DayRows    int64      `json:"day_rows"`
	Status     string     `json:"status" gorm:"size:16;not null;default:pending"`
	CursorID   int64      `json:"cursor_id"`
	RowsLoaded int64      `json:"rows_loaded"`
	DoneAt     *time.Time `json:"done_at"`
}

func (ArchiveRestoreObject) TableName() string { return "archive_restore_objects" }
