package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"
)

// The archive worker's state machine on the SQLite lane (archive plan PR 4).

func seedArchiveChunks(t *testing.T, d *Database, table string, statuses ...string) []models.ArchiveChunk {
	t.Helper()
	p := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	out := make([]models.ArchiveChunk, len(statuses))
	for i, s := range statuses {
		c := models.ArchiveChunk{SourceTable: table, Seq: int64(i + 1), IDLo: int64(i * 10), IDHi: int64(i*10 + 10),
			PeriodStart: p.AddDate(0, 0, i), PeriodEnd: p.AddDate(0, 0, i+1), Month: "2026-10", Status: s}
		if err := d.db.Create(&c).Error; err != nil {
			t.Fatal(err)
		}
		out[i] = c
	}
	return out
}

func TestArchiveRetryBackoff(t *testing.T) {
	want := []time.Duration{time.Minute, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 2 * time.Hour}
	for attempts, w := range want {
		if got := ArchiveRetryBackoff(attempts); got != w {
			t.Errorf("ArchiveRetryBackoff(%d) = %s, want %s", attempts, got, w)
		}
	}
}

// TestNextArchiveChunk_OrderAndBackoff: the lowest open seq is next; a failed
// chunk is skipped until its backoff from the failure has passed, and later
// chunks go ahead meanwhile; verified chunks never come back.
func TestNextArchiveChunk_OrderAndBackoff(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cs := seedArchiveChunks(t, d, export.TableSyslog, models.ArchiveChunkVerified, models.ArchiveChunkPending, models.ArchiveChunkPending)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	next := func(at time.Time) int64 {
		t.Helper()
		c, err := d.NextArchiveChunk(archiveCtx, export.TableSyslog, at)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			return 0
		}
		return c.Seq
	}
	if s := next(now); s != 2 {
		t.Fatalf("next is seq %d, want 2", s)
	}
	c := cs[1]
	if _, err := d.BeginArchiveChunkExport(archiveCtx, &c, "runner-a", now); err != nil {
		t.Fatal(err)
	}
	if err := d.FailArchiveChunk(archiveCtx, &c, "upload: boom", now); err != nil {
		t.Fatal(err)
	}
	if s := next(now.Add(59 * time.Second)); s != 3 {
		t.Fatalf("inside the backoff next is seq %d, want 3 (later chunks go ahead)", s)
	}
	if s := next(now.Add(time.Minute)); s != 2 {
		t.Fatalf("after the backoff next is seq %d, want 2", s)
	}
	// Second failure: 5 minutes.
	if _, err := d.BeginArchiveChunkExport(archiveCtx, &c, "runner-a", now); err != nil {
		t.Fatal(err)
	}
	if err := d.FailArchiveChunk(archiveCtx, &c, strings.Repeat("x", 3000), now); err != nil {
		t.Fatal(err)
	}
	if c.Attempts != 2 || len(c.Error) != archiveErrorMax {
		t.Fatalf("attempts %d, error length %d", c.Attempts, len(c.Error))
	}
	if s := next(now.Add(4 * time.Minute)); s != 3 {
		t.Fatalf("4 min after the second failure next is %d, want 3", s)
	}
	if s := next(now.Add(5 * time.Minute)); s != 2 {
		t.Fatalf("5 min after the second failure next is %d, want 2", s)
	}
}

// TestArchiveChunkStateMachine: an export attempt supersedes the previous
// attempt's objects; verifying needs every object uploaded; the verified
// chunk carries the totals of its objects; a stale status is refused.
func TestArchiveChunkStateMachine(t *testing.T) {
	d := NewDatabaseForTesting(t)
	c := seedArchiveChunks(t, d, export.TableSyslog, models.ArchiveChunkPending)[0]
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	ts := func(h int) *time.Time { v := time.Date(2026, 10, 1, h, 0, 0, 0, time.UTC); return &v }
	hist := func(s string) *string { return &s }
	var lastReuse map[string]models.ArchiveObject
	attempt := func() []models.ArchiveObject {
		t.Helper()
		reuse, err := d.BeginArchiveChunkExport(archiveCtx, &c, "runner-a", at)
		if err != nil {
			t.Fatal(err)
		}
		lastReuse = reuse
		dev1, dev2 := uint(1), uint(2)
		objs := []models.ArchiveObject{
			{ChunkID: c.ID, Stream: "syslog", DeviceID: &dev1, ObjectKey: "p/a", SchemaVersion: 2, Compression: "gzip", RowCount: 3,
				MinTs: ts(1), MaxTs: ts(5), MsgDayHistogram: hist(`{"2026-10-01":3}`), Status: models.ArchiveObjectPending},
			{ChunkID: c.ID, Stream: "syslog", DeviceID: &dev2, ObjectKey: "p/b", SchemaVersion: 2, Compression: "gzip", RowCount: 2,
				MinTs: ts(0), MaxTs: ts(3), MsgDayHistogram: hist(`{"2026-09-30":1,"2026-10-01":1}`), Status: models.ArchiveObjectPending},
		}
		if err := d.RecordArchiveExport(archiveCtx, &c, objs, at); err != nil {
			t.Fatal(err)
		}
		if c.Status != models.ArchiveChunkUploading {
			t.Fatalf("after recording the export: %s", c.Status)
		}
		return objs
	}
	first := attempt()
	if err := d.MarkArchiveObjectUploaded(archiveCtx, &first[0], "etag-a", "", 0, nil, at); err != nil {
		t.Fatal(err)
	}
	second := attempt() // a re-export: the first attempt's objects are superseded
	if len(lastReuse) != 1 || lastReuse["p/a"].ETag != "etag-a" {
		t.Fatalf("reusable uploads of the first attempt: %v, want only p/a", lastReuse)
	}
	var n int64
	d.db.Model(&models.ArchiveObject{}).Where("chunk_id = ? AND status = ?", c.ID, models.ArchiveObjectSuperseded).Count(&n)
	if n != 2 || c.Attempts != 2 {
		t.Fatalf("%d superseded objects after a re-export (attempts %d), want 2", n, c.Attempts)
	}
	open, err := d.ArchiveChunkObjects(archiveCtx, c.ID)
	if err != nil || len(open) != 2 || open[0].ID != second[0].ID {
		t.Fatalf("open objects %v %v", open, err)
	}
	if err := d.MarkArchiveObjectUploaded(archiveCtx, &second[0], "etag-a2", "v1", 0, nil, at); err != nil {
		t.Fatal(err)
	}
	if err := d.SetArchiveChunkStatus(archiveCtx, &c, models.ArchiveChunkVerifying, at); err != nil {
		t.Fatal(err)
	}
	open, _ = d.ArchiveChunkObjects(archiveCtx, c.ID)
	if err := d.MarkArchiveChunkVerified(archiveCtx, &c, open, at); err == nil || c.Status == models.ArchiveChunkVerified {
		t.Fatal("verified with an object that was never uploaded")
	}
	if err := d.MarkArchiveObjectUploaded(archiveCtx, &second[1], "etag-b2", "v2", 0, nil, at); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkArchiveObjectUploaded(archiveCtx, &second[1], "etag-b2", "v2", 0, nil, at); err == nil {
		t.Fatal("an uploaded object was recorded as uploaded twice")
	}
	open, _ = d.ArchiveChunkObjects(archiveCtx, c.ID)
	stale := c
	if err := d.MarkArchiveChunkVerified(archiveCtx, &c, open, at); err != nil {
		t.Fatal(err)
	}
	if c.Status != models.ArchiveChunkVerified || c.RowCount != 5 || !c.MinTs.Equal(*ts(0)) || !c.MaxTs.Equal(*ts(5)) ||
		c.MsgDayHistogram == nil || *c.MsgDayHistogram != `{"2026-09-30":1,"2026-10-01":4}` {
		t.Fatalf("verified chunk %+v", c)
	}
	if err := d.FailArchiveChunk(archiveCtx, &stale, "late", at); err == nil {
		t.Fatal("a stale status was overwritten")
	}
}

// TestArchiveTableProgress: V is the id_hi of the last chunk of the gapless
// verified run from seq 1; a verified chunk after an open one does not count.
func TestArchiveTableProgress(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if p, err := d.ArchiveTableProgress(archiveCtx, export.TableFlows); err != nil || p.Chunks {
		t.Fatalf("no chunks: %+v %v", p, err)
	}
	seedArchiveChunks(t, d, export.TableSyslog, models.ArchiveChunkPending, models.ArchiveChunkVerified)
	p, err := d.ArchiveTableProgress(archiveCtx, export.TableSyslog)
	if err != nil || !p.Chunks || p.VerifiedThroughID != 0 || p.VerifiedThroughEnd != nil || p.FirstStart == nil {
		t.Fatalf("first chunk open: %+v %v", p, err)
	}
	seedArchiveChunks(t, d, export.TableCounters, models.ArchiveChunkVerified, models.ArchiveChunkVerified, models.ArchiveChunkFailed, models.ArchiveChunkVerified)
	p, err = d.ArchiveTableProgress(archiveCtx, export.TableCounters)
	if err != nil || p.VerifiedThroughID != 20 || !p.VerifiedThroughEnd.Equal(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("V behind the failed chunk: %+v %v", p, err)
	}
	seedArchiveChunks(t, d, export.TableFlows, models.ArchiveChunkVerified, models.ArchiveChunkVerified)
	if p, _ := d.ArchiveTableProgress(archiveCtx, export.TableFlows); p.VerifiedThroughID != 20 {
		t.Fatalf("all verified: V %d, want 20", p.VerifiedThroughID)
	}
	counts, err := d.ArchiveChunkStatusCounts(archiveCtx)
	if err != nil || counts[export.TableCounters][models.ArchiveChunkVerified] != 3 || counts[export.TableCounters][models.ArchiveChunkFailed] != 1 {
		t.Fatalf("counts %v %v", counts, err)
	}
}

// TestArchiveMismatchCapAndVerifyBackoff: a mismatch supersedes the objects
// it found (none is reusable by the next export) and fails the chunk, the
// third parks it in needs_attention, which NextArchiveChunk never returns; a
// transient verification failure keeps the chunk in verifying behind its own
// backoff; a stale copy of a chunk (another runner claimed it) cannot write.
func TestArchiveMismatchCapAndVerifyBackoff(t *testing.T) {
	d := NewDatabaseForTesting(t)
	cs := seedArchiveChunks(t, d, export.TableSyslog, models.ArchiveChunkPending, models.ArchiveChunkPending)
	c := cs[0]
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	next := func(now time.Time) int64 {
		t.Helper()
		n, err := d.NextArchiveChunk(archiveCtx, export.TableSyslog, now)
		if err != nil {
			t.Fatal(err)
		}
		if n == nil {
			return 0
		}
		return n.Seq
	}
	for i := 1; i <= models.ArchiveMaxMismatches; i++ {
		if _, err := d.BeginArchiveChunkExport(archiveCtx, &c, "runner-a", at); err != nil {
			t.Fatal(err)
		}
		o := models.ArchiveObject{ChunkID: c.ID, Stream: "syslog", ObjectKey: "p/a", SchemaVersion: 2, Compression: "gzip", Status: models.ArchiveObjectPending}
		if err := d.RecordArchiveExport(archiveCtx, &c, []models.ArchiveObject{o}, at); err != nil {
			t.Fatal(err)
		}
		objs, _ := d.ArchiveChunkObjects(archiveCtx, c.ID)
		if err := d.MarkArchiveObjectUploaded(archiveCtx, &objs[0], "etag", "", 0, nil, at); err != nil {
			t.Fatal(err)
		}
		if err := d.SetArchiveChunkStatus(archiveCtx, &c, models.ArchiveChunkVerifying, at); err != nil {
			t.Fatal(err)
		}
		parked, err := d.RecordArchiveMismatch(archiveCtx, &c, "count check late_commit", at)
		if err != nil {
			t.Fatal(err)
		}
		if parked != (i == models.ArchiveMaxMismatches) || c.Mismatches != i {
			t.Fatalf("mismatch %d: parked %v, mismatches %d", i, parked, c.Mismatches)
		}
		if open, _ := d.ArchiveChunkObjects(archiveCtx, c.ID); len(open) != 0 {
			t.Fatalf("mismatch %d left %d objects that the next export could reuse", i, len(open))
		}
	}
	if c.Status != models.ArchiveChunkNeedsAttention {
		t.Fatalf("after %d mismatches: %s", models.ArchiveMaxMismatches, c.Status)
	}
	if s := next(at.Add(24 * time.Hour)); s != 2 {
		t.Fatalf("next is seq %d, want 2 (seq 1 needs attention)", s)
	}

	v := cs[1]
	if _, err := d.BeginArchiveChunkExport(archiveCtx, &v, "runner-a", at); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordArchiveExport(archiveCtx, &v, nil, at); err != nil {
		t.Fatal(err)
	}
	if err := d.SetArchiveChunkStatus(archiveCtx, &v, models.ArchiveChunkVerifying, at); err != nil {
		t.Fatal(err)
	}
	stale := v
	if err := d.ClaimArchiveChunk(archiveCtx, &v, "runner-b"); err != nil {
		t.Fatal(err)
	}
	if err := d.FailArchiveChunk(archiveCtx, &stale, "stale worker", at); err == nil {
		t.Fatal("a stale worker failed a chunk another runner claimed")
	}
	if err := d.DeferArchiveVerify(archiveCtx, &v, "get: 500", at); err != nil {
		t.Fatal(err)
	}
	if v.Status != models.ArchiveChunkVerifying || v.VerifyFailures != 1 || v.Attempts != 1 {
		t.Fatalf("after a transient verify failure: %s verify_failures %d attempts %d", v.Status, v.VerifyFailures, v.Attempts)
	}
	if s := next(at.Add(59 * time.Second)); s != 0 {
		t.Fatalf("verifying chunk returned inside its backoff (seq %d)", s)
	}
	if s := next(at.Add(time.Minute)); s != 2 {
		t.Fatalf("after the backoff next is %d, want 2", s)
	}
}
