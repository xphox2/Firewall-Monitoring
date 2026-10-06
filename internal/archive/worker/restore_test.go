package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The restore worker (archive plan PR 9) against the B2-strict fake and
// SQLite. Synthetic data only: RFC 5737 addresses, fw-example-NN, alice.

func i16(v int16) *int16 { return &v }

// restoreFixture seeds syslog around the v1/v2 boundary (migration v74 on 1
// October: September objects are schema v1, October's v2), archives every
// day through 2 October, and then deletes the rows from syslog_messages, so
// whatever a restore finds came from the bucket. It returns the rows as they
// were, by id. The "late" row has message time 30 September 22:00 but was
// received on 1 October: it sits in an October (v2) object.
func restoreFixture(t *testing.T, h *harness) (rows map[uint]models.SyslogMessage, late uint) {
	t.Helper()
	if err := h.db.Gorm().Exec(`CREATE TABLE schema_migrations (version integer primary key, name text, app_version text, applied_at datetime)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := h.db.Gorm().Create(&models.SchemaMigration{Version: 74, Name: "syslog_format_column", AppVersion: "0.11.298", AppliedAt: day(10, 1, 0, 0)}).Error; err != nil {
		t.Fatal(err)
	}
	type seed struct {
		created, ts time.Time
		dev         uint
		format      *int16
	}
	seeds := []seed{
		{day(9, 29, 9, 0), day(9, 29, 8, 59), 1, nil},
		{day(9, 29, 15, 0), day(9, 29, 14, 59), 2, nil},
		{day(9, 30, 9, 0), day(9, 30, 8, 59), 1, i16(1)}, // stored format, but September objects are v1
		{day(9, 30, 15, 0), day(9, 30, 14, 59), 2, nil},
		{day(10, 1, 9, 0), day(10, 1, 8, 59), 1, i16(1)},
		{day(10, 1, 10, 0), day(9, 30, 22, 0), 2, i16(2)}, // late: received a day after its message time
		{day(10, 1, 15, 0), day(10, 1, 14, 59), 2, i16(3)},
		{day(10, 2, 9, 0), day(10, 2, 8, 59), 1, nil},
	}
	rows = map[uint]models.SyslogMessage{}
	for i, s := range seeds {
		m := models.SyslogMessage{Timestamp: s.ts, DeviceID: s.dev, ProbeID: 3, Hostname: fmt.Sprintf("fw-example-%02d", s.dev),
			AppName: "traffic", ProcessID: "-", MessageID: "0000000013", StructuredData: `[meta src="192.0.2.10"]`,
			Message:  fmt.Sprintf("srcip=192.0.2.10 dstip=198.51.100.7 user=\"alice\" url=\"https://example.com/?a=1&b=<%d>\"\tn=%d \u2028", i, i),
			Priority: 189, Facility: 23, Severity: 5, SourceIP: "203.0.113.4", CreatedAt: s.created, StoredFormat: s.format}
		if err := h.db.Gorm().Create(&m).Error; err != nil {
			t.Fatal(err)
		}
		rows[m.ID] = m
		if i == 5 {
			late = m.ID
		}
	}
	h.tickAt(day(10, 3, 3, 0))
	for _, c := range h.chunks(export.TableSyslog) {
		if c.Status != models.ArchiveChunkVerified {
			t.Fatalf("chunk %d not verified: %s %s", c.Seq, c.Status, c.Error)
		}
	}
	if n := len(h.chunks(export.TableSyslog)); n != 4 {
		t.Fatalf("%d syslog chunks, want 4 (29 Sep - 2 Oct)", n)
	}
	if err := h.db.Gorm().Exec("DELETE FROM syslog_messages").Error; err != nil {
		t.Fatal(err)
	}
	return rows, late
}

// newRestore builds the restore worker over the harness's database and bucket.
func (h *harness) newRestore() *RestoreWorker {
	h.t.Helper()
	r, err := newRestoreWorker(h.db, h.store.(*s3.Client), h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	r.sleep = func(context.Context, time.Duration) error { return nil }
	return r
}

// seedFreeSpace records a server_metrics sample of the database volume now
// (the restore's disk precheck refuses an unknown free space).
func seedFreeSpace(t *testing.T, db *database.Database, free uint64) {
	t.Helper()
	if err := db.Gorm().Create(&models.ServerMetric{Timestamp: time.Now(), DataDiskFreeBytes: &free}).Error; err != nil {
		t.Fatal(err)
	}
}

func (h *harness) queueRestore(req database.ArchiveRestoreRequest) *models.ArchiveRestoreJob {
	h.t.Helper()
	seedFreeSpace(h.t, h.db, 1<<40)
	if req.RequestedBy == "" {
		req.RequestedBy = "alice"
	}
	job, _, err := h.db.QueueArchiveRestore(ctx, req, h.clk.now())
	if err != nil {
		h.t.Fatalf("queue restore: %v", err)
	}
	return job
}

func (h *harness) restoreJob(id uint) *models.ArchiveRestoreJob {
	h.t.Helper()
	j, err := h.db.GetArchiveRestoreJob(id)
	if err != nil {
		h.t.Fatal(err)
	}
	return j
}

func stagedSyslog(t *testing.T, db *database.Database, table string) map[uint]models.SyslogMessage {
	t.Helper()
	var got []models.SyslogMessage
	if err := db.Gorm().Table(table).Order("id").Find(&got).Error; err != nil {
		t.Fatal(err)
	}
	out := map[uint]models.SyslogMessage{}
	for _, m := range got {
		if _, dup := out[m.ID]; dup {
			t.Fatalf("%s holds id %d twice", table, m.ID)
		}
		m.Timestamp, m.CreatedAt = m.Timestamp.UTC(), m.CreatedAt.UTC()
		out[m.ID] = m
	}
	return out
}

func normRow(m models.SyslogMessage) models.SyslogMessage {
	m.Timestamp, m.CreatedAt = m.Timestamp.UTC(), m.CreatedAt.UTC()
	return m
}

// TestRestore_SyslogDayAcrossSchemas: restoring 30 September selects, by the
// objects' message-day histograms, the two September (schema v1) objects of
// that day and the one October (v2) object holding the late row, verifies
// each download and stages exactly that day's rows with their original ids
// and every column — the v1 rows without the format the archive never had,
// the v2 row with it. Only GETs reach the bucket; the live table stays empty.
func TestRestore_SyslogDayAcrossSchemas(t *testing.T) {
	h := newHarness(t, day(10, 3, 3, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	orig, late := restoreFixture(t, h)
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 30, 0, 0), To: day(9, 30, 0, 0)})
	if job.ObjectsTotal != 3 || job.RowsEstimate != 3 || job.StagingTable != fmt.Sprintf("restore_%d_syslog_messages", job.ID) || job.Status != models.ArchiveRestorePending {
		t.Fatalf("queued job %+v", job)
	}
	objs, _ := h.db.ArchiveRestoreObjects(ctx, job.ID)
	schemas := map[int]int{}
	for _, o := range objs {
		schemas[o.SchemaVersion]++
		if o.Sha256Object == "" || o.Sha256Content == "" || o.ETag == "" || o.ChunkIDHi <= o.ChunkIDLo {
			t.Fatalf("object %s without its recorded hashes / chunk range", o.ObjectKey)
		}
	}
	if schemas[1] != 2 || schemas[2] != 1 {
		t.Fatalf("selected objects by schema %v, want two v1 (30 Sep) and one v2 (the late row in 1 Oct)", schemas)
	}

	before := len(h.srv.Requests())
	h.newRestore().Tick(ctx)
	for _, r := range h.srv.Requests()[before:] {
		if r.Op != s3test.OpGetObject {
			t.Fatalf("the restore sent %s %s: it must only read", r.Op, r.Key)
		}
	}
	j := h.restoreJob(job.ID)
	if j.Status != models.ArchiveRestoreDone || j.ObjectsDone != 3 || j.RowsLoaded != 3 || j.Error != "" || j.FinishedAt == nil {
		t.Fatalf("job after the run: %+v", j)
	}
	got := stagedSyslog(t, h.db, job.StagingTable)
	want := map[uint]models.SyslogMessage{}
	for id, m := range orig {
		if m.Timestamp.Format(time.DateOnly) != "2026-09-30" {
			continue
		}
		if id != late {
			m.StoredFormat = nil // archived as schema v1
		}
		want[id] = normRow(m)
	}
	if len(want) != 3 || !reflect.DeepEqual(got, want) {
		t.Fatalf("staged rows:\n got %+v\nwant %+v", got, want)
	}
	if *got[late].StoredFormat != 2 {
		t.Fatal("the v2 row lost its format")
	}
	var live int64
	h.db.Gorm().Model(&models.SyslogMessage{}).Count(&live)
	if live != 0 {
		t.Fatalf("%d rows written into syslog_messages: a restore stages only", live)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.StagingDir, fmt.Sprintf("restore-%d", job.ID), "object-1.ndjson.gz")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a downloaded object was left in the staging directory: %v", err)
	}
}

// TestRestore_CorruptedObjectRefused: a download whose bytes differ from what
// was archived, and an object whose recorded row count is not what it holds,
// are each refused: the job fails with REFUSED, nothing of the object is
// staged, the metric counts it; once the bucket answers truthfully again a
// resume completes the job.
func TestRestore_CorruptedObjectRefused(t *testing.T) {
	h := newHarness(t, day(10, 3, 3, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	restoreFixture(t, h)
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 29, 0, 0), To: day(9, 29, 0, 0)})
	before := metricValue(t, `fwmon_archive_restore_refused_total{stream="syslog"}`)
	h.srv.SetMutateGet(func(key string, body []byte) []byte {
		if !strings.Contains(key, "/device-") {
			return body
		}
		b := append([]byte(nil), body...)
		b[len(b)/2] ^= 0x40
		return b
	})
	r := h.newRestore()
	r.Tick(ctx)
	j := h.restoreJob(job.ID)
	if j.Status != models.ArchiveRestoreFailed || !strings.Contains(j.Error, "REFUSED") || j.RowsLoaded != 0 || j.ObjectsDone != 0 {
		t.Fatalf("after a corrupted download: %+v", j)
	}
	if n := len(stagedSyslog(t, h.db, job.StagingTable)); n != 0 {
		t.Fatalf("%d rows of a refused object staged", n)
	}
	if d := metricValue(t, `fwmon_archive_restore_refused_total{stream="syslog"}`) - before; d != 1 {
		t.Fatalf("restore_refused_total grew by %v", d)
	}

	// The bucket is fine again, but the manifest's row count of the first
	// object is off by one: the download's content check refuses it.
	h.srv.SetMutateGet(nil)
	objs, _ := h.db.ArchiveRestoreObjects(ctx, job.ID)
	h.db.Gorm().Model(&models.ArchiveRestoreObject{}).Where("id = ?", objs[0].ID).Update("row_count", objs[0].RowCount+1)
	if ok, err := h.db.ResumeArchiveRestoreJob(job.ID); !ok || err != nil {
		t.Fatalf("resume: %v %v", ok, err)
	}
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreFailed || !strings.Contains(j.Error, "REFUSED") || !strings.Contains(j.Error, "rows") {
		t.Fatalf("after a wrong row count: %+v", j)
	}
	h.db.Gorm().Model(&models.ArchiveRestoreObject{}).Where("id = ?", objs[0].ID).Update("row_count", objs[0].RowCount)
	if ok, _ := h.db.ResumeArchiveRestoreJob(job.ID); !ok {
		t.Fatal("resume refused")
	}
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreDone || j.RowsLoaded != 2 {
		t.Fatalf("after the resume: %+v", j)
	}
}

// TestRestore_ResumeAfterCrash: a load transaction that dies mid-object
// commits nothing of its batch; the job, left running by a process that
// died, is requeued once its heartbeat is stale, and the next run resumes
// from the object's committed cursor: every row staged exactly once.
func TestRestore_ResumeAfterCrash(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	var created []time.Time
	for i := 0; i < 23; i++ {
		created = append(created, day(10, 4, 1, i))
	}
	ids := seedSyslog(t, h.db, created...) // devices 1 and 2 alternate: 12 and 11 rows
	h.tick(ctx)
	if c := h.chunks(export.TableSyslog); len(c) != 1 || c[0].Status != models.ArchiveChunkVerified {
		t.Fatalf("chunks %+v", c)
	}
	h.db.Gorm().Exec("DELETE FROM syslog_messages")
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(10, 4, 0, 0), To: day(10, 4, 0, 0)})

	// Batches of 5 lines; the third batch of the first object (device 1)
	// dies inside its transaction.
	batches := 0
	database.SetArchiveRestoreBatchForTesting(t, 5, func(*models.ArchiveRestoreObject, int64) error {
		batches++
		if batches == 3 {
			return errors.New("simulated crash inside the load transaction")
		}
		return nil
	})
	r := h.newRestore()
	r.Tick(ctx)
	j := h.restoreJob(job.ID)
	if j.Status != models.ArchiveRestoreFailed || j.RowsLoaded != 10 {
		t.Fatalf("after the crash: %+v", j)
	}
	objs, _ := h.db.ArchiveRestoreObjects(ctx, job.ID)
	if objs[0].RowsLoaded != 10 || objs[0].CursorID != ids[18] || objs[0].Status != models.ArchiveRestoreObjectPending {
		t.Fatalf("first object after the crash: loaded %d cursor %d (want 10, id %d)", objs[0].RowsLoaded, objs[0].CursorID, ids[18])
	}
	if n := len(stagedSyslog(t, h.db, job.StagingTable)); n != 10 {
		t.Fatalf("%d rows staged; the rolled-back batch must add none", n)
	}
	// The process "died" with the job running: requeued once stale.
	h.db.Gorm().Model(&models.ArchiveRestoreJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{"status": models.ArchiveRestoreRunning, "runner_id": "dead-runner", "updated_at": time.Now().Add(-time.Hour)})
	r.Tick(ctx)
	j = h.restoreJob(job.ID)
	got := stagedSyslog(t, h.db, job.StagingTable)
	if j.Status != models.ArchiveRestoreDone || j.RowsLoaded != 23 || len(got) != 23 || j.ObjectsDone != 2 {
		t.Fatalf("after the resume: %d staged, job %+v", len(got), j)
	}
	for _, id := range ids {
		if _, ok := got[uint(id)]; !ok {
			t.Fatalf("id %d missing", id)
		}
	}
}

// TestRestore_CancelResumeDropAndTTL: a cancel lands between batches and keeps
// the cursors; a resume finishes the job; a drop removes the staging table
// (refused while the job runs); a finished job past its TTL is dropped by the
// worker, except while a backfill over its table is active.
func TestRestore_CancelResumeDropAndTTL(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	var created []time.Time
	for i := 0; i < 12; i++ {
		created = append(created, day(10, 4, 2, i))
	}
	seedSyslog(t, h.db, created...)
	h.tick(ctx)
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(10, 4, 0, 0), To: day(10, 4, 0, 0), TTLDays: 1})
	database.SetArchiveRestoreBatchForTesting(t, 2, nil)
	r := h.newRestore()
	r.afterBatch = func(j *models.ArchiveRestoreJob, _ *models.ArchiveRestoreObject) error {
		if _, err := h.db.DropArchiveRestore(ctx, j.ID, time.Now()); !errors.Is(err, database.ErrArchiveRestoreBusy) {
			t.Errorf("drop of a running restore: %v, want ErrArchiveRestoreBusy", err)
		}
		if st, ok, err := h.db.CancelArchiveRestoreJob(j.ID); err != nil || !ok || st != models.ArchiveRestoreCancelling {
			t.Errorf("cancel: %s %v %v", st, ok, err)
		}
		return nil
	}
	r.Tick(ctx)
	j := h.restoreJob(job.ID)
	if j.Status != models.ArchiveRestoreCancelled || j.RowsLoaded != 2 {
		t.Fatalf("after the cancel: %+v", j)
	}
	r.afterBatch = nil
	if ok, _ := h.db.ResumeArchiveRestoreJob(job.ID); !ok {
		t.Fatal("resume refused")
	}
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreDone || j.RowsLoaded != 12 {
		t.Fatalf("after the resume: %+v", j)
	}
	if n := len(stagedSyslog(t, h.db, job.StagingTable)); n != 12 {
		t.Fatalf("%d staged, want 12", n)
	}

	// A backfill over the table is active: neither a drop nor the TTL takes it.
	bf := models.NormalizeBackfillJob{Status: database.NormalizeBackfillStatusRunning, Since: day(10, 4, 0, 0), Until: day(10, 5, 0, 0), SourceTable: job.StagingTable}
	h.db.Gorm().Create(&bf)
	if _, err := h.db.DropArchiveRestore(ctx, job.ID, time.Now()); !errors.Is(err, database.ErrArchiveRestoreInUse) {
		t.Fatalf("drop under an active backfill: %v", err)
	}
	h.db.Gorm().Model(&models.ArchiveRestoreJob{}).Where("id = ?", job.ID).Update("expires_at", time.Now().Add(-time.Minute))
	r.Tick(ctx)
	if !h.db.Gorm().Migrator().HasTable(job.StagingTable) || h.restoreJob(job.ID).Status != models.ArchiveRestoreDone {
		t.Fatal("the TTL dropped a staging table a backfill is reading")
	}
	h.db.Gorm().Model(&bf).Update("status", database.NormalizeBackfillStatusDone)
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreDropped || j.DroppedAt == nil || h.db.Gorm().Migrator().HasTable(job.StagingTable) {
		t.Fatalf("after the TTL: %+v, table exists %v", j, h.db.Gorm().Migrator().HasTable(job.StagingTable))
	}
	if ok, _ := h.db.ResumeArchiveRestoreJob(job.ID); ok {
		t.Fatal("a dropped restore was resumed")
	}
}

// TestRestore_RenormalizeQueuesBackfill: a syslog restore with renormalize
// (and replace) queues the normalized-event backfill over its staging table
// once loaded — or waits as loaded while another backfill is active, and is
// queued by a later tick.
func TestRestore_RenormalizeQueuesBackfill(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0))
	h.tick(ctx)
	other := models.NormalizeBackfillJob{Status: database.NormalizeBackfillStatusRunning, Since: day(10, 1, 0, 0), Until: day(10, 2, 0, 0)}
	h.db.Gorm().Create(&other)
	dev := uint(1)
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(10, 4, 0, 0), To: day(10, 4, 0, 0),
		DeviceID: &dev, Renormalize: true, Replace: true})
	r := h.newRestore()
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreLoaded || j.BackfillJobID != nil || j.RowsLoaded != 1 {
		t.Fatalf("with another backfill active: %+v", j)
	}
	// Past its TTL while loaded: kept, its re-normalize has not run yet.
	h.db.Gorm().Model(&models.ArchiveRestoreJob{}).Where("id = ?", job.ID).Update("expires_at", time.Now().Add(-time.Hour))
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreLoaded || !h.db.Gorm().Migrator().HasTable(job.StagingTable) {
		t.Fatalf("the TTL dropped a loaded restore: %+v", j)
	}
	h.db.Gorm().Model(&other).Update("status", database.NormalizeBackfillStatusDone)
	r.Tick(ctx)
	j := h.restoreJob(job.ID)
	if j.Status != models.ArchiveRestoreDone || j.BackfillJobID == nil {
		t.Fatalf("after the queue freed: %+v", j)
	}
	bf, err := h.db.GetNormalizeBackfillJob(*j.BackfillJobID)
	if err != nil {
		t.Fatal(err)
	}
	if bf.SourceTable != job.StagingTable || !bf.Replace || bf.RestoreJobID == nil || *bf.RestoreJobID != job.ID || bf.DeviceID == nil || *bf.DeviceID != 1 ||
		!bf.Since.Equal(day(10, 4, 0, 0)) || !bf.Until.Equal(day(10, 5, 0, 0)) || bf.Status != database.NormalizeBackfillStatusPending {
		t.Fatalf("queued backfill %+v", bf)
	}
}

// TestRestore_FlowsStageOnly: an sflow restore stages the sflow rows of the
// hour (every column, original ids), never the netflow ones, and cannot be
// re-normalized.
func TestRestore_FlowsStageOnly(t *testing.T) {
	h := newHarness(t, day(10, 5, 10, 20), func(c *config.ArchiveConfig) { c.SyslogEnabled = false })
	var orig []models.FlowSample
	for i, src := range []uint8{0, 1, 0, 3} {
		start := day(10, 5, 9, 29)
		f := models.FlowSample{Timestamp: day(10, 5, 9, 30), DeviceID: 7, ProbeID: 3, SamplerAddress: "192.0.2.1", SequenceNumber: 4000000000 + uint32(i),
			SrcAddr: "192.0.2.10", DstAddr: "2001:db8::7", SrcPort: 51234, DstPort: 443, Protocol: 6, Bytes: 1 << 40, Packets: 12,
			FlowSource: src, FlowStart: &start, AppName: "HTTPS.BROWSER", ClassRev: 9, ScopeLocal: true, CreatedAt: day(10, 5, 9, 31)}
		if err := h.db.Gorm().Create(&f).Error; err != nil {
			t.Fatal(err)
		}
		f.Timestamp, f.CreatedAt = f.Timestamp.UTC(), f.CreatedAt.UTC()
		orig = append(orig, f)
	}
	h.tick(ctx)
	if fc := h.chunks(export.TableFlows); len(fc) != 1 || fc[0].Status != models.ArchiveChunkVerified {
		t.Fatalf("flow chunks %+v", fc)
	}
	h.db.Gorm().Exec("DELETE FROM flow_samples")
	if _, _, err := h.db.QueueArchiveRestore(ctx, database.ArchiveRestoreRequest{Stream: export.StreamSFlow, From: day(10, 5, 0, 0), To: day(10, 5, 0, 0),
		Renormalize: true}, h.clk.now()); !errors.Is(err, database.ErrArchiveRestoreInvalid) {
		t.Fatalf("a flow renormalize: %v", err)
	}
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSFlow, From: day(10, 5, 0, 0), To: day(10, 5, 0, 0)})
	if job.StagingTable != fmt.Sprintf("restore_%d_flow_samples", job.ID) || job.ObjectsTotal != 1 {
		t.Fatalf("job %+v", job)
	}
	h.newRestore().Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreDone || j.RowsLoaded != 2 {
		t.Fatalf("job %+v", j)
	}
	var got []models.FlowSample
	h.db.Gorm().Table(job.StagingTable).Order("id").Find(&got)
	if len(got) != 2 {
		t.Fatalf("%d flows staged, want the 2 sflow rows", len(got))
	}
	for i, want := range []models.FlowSample{orig[0], orig[2]} {
		g := got[i]
		g.Timestamp, g.CreatedAt = g.Timestamp.UTC(), g.CreatedAt.UTC()
		st := g.FlowStart.UTC()
		g.FlowStart = &st
		if !reflect.DeepEqual(g, want) {
			t.Fatalf("flow %d:\n got %+v\nwant %+v", i, g, want)
		}
	}
}

// sealedFixture archives and seals September (as in the seal tests) and
// deletes the database manifest's object rows, so only the bucket knows.
func sealedFixture(t *testing.T, h *harness) []int64 {
	t.Helper()
	ids := syslogMonths(t, h)
	h.tickAt(day(10, 3, 0, 0))
	if m := h.month(export.StreamSyslog, "2026-09"); m == nil || m.Status != models.ArchiveMonthSealed {
		t.Fatalf("September not sealed: %+v", m)
	}
	h.db.Gorm().Exec("DELETE FROM syslog_messages")
	return ids
}

// TestRestore_FromBucket: with the database manifest gone, a bucket restore
// selects from the sealed months' _MONTH.json (checked against its ETag and
// recorded sha256), stages the day, and notes the months it could not search.
func TestRestore_FromBucket(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	sealedFixture(t, h)
	h.db.Gorm().Exec("DELETE FROM archive_objects")
	if _, _, err := h.db.QueueArchiveRestore(ctx, database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 10, 0, 0), To: day(9, 10, 0, 0)}, h.clk.now()); !errors.Is(err, database.ErrArchiveRestoreNothing) {
		t.Fatalf("a manifest restore without the manifest: %v", err)
	}
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 10, 0, 0), To: day(9, 10, 0, 0), FromBucket: true})
	if job.SelectedAt != nil || job.ObjectsTotal != 0 {
		t.Fatalf("a bucket restore selected at creation: %+v", job)
	}
	h.newRestore().Tick(ctx)
	j := h.restoreJob(job.ID)
	if j.Status != models.ArchiveRestoreDone || j.ObjectsTotal != 2 || j.RowsLoaded != 2 || !strings.Contains(j.Note, "2026-08, 2026-10") {
		t.Fatalf("bucket restore: %+v", j)
	}
	for _, m := range stagedSyslog(t, h.db, job.StagingTable) {
		if m.Timestamp.Format(time.DateOnly) != "2026-09-10" {
			t.Fatalf("staged a row of %s", m.Timestamp)
		}
	}
}

// tamperedStore serves _MONTH.json with one byte changed (its ETag and
// recorded sha256 then no longer match).
type tamperedStore struct{ RestoreStore }

func (s tamperedStore) GetBytes(ctx context.Context, rel, version string, limit int64) ([]byte, s3.ObjectInfo, error) {
	b, info, err := s.RestoreStore.GetBytes(ctx, rel, version, limit)
	if err == nil && strings.HasSuffix(rel, export.MonthManifestName) {
		b = append([]byte(nil), b...)
		b[10] ^= 0x01
	}
	return b, info, err
}

// TestRestore_FromBucketTamperedManifestRefused: a _MONTH.json that does not
// match what the seal recorded is refused before anything is selected.
func TestRestore_FromBucketTamperedManifestRefused(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	sealedFixture(t, h)
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 10, 0, 0), To: day(9, 10, 0, 0), FromBucket: true})
	r := h.newRestore()
	r.store = tamperedStore{r.store}
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreFailed || !strings.Contains(j.Error, "REFUSED") || j.ObjectsTotal != 0 {
		t.Fatalf("tampered _MONTH.json: %+v", j)
	}
}

// TestRestore_BucketOutageFailsResumable: a 503 on the download fails the job
// (not REFUSED: nothing was found wrong) and a resume completes it.
func TestRestore_BucketOutageFailsResumable(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0))
	h.tick(ctx)
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(10, 4, 0, 0), To: day(10, 4, 0, 0)})
	h.srv.SetFail(func(op s3test.Op, _ *http.Request) (int, string) {
		if op == s3test.OpGetObject {
			return http.StatusServiceUnavailable, "ServiceUnavailable"
		}
		return 0, ""
	})
	r := h.newRestore()
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreFailed || strings.Contains(j.Error, "REFUSED") {
		t.Fatalf("after a 503: %+v", j)
	}
	h.srv.SetFail(nil)
	h.db.ResumeArchiveRestoreJob(job.ID)
	r.Tick(ctx)
	if j := h.restoreJob(job.ID); j.Status != models.ArchiveRestoreDone || j.RowsLoaded != 2 {
		t.Fatalf("after the resume: %+v", j)
	}
}

var _ io.Writer = (*contentCheck)(nil)

// TestRestore_FromBucketIDConflict: a bucket restore re-normalized into a
// database whose ids match the archive's is queued; once a live row holds a
// restored id with other content (a rebuilt database), the re-normalize is
// refused and the staged rows are kept.
func TestRestore_FromBucketIDConflict(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	ids := sealedFixture(t, h)
	ok := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 10, 0, 0), To: day(9, 10, 0, 0), FromBucket: true, Renormalize: true})
	r := h.newRestore()
	r.Tick(ctx)
	if j := h.restoreJob(ok.ID); j.Status != models.ArchiveRestoreDone || j.BackfillJobID == nil {
		t.Fatalf("no conflict: %+v", j)
	}
	h.db.Gorm().Model(&models.NormalizeBackfillJob{}).Where("id = ?", *h.restoreJob(ok.ID).BackfillJobID).Update("status", database.NormalizeBackfillStatusDone)
	// The rebuilt database's own row 10 September, under a restored id.
	live := models.SyslogMessage{ID: uint(ids[10]), Timestamp: day(9, 10, 12, 0), DeviceID: 1, ProbeID: 1, Hostname: "fw-example-01",
		Message: "srcip=192.0.2.99", Severity: 5, CreatedAt: day(10, 2, 21, 0)}
	if err := h.db.Gorm().Create(&live).Error; err != nil {
		t.Fatal(err)
	}
	bad := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 10, 0, 0), To: day(9, 10, 0, 0), FromBucket: true, Renormalize: true})
	r.Tick(ctx)
	j := h.restoreJob(bad.ID)
	if j.Status != models.ArchiveRestoreFailed || !strings.Contains(j.Error, "no longer match the archive") || j.BackfillJobID != nil || j.RowsLoaded != 2 {
		t.Fatalf("conflict: %+v", j)
	}
	if n := len(stagedSyslog(t, h.db, bad.StagingTable)); n != 2 {
		t.Fatalf("%d staged rows kept, want 2", n)
	}
}

// TestRestore_DecoderRefusalBeforeAnyBatch: an object whose last line the
// decoder refuses (the row format drifted) is refused whole — every line is
// decoded before the first batch — so nothing of it is staged, even with
// batches of one line.
func TestRestore_DecoderRefusalBeforeAnyBatch(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0), day(10, 4, 3, 0), day(10, 4, 4, 0))
	h.tick(ctx)
	objs := h.objects(h.chunks(export.TableSyslog)[0].ID)
	body, found := h.get(objs[0].ObjectKey)
	if !found {
		t.Fatal("object missing")
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	last := lines[len(lines)-2]
	raw = append(raw, []byte(strings.Replace(last, `{"id":`, `{"extra":1,"id":`, 1))...)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(raw)
	zw.Close()
	path := filepath.Join(t.TempDir(), "o.ndjson.gz")
	if err := os.WriteFile(path, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	job := &models.ArchiveRestoreJob{Stream: "syslog", SourceTable: export.TableSyslog, FromDay: "2026-10-04", ToDay: "2026-10-04",
		Status: models.ArchiveRestoreRunning, RunnerID: "runner-x", RateRowsPerSec: 100000, ExpiresAt: time.Now().Add(time.Hour)}
	h.db.Gorm().Create(job)
	job.StagingTable = fmt.Sprintf("restore_%d_syslog_messages", job.ID)
	h.db.Gorm().Model(job).Update("staging_table", job.StagingTable)
	if err := h.db.EnsureArchiveRestoreTable(ctx, job); err != nil {
		t.Fatal(err)
	}
	obj := &models.ArchiveRestoreObject{JobID: job.ID, ObjectKey: objs[0].ObjectKey, SchemaVersion: objs[0].SchemaVersion, Status: models.ArchiveRestoreObjectPending}
	h.db.Gorm().Create(obj)
	database.SetArchiveRestoreBatchForTesting(t, 1, nil)
	r := h.newRestore()
	err = r.stage(ctx, job, "runner-x", obj, restoreFilter{from: day(10, 4, 0, 0), end: day(10, 5, 0, 0)}, file)
	if err == nil || !errors.Is(err, errRestoreRefused) {
		t.Fatalf("stage: %v", err)
	}
	if n := len(stagedSyslog(t, h.db, job.StagingTable)); n != 0 {
		t.Fatalf("%d rows staged before the refused line", n)
	}
}

// TestRestore_WorkerDiskPrecheck: the worker re-checks the disk before it
// loads: a job queued while the free space was known fails once it is
// unknown; a forced job runs anyway.
func TestRestore_WorkerDiskPrecheck(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0))
	h.tick(ctx)
	plain := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(10, 4, 0, 0), To: day(10, 4, 0, 0)})
	forced := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(10, 4, 0, 0), To: day(10, 4, 0, 0), Force: true})
	h.db.Gorm().Where("1 = 1").Delete(&models.ServerMetric{})
	r := h.newRestore()
	r.Tick(ctx)
	r.Tick(ctx)
	if j := h.restoreJob(plain.ID); j.Status != models.ArchiveRestoreFailed || !strings.Contains(j.Error, "unknown") || j.RowsLoaded != 0 {
		t.Fatalf("unforced, free space unknown: %+v", j)
	}
	if j := h.restoreJob(forced.ID); j.Status != models.ArchiveRestoreDone || j.RowsLoaded != 2 {
		t.Fatalf("forced: %+v", j)
	}
}
