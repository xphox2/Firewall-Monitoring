package worker

import (
	"bytes"
	"compress/gzip"
	"crypto/md5" // #nosec G501 -- test computes an S3 ETag
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// The month seal (archive plan PR 7) against the B2-strict fake and SQLite.
// Synthetic data only.

func (c *clock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// tickAt runs one pass with the worker's clock at t.
func (h *harness) tickAt(t time.Time) {
	h.clk.set(t.Add(-passEvery))
	h.w.lastPass = time.Time{}
	h.tick(ctx)
}

// syslogMonths seeds two rows a day (devices 1 and 2) from 5 September to
// 31 October 2026 and records migration v74 on 6 October: September is
// schema v1, October v2 — the production shape.
func syslogMonths(t *testing.T, h *harness) []int64 {
	t.Helper()
	if err := h.db.Gorm().Exec(`CREATE TABLE schema_migrations (version integer primary key, name text, app_version text, applied_at datetime)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := h.db.Gorm().Create(&models.SchemaMigration{Version: 74, Name: "syslog_format_column", AppVersion: "0.11.298", AppliedAt: day(10, 1, 0, 0)}).Error; err != nil {
		t.Fatal(err)
	}
	var created []time.Time
	for d := day(9, 5, 9, 0); d.Before(day(11, 1, 0, 0)); d = d.AddDate(0, 0, 1) {
		created = append(created, d, d.Add(6*time.Hour))
	}
	return seedSyslog(t, h.db, created...)
}

func (h *harness) month(stream, month string) *models.ArchiveMonth {
	h.t.Helper()
	m, err := h.db.ArchiveMonthState(ctx, stream, month)
	if err != nil {
		h.t.Fatal(err)
	}
	return m
}

// monthManifestOf downloads and decodes a sealed month's _MONTH.json.
func (h *harness) monthManifestOf(m *models.ArchiveMonth) (monthManifest, []byte) {
	h.t.Helper()
	b, ok := h.get(m.ManifestKey)
	if !ok {
		h.t.Fatalf("%s is not in the bucket", m.ManifestKey)
	}
	var mm monthManifest
	if err := json.Unmarshal(b, &mm); err != nil {
		h.t.Fatal(err)
	}
	return mm, b
}

func (h *harness) verifyMonth(stream, month string) *MonthReport {
	h.t.Helper()
	puts := len(h.srv.Requests())
	rep, err := VerifyMonth(ctx, h.store.(*s3.Client), stream, month, nil)
	if err != nil {
		h.t.Fatalf("VerifyMonth %s %s: %v", stream, month, err)
	}
	for _, r := range h.srv.Requests()[puts:] {
		if r.Op != s3test.OpGetObject {
			h.t.Fatalf("VerifyMonth sent %s %s: it must only read", r.Op, r.Key)
		}
	}
	return rep
}

// TestSeal_PartialSeptemberThenOctober: September (archive began on the 5th)
// is sealed PARTIAL only once 1 October + 48 h has passed, with its first row
// id, every object pinned and the digest; October is then sealed as a full
// month that starts exactly where September ended. --verify-month passes on
// both from the bucket alone.
func TestSeal_PartialSeptemberThenOctober(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	ids := syslogMonths(t, h)
	sealedBefore := metricValue(t, `fwmon_archive_months_sealed_total{stream="syslog"}`)

	h.tickAt(day(10, 2, 23, 59)) // every September day is verified, the grace is not over
	if n := len(h.chunks(export.TableSyslog)); n != 27 {
		t.Fatalf("%d chunks, want 27 (5 Sep - 1 Oct)", n)
	}
	if m := h.month(export.StreamSyslog, "2026-09"); m != nil {
		t.Fatalf("September touched before 1 Oct + 48 h: %+v", m)
	}
	if n := h.puts(`_MONTH\.json$`); n != 0 {
		t.Fatalf("%d _MONTH.json written before the grace", n)
	}

	h.tickAt(day(10, 3, 0, 0))
	sep := h.month(export.StreamSyslog, "2026-09")
	if sep == nil || sep.Status != models.ArchiveMonthSealed || !sep.Partial || sep.SealedAt == nil || sep.ChunkCount != 26 || sep.RowCount != 52 ||
		*sep.FirstID != 0 || sep.ManifestKey != testPrefix+"/syslog/v1/2026-09/_MONTH.json" {
		t.Fatalf("September: %+v", sep)
	}
	mm, body := h.monthManifestOf(sep)
	cs := h.chunks(export.TableSyslog)
	if !mm.Partial || mm.FirstID != 0 || mm.FirstRowID == nil || *mm.FirstRowID != ids[0] || mm.LastID != cs[25].IDHi ||
		mm.PeriodStart != "2026-09-05T00:00:00Z" || mm.PeriodEnd != "2026-10-01T00:00:00Z" || mm.ChunkCount != 26 || mm.ObjectCount != 52 ||
		mm.Rows != 52 || mm.SchemaVersion != 1 || !strings.Contains(mm.PartialNote, "began in this month") || len(mm.MsgDayHistogram) != 26 {
		t.Fatalf("September _MONTH.json: %+v", mm)
	}
	sum := sha256.Sum256(body)
	if sep.ManifestSha256 != hex.EncodeToString(sum[:]) || sep.MonthDigest != mm.MonthDigest || *sep.LastID != mm.LastID {
		t.Fatalf("the database records %s / %s, the bucket holds %x / %s", sep.ManifestSha256, sep.MonthDigest, sum, mm.MonthDigest)
	}
	for i, c := range mm.Chunks {
		if c.Seq != cs[i].Seq || c.IDLo != cs[i].IDLo || c.IDHi != cs[i].IDHi || len(c.Objects) != 2 || c.Manifest.Sha256 == "" ||
			!strings.HasSuffix(c.Manifest.Key, "/chunk.json") || c.Objects[0].Sha256Content == "" || c.Objects[0].Rows != 1 {
			t.Fatalf("chunk entry %d: %+v", i, c)
		}
	}
	if r, ok := h.srv.RetentionOf(sep.ManifestKey); !ok || r.Mode != "GOVERNANCE" || r.RetainUntil.Before(day(10, 3, 0, 0).AddDate(0, 0, 399)) {
		t.Fatalf("_MONTH.json Object Lock: %+v %v", r, ok)
	}
	if got := metricValue(t, `fwmon_archive_months_sealed_total{stream="syslog"}`); got != sealedBefore+1 {
		t.Fatalf("months_sealed_total %v, want %v", got, sealedBefore+1)
	}
	if rep := h.verifyMonth(export.StreamSyslog, "2026-09"); !rep.OK() || !rep.Partial || rep.Rows != 52 || rep.Chunks != 26 || rep.SchemaVersion != 1 {
		t.Fatalf("verify-month September: %+v", rep)
	}

	// Another pass writes nothing more into September.
	puts := len(h.srv.Requests())
	h.tickAt(day(10, 3, 0, 10))
	for _, r := range h.srv.Requests()[puts:] {
		if r.Op == s3test.OpPutObject && strings.Contains(r.Key, "/2026-09/") {
			t.Fatalf("a pass after the seal wrote %s", r.Key)
		}
	}

	h.tickAt(day(11, 3, 0, 0))
	oct := h.month(export.StreamSyslog, "2026-10")
	if oct == nil || oct.Status != models.ArchiveMonthSealed || oct.Partial || oct.ChunkCount != 31 || *oct.FirstID != *sep.LastID ||
		oct.ManifestKey != testPrefix+"/syslog/v2/2026-10/_MONTH.json" {
		t.Fatalf("October: %+v (September ends at %d)", oct, *sep.LastID)
	}
	om, _ := h.monthManifestOf(oct)
	if om.Partial || om.PartialNote != "" || om.FirstID != mm.LastID || om.PeriodStart != "2026-10-01T00:00:00Z" || om.PeriodEnd != "2026-11-01T00:00:00Z" ||
		om.Rows != 62 || om.SchemaVersion != 2 {
		t.Fatalf("October _MONTH.json: %+v", om)
	}
	if rep := h.verifyMonth(export.StreamSyslog, "2026-10"); !rep.OK() || rep.Partial || rep.Rows != 62 {
		t.Fatalf("verify-month October: %+v", rep)
	}
	if n := h.puts(`_MONTH\.json$`); n != 2 {
		t.Fatalf("%d _MONTH.json PUTs, want 2", n)
	}
}

// TestSeal_IncompleteMonthNeverSealed: a parked chunk, a chunk not verified
// yet and a gap in the ids each keep the month unsealed (seal_failed with
// the reason, the metric set, no _MONTH.json) — and the later month waits
// behind it; once the month is whole again it seals on the next pass.
func TestSeal_IncompleteMonthNeverSealed(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 2, 23, 0))
	cs := h.chunks(export.TableSyslog)
	mid := cs[10]
	set := func(id uint, fields map[string]any) {
		t.Helper()
		if err := h.db.Gorm().Model(&models.ArchiveChunk{}).Where("id = ?", id).Updates(fields).Error; err != nil {
			t.Fatal(err)
		}
	}
	blocked := func(reason string) float64 {
		return metricValue(t, `fwmon_archive_seal_blocked{reason="`+reason+`",stream="syslog"}`)
	}

	for _, c := range []struct {
		name, reason, msg string
		fields            map[string]any
	}{
		{"parked", sealNeedsAttention, "need attention", map[string]any{"status": models.ArchiveChunkNeedsAttention}},
		// Failed just now: its retry is not due within this pass.
		{"unverified", sealIncomplete, "not verified", map[string]any{"status": models.ArchiveChunkFailed, "attempts": 1, "updated_at": day(10, 3, 1, 0)}},
		{"id gap", sealGap, "does not continue", map[string]any{"id_lo": mid.IDLo + 1}},
		{"seq gap", sealGap, "does not continue", map[string]any{"seq": mid.Seq + 1000}},
	} {
		set(mid.ID, c.fields)
		h.tickAt(day(10, 3, 1, 0))
		m := h.month(export.StreamSyslog, "2026-09")
		if m == nil || m.Status != models.ArchiveMonthSealFailed || !strings.Contains(m.Error, c.msg) || m.SealedAt != nil {
			t.Fatalf("%s: September %+v", c.name, m)
		}
		if blocked(c.reason) != 1 {
			t.Fatalf("%s: fwmon_archive_seal_blocked{reason=%q} is not 1", c.name, c.reason)
		}
		if n := h.puts(`_MONTH\.json$`); n != 0 {
			t.Fatalf("%s: %d _MONTH.json written for an incomplete month", c.name, n)
		}
		set(mid.ID, map[string]any{"status": mid.Status, "id_lo": mid.IDLo, "seq": mid.Seq})
	}

	// The last day of September is not cut yet: incomplete. October, due a
	// month later, waits behind it.
	var last models.ArchiveChunk
	h.db.Gorm().Where("table_name = ? AND period_start = ?", export.TableSyslog, day(9, 30, 0, 0)).First(&last)
	set(last.ID, map[string]any{"period_end": day(9, 30, 12, 0)})
	h.tickAt(day(11, 3, 0, 0))
	if m := h.month(export.StreamSyslog, "2026-09"); m.Status != models.ArchiveMonthSealFailed || !strings.Contains(m.Error, "does not continue") && !strings.Contains(m.Error, "reach") {
		t.Fatalf("September with a short last day: %+v", m)
	}
	if m := h.month(export.StreamSyslog, "2026-10"); m != nil {
		t.Fatalf("October evaluated while September is not sealed: %+v", m)
	}
	set(last.ID, map[string]any{"period_end": day(10, 1, 0, 0)})
	h.tickAt(day(11, 3, 0, 10))
	for _, month := range []string{"2026-09", "2026-10"} {
		if m := h.month(export.StreamSyslog, month); m == nil || m.Status != models.ArchiveMonthSealed || m.Error != "" {
			t.Fatalf("%s once whole: %+v", month, m)
		}
	}
	if blocked(sealIncomplete) != 0 || blocked(sealGap) != 0 {
		t.Fatal("seal_blocked still set after the seal")
	}
}

// TestSeal_PreviousMonthMustJoin: a month whose first chunk does not start
// where the sealed previous month ended (its recorded last_id) is a gap.
func TestSeal_PreviousMonthMustJoin(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 3, 0, 0))
	sep := h.month(export.StreamSyslog, "2026-09")
	if sep.Status != models.ArchiveMonthSealed {
		t.Fatalf("September: %+v", sep)
	}
	h.db.Gorm().Model(&models.ArchiveMonth{}).Where("id = ?", sep.ID).Update("last_id", *sep.LastID-1)
	h.tickAt(day(11, 3, 0, 0))
	if m := h.month(export.StreamSyslog, "2026-10"); m.Status != models.ArchiveMonthSealFailed || !strings.Contains(m.Error, "previous month 2026-09") {
		t.Fatalf("October after a September that ends elsewhere: %+v", m)
	}
}

// TestSeal_ReverifyFindsChangedObject: a stored object or chunk.json that no
// longer matches what the database recorded refuses the seal (HEAD and full
// modes); a corrupt read-back only fails in full mode.
func TestSeal_ReverifyFindsChangedObject(t *testing.T) {
	for _, mode := range []string{config.SealReverifyHead, config.SealReverifyFull} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false; c.SealReverify = mode })
			syslogMonths(t, h)
			h.tickAt(day(10, 2, 23, 0))
			objs := h.objects(h.chunks(export.TableSyslog)[3].ID)
			key := objs[0].ObjectKey

			if mode == config.SealReverifyFull {
				h.srv.SetMutateGet(func(k string, b []byte) []byte {
					if k == testBucket+"/"+key || strings.HasSuffix(k, key) {
						b[len(b)/2] ^= 0xff
					}
					return b
				})
				h.tickAt(day(10, 3, 0, 0))
				if m := h.month(export.StreamSyslog, "2026-09"); m.Status != models.ArchiveMonthSealFailed || !strings.Contains(m.Error, "reverify") {
					t.Fatalf("corrupt read-back: %+v", m)
				}
				h.srv.SetMutateGet(nil)
			}

			// Replace the stored object (same key, other bytes).
			rel := strings.TrimPrefix(key, testPrefix+"/")
			other := []byte("not the archived object\n")
			if _, err := h.store.Put(ctx, rel, bytes.NewReader(other), int64(len(other)), nil); err != nil {
				t.Fatal(err)
			}
			h.tickAt(day(10, 3, 1, 0))
			m := h.month(export.StreamSyslog, "2026-09")
			if m.Status != models.ArchiveMonthSealFailed || !strings.Contains(m.Error, "reverify") || !strings.Contains(m.Error, key) {
				t.Fatalf("replaced object: %+v", m)
			}
			if metricValue(t, `fwmon_archive_seal_blocked{reason="reverify",stream="syslog"}`) != 1 {
				t.Fatal("seal_blocked{reverify} not set")
			}
			if n := h.puts(`_MONTH\.json$`); n != 0 {
				t.Fatalf("%d _MONTH.json written", n)
			}
		})
	}
}

// TestSeal_ChunkManifestChanged: a chunk.json that is not the one the
// database describes refuses the seal.
func TestSeal_ChunkManifestChanged(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 2, 23, 0))
	c := h.chunks(export.TableSyslog)[2]
	rel := export.FolderRel(export.StreamSyslog, export.SyslogSchemaV1, c.PeriodStart, false) + "/chunk.json"
	other := []byte(`{"kind":"fwmon-archive-chunk"}` + "\n")
	if _, err := h.store.Put(ctx, rel, bytes.NewReader(other), int64(len(other)), nil); err != nil {
		t.Fatal(err)
	}
	h.tickAt(day(10, 3, 0, 0))
	if m := h.month(export.StreamSyslog, "2026-09"); m.Status != models.ArchiveMonthSealFailed || !strings.Contains(m.Error, "is not the chunk's manifest") {
		t.Fatalf("changed chunk.json: %+v", m)
	}
}

// TestSeal_BucketFailureRetriedAfterBackoff: a 503 on the _MONTH.json PUT
// leaves the month unsealed (seal_failed, errors_total{stage="seal"}); the
// stream rests until its backoff, then the seal completes.
func TestSeal_BucketFailureRetriedAfterBackoff(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 2, 23, 0))
	errsBefore := metricValue(t, `fwmon_archive_errors_total{stage="seal"}`)
	h.srv.SetFail(func(op s3test.Op, r *http.Request) (int, string) {
		if op == s3test.OpPutObject && strings.HasSuffix(r.URL.Path, "/_MONTH.json") {
			return http.StatusServiceUnavailable, "ServiceUnavailable"
		}
		return 0, ""
	})
	h.tickAt(day(10, 3, 0, 0))
	if m := h.month(export.StreamSyslog, "2026-09"); m.Status != models.ArchiveMonthSealFailed || m.SealedAt != nil {
		t.Fatalf("after a failed PUT: %+v", m)
	}
	if got := metricValue(t, `fwmon_archive_errors_total{stage="seal"}`); got != errsBefore+1 {
		t.Fatalf("errors_total{seal} %v, want %v", got, errsBefore+1)
	}
	if metricValue(t, `fwmon_archive_seal_blocked{reason="bucket",stream="syslog"}`) != 1 {
		t.Fatal("seal_blocked{bucket} not set")
	}
	h.srv.SetFail(nil)
	attempts := h.srv.Count(s3test.OpPutObject)
	h.tickAt(day(10, 3, 0, 0).Add(30 * time.Second)) // within the 1-minute backoff
	if n := h.srv.Count(s3test.OpPutObject); n != attempts {
		t.Fatal("the seal was retried within its backoff")
	}
	h.tickAt(day(10, 3, 0, 20))
	if m := h.month(export.StreamSyslog, "2026-09"); m.Status != models.ArchiveMonthSealed {
		t.Fatalf("after the backoff: %+v", m)
	}
}

// TestSeal_CrashAfterUploadNotRewritten: a seal interrupted after its
// _MONTH.json was stored (the database still says sealing) finishes on the
// next pass by reading that copy back — the same bytes, so no second PUT —
// while a different _MONTH.json already in the folder is never overwritten.
func TestSeal_CrashAfterUploadNotRewritten(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 3, 0, 0))
	sep := h.month(export.StreamSyslog, "2026-09")
	h.db.Gorm().Model(&models.ArchiveMonth{}).Where("id = ?", sep.ID).Updates(map[string]any{"status": models.ArchiveMonthSealing, "sealed_at": nil})
	h.tickAt(day(10, 3, 0, 10))
	if m := h.month(export.StreamSyslog, "2026-09"); m.Status != models.ArchiveMonthSealed || m.ManifestSha256 != sep.ManifestSha256 {
		t.Fatalf("resumed seal: %+v", m)
	}
	if n := h.puts(`/2026-09/_MONTH\.json$`); n != 1 {
		t.Fatalf("%d _MONTH.json PUTs, want 1 (the resumed seal reads the stored copy back)", n)
	}

	// October: a different _MONTH.json is already there.
	rel := export.MonthFolderRel(export.StreamSyslog, export.SyslogSchemaV2, "2026-10") + "/" + export.MonthManifestName
	planted := []byte(`{"kind":"fwmon-archive-month","month":"2026-10"}` + "\n")
	if _, err := h.store.Put(ctx, rel, bytes.NewReader(planted), int64(len(planted)), nil); err != nil {
		t.Fatal(err)
	}
	h.tickAt(day(11, 3, 0, 0))
	if m := h.month(export.StreamSyslog, "2026-10"); m.Status != models.ArchiveMonthSealFailed || !strings.Contains(m.Error, "never overwritten") {
		t.Fatalf("October over a planted manifest: %+v", m)
	}
	if b, _ := h.get(testPrefix + "/" + rel); !bytes.Equal(b, planted) {
		t.Fatal("the planted _MONTH.json was overwritten")
	}
	if metricValue(t, `fwmon_archive_seal_blocked{reason="conflict",stream="syslog"}`) != 1 {
		t.Fatal("seal_blocked{conflict} not set")
	}
}

// TestSeal_WriteIntoSealedMonthRefused: once a month is sealed the worker
// writes nothing into its folder: a chunk of it that is (by hand) pending
// again is refused before the attempt changes anything, counted, and parked
// in needs_attention; the folder and the month's object rows are unchanged.
// The write path itself (put) refuses every key in a sealed month's folder.
func TestSeal_WriteIntoSealedMonthRefused(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 3, 0, 0))
	if m := h.month(export.StreamSyslog, "2026-09"); m.Status != models.ArchiveMonthSealed {
		t.Fatalf("September: %+v", m)
	}
	c := h.chunks(export.TableSyslog)[4]
	h.db.Gorm().Model(&models.ArchiveChunk{}).Where("id = ?", c.ID).Updates(map[string]any{"status": models.ArchiveChunkPending})
	refused := metricValue(t, `fwmon_archive_sealed_write_refused_total{stream="syslog"}`)
	before := h.puts(`/2026-09/`)
	h.tickAt(day(10, 3, 0, 10))
	if n := h.puts(`/2026-09/`); n != before {
		t.Fatalf("%d PUTs into the sealed September", n-before)
	}
	if got := metricValue(t, `fwmon_archive_sealed_write_refused_total{stream="syslog"}`); got != refused+1 {
		t.Fatalf("sealed_write_refused_total %v, want %v", got, refused+1)
	}
	var got models.ArchiveChunk
	h.db.Gorm().First(&got, c.ID)
	if got.Status != models.ArchiveChunkNeedsAttention || !strings.Contains(got.Error, "sealed month") {
		t.Fatalf("chunk after the refused write: %s %q", got.Status, got.Error)
	}
	for _, o := range h.objects(c.ID) {
		if o.Status != models.ArchiveObjectVerified {
			t.Fatalf("object %s of the sealed month is %s: the refused attempt changed it", o.ObjectKey, o.Status)
		}
	}

	// The guard itself: a key outside any month folder, and a sealed one.
	if _, err := h.w.put(ctx, "syslog/v1/notamonth", bytes.NewReader(nil), 0, nil); err == nil {
		t.Error("a key outside a month folder was written")
	}
	if _, err := h.w.put(ctx, "syslog/v1/2026-09/_MONTH.json", bytes.NewReader(nil), 0, nil); err == nil || !strings.Contains(err.Error(), "sealed month") {
		t.Errorf("a second _MONTH.json into the sealed September: %v", err)
	}
}

// TestSeal_FlowStreams: the flow table's chunks seal the sflow and netflow
// months separately (an hour without netflow pinned with its empty
// chunk.json), and the counters month too; the month the archive began in is
// partial for each.
func TestSeal_FlowStreams(t *testing.T) {
	h := newHarness(t, day(9, 30, 21, 30), func(c *config.ArchiveConfig) { c.SyslogEnabled = false })
	add := func(src uint8, at time.Time) {
		f := models.FlowSample{Timestamp: at, DeviceID: 7, SamplerAddress: "192.0.2.1", SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7", FlowSource: src}
		if err := h.db.Gorm().Create(&f).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctr := models.FlowInterfaceCounter{Timestamp: day(9, 30, 21, 0), DeviceID: 7, SamplerAddress: "192.0.2.1", IfIndex: 3}
	if err := h.db.Gorm().Create(&ctr).Error; err != nil {
		t.Fatal(err)
	}
	add(0, day(9, 30, 21, 10))
	add(2, day(9, 30, 21, 20))
	for at := day(9, 30, 21, 40); at.Before(day(10, 1, 1, 0)); at = at.Add(passEvery) {
		if at.Minute() == 30 {
			add(0, at)
		}
		h.tickAt(at)
	}
	h.tickAt(day(10, 3, 0, 0))
	for _, s := range []string{export.StreamSFlow, export.StreamNetFlow, export.StreamSFlowCounters} {
		m := h.month(s, "2026-09")
		if m == nil || m.Status != models.ArchiveMonthSealed || !m.Partial {
			t.Fatalf("%s September: %+v", s, m)
		}
		rep := h.verifyMonth(s, "2026-09")
		if !rep.OK() || !rep.Partial {
			t.Fatalf("verify-month %s: %+v", s, rep)
		}
		if m := h.month(s, "2026-10"); m != nil {
			t.Fatalf("%s October touched in October: %+v", s, m)
		}
	}
	sf, _ := h.monthManifestOf(h.month(export.StreamSFlow, "2026-09"))
	nf, _ := h.monthManifestOf(h.month(export.StreamNetFlow, "2026-09"))
	if sf.Rows != 3 || nf.Rows != 1 || sf.ChunkCount != nf.ChunkCount || sf.LastID != nf.LastID || sf.PeriodEnd != "2026-10-01T00:00:00Z" {
		t.Fatalf("sflow %+v\nnetflow %+v", sf, nf)
	}
	empty := 0
	for _, c := range nf.Chunks {
		if len(c.Objects) == 0 && c.Manifest.Key != "" {
			empty++
		}
	}
	if empty != nf.ChunkCount-1 {
		t.Fatalf("netflow: %d of %d hours pinned as empty, want all but one", empty, nf.ChunkCount)
	}
}

// TestMonthDigest: the digest is a function of the chunk ranges and object
// names, rows and content hashes only — not the prefix or the version ids —
// and any of those changing changes it.
func TestMonthDigest(t *testing.T) {
	chunks := func() []monthChunk {
		return []monthChunk{
			{Seq: 1, IDLo: 0, IDHi: 10, Objects: []manifestObject{{Key: "p/syslog/v2/2026-10/2026-10-01/device-1.ndjson.gz", Rows: 4, Sha256Content: "aa", VersionID: "v1"}}},
			{Seq: 2, IDLo: 10, IDHi: 10, Objects: []manifestObject{}},
		}
	}
	base, err := monthDigest("p/syslog/v2/2026-10", chunks())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := monthDigest("p/syslog/v2/2026-10", chunks())
	moved := chunks()
	moved[0].Objects[0].Key = "q/r/syslog/v2/2026-10/2026-10-01/device-1.ndjson.gz"
	movedDigest, _ := monthDigest("q/r/syslog/v2/2026-10", moved)
	ver := chunks()
	ver[0].Objects[0].VersionID = "v2"
	verDigest, _ := monthDigest("p/syslog/v2/2026-10", ver)
	if base != again || base != movedDigest || base != verDigest {
		t.Fatalf("digest not stable: %s %s %s %s", base, again, movedDigest, verDigest)
	}
	for name, mod := range map[string]func([]monthChunk){
		"content": func(c []monthChunk) { c[0].Objects[0].Sha256Content = "ab" },
		"rows":    func(c []monthChunk) { c[0].Objects[0].Rows = 5 },
		"id_hi":   func(c []monthChunk) { c[1].IDHi = 11 },
		"seq":     func(c []monthChunk) { c[1].Seq = 3 },
		"name":    func(c []monthChunk) { c[0].Objects[0].Key = "p/syslog/v2/2026-10/2026-10-01/device-2.ndjson.gz" },
	} {
		cs := chunks()
		mod(cs)
		if d, _ := monthDigest("p/syslog/v2/2026-10", cs); d == base {
			t.Errorf("changing %s keeps the digest", name)
		}
	}
	if _, err := monthDigest("p/syslog/v2/2026-11", chunks()); err == nil {
		t.Error("an object outside the month folder was digested")
	}
}

// TestVerifyMonth_DetectsTampering: --verify-month reports a replaced
// object, a corrupt read-back, a _MONTH.json edited after the seal and an
// unsealed month — reading only.
func TestVerifyMonth_DetectsTampering(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 3, 0, 0))
	if rep := h.verifyMonth(export.StreamSyslog, "2026-09"); !rep.OK() {
		t.Fatalf("intact month: %v", rep.Problems)
	}
	if _, err := VerifyMonth(ctx, h.store.(*s3.Client), export.StreamSyslog, "2026-10", nil); err == nil || !strings.Contains(err.Error(), "not sealed") {
		t.Errorf("unsealed October: %v", err)
	}
	for _, bad := range [][2]string{{"syslog", "2026-13"}, {"syslog", "2026-9"}, {"dns", "2026-09"}} {
		if _, err := VerifyMonth(ctx, h.store.(*s3.Client), bad[0], bad[1], nil); err == nil {
			t.Errorf("VerifyMonth %v accepted", bad)
		}
	}

	key := h.objects(h.chunks(export.TableSyslog)[7].ID)[1].ObjectKey
	h.srv.SetMutateGet(func(k string, b []byte) []byte {
		if strings.HasSuffix(k, key) {
			b[len(b)-3] ^= 0x01
		}
		return b
	})
	if rep := h.verifyMonth(export.StreamSyslog, "2026-09"); rep.OK() || !strings.Contains(strings.Join(rep.Problems, "\n"), key) {
		t.Fatalf("corrupt read-back: %v", rep.Problems)
	}
	h.srv.SetMutateGet(nil)

	other := []byte("replaced\n")
	if _, err := h.store.Put(ctx, strings.TrimPrefix(key, testPrefix+"/"), bytes.NewReader(other), int64(len(other)), nil); err != nil {
		t.Fatal(err)
	}
	if rep := h.verifyMonth(export.StreamSyslog, "2026-09"); rep.OK() || len(rep.Problems) != 1 {
		t.Fatalf("replaced object: %v", rep.Problems)
	}

	// An edited _MONTH.json (rows changed, stored again without the seal's
	// recorded hash).
	sep := h.month(export.StreamSyslog, "2026-09")
	_, body := h.monthManifestOf(sep)
	edited := bytes.Replace(body, []byte(`"rows": 52`), []byte(`"rows": 50`), 1)
	if _, err := h.store.Put(ctx, strings.TrimPrefix(sep.ManifestKey, testPrefix+"/"), bytes.NewReader(edited), int64(len(edited)), nil); err != nil {
		t.Fatal(err)
	}
	rep := h.verifyMonth(export.StreamSyslog, "2026-09")
	all := strings.Join(rep.Problems, "\n")
	if rep.OK() || !strings.Contains(all, "recorded at the seal") || !strings.Contains(all, "totals") {
		t.Fatalf("edited _MONTH.json: %v", rep.Problems)
	}
}

// TestVerifyMonth_ForgedObjectCaughtByContent: an object replaced together
// with its recorded size, ETag and sha256_object in _MONTH.json (and the
// manifest's own recorded hash) still fails: its decompressed content does not
// hash to the sha256_content the month digest covers.
func TestVerifyMonth_ForgedObjectCaughtByContent(t *testing.T) {
	h := newHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 3, 0, 0))
	sep := h.month(export.StreamSyslog, "2026-09")
	mm, _ := h.monthManifestOf(sep)
	o := &mm.Chunks[5].Objects[0]

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	fmt.Fprintf(zw, `{"id":%d,"message":"forged"}`+"\n", o.MinID)
	zw.Close()
	forged := gz.Bytes()
	if _, err := h.store.Put(ctx, strings.TrimPrefix(o.Key, testPrefix+"/"), bytes.NewReader(forged), int64(len(forged)), nil); err != nil {
		t.Fatal(err)
	}
	sum, sha := md5.Sum(forged), sha256.Sum256(forged) // #nosec G401 -- test computes an S3 ETag
	mm.ObjectBytes += int64(len(forged)) - o.ObjectBytes
	o.ObjectBytes, o.ETag, o.Sha256Object = int64(len(forged)), hex.EncodeToString(sum[:]), hex.EncodeToString(sha[:])
	body, err := json.MarshalIndent(mm, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	msha := sha256.Sum256(body)
	if _, err := h.store.Put(ctx, strings.TrimPrefix(sep.ManifestKey, testPrefix+"/"), bytes.NewReader(body), int64(len(body)),
		map[string]string{"fwmon-archive-sha256-content": hex.EncodeToString(msha[:])}); err != nil {
		t.Fatal(err)
	}
	rep := h.verifyMonth(export.StreamSyslog, "2026-09")
	if all := strings.Join(rep.Problems, "\n"); rep.OK() || !strings.Contains(all, "decompressed sha256 differs") {
		t.Fatalf("forged object: %v", rep.Problems)
	}
}
