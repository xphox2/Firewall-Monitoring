package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"
)

// The archive worker against the B2-strict fake (gofakes3 behind the B2
// rules: Content-MD5 required and checked, no checksum headers, Object Lock
// recorded) and the SQLite test database. Synthetic data only: RFC 5737
// addresses, fw-example-NN hosts.

const (
	testBucket = "example-bucket"
	testPrefix = "fwmon-test/archive"
)

// clock is the worker's injectable time.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	t     *testing.T
	db    *database.Database
	srv   *s3test.Server
	cfg   config.ArchiveConfig
	store Store
	clk   *clock
	w     *Worker
}

func testConfig(srv *s3test.Server, staging string) config.ArchiveConfig {
	return config.ArchiveConfig{
		SyslogEnabled: true, FlowsEnabled: true,
		Endpoint: srv.URL, Region: "us-east-005", Bucket: testBucket, Prefix: testPrefix,
		AccessKeyID: "005exampleKeyID", SecretAccessKey: config.Secret("not-a-real-secret-archive-test-fixture"),
		PathStyle: true, ObjectLockDays: 400, ObjectLockMode: "GOVERNANCE", MinAgeHours: 2,
		SyslogRateRowsPerSec: 100000, FlowRateRowsPerSec: 100000,
		AllowPrivateEndpoint: true, StagingDir: staging,
	}
}

// newHarness builds a worker over a fresh SQLite database and fake bucket.
// mod adjusts the configuration first.
func newHarness(t *testing.T, start time.Time, mod func(*config.ArchiveConfig)) *harness {
	t.Helper()
	srv := s3test.NewB2Strict(t, testBucket)
	cfg := testConfig(srv, t.TempDir())
	if mod != nil {
		mod(&cfg)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client, err := s3.New(cfg, s3.WithRootCAs(pool), s3.WithMaxAttempts(1))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, db: database.NewDatabaseForTesting(t), srv: srv, cfg: cfg, store: client, clk: &clock{t: start}}
	orig := stagingFree
	stagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { stagingFree = orig })
	h.w = h.restart()
	return h
}

// restart builds a new worker over the same database, bucket and staging
// directory: what the poller does after a crash.
func (h *harness) restart() *Worker {
	h.t.Helper()
	w, err := newWorker(h.db, h.store, h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	w.now = h.clk.now
	h.w = w
	return w
}

// tick advances past the pass interval and runs one tick.
func (h *harness) tick(ctx context.Context) {
	h.clk.add(passEvery)
	h.w.Tick(ctx)
}

func (h *harness) chunks(table string) []models.ArchiveChunk {
	h.t.Helper()
	var cs []models.ArchiveChunk
	if err := h.db.Gorm().Where("table_name = ?", table).Order("seq").Find(&cs).Error; err != nil {
		h.t.Fatal(err)
	}
	return cs
}

func (h *harness) objects(chunkID uint) []models.ArchiveObject {
	h.t.Helper()
	var os []models.ArchiveObject
	if err := h.db.Gorm().Where("chunk_id = ?", chunkID).Order("id").Find(&os).Error; err != nil {
		h.t.Fatal(err)
	}
	return os
}

// get downloads an object from the fake directly (path-style).
func (h *harness) get(key string) ([]byte, bool) {
	h.t.Helper()
	res, err := h.srv.Client().Get(h.srv.URL + "/" + testBucket + "/" + key)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return b, res.StatusCode == http.StatusOK
}

// lines gunzips an object and decodes its NDJSON lines.
func (h *harness) lines(key string) []map[string]any {
	h.t.Helper()
	b, ok := h.get(key)
	if !ok {
		h.t.Fatalf("%s is not in the bucket", key)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	var out []map[string]any
	sc := bufio.NewScanner(zr)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			h.t.Fatalf("%s: %v", key, err)
		}
		out = append(out, m)
	}
	return out
}

func (h *harness) manifest(rel string) chunkManifest {
	h.t.Helper()
	b, ok := h.get(testPrefix + "/" + rel)
	if !ok {
		h.t.Fatalf("manifest %s is not in the bucket", rel)
	}
	var m chunkManifest
	if err := json.Unmarshal(b, &m); err != nil {
		h.t.Fatal(err)
	}
	return m
}

// puts counts PutObject requests (accepted or not) for keys matching re.
func (h *harness) puts(re string) int {
	n := 0
	rx := regexp.MustCompile(re)
	for _, r := range h.srv.Requests() {
		if r.Op == s3test.OpPutObject && rx.MatchString(r.Key) {
			n++
		}
	}
	return n
}

func seedSyslog(t *testing.T, db *database.Database, created ...time.Time) []int64 {
	t.Helper()
	ids := make([]int64, len(created))
	for i, c := range created {
		m := models.SyslogMessage{Timestamp: c.Add(-20 * time.Second), DeviceID: uint(1 + i%2), ProbeID: 1,
			Hostname: "fw-example-0" + strconv.Itoa(1+i%2), Message: "srcip=192.0.2.10 dstip=198.51.100.7 n=" + strconv.Itoa(i),
			Severity: 5, CreatedAt: c}
		if err := db.Gorm().Create(&m).Error; err != nil {
			t.Fatal(err)
		}
		ids[i] = int64(m.ID)
	}
	return ids
}

// metricValue scrapes the process's /metrics for one series ("" = absent).
func metricValue(t *testing.T, series string) float64 {
	t.Helper()
	w := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, l := range strings.Split(w.Body.String(), "\n") {
		if v, ok := strings.CutPrefix(l, series+" "); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				t.Fatal(err)
			}
			return f
		}
	}
	return 0
}

var ctx = context.Background()

func day(m time.Month, d, hh, mm int) time.Time { return time.Date(2026, m, d, hh, mm, 0, 0, time.UTC) }

// TestWorker_SyslogEndToEnd: the due ingest days are cut, exported per
// device, uploaded with Object Lock, read back, counted and recorded as
// verified with their chunk.json; a day not yet old enough is not touched.
func TestWorker_SyslogEndToEnd(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	ids := seedSyslog(t, h.db,
		day(10, 3, 1, 0), day(10, 3, 2, 0), day(10, 3, 23, 59), // 3 Oct: devices 1, 2, 1
		day(10, 4, 0, 0), day(10, 4, 12, 0), // 4 Oct: 1, 2
		day(10, 5, 9, 0)) // today: not due
	before := metricValue(t, `fwmon_archive_objects_total{stream="syslog"}`)
	h.tick(ctx) // 12:00

	cs := h.chunks(export.TableSyslog)
	if len(cs) != 2 {
		t.Fatalf("%d chunks, want 2 (3 and 4 Oct; 5 Oct is not over)", len(cs))
	}
	wantRows := [][]int64{{ids[0], ids[1], ids[2]}, {ids[3], ids[4]}}
	for i, c := range cs {
		if c.Status != models.ArchiveChunkVerified || c.Attempts != 1 || c.VerifiedAt == nil || c.RowCount != int64(len(wantRows[i])) {
			t.Fatalf("chunk %d: status %s attempts %d rows %d", c.Seq, c.Status, c.Attempts, c.RowCount)
		}
		folder := export.FolderRel(export.StreamSyslog, export.SyslogSchemaV2, c.PeriodStart, false)
		objs := h.objects(c.ID)
		var got []int64
		for _, o := range objs {
			if o.Status != models.ArchiveObjectVerified || o.VerifiedAt == nil || o.ETag == "" || o.LockUntil == nil {
				t.Fatalf("object %s: %+v", o.ObjectKey, o)
			}
			if !strings.HasPrefix(o.ObjectKey, testPrefix+"/"+folder+"/device-") {
				t.Fatalf("key %s is not in %s", o.ObjectKey, folder)
			}
			r, ok := h.srv.RetentionOf(o.ObjectKey)
			if !ok || r.Mode != "GOVERNANCE" || time.Until(r.RetainUntil) < 399*24*time.Hour {
				t.Fatalf("%s retention %+v", o.ObjectKey, r)
			}
			for _, l := range h.lines(o.ObjectKey) {
				if uint(l["device_id"].(float64)) != *o.DeviceID {
					t.Fatalf("%s holds a row of device %v", o.ObjectKey, l["device_id"])
				}
				if _, ok := l["format"]; !ok {
					t.Fatalf("schema v2 row without format: %v", l)
				}
				got = append(got, int64(l["id"].(float64)))
			}
		}
		if len(got) != len(wantRows[i]) {
			t.Fatalf("chunk %d: bucket holds ids %v, want %v", c.Seq, got, wantRows[i])
		}
		m := h.manifest(folder + "/" + export.ChunkManifestName)
		if m.Kind != ChunkManifestKind || m.Seq != c.Seq || m.IDLo != c.IDLo || m.IDHi != c.IDHi || m.Rows != c.RowCount ||
			len(m.Objects) != len(objs) || m.SchemaVersion != export.SyslogSchemaV2 {
			t.Fatalf("chunk.json %+v", m)
		}
		if _, ok := h.srv.RetentionOf(testPrefix + "/" + folder + "/" + export.ChunkManifestName); !ok {
			t.Fatal("chunk.json has no Object Lock retention")
		}
	}
	if d := metricValue(t, `fwmon_archive_objects_total{stream="syslog"}`) - before; d != 4 {
		t.Fatalf("objects_total grew by %v, want 4 (two devices x two days)", d)
	}
	if v := metricValue(t, `fwmon_archive_verified_through_id{table="syslog_messages"}`); v != float64(ids[4]) {
		t.Fatalf("verified_through_id %v, want %d", v, ids[4])
	}
	// Lag: from the end of 4 Oct (verified) to now, 12:00 on 5 Oct.
	if v := metricValue(t, `fwmon_archive_lag_seconds{stream="syslog"}`); v != (12 * time.Hour).Seconds() {
		t.Fatalf("lag %v s", v)
	}
	// Nothing new is due: a later tick uploads nothing more.
	n := len(h.srv.Requests())
	h.tick(ctx)
	if got := h.puts(`.`); got != 6 {
		t.Fatalf("%d PutObject in all, want 6 (4 objects + 2 chunk.json)", got)
	}
	if len(h.chunks(export.TableSyslog)) != 2 || len(h.srv.Requests()) != n {
		t.Fatalf("a second tick re-did work (%d requests before, %d after)", n, len(h.srv.Requests()))
	}
}

// TestWorker_FlowsSplitAndEmptyStream: one flow_samples chunk feeds the sflow
// and netflow folders by flow_source; an hour without netflow rows still gets
// a netflow chunk.json with no objects; counters get their daily chunk.
func TestWorker_FlowsSplitAndEmptyStream(t *testing.T) {
	h := newHarness(t, day(10, 5, 10, 20), func(c *config.ArchiveConfig) { c.SyslogEnabled = false })
	addFlows := func(srcs ...uint8) {
		for _, src := range srcs {
			f := models.FlowSample{Timestamp: day(10, 5, 9, 30), DeviceID: 7, SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7", FlowSource: src}
			if err := h.db.Gorm().Create(&f).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	addFlows(0, 1, 0, 2, 3, 0)
	ctr := models.FlowInterfaceCounter{Timestamp: day(10, 4, 23, 0), DeviceID: 7, SamplerAddress: "192.0.2.1", IfIndex: 3}
	if err := h.db.Gorm().Create(&ctr).Error; err != nil {
		t.Fatal(err)
	}
	h.tick(ctx) // 10:30: marks 10:00 (flows) and 5 Oct 00:00 (counters); both first chunks are due

	fc := h.chunks(export.TableFlows)
	if len(fc) != 1 || fc[0].Status != models.ArchiveChunkVerified || fc[0].RowCount != 6 {
		t.Fatalf("flow chunks %+v", fc)
	}
	for stream, want := range map[string][]float64{export.StreamSFlow: {0, 0, 0}, export.StreamNetFlow: {1, 2, 3}} {
		key := testPrefix + "/" + export.ObjectRel(export.ObjectID{Stream: stream}, export.FlowSchemaV1, fc[0].PeriodStart, true)
		if !strings.Contains(key, "/2026-10-05T09/flows.ndjson.gz") {
			t.Fatalf("flow key %s", key)
		}
		var got []float64
		for _, l := range h.lines(key) {
			got = append(got, l["flow_source"].(float64))
		}
		if len(got) != len(want) || got[0] != want[0] || got[len(got)-1] != want[len(want)-1] {
			t.Fatalf("%s rows by flow_source %v, want %v", stream, got, want)
		}
	}
	cc := h.chunks(export.TableCounters)
	if len(cc) != 1 || cc[0].Status != models.ArchiveChunkVerified || cc[0].RowCount != 1 {
		t.Fatalf("counter chunks %+v", cc)
	}
	if m := h.manifest(export.FolderRel(export.StreamSFlowCounters, export.CounterSchemaV1, cc[0].PeriodStart, false) + "/chunk.json"); len(m.Objects) != 1 {
		t.Fatalf("counters chunk.json %+v", m)
	}

	addFlows(0, 0) // sflow only in the 10:00 hour
	h.clk.add(36 * time.Minute)
	h.tick(ctx) // 11:16: mark 11:00, the 10:00 hour is due

	fc = h.chunks(export.TableFlows)
	if len(fc) != 2 || fc[1].Status != models.ArchiveChunkVerified || fc[1].RowCount != 2 {
		t.Fatalf("second flow chunk %+v", fc)
	}
	nf := h.manifest(export.FolderRel(export.StreamNetFlow, export.FlowSchemaV1, fc[1].PeriodStart, true) + "/chunk.json")
	if nf.Objects == nil || len(nf.Objects) != 0 || nf.Rows != 0 || nf.ChunkRows != 2 {
		t.Fatalf("empty netflow hour chunk.json %+v", nf)
	}
	b, _ := h.get(testPrefix + "/" + export.FolderRel(export.StreamNetFlow, export.FlowSchemaV1, fc[1].PeriodStart, true) + "/chunk.json")
	if !bytes.Contains(b, []byte(`"objects": []`)) {
		t.Fatalf("empty netflow chunk.json does not list objects as []: %s", b)
	}
	if sf := h.manifest(export.FolderRel(export.StreamSFlow, export.FlowSchemaV1, fc[1].PeriodStart, true) + "/chunk.json"); len(sf.Objects) != 1 || sf.Rows != 2 {
		t.Fatalf("sflow chunk.json %+v", sf)
	}
}

// TestWorker_UploadFailureRetriesWithBackoff: a 503 on one object's PUT fails
// the attempt (never verified, no chunk.json); the chunk waits out its
// backoff, then a new attempt supersedes the first attempt's objects and
// verifies — sending only the object that never arrived: the one already
// uploaded with the same bytes is not written (and retained) twice.
func TestWorker_UploadFailureRetriesWithBackoff(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0), day(10, 4, 3, 0))
	h.srv.SetFail(func(op s3test.Op, r *http.Request) (int, string) {
		if op == s3test.OpPutObject && strings.HasSuffix(r.URL.Path, "/device-2.ndjson.gz") {
			return http.StatusServiceUnavailable, "ServiceUnavailable"
		}
		return 0, ""
	})
	before := metricValue(t, `fwmon_archive_errors_total{stage="upload"}`)
	h.tick(ctx)
	c := h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkFailed || c.Attempts != 1 || !strings.Contains(c.Error, "upload") || c.VerifiedAt != nil {
		t.Fatalf("after a 503: %s attempts %d error %q", c.Status, c.Attempts, c.Error)
	}
	if d := metricValue(t, `fwmon_archive_errors_total{stage="upload"}`) - before; d != 1 {
		t.Fatalf("errors_total{stage=upload} grew by %v", d)
	}
	if n := h.puts(`chunk\.json$`); n != 0 {
		t.Fatalf("chunk.json written for a failed chunk (%d)", n)
	}
	h.srv.SetFail(nil)

	// Within the 1-minute backoff: not retried.
	h.clk.add(30 * time.Second)
	h.w.pass(ctx)
	if c := h.chunks(export.TableSyslog)[0]; c.Status != models.ArchiveChunkFailed || c.Attempts != 1 {
		t.Fatalf("retried inside the backoff: %s attempts %d", c.Status, c.Attempts)
	}
	h.clk.add(time.Minute)
	h.w.pass(ctx)
	c = h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkVerified || c.Attempts != 2 || c.Error != "" {
		t.Fatalf("after the backoff: %s attempts %d error %q", c.Status, c.Attempts, c.Error)
	}
	var verified, superseded int
	for _, o := range h.objects(c.ID) {
		switch o.Status {
		case models.ArchiveObjectVerified:
			verified++
		case models.ArchiveObjectSuperseded:
			superseded++
		default:
			t.Fatalf("object %s left %s", o.ObjectKey, o.Status)
		}
	}
	if verified != 2 || superseded != 2 {
		t.Fatalf("%d verified, %d superseded objects; want 2 and 2", verified, superseded)
	}
	if n := h.puts(`/device-1\.ndjson\.gz$`); n != 1 {
		t.Fatalf("device-1 PUT %d times, want 1 (the first attempt's upload is reused)", n)
	}
	if n := h.puts(`/device-2\.ndjson\.gz$`); n != 2 {
		t.Fatalf("device-2 PUT %d times, want 2 (refused, then sent)", n)
	}
}

// TestWorker_CorruptReadBackNeverVerified: a read-back that differs from what
// was uploaded fails the chunk — no object verified, no chunk.json — and the
// next attempt exports and uploads it again. Two corruptions: a flipped byte
// in the compressed data (the decompressed content differs too), and one in
// the gzip header's comment, which decompresses to the same NDJSON: only the
// stored-bytes hash (sha256_object) can see that one.
func TestWorker_CorruptReadBackNeverVerified(t *testing.T) {
	for name, at := range map[string]func(b []byte) int{
		"data":           func(b []byte) int { return len(b) / 2 },
		"header comment": func([]byte) int { return 12 },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
			seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0))
			h.srv.SetMutateGet(func(key string, b []byte) []byte {
				if strings.HasSuffix(key, "/device-1.ndjson.gz") {
					b[at(b)] ^= 0x01
				}
				return b
			})
			h.tick(ctx)
			c := h.chunks(export.TableSyslog)[0]
			if c.Status != models.ArchiveChunkFailed || !strings.Contains(c.Error, "verify") {
				t.Fatalf("after a corrupt read-back: %s %q", c.Status, c.Error)
			}
			for _, o := range h.objects(c.ID) {
				if o.Status == models.ArchiveObjectVerified || o.VerifiedAt != nil {
					t.Fatalf("object %s verified from a corrupt read-back", o.ObjectKey)
				}
			}
			if n := h.puts(`chunk\.json$`); n != 0 {
				t.Fatal("chunk.json written after a corrupt read-back")
			}
			h.srv.SetMutateGet(nil)
			h.clk.add(2 * time.Minute)
			h.w.pass(ctx)
			if c := h.chunks(export.TableSyslog)[0]; c.Status != models.ArchiveChunkVerified || c.Attempts != 2 {
				t.Fatalf("second attempt: %s attempts %d", c.Status, c.Attempts)
			}
		})
	}
}

// TestWorker_ReadBackMustMatchRecordedObject: the stored bytes match their
// hash, but the decompressed content is not what the export recorded for the
// object (here: the recorded sha256_content is altered before the
// read-back). The chunk is not verified.
func TestWorker_ReadBackMustMatchRecordedObject(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0))
	h.w.afterUploaded = func(_ context.Context, c *models.ArchiveChunk) error {
		return h.db.Gorm().Model(&models.ArchiveObject{}).Where("chunk_id = ?", c.ID).
			Update("sha256_content", strings.Repeat("0", 64)).Error
	}
	h.tick(ctx)
	c := h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkFailed || !strings.Contains(c.Error, "sha256_content") {
		t.Fatalf("content differing from the record: %s %q", c.Status, c.Error)
	}
}

// TestWorker_BucketOutageRestsTable: while a chunk is in a long backoff after
// a bucket failure, the table's later chunks are not exported (each would
// read a day of rows only to fail the same way).
func TestWorker_BucketOutageRestsTable(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 3, 1, 0), day(10, 4, 1, 0))
	h.srv.SetFail(func(op s3test.Op, _ *http.Request) (int, string) {
		if op == s3test.OpPutObject {
			return http.StatusServiceUnavailable, "ServiceUnavailable"
		}
		return 0, ""
	})
	for range 4 { // attempts 1, 2, 3 of chunk 1 (backoffs 1, 5, 30 min), then a pass inside the 30 min
		h.tick(ctx)
	}
	cs := h.chunks(export.TableSyslog)
	if cs[0].Status != models.ArchiveChunkFailed || cs[0].Attempts != 3 {
		t.Fatalf("chunk 1: %s attempts %d, want failed after 3", cs[0].Status, cs[0].Attempts)
	}
	if cs[1].Status != models.ArchiveChunkPending || cs[1].Attempts != 0 {
		t.Fatalf("chunk 2 was tried during the outage: %s attempts %d", cs[1].Status, cs[1].Attempts)
	}
	h.srv.SetFail(nil)
	h.clk.add(30 * time.Minute)
	h.tick(ctx)
	for _, c := range h.chunks(export.TableSyslog) {
		if c.Status != models.ArchiveChunkVerified {
			t.Fatalf("after the outage: chunk %d %s", c.Seq, c.Status)
		}
	}
}

// tamperStore reports a different hash for an upload than the staged bytes
// had: the staged file is not what the export wrote.
type tamperStore struct{ Store }

func (s tamperStore) Put(ctx context.Context, rel string, body io.ReaderAt, size int64, meta map[string]string) (s3.PutResult, error) {
	r, err := s.Store.Put(ctx, rel, body, size, meta)
	r.SHA256 = strings.Repeat("f", 64)
	return r, err
}

func TestWorker_StagedBytesMustBeTheExport(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0))
	h.store = tamperStore{h.store}
	h.restart()
	h.tick(ctx)
	if c := h.chunks(export.TableSyslog)[0]; c.Status != models.ArchiveChunkFailed || !strings.Contains(c.Error, "the export wrote") {
		t.Fatalf("staged bytes differing from the export: %s %q", c.Status, c.Error)
	}
}

// TestWorker_CountMismatchReexports: a row that commits into the chunk's
// range after the export (late commit), or one deleted from it (a device
// purge), makes the table differ from what the bucket holds: the attempt
// fails and is never verified, and the next attempt exports the range as the
// table now has it.
func TestWorker_CountMismatchReexports(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(h *harness, ids []int64) error
		verdict string
		rows    int64
	}{
		{"late commit", func(h *harness, ids []int64) error {
			// Re-insert the row with the gap's id: a commit the export missed.
			m := models.SyslogMessage{ID: uint(ids[1]), Timestamp: day(10, 4, 2, 0), DeviceID: 1, ProbeID: 1, Hostname: "fw-example-01",
				Message: "srcip=192.0.2.11 late", Severity: 5, CreatedAt: day(10, 4, 2, 0)}
			return h.db.Gorm().Create(&m).Error
		}, database.ArchiveCountLateCommit, 4},
		{"purge", func(h *harness, ids []int64) error {
			return h.db.Gorm().Exec("DELETE FROM syslog_messages WHERE id = ?", ids[3]).Error
		}, database.ArchiveCountShortfall, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
			ids := seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0), day(10, 4, 3, 0), day(10, 4, 4, 0))
			// Leave a gap at ids[1] for the late commit to fill.
			if err := h.db.Gorm().Exec("DELETE FROM syslog_messages WHERE id = ?", ids[1]).Error; err != nil {
				t.Fatal(err)
			}
			done := false
			h.w.beforeCount = func(context.Context, *models.ArchiveChunk) error {
				if done {
					return nil
				}
				done = true
				return tc.mutate(h, ids)
			}
			h.tick(ctx)
			c := h.chunks(export.TableSyslog)[0]
			if c.Status != models.ArchiveChunkFailed || !strings.Contains(c.Error, "count check "+tc.verdict) {
				t.Fatalf("after the %s: %s %q", tc.name, c.Status, c.Error)
			}
			if n := h.puts(`chunk\.json$`); n != 0 {
				t.Fatal("chunk.json written for a count mismatch")
			}
			h.clk.add(2 * time.Minute)
			h.w.pass(ctx)
			c = h.chunks(export.TableSyslog)[0]
			if c.Status != models.ArchiveChunkVerified || c.RowCount != tc.rows {
				t.Fatalf("re-export: %s rows %d, want verified with %d", c.Status, c.RowCount, tc.rows)
			}
			var n int64
			for _, o := range h.objects(c.ID) {
				if o.Status == models.ArchiveObjectVerified {
					n += int64(len(h.lines(o.ObjectKey)))
				}
			}
			if n != tc.rows {
				t.Fatalf("the bucket holds %d rows, want %d", n, tc.rows)
			}
		})
	}
}

// errCrash stands for the process dying: the hook cancels the run's context
// as a shutdown would, so nothing after it reaches the database.
var errCrash = errors.New("simulated crash")

// TestWorker_CrashBetweenUploadAndRecord: the process dies after an object
// reached the bucket but before the database recorded it. The chunk stays
// uploading (not failed, not verified); after a restart the chunk is exported
// again, the same key is uploaded again, and it verifies.
func TestWorker_CrashBetweenUploadAndRecord(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0))
	run, crash := context.WithCancel(ctx)
	h.w.afterPut = func(context.Context, *models.ArchiveChunk, *models.ArchiveObject) error {
		crash()
		return errCrash
	}
	h.tick(run)
	c := h.chunks(export.TableSyslog)[0]
	objs := h.objects(c.ID)
	if c.Status != models.ArchiveChunkUploading || c.Attempts != 1 || c.Error != "" {
		t.Fatalf("after the crash: %s attempts %d error %q", c.Status, c.Attempts, c.Error)
	}
	if objs[0].Status != models.ArchiveObjectPending || objs[0].ETag != "" {
		t.Fatalf("the uploaded object was recorded: %+v", objs[0])
	}
	if _, ok := h.get(objs[0].ObjectKey); !ok {
		t.Fatal("the object did not reach the bucket before the crash")
	}
	if ents, _ := os.ReadDir(h.cfg.StagingDir); len(ents) != 0 {
		t.Fatalf("staging left behind: %v", ents)
	}

	h.restart()
	h.tick(ctx)
	c = h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkVerified || c.Attempts != 2 {
		t.Fatalf("after the restart: %s attempts %d", c.Status, c.Attempts)
	}
	if n := h.puts(regexp.QuoteMeta(objs[0].ObjectKey) + "$"); n != 2 {
		t.Fatalf("%s PUT %d times, want 2", objs[0].ObjectKey, n)
	}
	var verified int
	for _, o := range h.objects(c.ID) {
		if o.Status == models.ArchiveObjectVerified {
			verified++
		}
	}
	if verified != 2 {
		t.Fatalf("%d verified objects, want 2", verified)
	}
}

// TestWorker_CrashDuringVerifyResumesWithoutReupload: the process dies after
// the read-back but before the chunk was recorded verified. A restart reads
// the objects back again and finishes — no data object is uploaded again.
func TestWorker_CrashDuringVerifyResumesWithoutReupload(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0))
	run, crash := context.WithCancel(ctx)
	h.w.beforeCount = func(context.Context, *models.ArchiveChunk) error {
		crash()
		return errCrash
	}
	h.tick(run)
	c := h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkVerifying {
		t.Fatalf("after the crash: %s", c.Status)
	}
	dataPuts, gets := h.puts(`\.ndjson\.gz$`), h.srv.Count(s3test.OpGetObject)

	h.restart()
	h.tick(ctx)
	c = h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkVerified || c.Attempts != 1 {
		t.Fatalf("after the restart: %s attempts %d", c.Status, c.Attempts)
	}
	if n := h.puts(`\.ndjson\.gz$`); n != dataPuts {
		t.Fatalf("data objects uploaded again (%d PUTs, %d before)", n, dataPuts)
	}
	if n := h.srv.Count(s3test.OpGetObject); n < gets+2 {
		t.Fatalf("the restart did not read the objects back (%d GETs, %d before)", n, gets)
	}
}

// TestWorker_DisabledDoesNothing: with both streams off the worker takes no
// lock, makes no request and writes nothing; with one stream on, the other's
// tables are never marked or cut.
func TestWorker_DisabledDoesNothing(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.SyslogEnabled, c.FlowsEnabled = false, false })
	seedSyslog(t, h.db, day(10, 3, 1, 0), day(10, 4, 1, 0))
	f := models.FlowSample{Timestamp: day(10, 5, 9, 0), DeviceID: 7, SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7"}
	if err := h.db.Gorm().Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	for range 3 {
		h.tick(ctx)
	}
	var chunks, marks int64
	h.db.Gorm().Model(&models.ArchiveChunk{}).Count(&chunks)
	h.db.Gorm().Model(&models.ArchiveIDMark{}).Count(&marks)
	if n := len(h.srv.Requests()); n != 0 || chunks != 0 || marks != 0 {
		t.Fatalf("disabled worker: %d requests, %d chunks, %d marks", n, chunks, marks)
	}

	h.cfg.SyslogEnabled = true
	h.restart()
	h.tick(ctx)
	h.db.Gorm().Model(&models.ArchiveIDMark{}).Count(&marks)
	if len(h.chunks(export.TableSyslog)) != 2 || len(h.chunks(export.TableFlows)) != 0 || marks != 0 {
		t.Fatalf("syslog only: %d syslog chunks, %d flow chunks, %d marks", len(h.chunks(export.TableSyslog)), len(h.chunks(export.TableFlows)), marks)
	}

	h.cfg.SyslogEnabled, h.cfg.FlowsEnabled = false, true
	h.restart()
	seedSyslog(t, h.db, day(10, 5, 1, 0))
	h.clk.add(24 * time.Hour)
	h.tick(ctx)
	if len(h.chunks(export.TableSyslog)) != 2 || len(h.chunks(export.TableFlows)) == 0 {
		t.Fatalf("flows only: %d syslog chunks (want still 2), %d flow chunks", len(h.chunks(export.TableSyslog)), len(h.chunks(export.TableFlows)))
	}
}

// TestWorker_StagingCleanupAndFloor: a restart removes only the chunk
// directories it owns from the staging directory, and a chunk is not exported
// while the staging filesystem is below the free-space floor.
func TestWorker_StagingCleanupAndFloor(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	dir := h.cfg.StagingDir
	for _, p := range []string{"chunk-12/syslog-device-1.ndjson.gz", "chunk-x/keep", "keep.txt"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.restart()
	if _, err := os.Stat(filepath.Join(dir, "chunk-12")); !os.IsNotExist(err) {
		t.Fatal("a leftover chunk directory survived the restart")
	}
	for _, p := range []string{"chunk-x/keep", "keep.txt"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("%s was removed: %v", p, err)
		}
	}

	seedSyslog(t, h.db, day(10, 4, 1, 0))
	orig := stagingMinFree
	stagingMinFree = 1 << 50
	t.Cleanup(func() { stagingMinFree = orig })
	h.tick(ctx)
	c := h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkFailed || !strings.Contains(c.Error, "below the") || h.puts(`.`) != 0 {
		t.Fatalf("below the floor: %s %q, %d PUTs", c.Status, c.Error, h.puts(`.`))
	}
}

// TestWorker_WindowHoldsSyslogOnly: outside ARCHIVE_WINDOW (UTC, whatever the
// server's zone) no syslog chunk is started, while flows run; inside it the
// syslog day is archived.
func TestWorker_WindowHoldsSyslogOnly(t *testing.T) {
	start := day(10, 5, 10, 20)
	window := "12:00-13:00" // UTC; the first tick is at 10:30 UTC
	h := newHarness(t, start, func(c *config.ArchiveConfig) { c.Window = window })
	seedSyslog(t, h.db, day(10, 4, 1, 0))
	f := models.FlowSample{Timestamp: day(10, 5, 9, 0), DeviceID: 7, SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7"}
	if err := h.db.Gorm().Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	h.tick(ctx)
	if n := len(h.chunks(export.TableSyslog)); n != 0 {
		t.Fatalf("%d syslog chunks outside the window %s", n, window)
	}
	if fc := h.chunks(export.TableFlows); len(fc) != 1 || fc[0].Status != models.ArchiveChunkVerified {
		t.Fatalf("flows held by the syslog window: %+v", fc)
	}
	h.clk.add(2 * time.Hour)
	h.tick(ctx)
	if cs := h.chunks(export.TableSyslog); len(cs) != 1 || cs[0].Status != models.ArchiveChunkVerified {
		t.Fatalf("inside the window: %+v", cs)
	}
}

// TestWorker_SyslogSchemaByMonth: months before the stored `format` existed
// (migration v74) are written as syslog schema v1 (no format field) under
// v1/, the month it was applied in and later as v2.
func TestWorker_SyslogSchemaByMonth(t *testing.T) {
	h := newHarness(t, day(10, 7, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	if err := h.db.Gorm().Exec(`CREATE TABLE schema_migrations (version integer primary key, name text, app_version text, applied_at datetime)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := h.db.Gorm().Create(&models.SchemaMigration{Version: 74, Name: "syslog_format_column", AppVersion: "0.11.298", AppliedAt: day(10, 6, 9, 0)}).Error; err != nil {
		t.Fatal(err)
	}
	seedSyslog(t, h.db, day(9, 30, 22, 0), day(10, 1, 3, 0))
	h.tick(ctx)
	cs := h.chunks(export.TableSyslog)
	if len(cs) < 2 {
		t.Fatalf("%d chunks", len(cs))
	}
	for _, c := range cs[:2] {
		for _, o := range h.objects(c.ID) {
			want := map[string]int{"2026-09": 1, "2026-10": 2}[c.Month]
			if o.SchemaVersion != want || !strings.Contains(o.ObjectKey, "/syslog/v"+strconv.Itoa(want)+"/"+c.Month+"/") {
				t.Fatalf("%s: schema %d key %s, want v%d", c.Month, o.SchemaVersion, o.ObjectKey, want)
			}
			_, hasFormat := h.lines(o.ObjectKey)[0]["format"]
			if hasFormat != (want == 2) {
				t.Fatalf("%s: format field present=%v in schema v%d", c.Month, hasFormat, want)
			}
		}
	}
}

// TestWorker_TransientReadBackRetriesVerifyOnly: a 500 on the read-back says
// nothing about the stored object, so the chunk stays uploaded and verifying
// — no second data PUT, no new retained copy — and is read back again after
// its backoff.
func TestWorker_TransientReadBackRetriesVerifyOnly(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0), day(10, 4, 2, 0))
	h.srv.SetFail(func(op s3test.Op, _ *http.Request) (int, string) {
		if op == s3test.OpGetObject {
			return http.StatusInternalServerError, "InternalError"
		}
		return 0, ""
	})
	h.tick(ctx)
	c := h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkVerifying || c.VerifyFailures != 1 || c.Attempts != 1 || c.Mismatches != 0 {
		t.Fatalf("after a GET 500: %s verify_failures %d attempts %d mismatches %d", c.Status, c.VerifyFailures, c.Attempts, c.Mismatches)
	}
	h.srv.SetFail(nil)
	h.clk.add(30 * time.Second)
	h.w.pass(ctx)
	if c := h.chunks(export.TableSyslog)[0]; c.Status != models.ArchiveChunkVerifying {
		t.Fatalf("re-verified inside the backoff: %s", c.Status)
	}
	h.clk.add(time.Minute)
	h.w.pass(ctx)
	c = h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkVerified || c.Attempts != 1 {
		t.Fatalf("after the backoff: %s attempts %d", c.Status, c.Attempts)
	}
	if n := h.puts(`\.ndjson\.gz$`); n != 2 {
		t.Fatalf("%d data PUTs, want 2 (one per object, never re-sent)", n)
	}
}

// TestWorker_ResumedVerifyKeepsStoredManifest: the chunk.json is in the
// bucket when the final database update fails; the retry finds the identical
// manifest there and reads it back instead of writing it again.
func TestWorker_ResumedVerifyKeepsStoredManifest(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0))
	failed := false
	h.w.beforeMark = func(context.Context, *models.ArchiveChunk) error {
		if failed {
			return nil
		}
		failed = true
		return errors.New("database went away")
	}
	h.tick(ctx)
	if c := h.chunks(export.TableSyslog)[0]; c.Status != models.ArchiveChunkVerifying || c.VerifyFailures != 1 {
		t.Fatalf("after the failed mark: %s verify_failures %d", c.Status, c.VerifyFailures)
	}
	h.clk.add(2 * time.Minute)
	h.w.pass(ctx)
	if c := h.chunks(export.TableSyslog)[0]; c.Status != models.ArchiveChunkVerified {
		t.Fatalf("after the retry: %s", c.Status)
	}
	if n, d := h.puts(`chunk\.json$`), h.puts(`\.ndjson\.gz$`); n != 1 || d != 1 {
		t.Fatalf("%d chunk.json and %d data PUTs, want 1 and 1", n, d)
	}
}

// TestWorker_RepeatedMismatchStopsAtCap: a chunk whose read-back never
// matches is exported ArchiveMaxMismatches times, then parked in
// needs_attention (metric and log) and left alone: no further export, PUT or
// read-back of it.
func TestWorker_RepeatedMismatchStopsAtCap(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 4, 1, 0))
	h.srv.SetMutateGet(func(key string, b []byte) []byte {
		if strings.HasSuffix(key, ".ndjson.gz") {
			b[len(b)/2] ^= 0x01
		}
		return b
	})
	before := metricValue(t, `fwmon_archive_needs_attention_total{table="syslog_messages"}`)
	for range 6 {
		h.tick(ctx)
	}
	c := h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkNeedsAttention || c.Attempts != models.ArchiveMaxMismatches || c.Mismatches != models.ArchiveMaxMismatches {
		t.Fatalf("after repeated mismatches: %s attempts %d mismatches %d", c.Status, c.Attempts, c.Mismatches)
	}
	if n := h.puts(`\.ndjson\.gz$`); n != models.ArchiveMaxMismatches {
		t.Fatalf("%d data PUTs, want %d (one per export, then none)", n, models.ArchiveMaxMismatches)
	}
	if d := metricValue(t, `fwmon_archive_needs_attention_total{table="syslog_messages"}`) - before; d != 1 {
		t.Fatalf("needs_attention_total grew by %v", d)
	}
	if v := metricValue(t, `fwmon_archive_chunks{status="needs_attention",table="syslog_messages"}`); v != 1 {
		t.Fatalf("chunks{needs_attention} = %v", v)
	}
	n := len(h.srv.Requests())
	h.clk.add(48 * time.Hour)
	h.tick(ctx)
	for _, r := range h.srv.Requests()[n:] {
		if strings.Contains(r.Key, "/2026-10-04/") {
			t.Fatalf("a parked chunk was touched: %s %s", r.Op, r.Key)
		}
	}
}

// TestWorker_StagingRequiredAndProbed: no staging directory, no worker; a
// failed free-space probe refuses the export instead of writing blind.
func TestWorker_StagingRequiredAndProbed(t *testing.T) {
	h := newHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	cfg := h.cfg
	cfg.StagingDir = ""
	if _, err := newWorker(h.db, h.store, cfg); err == nil || !strings.Contains(err.Error(), "ARCHIVE_STAGING_DIR") {
		t.Fatalf("worker without a staging directory: %v", err)
	}
	seedSyslog(t, h.db, day(10, 4, 1, 0))
	stagingFree = func(context.Context, string) (uint64, error) { return 0, errors.New("statfs: permission denied") }
	h.tick(ctx)
	c := h.chunks(export.TableSyslog)[0]
	if c.Status != models.ArchiveChunkFailed || !strings.Contains(c.Error, "unknown") || h.puts(`.`) != 0 {
		t.Fatalf("free space unknown: %s %q, %d PUTs", c.Status, c.Error, h.puts(`.`))
	}
}
