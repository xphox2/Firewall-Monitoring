//go:build integration

package worker

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestWorker_PG runs the archive worker on a wall PostgreSQL (TEST_PG_DSN):
// the advisory lock keeps a second holder out, the settle guard runs for
// wall (shrunk to a fraction of a second), and syslog days plus one flow
// hour go through export, upload, read-back and the count check to verified.
func TestWorker_PG(t *testing.T) {
	d := database.NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	srv := s3test.NewB2Strict(t, testBucket)
	cfg := testConfig(srv, t.TempDir())
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client, err := s3.New(cfg, s3.WithRootCAs(pool), s3.WithMaxAttempts(1))
	if err != nil {
		t.Fatal(err)
	}
	orig := stagingFree
	stagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { stagingFree = orig })
	w, err := newWorker(d, client, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The worker's clock runs 30-90 minutes ahead of the database's, at half
	// past an hour, so the first flow hour is due whenever the test runs. The
	// settle guard itself uses the database clock.
	wall := time.Now().UTC()
	offset := wall.Truncate(time.Hour).Add(90 * time.Minute).Sub(wall)
	w.now = func() time.Time { return time.Now().UTC().Add(offset) }

	today := wall.Truncate(24 * time.Hour)
	var syslogRows int64
	for i, c := range []time.Time{today.AddDate(0, 0, -3).Add(9 * time.Hour), today.AddDate(0, 0, -3).Add(15 * time.Hour), today.AddDate(0, 0, -2).Add(9 * time.Hour)} {
		m := models.SyslogMessage{Timestamp: c.Add(-time.Second), DeviceID: uint(1 + i%2), ProbeID: 1, Hostname: "fw-example-01",
			Message: "srcip=192.0.2.10 dstip=198.51.100.7", Severity: 5, CreatedAt: c}
		if err := d.Gorm().Create(&m).Error; err != nil {
			t.Fatal(err)
		}
		syslogRows++
	}
	for _, src := range []uint8{0, 1, 0, 3} {
		f := models.FlowSample{Timestamp: wall.Add(-10 * time.Minute), DeviceID: 7, SamplerAddress: "192.0.2.1", SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7", FlowSource: src}
		if err := d.Gorm().Create(&f).Error; err != nil {
			t.Fatal(err)
		}
	}

	// Another session holds the archive lock: the tick does nothing at all.
	release, ok, err := d.AcquireArchiveLock()
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	w.Tick(context.Background())
	if n := len(srv.Requests()); n != 0 {
		t.Fatalf("a tick without the lock made %d requests", n)
	}
	var marks int64
	d.Gorm().Model(&models.ArchiveIDMark{}).Count(&marks)
	if marks != 0 {
		t.Fatalf("a tick without the lock took %d marks", marks)
	}
	release()

	// No statement_timeout: no cut can be proven settled, so nothing is
	// planned, and the metric says why.
	database.SetArchiveSettleForTesting(t, 0, 100*time.Millisecond)
	w.Tick(context.Background())
	var planned int64
	d.Gorm().Model(&models.ArchiveChunk{}).Count(&planned)
	if planned != 0 || metricValue(t, `fwmon_archive_unsettled{reason="no_statement_timeout",table="syslog_messages"}`) != 1 {
		t.Fatalf("without a statement_timeout: %d chunks planned, unsettled metric %v", planned,
			metricValue(t, `fwmon_archive_unsettled{reason="no_statement_timeout",table="syslog_messages"}`))
	}
	database.SetArchiveSettleForTesting(t, 200*time.Millisecond, 100*time.Millisecond)

	// The first tick marks and plans; chunks wait out the settle window
	// (cut_at + 300 ms) and are exported by the following passes.
	deadline := time.Now().Add(30 * time.Second)
	for {
		w.lastPass = time.Time{}
		w.Tick(context.Background())
		var open int64
		d.Gorm().Model(&models.ArchiveChunk{}).Where("status <> ?", models.ArchiveChunkVerified).Count(&open)
		var all int64
		d.Gorm().Model(&models.ArchiveChunk{}).Count(&all)
		if all > 0 && open == 0 {
			break
		}
		if time.Now().After(deadline) {
			var cs []models.ArchiveChunk
			d.Gorm().Order("id").Find(&cs)
			t.Fatalf("chunks not verified within 30 s: %+v", cs)
		}
		time.Sleep(200 * time.Millisecond)
	}

	var sys []models.ArchiveChunk
	d.Gorm().Where("table_name = ?", export.TableSyslog).Order("seq").Find(&sys)
	var got int64
	for _, c := range sys {
		if c.GuardXmax == nil {
			t.Fatalf("syslog chunk %d verified without a settle guard", c.Seq)
		}
		got += c.RowCount
	}
	if len(sys) < 2 || got != syslogRows || sys[0].RowCount != 2 || sys[1].RowCount != 1 {
		t.Fatalf("syslog chunks %+v: %d rows, want %d (2 then 1)", sys, got, syslogRows)
	}
	var fl []models.ArchiveChunk
	d.Gorm().Where("table_name = ?", export.TableFlows).Order("seq").Find(&fl)
	if len(fl) != 1 || fl[0].RowCount != 4 || fl[0].GuardXmax == nil {
		t.Fatalf("flow chunks %+v", fl)
	}
	var objs []models.ArchiveObject
	d.Gorm().Where("chunk_id = ?", fl[0].ID).Order("stream").Find(&objs)
	if len(objs) != 2 || objs[0].Stream != export.StreamNetFlow || objs[0].RowCount != 2 || objs[1].RowCount != 2 ||
		objs[0].Status != models.ArchiveObjectVerified || !strings.HasSuffix(objs[1].ObjectKey, "/flows.ndjson.gz") {
		t.Fatalf("flow objects %+v", objs)
	}
}

// TestWorker_PG_TwoWorkers: two pollers' workers ticking at the same time on
// one database archive every chunk exactly once — the advisory lock lets one
// in at a time and the other's tick returns — so no object or manifest is
// uploaded twice.
func TestWorker_PG_TwoWorkers(t *testing.T) {
	d := database.NewIntegrationDB(t)
	database.SetArchiveSettleForTesting(t, 200*time.Millisecond, 100*time.Millisecond)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	srv := s3test.NewB2Strict(t, testBucket)
	cfg := testConfig(srv, t.TempDir())
	cfg.FlowsEnabled = false
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	orig := stagingFree
	stagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { stagingFree = orig })
	var ws [2]*Worker
	for i := range ws {
		client, err := s3.New(cfg, s3.WithRootCAs(pool), s3.WithMaxAttempts(1))
		if err != nil {
			t.Fatal(err)
		}
		c := cfg
		c.StagingDir = t.TempDir()
		if ws[i], err = newWorker(d, client, c); err != nil {
			t.Fatal(err)
		}
		ws[i].runner = "worker-" + string(rune('a'+i))
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for i, c := range []time.Time{today.AddDate(0, 0, -3).Add(9 * time.Hour), today.AddDate(0, 0, -2).Add(9 * time.Hour), today.AddDate(0, 0, -2).Add(10 * time.Hour)} {
		m := models.SyslogMessage{Timestamp: c, DeviceID: uint(1 + i%2), ProbeID: 1, Hostname: "fw-example-01",
			Message: "srcip=192.0.2.10 dstip=198.51.100.7", Severity: 5, CreatedAt: c}
		if err := d.Gorm().Create(&m).Error; err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		done := make(chan struct{}, 2)
		for _, w := range ws {
			w.lastPass = time.Time{}
			go func() { w.Tick(context.Background()); done <- struct{}{} }()
		}
		<-done
		<-done
		var open, all int64
		d.Gorm().Model(&models.ArchiveChunk{}).Where("status <> ?", models.ArchiveChunkVerified).Count(&open)
		d.Gorm().Model(&models.ArchiveChunk{}).Count(&all)
		if all >= 2 && open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not verified within 30 s: %d of %d open", open, all)
		}
		time.Sleep(200 * time.Millisecond)
	}
	puts := map[string]int{}
	for _, r := range srv.Requests() {
		if r.Op == s3test.OpPutObject {
			puts[r.Key]++
		}
	}
	if len(puts) == 0 {
		t.Fatal("nothing was uploaded")
	}
	for k, n := range puts {
		if n != 1 {
			t.Errorf("%s uploaded %d times", k, n)
		}
	}
	var attempts []int
	d.Gorm().Model(&models.ArchiveChunk{}).Order("seq").Pluck("attempts", &attempts)
	for i, a := range attempts {
		if a != 1 {
			t.Errorf("chunk %d exported %d times", i+1, a)
		}
	}
}

// TestWorker_PG_LeafMoveDuringExport: a partition move recorded while a
// chunk is being exported (its rows may be missing from the export) makes the
// attempt wait — nothing uploaded, no mismatch counted — and the next pass
// exports and verifies the chunk.
func TestWorker_PG_LeafMoveDuringExport(t *testing.T) {
	d := database.NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	srv := s3test.NewB2Strict(t, testBucket)
	cfg := testConfig(srv, t.TempDir())
	cfg.FlowsEnabled = false
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client, err := s3.New(cfg, s3.WithRootCAs(pool), s3.WithMaxAttempts(1))
	if err != nil {
		t.Fatal(err)
	}
	orig := stagingFree
	stagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { stagingFree = orig })
	w, err := newWorker(d, client, cfg)
	if err != nil {
		t.Fatal(err)
	}
	database.SetArchiveSettleForTesting(t, 200*time.Millisecond, 100*time.Millisecond)
	wall := time.Now().UTC()
	day := wall.Truncate(24*time.Hour).AddDate(0, 0, -2).Add(9 * time.Hour)
	for i := 0; i < 3; i++ {
		m := models.SyslogMessage{Timestamp: day.Add(time.Duration(i) * time.Minute), DeviceID: 1, ProbeID: 1, Hostname: "fw-example-01",
			Message: "srcip=192.0.2.10 dstip=198.51.100.7", Severity: 5, CreatedAt: day.Add(time.Duration(i) * time.Minute)}
		if err := d.Gorm().Create(&m).Error; err != nil {
			t.Fatal(err)
		}
	}
	moves := 0
	w.afterExport = func(context.Context, *models.ArchiveChunk) error {
		if moves == 0 {
			database.BumpArchiveLeafMoveEpochForTesting(t, d, export.TableSyslog)
		}
		moves++
		return nil
	}
	tick := func() []models.ArchiveChunk {
		w.lastPass = time.Time{}
		w.Tick(context.Background())
		var cs []models.ArchiveChunk
		d.Gorm().Where("table_name = ?", export.TableSyslog).Order("seq").Find(&cs)
		return cs
	}
	deadline := time.Now().Add(30 * time.Second)
	for moves == 0 {
		tick()
		if time.Now().After(deadline) {
			t.Fatal("no export within 30 s")
		}
		time.Sleep(200 * time.Millisecond)
	}
	var c models.ArchiveChunk
	d.Gorm().Where("table_name = ?", export.TableSyslog).Order("seq").First(&c)
	var objs int64
	d.Gorm().Model(&models.ArchiveObject{}).Where("chunk_id = ?", c.ID).Count(&objs)
	if c.Status == models.ArchiveChunkVerified || c.Mismatches != 0 || objs != 0 || srv.Count(s3test.OpPutObject) != 0 {
		t.Fatalf("after a move during the export: %+v, %d objects, %d PUTs; want unverified, no mismatch, nothing recorded or uploaded", c, objs, srv.Count(s3test.OpPutObject))
	}
	if metricValue(t, `fwmon_archive_unsettled{reason="unattached_leaf",table="syslog_messages"}`) != 1 {
		t.Fatal("the unsettled metric does not say unattached_leaf")
	}
	for {
		cs := tick()
		if len(cs) > 0 && cs[0].Status == models.ArchiveChunkVerified {
			if cs[0].Mismatches != 0 {
				t.Fatalf("verified with %d mismatches counted", cs[0].Mismatches)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not verified after the move: %+v", cs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
