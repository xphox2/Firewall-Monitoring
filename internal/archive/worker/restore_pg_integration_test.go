//go:build integration

package worker

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// pgTraffic is a synthetic FortiGate traffic line (RFC 5737 addresses,
// fw-example-01, alice).
const pgTraffic = `date=2026-10-01 time=12:00:01 devname="fw-example-01" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.10 srcport=%d srcintf="port2" srcintfrole="lan" dstip=203.0.113.20 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=%d proto=6 action="accept" policyid=10 policytype="policy" policyname="LAN-to-WAN" service="HTTPS" sentbyte=5231 rcvdbyte=12033 sentpkt=22 rcvdpkt=19 user="alice"`

// TestRestore_PG: on PostgreSQL 16 (partitioned syslog_messages, the pgx COPY
// path), a syslog day and a flow hour are archived, deleted from the live
// tables, restored to staging tables (LIKE the partitioned parent) with every
// column and the original ids, and the syslog day is re-normalized in replace
// mode twice: every traffic row has exactly one net_events row, the parser's,
// never the planted pre-fix one.
func TestRestore_PG(t *testing.T) {
	d := database.NewIntegrationDB(t)
	database.SetArchiveSettleForTesting(t, 200*time.Millisecond, 100*time.Millisecond)
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
	wall := time.Now().UTC()
	offset := wall.Truncate(time.Hour).Add(90 * time.Minute).Sub(wall)
	w.now = func() time.Time { return time.Now().UTC().Add(offset) }

	dev := models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate"}
	if err := d.Gorm().Create(&dev).Error; err != nil {
		t.Fatal(err)
	}
	dayStart := wall.Truncate(24*time.Hour).AddDate(0, 0, -2)
	const n = 40
	for i := 0; i < n; i++ {
		ts := dayStart.Add(time.Duration(9*60+i) * time.Minute)
		m := models.SyslogMessage{Timestamp: ts, DeviceID: dev.ID, ProbeID: 1, Hostname: "fw-example-01", AppName: "traffic",
			Message: fmt.Sprintf(pgTraffic, 40000+i, 2000000+i), Priority: 189, Facility: 20, Severity: 5, SourceIP: "192.0.2.1", CreatedAt: ts.Add(time.Second)}
		if i%2 == 0 {
			f := models.SyslogFormatFortiOSKV
			m.StoredFormat = &f
		}
		if err := d.Gorm().Create(&m).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, src := range []uint8{0, 1, 0} {
		start := wall.Add(-11 * time.Minute)
		f := models.FlowSample{Timestamp: wall.Add(-10 * time.Minute), DeviceID: dev.ID, ProbeID: 1, SamplerAddress: "192.0.2.1", SequenceNumber: 4000000000,
			SamplingRate: 1000, SrcAddr: "192.0.2.10", DstAddr: "2001:db8::7", SrcPort: 51234, DstPort: 443, Protocol: 6, Bytes: 1 << 40, Packets: 12,
			InputIfIndex: 4000000001, FlowSource: src, FlowStart: &start, ServicePort: 443, ClassRev: 9, ScopeLocal: true, SrcASN: 4200000000, AppName: "HTTPS.BROWSER"}
		if err := d.Gorm().Create(&f).Error; err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		w.lastPass = time.Time{}
		w.Tick(context.Background())
		var open, sys, fl int64
		d.Gorm().Model(&models.ArchiveChunk{}).Where("status <> ?", models.ArchiveChunkVerified).Count(&open)
		d.Gorm().Model(&models.ArchiveChunk{}).Where("table_name = ? AND row_count > 0", export.TableSyslog).Count(&sys)
		d.Gorm().Model(&models.ArchiveChunk{}).Where("table_name = ? AND row_count > 0", export.TableFlows).Count(&fl)
		if open == 0 && sys > 0 && fl > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not archived within 30 s (%d open)", open)
		}
		time.Sleep(200 * time.Millisecond)
	}
	var origSys []models.SyslogMessage
	var origFlows []models.FlowSample
	d.Gorm().Order("id").Find(&origSys)
	d.Gorm().Where("flow_source = 0").Order("id").Find(&origFlows)
	d.Gorm().Exec("DELETE FROM syslog_messages")
	d.Gorm().Exec("DELETE FROM flow_samples")

	// The pre-fix normalized rows of the first ten raw rows.
	var stale []models.NetEvent
	for _, m := range origSys[:10] {
		ts := m.Timestamp
		id := int64(m.ID)
		stale = append(stale, models.NetEvent{Ts: ts, DeviceID: dev.ID, Action: 99, RawID: &id, RawTS: &ts})
	}
	if err := d.SaveNetEvents(stale); err != nil {
		t.Fatal(err)
	}

	seedFreeSpace(t, d, 1<<40)
	queue := func(req database.ArchiveRestoreRequest) *models.ArchiveRestoreJob {
		req.RequestedBy = "alice"
		job, _, err := d.QueueArchiveRestore(context.Background(), req, time.Now())
		if err != nil {
			t.Fatalf("queue %s: %v", req.Stream, err)
		}
		return job
	}
	sysJob := queue(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: dayStart, To: dayStart, Renormalize: true, Replace: true})
	flowDay := wall.Add(-10 * time.Minute).Truncate(24 * time.Hour)
	flowJob := queue(database.ArchiveRestoreRequest{Stream: export.StreamSFlow, From: flowDay, To: flowDay})
	database.SetArchiveRestoreBatchForTesting(t, 7, nil)
	r, err := newRestoreWorker(d, client, cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.sleep = func(context.Context, time.Duration) error { return nil }
	r.Tick(context.Background())
	r.Tick(context.Background())
	for _, id := range []uint{sysJob.ID, flowJob.ID} {
		if j, _ := d.GetArchiveRestoreJob(id); j.Status != models.ArchiveRestoreDone || j.Error != "" {
			t.Fatalf("restore %d: %+v", id, j)
		}
	}
	var gotSys []models.SyslogMessage
	d.Gorm().Table(sysJob.StagingTable).Order("id").Find(&gotSys)
	if len(gotSys) != n {
		t.Fatalf("%d syslog rows staged, want %d", len(gotSys), n)
	}
	for i := range gotSys {
		g, o := gotSys[i], origSys[i]
		g.Timestamp, g.CreatedAt, o.Timestamp, o.CreatedAt = g.Timestamp.UTC(), g.CreatedAt.UTC(), o.Timestamp.UTC(), o.CreatedAt.UTC()
		if !reflect.DeepEqual(g, o) {
			t.Fatalf("syslog row %d:\n got %+v\nwant %+v", i, g, o)
		}
	}
	var gotFlows []models.FlowSample
	d.Gorm().Table(flowJob.StagingTable).Order("id").Find(&gotFlows)
	if len(gotFlows) != len(origFlows) || len(gotFlows) != 2 {
		t.Fatalf("%d flows staged, want the %d sflow rows", len(gotFlows), len(origFlows))
	}
	for i := range gotFlows {
		g, o := gotFlows[i], origFlows[i]
		norm := func(f *models.FlowSample) {
			f.Timestamp, f.CreatedAt = f.Timestamp.UTC(), f.CreatedAt.UTC()
			if f.FlowStart != nil {
				s := f.FlowStart.UTC()
				f.FlowStart = &s
			}
		}
		norm(&g)
		norm(&o)
		if !reflect.DeepEqual(g, o) {
			t.Fatalf("flow %d:\n got %+v\nwant %+v", i, g, o)
		}
	}

	// The queued replace backfill, then a second one: exactly one parser row
	// per raw row each time.
	runBackfill := func() *models.NormalizeBackfillJob {
		job, err := d.ClaimNextNormalizeBackfillJob("pg-runner")
		if err != nil || job == nil {
			t.Fatalf("claim: %v %v", job, err)
		}
		if err := d.RunNormalizeBackfill(context.Background(), job.ID, "pg-runner"); err != nil {
			t.Fatalf("backfill: %v", err)
		}
		got, _ := d.GetNormalizeBackfillJob(job.ID)
		return got
	}
	check := func(bf *models.NormalizeBackfillJob, replaced int64) {
		t.Helper()
		var rows, distinct, wrong int64
		d.Gorm().Model(&models.NetEvent{}).Count(&rows)
		d.Gorm().Raw("SELECT count(DISTINCT raw_id) FROM net_events").Scan(&distinct)
		d.Gorm().Model(&models.NetEvent{}).Where("action = ?", 99).Count(&wrong)
		if bf.Status != database.NormalizeBackfillStatusDone || rows != n || distinct != n || wrong != 0 || bf.RowsReplaced != replaced || bf.RowsWritten != n {
			t.Fatalf("after the replace backfill: %d net_events (%d distinct raw ids, %d pre-fix); job %+v", rows, distinct, wrong, bf)
		}
	}
	check(runBackfill(), 10)
	since, _ := database.ParseArchiveRestoreDay(sysJob.FromDay)
	again := &models.NormalizeBackfillJob{RequestedBy: "test", Since: since, Until: since.AddDate(0, 0, 1), RateRowsPerSec: database.NormalizeBackfillMaxRate,
		SourceTable: sysJob.StagingTable, Replace: true}
	if err := d.CreateNormalizeBackfillJob(again); err != nil {
		t.Fatal(err)
	}
	check(runBackfill(), n)

	if _, err := d.DropArchiveRestore(context.Background(), sysJob.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if d.Gorm().Migrator().HasTable(sysJob.StagingTable) {
		t.Fatal("the staging table survived its drop")
	}
}
