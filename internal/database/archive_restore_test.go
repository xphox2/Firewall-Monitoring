package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
)

// Archive restore to staging (archive plan PR 9), SQLite lane. Synthetic data
// only: RFC 5737 addresses, fw-example-NN, alice.

func rday(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }

func TestArchiveRestoreRequest_Validate(t *testing.T) {
	dev0 := uint(0)
	for name, tc := range map[string]struct {
		req ArchiveRestoreRequest
		ok  bool
	}{
		"syslog day":            {ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 1)}, true},
		"31 days":               {ArchiveRestoreRequest{Stream: "netflow", From: rday(10, 1), To: rday(10, 31)}, true},
		"32 days":               {ArchiveRestoreRequest{Stream: "netflow", From: rday(10, 1), To: rday(11, 1)}, false},
		"to before from":        {ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 2), To: rday(10, 1)}, false},
		"unknown stream":        {ArchiveRestoreRequest{Stream: "flows", From: rday(10, 1), To: rday(10, 1)}, false},
		"flow renormalize":      {ArchiveRestoreRequest{Stream: "sflow", From: rday(10, 1), To: rday(10, 1), Renormalize: true}, false},
		"replace alone":         {ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 1), Replace: true}, false},
		"renormalize + replace": {ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 1), Renormalize: true, Replace: true}, true},
		"rate too low":          {ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 1), Rate: 99}, false},
		"ttl too long":          {ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 1), TTLDays: 91}, false},
		"device 0":              {ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 1), DeviceID: &dev0}, false},
		"no days":               {ArchiveRestoreRequest{Stream: "syslog"}, false},
	} {
		err := tc.req.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && !errors.Is(err, ErrArchiveRestoreInvalid) {
			t.Errorf("%s: %v does not wrap ErrArchiveRestoreInvalid", name, err)
		}
		if tc.ok && (tc.req.Rate != ArchiveRestoreDefaultRate && tc.req.Rate == 0 || tc.req.TTLDays == 0) {
			t.Errorf("%s: defaults not filled: %+v", name, tc.req)
		}
	}
	if !IsArchiveRestoreTable("restore_12_syslog_messages") || IsArchiveRestoreTable("syslog_messages") ||
		IsArchiveRestoreTable("restore_1_syslog_messages; DROP TABLE x") || IsArchiveRestoreTable("restore_x_flow_samples") {
		t.Fatal("IsArchiveRestoreTable")
	}
}

// seedManifest records one verified syslog chunk with a verified object per
// device, a superseded object, and an sflow object of a flow chunk.
func seedManifest(t *testing.T, d *Database) {
	t.Helper()
	hist := func(s string) *string { return &s }
	ts := func(m time.Month, dd, h int) *time.Time { v := time.Date(2026, m, dd, h, 0, 0, 0, time.UTC); return &v }
	dev := func(v uint) *uint { return &v }
	c := models.ArchiveChunk{SourceTable: export.TableSyslog, Seq: 1, IDLo: 0, IDHi: 100, PeriodStart: rday(10, 2), PeriodEnd: rday(10, 3), Month: "2026-10",
		Status: models.ArchiveChunkVerified}
	f := models.ArchiveChunk{SourceTable: export.TableFlows, Seq: 1, IDLo: 0, IDHi: 50, PeriodStart: rday(10, 2), PeriodEnd: rday(10, 2).Add(time.Hour), Month: "2026-10",
		Status: models.ArchiveChunkVerified}
	for _, ch := range []*models.ArchiveChunk{&c, &f} {
		if err := d.db.Create(ch).Error; err != nil {
			t.Fatal(err)
		}
	}
	objs := []models.ArchiveObject{
		// Received on 2 Oct: device 1 holds rows of 1 and 2 Oct, device 2 of 2 Oct only.
		{ChunkID: c.ID, Stream: "syslog", DeviceID: dev(1), ObjectKey: "p/syslog/v2/2026-10/2026-10-02/device-1.ndjson.gz", SchemaVersion: 2, RowCount: 5,
			MinTs: ts(10, 1, 23), MaxTs: ts(10, 2, 9), MsgDayHistogram: hist(`{"2026-10-01":2,"2026-10-02":3}`), Status: models.ArchiveObjectVerified},
		{ChunkID: c.ID, Stream: "syslog", DeviceID: dev(2), ObjectKey: "p/syslog/v2/2026-10/2026-10-02/device-2.ndjson.gz", SchemaVersion: 2, RowCount: 4,
			MinTs: ts(10, 2, 1), MaxTs: ts(10, 2, 9), MsgDayHistogram: hist(`{"2026-10-02":4}`), Status: models.ArchiveObjectVerified},
		{ChunkID: c.ID, Stream: "syslog", DeviceID: dev(1), ObjectKey: "p/syslog/v2/2026-10/2026-10-02/device-1.ndjson.gz", SchemaVersion: 2, RowCount: 6,
			MinTs: ts(10, 1, 23), MaxTs: ts(10, 2, 9), MsgDayHistogram: hist(`{"2026-10-01":3,"2026-10-02":3}`), Status: models.ArchiveObjectSuperseded},
		{ChunkID: f.ID, Stream: "sflow", ObjectKey: "p/sflow/v1/2026-10/2026-10-02T00/flows.ndjson.gz", SchemaVersion: 1, RowCount: 7,
			MinTs: ts(10, 1, 23), MaxTs: ts(10, 2, 0), MsgDayHistogram: hist(`{"2026-10-01":1,"2026-10-02":6}`), Status: models.ArchiveObjectVerified},
	}
	if err := d.db.Create(&objs).Error; err != nil {
		t.Fatal(err)
	}
}

// TestSelectArchiveRestoreObjects: objects are picked by their message-day
// histogram (a row of 1 Oct received on 2 Oct is found), only verified ones,
// per stream, per device for syslog, with the rows of the requested days.
func TestSelectArchiveRestoreObjects(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedManifest(t, d)
	big := uint64(1 << 40)
	if err := d.db.Create(&models.ServerMetric{Timestamp: time.Now(), DataDiskFreeBytes: &big}).Error; err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	objs, rows, err := d.SelectArchiveRestoreObjects(ctx, "syslog", rday(10, 1), rday(10, 1), nil)
	if err != nil || len(objs) != 1 || rows != 2 || objs[0].DayRows != 2 || objs[0].RowCount != 5 || objs[0].ChunkIDHi != 100 || objs[0].ChunkSeq != 1 {
		t.Fatalf("1 Oct: %+v rows %d err %v", objs, rows, err)
	}
	if objs, rows, _ = d.SelectArchiveRestoreObjects(ctx, "syslog", rday(10, 1), rday(10, 2), nil); len(objs) != 2 || rows != 9 {
		t.Fatalf("1-2 Oct: %d objects, %d rows", len(objs), rows)
	}
	dev := uint(2)
	if objs, rows, _ = d.SelectArchiveRestoreObjects(ctx, "syslog", rday(10, 1), rday(10, 2), &dev); len(objs) != 1 || rows != 4 || !strings.HasSuffix(objs[0].ObjectKey, "device-2.ndjson.gz") {
		t.Fatalf("device 2: %+v", objs)
	}
	if objs, _, _ = d.SelectArchiveRestoreObjects(ctx, "syslog", rday(10, 3), rday(10, 4), nil); len(objs) != 0 {
		t.Fatalf("3-4 Oct: %+v", objs)
	}
	if objs, rows, _ = d.SelectArchiveRestoreObjects(ctx, "sflow", rday(10, 1), rday(10, 1), &dev); len(objs) != 1 || rows != 1 {
		t.Fatalf("sflow 1 Oct (flow objects hold every device): %+v", objs)
	}
	if objs, _, _ = d.SelectArchiveRestoreObjects(ctx, "netflow", rday(10, 1), rday(10, 2), nil); len(objs) != 0 {
		t.Fatalf("netflow: %+v", objs)
	}
	if _, _, err := d.QueueArchiveRestore(ctx, ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 5), To: rday(10, 5)}, time.Now()); !errors.Is(err, ErrArchiveRestoreNothing) {
		t.Fatalf("nothing archived for the day: %v", err)
	}
	job, _, err := d.QueueArchiveRestore(ctx, ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 2), RequestedBy: "alice"}, time.Now())
	if err != nil || job.ObjectsTotal != 2 || job.RowsEstimate != 9 || job.SelectedAt == nil || !strings.Contains(job.Note, "verified through") {
		t.Fatalf("queued: %+v %v", job, err)
	}
}

// TestQueueArchiveRestore_DiskPrecheck: a restore is refused while the
// database volume's free space is unknown, or when its staged rows (plus,
// re-normalized, their normalized rows) would take half of it or more;
// force queues it anyway and the job carries the force.
func TestQueueArchiveRestore_DiskPrecheck(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedManifest(t, d)
	req := ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 2)}
	if _, est, err := d.QueueArchiveRestore(context.Background(), req, time.Now()); !errors.Is(err, ErrArchiveRestoreDisk) || est.FreeKnown || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown free space: %+v %v", est, err)
	}
	forced := req
	forced.Force = true
	if job, _, err := d.QueueArchiveRestore(context.Background(), forced, time.Now()); err != nil || !job.Force {
		t.Fatalf("forced: %+v %v", job, err)
	}
	if _, _, err := d.QueueArchiveRestore(context.Background(), ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 2), FromBucket: true}, time.Now()); err != nil {
		t.Fatalf("a bucket restore is prechecked by the worker after its selection: %v", err)
	}
	free := uint64(2*9*1300 + 1) // room for the staged rows ...
	if err := d.db.Create(&models.ServerMetric{Timestamp: time.Now().Add(-time.Second), DataDiskFreeBytes: &free}).Error; err != nil {
		t.Fatal(err)
	}
	renorm := ArchiveRestoreRequest{Stream: "syslog", From: rday(10, 1), To: rday(10, 2), Renormalize: true}
	if _, est, err := d.QueueArchiveRestore(context.Background(), renorm, time.Now()); !errors.Is(err, ErrArchiveRestoreDisk) || est.NormalizedBytes != 9*512 {
		t.Fatalf("... not for their normalized rows too: %+v %v", est, err)
	}
	free = uint64(2 * 9 * 1300) // exactly twice the estimate: not under half
	if err := d.db.Create(&models.ServerMetric{Timestamp: time.Now(), DataDiskFreeBytes: &free}).Error; err != nil {
		t.Fatal(err)
	}
	_, est, err := d.QueueArchiveRestore(context.Background(), req, time.Now())
	if !errors.Is(err, ErrArchiveRestoreDisk) || est.Bytes != 9*1300 || !est.FreeKnown || est.Enough {
		t.Fatalf("precheck: %+v %v", est, err)
	}
	free++
	if err := d.db.Create(&models.ServerMetric{Timestamp: time.Now().Add(time.Second), DataDiskFreeBytes: &free}).Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.QueueArchiveRestore(context.Background(), req, time.Now()); err != nil {
		t.Fatalf("with room: %v", err)
	}
}

// stagingJob creates a syslog restore job row and its staging table.
func stagingJob(t *testing.T, d *Database) *models.ArchiveRestoreJob {
	t.Helper()
	job := &models.ArchiveRestoreJob{Stream: "syslog", SourceTable: export.TableSyslog, FromDay: "2026-10-01", ToDay: "2026-10-01",
		Status: models.ArchiveRestoreDone, ExpiresAt: time.Now().Add(time.Hour)}
	if err := d.db.Create(job).Error; err != nil {
		t.Fatal(err)
	}
	job.StagingTable = ArchiveRestoreTableName(job.ID, export.TableSyslog)
	d.db.Model(job).Update("staging_table", job.StagingTable)
	if err := d.EnsureArchiveRestoreTable(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureArchiveRestoreTable(context.Background(), job); err != nil {
		t.Fatalf("a second ensure: %v", err)
	}
	return job
}

// TestArchiveRestore_StagingOutsideRetention: the retention pass, which
// deletes old syslog_messages rows, leaves a staging table's identical rows
// alone; dropping the restore removes the table and nothing else.
func TestArchiveRestore_StagingOutsideRetention(t *testing.T) {
	d := NewDatabaseForTesting(t)
	job := stagingJob(t, d)
	old := time.Now().Add(-90 * 24 * time.Hour).UTC()
	for i := 1; i <= 5; i++ {
		m := models.SyslogMessage{ID: uint(i), Timestamp: old, DeviceID: 1, ProbeID: 1, Hostname: "fw-example-01", Message: "srcip=192.0.2.10", Severity: 3, CreatedAt: old}
		if err := d.db.Create(&m).Error; err != nil {
			t.Fatal(err)
		}
		if err := d.db.Table(job.StagingTable).Create(&m).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 30, SyslogCriticalDays: 30, SyslogInfoDays: 7, FlowDays: 30}); err != nil {
		t.Fatal(err)
	}
	var live, staged int64
	d.db.Model(&models.SyslogMessage{}).Count(&live)
	d.db.Table(job.StagingTable).Count(&staged)
	if live != 0 || staged != 5 {
		t.Fatalf("after retention: %d live (want 0), %d staged (want 5)", live, staged)
	}
	if _, err := d.DropArchiveRestore(context.Background(), job.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if d.db.Migrator().HasTable(job.StagingTable) || !d.db.Migrator().HasTable("syslog_messages") {
		t.Fatal("drop: wrong tables")
	}
	if _, err := d.DropArchiveRestore(context.Background(), job.ID, time.Now()); !errors.Is(err, ErrArchiveRestoreBusy) {
		t.Fatalf("a second drop: %v", err)
	}
}

// restoreBackfillFixture stages, for a FortiGate device, traffic and login
// rows of the last two days plus one traffic and one login row older than
// the net_events retention floor, and one row of a device that no longer
// exists. Ids are the archive's (well above anything in syslog_messages).
type rbFixture struct {
	job                  *models.ArchiveRestoreJob
	dev                  *models.Device
	rows                 []models.SyslogMessage
	net, sec             int // in-retention traffic, logins (any age)
	oldNet, gone, unpars int
	since, until         time.Time
}

func restoreBackfillFixture(t *testing.T, d *Database, n int) rbFixture {
	t.Helper()
	f := rbFixture{dev: &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate"}}
	if err := d.db.Create(f.dev).Error; err != nil {
		t.Fatal(err)
	}
	f.job = stagingJob(t, d)
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Add(-48 * time.Hour)
	add := func(id int, ts time.Time, dev uint, app, msg string) {
		f.rows = append(f.rows, models.SyslogMessage{ID: uint(id), Timestamp: ts, DeviceID: dev, ProbeID: 1, Hostname: "fw-example-01",
			AppName: app, Message: msg, Severity: 5, Facility: 20, SourceIP: "192.0.2.1", CreatedAt: ts.Add(72 * time.Hour)})
	}
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(i-i%3) * time.Minute)
		switch {
		case i%25 == 0:
			add(100000+i, ts, f.dev.ID, "event", bfUnparsed)
			f.unpars++
		case i%10 == 0:
			add(100000+i, ts, f.dev.ID, "event", bfLogin)
			f.sec++
		default:
			add(100000+i, ts, f.dev.ID, "traffic", fmt.Sprintf(bfTraffic, 40000+i, 2000000+i, 10+i%3, i%3, i%3))
			f.net++
		}
	}
	old := now.AddDate(0, 0, -60)
	add(90001, old, f.dev.ID, "traffic", fmt.Sprintf(bfTraffic, 40000, 2000000, 10, 0, 0))
	f.oldNet++
	add(90002, old.Add(time.Second), f.dev.ID, "event", bfLogin)
	f.sec++
	add(90003, start.Add(time.Minute), 4242, "traffic", fmt.Sprintf(bfTraffic, 40001, 2000001, 10, 0, 0))
	f.gone++
	if err := d.db.Table(f.job.StagingTable).CreateInBatches(&f.rows, 100).Error; err != nil {
		t.Fatal(err)
	}
	f.since, f.until = utcDay(old), utcDay(now).AddDate(0, 0, 1)
	return f
}

func queueRestoreBackfill(t *testing.T, d *Database, f rbFixture, replace bool) *models.NormalizeBackfillJob {
	t.Helper()
	id := f.job.ID
	job := &models.NormalizeBackfillJob{RequestedBy: "archive restore", Since: f.since, Until: f.until, RateRowsPerSec: NormalizeBackfillMaxRate,
		SourceTable: f.job.StagingTable, RestoreJobID: &id, Replace: replace}
	if err := d.CreateNormalizeBackfillJob(job); err != nil {
		t.Fatal(err)
	}
	return job
}

// staleRows plants "pre-fix" normalized rows for the first k traffic rows
// (a wrong action) and puts the first login's row in net_events (a wrong
// class), as an older parser might have.
func staleRows(t *testing.T, d *Database, f rbFixture, k int) (stale int) {
	t.Helper()
	var nets []models.NetEvent
	login := false
	for _, m := range f.rows {
		if m.DeviceID != f.dev.ID || m.Timestamp.Before(time.Now().AddDate(0, 0, -30)) {
			continue
		}
		switch {
		case m.AppName == "traffic" && k > 0:
			k--
		case m.Message == bfLogin && !login:
			login = true
		default:
			continue
		}
		ts := m.Timestamp
		nets = append(nets, models.NetEvent{Ts: ts, DeviceID: f.dev.ID, Action: 99, RawID: ptrInt64(int64(m.ID)), RawTS: &ts})
	}
	if err := d.SaveNetEvents(nets); err != nil {
		t.Fatal(err)
	}
	return len(nets)
}

// TestNormalizeBackfill_RestoreReplaceExactlyOnce: a replace-mode backfill
// over a restore's staging table rewrites the pre-fix rows (wrong action,
// wrong class) so every parsed raw row has exactly one normalized row, the
// parser's; a batch that dies inside its transaction and is resumed changes
// nothing; a second replace run leaves the same rows. A raw row whose re-parse
// writes nothing — unparsed, or older than its target table's retention (the
// old traffic row below the net_events floor, the old login below a 50-day
// sec_events retention) — keeps its earlier rows (rows_kept). Rows of a
// device that no longer exists are skipped, and the rollup rewind is queued.
func TestNormalizeBackfill_RestoreReplaceExactlyOnce(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.secEventRetentionDays = 50
	prevBatch := normalizeBackfillBatchSize
	normalizeBackfillBatchSize = 40
	t.Cleanup(func() { normalizeBackfillBatchSize = prevBatch })
	f := restoreBackfillFixture(t, d, 300)
	stale := staleRows(t, d, f, 30)
	// Pre-fix rows of raw rows whose re-parse writes nothing: the first
	// unparsed row, and the traffic row older than the net_events floor.
	var keep []models.NetEvent
	for _, m := range f.rows {
		if (m.Message == bfUnparsed && len(keep) == 0) || m.ID == 90001 {
			ts := m.Timestamp
			keep = append(keep, models.NetEvent{Ts: ts, DeviceID: f.dev.ID, Action: 99, RawID: ptrInt64(int64(m.ID)), RawTS: &ts})
		}
	}
	if len(keep) != 2 {
		t.Fatalf("%d rows to keep", len(keep))
	}
	if err := d.SaveNetEvents(keep); err != nil {
		t.Fatal(err)
	}
	written := f.net + f.sec - 1 // the old login is below the sec_events retention

	// Batch 3 dies inside its transaction (its delete, inserts and cursor
	// roll back together).
	normalizeBackfillTxHook = func(batch int) error {
		if batch == 3 {
			return errors.New("simulated crash")
		}
		return nil
	}
	job := queueRestoreBackfill(t, d, f, true)
	got, err := bfRun(t, d, job.ID)
	normalizeBackfillTxHook = nil
	if err == nil || got.Status != NormalizeBackfillStatusFailed || got.RowsScanned != 80 {
		t.Fatalf("after the crash: %v %+v", err, got)
	}
	if ok, err := d.ResumeNormalizeBackfillJob(job.ID); !ok || err != nil {
		t.Fatalf("resume: %v %v", ok, err)
	}
	got, err = bfRun(t, d, job.ID)
	if err != nil || got.Status != NormalizeBackfillStatusDone {
		t.Fatalf("resumed run: %v %+v", err, got)
	}
	check := func(run string, j *models.NormalizeBackfillJob, wantReplaced int) {
		t.Helper()
		net, sec, distinct := bfCounts(t, d) // fails on any raw id normalized twice
		if net != int64(f.net+2) || sec != int64(f.sec-1) || distinct != int64(written+2) {
			t.Fatalf("%s: %d net / %d sec / %d raw ids; want %d net (2 kept), %d sec (every parsed row exactly once)", run, net, sec, distinct, f.net+2, f.sec-1)
		}
		var wrong int64
		d.db.Model(&models.NetEvent{}).Where("action = ? AND raw_id IN ?", 99, []int64{int64(*keep[0].RawID), 90001}).Count(&wrong)
		var all99 int64
		d.db.Model(&models.NetEvent{}).Where("action = ?", 99).Count(&all99)
		if wrong != 2 || all99 != 2 {
			t.Fatalf("%s: %d pre-fix rows left (%d of the two kept); want exactly the 2 kept", run, all99, wrong)
		}
		if j.RowsReplaced != int64(wantReplaced) || j.RowsKept != 2 || j.RowsOutOfRetention != 2 || j.RowsSkipped != int64(f.gone) ||
			j.RowsUnparsed != int64(f.unpars) || j.RowsScanned != int64(len(f.rows)) || j.RowsWritten != int64(written) {
			t.Fatalf("%s counters: %+v (want replaced %d)", run, j, wantReplaced)
		}
	}
	check("first run", got, stale)
	observed := func() (n int64) {
		d.db.Raw("SELECT COALESCE(SUM(count), 0) FROM device_field_observed").Scan(&n)
		return n
	}
	obs := observed()
	if obs == 0 {
		t.Fatal("no device_field_observed counts")
	}
	var logins int64
	d.db.Model(&models.SecEvent{}).Where("class = ?", int16(normalize.ClassAuth)).Count(&logins)
	if logins == 0 {
		t.Fatal("no login reached sec_events")
	}
	if v, ok := d.GetSettingValue(netEventRollupRewindKey); !ok || v != utcDay(f.since).AddDate(0, 0, -1).Format("2006-01-02") {
		t.Fatalf("rewind marker %q %v", v, ok)
	}

	// A second replace run over the same table: the same rows, each raw row
	// with a normalized row now replaced once more.
	job2 := queueRestoreBackfill(t, d, f, true)
	got2, err := bfRun(t, d, job2.ID)
	if err != nil {
		t.Fatal(err)
	}
	check("second run", got2, written) // every row written is replaced
	if o := observed(); o != obs {
		t.Fatalf("device_field_observed counted the replaced rows again: %d, was %d", o, obs)
	}
}

// TestNormalizeBackfill_RestoreSkipMode: without replace, a raw row that
// already has a normalized row keeps it (the stale one stays) and a re-run
// writes nothing new.
func TestNormalizeBackfill_RestoreSkipMode(t *testing.T) {
	d := NewDatabaseForTesting(t)
	f := restoreBackfillFixture(t, d, 60)
	stale := staleRows(t, d, f, 5)
	got, err := bfRun(t, d, queueRestoreBackfill(t, d, f, false).ID)
	if err != nil || got.RowsSkipped != int64(stale+f.gone) || got.RowsReplaced != 0 || got.RowsWritten != int64(f.net+f.sec-stale) {
		t.Fatalf("skip mode: %v %+v (stale %d)", err, got, stale)
	}
	var wrong int64
	d.db.Model(&models.NetEvent{}).Where("action = ?", 99).Count(&wrong)
	if wrong != int64(stale) {
		t.Fatalf("%d stale rows left, want %d (skip mode keeps them)", wrong, stale)
	}
	again, err := bfRun(t, d, queueRestoreBackfill(t, d, f, false).ID)
	if err != nil || again.RowsWritten != 0 {
		t.Fatalf("re-run wrote %d: %v", again.RowsWritten, err)
	}
	if _, _, distinct := bfCounts(t, d); distinct != int64(f.net+f.sec) {
		t.Fatalf("%d raw ids normalized, want %d", distinct, f.net+f.sec)
	}
}

// TestNormalizeBackfill_RestoreSourceGuards: a source table that is not a
// syslog staging table, or one that was dropped, fails the job before any
// row is read.
func TestNormalizeBackfill_RestoreSourceGuards(t *testing.T) {
	d := NewDatabaseForTesting(t)
	for _, src := range []string{"syslog_messages", "restore_1_flow_samples", "restore_7_syslog_messages"} {
		job := &models.NormalizeBackfillJob{Since: rday(10, 1), Until: rday(10, 2), SourceTable: src, RateRowsPerSec: NormalizeBackfillMaxRate}
		if err := d.CreateNormalizeBackfillJob(job); err != nil {
			t.Fatal(err)
		}
		got, err := bfRun(t, d, job.ID)
		if err == nil || got.Status != NormalizeBackfillStatusFailed || got.RowsScanned != 0 {
			t.Fatalf("%s: %v %+v", src, err, got)
		}
	}
}
