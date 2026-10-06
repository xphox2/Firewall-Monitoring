package database

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm/schema"

	"firewall-mon/internal/models"
)

// S-5 (v0.11.297) unit tests on the SQLite lane. The PostgreSQL-only pieces —
// the per-leaf walk, the COPY path inside the batch transaction, the dedup
// probe against the daily leaves — are in normalize_backfill_pg_integration_test.go,
// which seeds the same shape at 30 000 rows.

// Synthetic FortiGate lines (RFC 5737 addresses, fw-example-01, alice). The
// traffic line is network class; the login line is auth class (sec_events);
// the odd line is key=value a FortiGate mapper cannot place (unparsed).
const (
	bfTraffic  = `date=2026-10-01 time=12:00:01 devname="fw-example-01" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.10 srcport=%d srcintf="port2" srcintfrole="lan" dstip=203.0.113.20 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=%d proto=6 action="accept" policyid=%d policytype="policy" poluuid="4b5c6d7e-0000-0000-0000-00000000000%d" policyname="LAN-to-WAN-%d" service="HTTPS" sentbyte=5231 rcvdbyte=12033 sentpkt=22 rcvdpkt=19 user="alice"`
	bfLogin    = `date=2026-10-01 time=12:03:00 devname="fw-example-01" devid="FGT60FTK00000000" logid="0100032001" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" user="alice" ui="https(192.0.2.10)" method="https" srcip=192.0.2.10 dstip=192.0.2.1 action="login" status="success" reason="none" profile="super_admin" msg="Administrator alice logged in successfully"`
	bfUnparsed = `logid="9999999999" type="nonesuch" subtype="x" level="notice" vd="root" msg="not a thing"`
)

// bfFixture is the seeded shape: n rows for dev over [start, start+span),
// every 10th a login (sec), every 25th unparsed, the rest traffic (net), with
// runs of three rows sharing one timestamp so the keyset pager has equal keys
// to get right at batch boundaries. created_at = ts (UTC): every row is
// "received" before the watermark.
type bfFixture struct {
	rows          []models.SyslogMessage
	net, sec, unp int
	first, last   time.Time
}

func seedBackfillRows(t *testing.T, d *Database, dev uint, start time.Time, span time.Duration, n int) bfFixture {
	t.Helper()
	f := bfFixture{first: start}
	step := span / time.Duration(n)
	for i := 0; i < n; i++ {
		ts := start.Add(step * time.Duration(i-i%3)) // runs of three equal timestamps
		m := models.SyslogMessage{Timestamp: ts, DeviceID: dev, ProbeID: 1, Hostname: "fw-example-01", Severity: 5, Facility: 20, CreatedAt: ts, SourceIP: "192.0.2.1"}
		switch {
		case i%25 == 0:
			m.AppName, m.Message = "event", bfUnparsed
			f.unp++
		case i%10 == 0:
			m.AppName, m.Message = "event", bfLogin
			f.sec++
		default:
			m.AppName, m.Message = "traffic", fmt.Sprintf(bfTraffic, 40000+i, 2000000+i, 10+i%3, i%3, i%3)
			f.net++
		}
		f.rows = append(f.rows, m)
		f.last = ts
	}
	if err := d.db.CreateInBatches(&f.rows, 200).Error; err != nil {
		t.Fatalf("seed syslog rows: %v", err)
	}
	return f
}

// bfSetup: a FortiGate device, the fixture over the last three days (ending
// an hour ago), the ingest watermark half an hour ago, a small batch size.
func bfSetup(t *testing.T, n int) (*Database, bfFixture, *models.Device, time.Time) {
	t.Helper()
	d := NewDatabaseForTesting(t)
	dev := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate"}
	if err := d.db.Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	f := seedBackfillRows(t, d, dev.ID, now.Add(-72*time.Hour), 71*time.Hour, n)
	until := now.Add(-30 * time.Minute)
	if _, err := d.InsertSettingIfAbsent(&models.SystemSetting{Key: NormalizeIngestStartedSetting, Value: until.Format(time.RFC3339), Type: "string"}); err != nil {
		t.Fatal(err)
	}
	orig := normalizeBackfillBatchSize
	normalizeBackfillBatchSize = 50
	t.Cleanup(func() { normalizeBackfillBatchSize = orig })
	return d, f, dev, until
}

func bfQueue(t *testing.T, d *Database, deviceID *uint) *models.NormalizeBackfillJob {
	t.Helper()
	since, until, err := d.NormalizeBackfillBounds(30, time.Now())
	if err != nil {
		t.Fatalf("bounds: %v", err)
	}
	job := &models.NormalizeBackfillJob{RequestedBy: "test", Since: since, Until: until, DeviceID: deviceID, RateRowsPerSec: NormalizeBackfillMaxRate}
	if err := d.CreateNormalizeBackfillJob(job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	return job
}

// bfRunner is the owner token the tests claim and run jobs under.
const bfRunner = "test-runner"

// bfRun claims and runs the job like the worker does, returning the row.
func bfRun(t *testing.T, d *Database, id uint) (*models.NormalizeBackfillJob, error) {
	t.Helper()
	won, err := d.ClaimNormalizeBackfillJob(id, bfRunner)
	if err != nil || !won {
		t.Fatalf("claim job %d: won=%v err=%v", id, won, err)
	}
	runErr := d.RunNormalizeBackfill(context.Background(), id, bfRunner)
	job, err := d.GetNormalizeBackfillJob(id)
	if err != nil {
		t.Fatal(err)
	}
	return job, runErr
}

func bfCounts(t *testing.T, d *Database) (net, sec int64, distinctRaw int64) {
	t.Helper()
	d.db.Model(&models.NetEvent{}).Count(&net)
	d.db.Model(&models.SecEvent{}).Count(&sec)
	var ids []int64
	if err := d.db.Raw("SELECT raw_id FROM net_events UNION ALL SELECT raw_id FROM sec_events").Scan(&ids).Error; err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if id == 0 {
			t.Fatal("a normalized row has no raw_id")
		}
		if seen[id] {
			t.Fatalf("raw_id %d normalized twice", id)
		}
		seen[id] = true
	}
	return net, sec, int64(len(seen))
}

// TestNormalizeBackfill_EndToEnd: every raw row in the window is visited once
// (keyset paging over runs of equal timestamps), the network class lands in
// net_events and the rest in sec_events with real raw_ids, unparsed rows are
// counted and stored nowhere, denied_events and the alert path are untouched,
// fw_rules spans the EVENT times, device_field_observed.last_seen is the
// newest event time (not now), the rewind marker names the day before the
// window, and a second job over the same window writes nothing (dedup).
func TestNormalizeBackfill_EndToEnd(t *testing.T) {
	d, f, _, until := bfSetup(t, 300)
	job := bfQueue(t, d, nil)
	if !job.Until.Equal(until) {
		t.Fatalf("job.Until = %s, want the watermark %s", job.Until, until)
	}
	job, err := bfRun(t, d, job.ID)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if job.Status != NormalizeBackfillStatusDone || job.Error != "" || job.FinishedAt == nil || job.StartedAt == nil {
		t.Fatalf("job after run: %+v", job)
	}
	if job.RowsScanned != int64(len(f.rows)) || job.RowsWritten != int64(f.net+f.sec) || job.RowsUnparsed != int64(f.unp) || job.RowsSkipped != 0 {
		t.Fatalf("counters scanned=%d written=%d unparsed=%d skipped=%d; want %d/%d/%d/0", job.RowsScanned, job.RowsWritten, job.RowsUnparsed, job.RowsSkipped, len(f.rows), f.net+f.sec, f.unp)
	}
	if job.CursorTs == nil || !job.CursorTs.Equal(f.last) || job.CursorID != int64(f.rows[len(f.rows)-1].ID) {
		t.Fatalf("cursor = %v/%d, want %s/%d", job.CursorTs, job.CursorID, f.last, f.rows[len(f.rows)-1].ID)
	}
	net, sec, distinct := bfCounts(t, d)
	if net != int64(f.net) || sec != int64(f.sec) || distinct != int64(f.net+f.sec) {
		t.Fatalf("net=%d sec=%d distinct raw=%d; want %d/%d/%d", net, sec, distinct, f.net, f.sec, f.net+f.sec)
	}
	var denied int64
	d.db.Model(&models.DeniedEvent{}).Count(&denied)
	if denied != 0 {
		t.Fatalf("the backfill projected %d denied_events rows; history must not re-run the live-stream projection", denied)
	}
	// Provenance: raw_ts is the syslog row's timestamp, ts equals it.
	var mismatched int64
	d.db.Raw("SELECT COUNT(*) FROM net_events WHERE raw_ts IS NULL OR raw_ts <> ts").Scan(&mismatched)
	if mismatched != 0 {
		t.Fatalf("%d net_events rows have raw_ts <> ts", mismatched)
	}
	// fw_rules: three policies, first_seen / last_seen at event times.
	var rules []models.FwRule
	if err := d.db.Order("rule_key").Find(&rules).Error; err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("fw_rules has %d rows, want 3: %+v", len(rules), rules)
	}
	for _, r := range rules {
		if r.FirstSeen.Before(f.first) || r.LastSeen.After(f.last) || !r.LastSeen.After(r.FirstSeen) {
			t.Fatalf("fw_rules %s spans [%s, %s], want inside the fixture [%s, %s]", r.RuleKey, r.FirstSeen, r.LastSeen, f.first, f.last)
		}
		if r.LastSeen.After(until) {
			t.Fatalf("fw_rules %s last_seen %s is after the watermark — stamped with now, not the event time", r.RuleKey, r.LastSeen)
		}
	}
	// device_field_observed: last_seen is the newest EVENT time, never now.
	obs, err := d.GetFieldObserved(0, f.first.Add(-time.Minute))
	if err != nil || len(obs) == 0 {
		t.Fatalf("GetFieldObserved: %d rows, %v", len(obs), err)
	}
	var total int64
	for _, o := range obs {
		total += o.Count
		if o.LastSeen.After(f.last) {
			t.Fatalf("device_field_observed %s last_seen %s is after the last event %s (stamped with now)", o.Field, o.LastSeen, f.last)
		}
	}
	if total == 0 {
		t.Fatal("device_field_observed recorded nothing")
	}
	// Rewind marker: the day before the window's first day.
	wantDay := utcDay(job.Since).AddDate(0, 0, -1).Format("2006-01-02")
	if v, ok := d.GetSettingValue(netEventRollupRewindKey); !ok || v != wantDay {
		t.Fatalf("rewind marker = %q %v, want %q", v, ok, wantDay)
	}

	// Second job, same window: every row already has a normalized row.
	job2 := bfQueue(t, d, nil)
	job2, err = bfRun(t, d, job2.ID)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if job2.Status != NormalizeBackfillStatusDone || job2.RowsWritten != 0 || job2.RowsSkipped != int64(f.net+f.sec) || job2.RowsUnparsed != int64(f.unp) {
		t.Fatalf("second job: %+v (want 0 written, %d skipped)", job2, f.net+f.sec)
	}
	if n2, s2, _ := bfCounts(t, d); n2 != net || s2 != sec {
		t.Fatalf("second job changed the tables: net %d→%d sec %d→%d", net, n2, sec, s2)
	}
}

// TestNormalizeBackfill_DeviceFilter: a device-scoped job walks only that
// device's rows.
func TestNormalizeBackfill_DeviceFilter(t *testing.T) {
	d, f, dev, _ := bfSetup(t, 120)
	other := &models.Device{Name: "fw-example-02", IPAddress: "192.0.2.2", Vendor: "fortigate"}
	if err := d.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	g := seedBackfillRows(t, d, other.ID, time.Now().UTC().Add(-48*time.Hour), 40*time.Hour, 60)
	job := bfQueue(t, d, &other.ID)
	job, err := bfRun(t, d, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.RowsScanned != int64(len(g.rows)) || job.RowsWritten != int64(g.net+g.sec) {
		t.Fatalf("device-scoped job scanned %d / wrote %d, want %d / %d (the other device has %d rows)", job.RowsScanned, job.RowsWritten, len(g.rows), g.net+g.sec, len(f.rows))
	}
	var foreign int64
	d.db.Model(&models.NetEvent{}).Where("device_id <> ?", other.ID).Count(&foreign)
	if foreign != 0 {
		t.Fatalf("%d net_events rows belong to another device", foreign)
	}
	_ = dev
}

// TestNormalizeBackfill_CancelThenResume_NoDuplicates: a cancel requested
// after the second batch is honoured at the next checkpoint (cancelled,
// cursor kept, partial rows), resume puts the job back to pending and the
// rerun continues from the cursor to the exact totals — no raw row twice.
func TestNormalizeBackfill_CancelThenResume_NoDuplicates(t *testing.T) {
	d, f, _, _ := bfSetup(t, 300)
	job := bfQueue(t, d, nil)
	normalizeBackfillBatchHook = func(j *models.NormalizeBackfillJob, batch int) error {
		if batch == 2 {
			if st, ok, err := d.CancelNormalizeBackfillJob(j.ID); err != nil || !ok || st != NormalizeBackfillStatusCancelling {
				t.Errorf("cancel from the hook: %s %v %v", st, ok, err)
			}
		}
		return nil
	}
	t.Cleanup(func() { normalizeBackfillBatchHook = nil })
	job, err := bfRun(t, d, job.ID)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if job.Status != NormalizeBackfillStatusCancelled || job.CursorTs == nil || job.RowsScanned != 100 {
		t.Fatalf("after cancel: %+v (want cancelled after 2 batches of 50)", job)
	}
	net1, _, _ := bfCounts(t, d)
	if net1 == 0 || net1 >= int64(f.net) {
		t.Fatalf("partial net_events = %d, want between 1 and %d", net1, f.net-1)
	}
	// The cancelled job's days are queued for a rollup re-close too.
	if _, ok := d.GetSettingValue(netEventRollupRewindKey); !ok {
		t.Fatal("a cancelled job that wrote rows left no rewind marker")
	}
	normalizeBackfillBatchHook = nil

	applied, err := d.ResumeNormalizeBackfillJob(job.ID)
	if err != nil || !applied {
		t.Fatalf("resume: applied=%v err=%v", applied, err)
	}
	job, err = bfRun(t, d, job.ID)
	if err != nil {
		t.Fatalf("resumed run: %v", err)
	}
	if job.Status != NormalizeBackfillStatusDone || job.RowsScanned != int64(len(f.rows)) || job.RowsWritten != int64(f.net+f.sec) || job.RowsSkipped != 0 {
		t.Fatalf("after resume: %+v; want done, %d scanned, %d written, 0 skipped", job, len(f.rows), f.net+f.sec)
	}
	net, sec, distinct := bfCounts(t, d)
	if net != int64(f.net) || sec != int64(f.sec) || distinct != int64(f.net+f.sec) {
		t.Fatalf("after resume net=%d sec=%d distinct=%d; want %d/%d/%d", net, sec, distinct, f.net, f.sec, f.net+f.sec)
	}
}

// TestNormalizeBackfill_BatchIsOneTransaction: a failure injected INSIDE the
// third batch's transaction (after the typed rows, before the cursor) rolls
// the whole batch back — net_events holds exactly the first two batches'
// rows, the cursor is the end of batch two — and a resume completes to the
// exact totals. With the rows written outside the transaction the count after
// the failure would include batch three.
func TestNormalizeBackfill_BatchIsOneTransaction(t *testing.T) {
	d, f, _, _ := bfSetup(t, 300)
	job := bfQueue(t, d, nil)
	boom := errors.New("injected: crash between the COPY and the cursor update")
	normalizeBackfillTxHook = func(batch int) error {
		if batch == 3 {
			return boom
		}
		return nil
	}
	t.Cleanup(func() { normalizeBackfillTxHook = nil })
	job, err := bfRun(t, d, job.ID)
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("run error = %v, want the injected failure", err)
	}
	if job.Status != NormalizeBackfillStatusFailed || job.RowsScanned != 100 || job.CursorID != int64(f.rows[99].ID) {
		t.Fatalf("after the failed batch: %+v; want failed, 100 scanned, cursor at raw id %d", job, f.rows[99].ID)
	}
	wantNet, wantSec := 0, 0
	for i := 0; i < 100; i++ {
		switch {
		case i%25 == 0:
		case i%10 == 0:
			wantSec++
		default:
			wantNet++
		}
	}
	net, sec, _ := bfCounts(t, d)
	if net != int64(wantNet) || sec != int64(wantSec) {
		t.Fatalf("after the rolled-back batch net=%d sec=%d, want exactly the first two batches %d/%d", net, sec, wantNet, wantSec)
	}
	normalizeBackfillTxHook = nil
	if applied, err := d.ResumeNormalizeBackfillJob(job.ID); err != nil || !applied {
		t.Fatalf("resume: %v %v", applied, err)
	}
	job, err = bfRun(t, d, job.ID)
	if err != nil || job.Status != NormalizeBackfillStatusDone {
		t.Fatalf("resumed run: %v %+v", err, job)
	}
	net, sec, distinct := bfCounts(t, d)
	if net != int64(f.net) || sec != int64(f.sec) || distinct != int64(f.net+f.sec) || job.RowsSkipped != 0 {
		t.Fatalf("after resume net=%d sec=%d distinct=%d skipped=%d; want %d/%d/%d/0", net, sec, distinct, job.RowsSkipped, f.net, f.sec, f.net+f.sec)
	}
}

// TestNormalizeBackfill_LiveRowsAreSkipped: a raw row the live ingest already
// normalized (created_at past the watermark — a replayed spool) is out of
// scope, and one inside the window that already has a net_events row (the
// batch that wrote the watermark) is skipped by the dedup probe.
func TestNormalizeBackfill_LiveRowsAreSkipped(t *testing.T) {
	d, f, dev, until := bfSetup(t, 60)
	// A spool replay: old timestamp, received after the watermark.
	replay := models.SyslogMessage{Timestamp: f.first.Add(time.Hour), DeviceID: dev.ID, ProbeID: 1, Hostname: "fw-example-01", AppName: "traffic", Severity: 5, Facility: 20,
		CreatedAt: until.Add(time.Minute), Message: fmt.Sprintf(bfTraffic, 50000, 3000000, 10, 0, 0)}
	if err := d.db.Create(&replay).Error; err != nil {
		t.Fatal(err)
	}
	// The watermark batch: a row in the window that the live ingest stored.
	first := f.rows[1]
	if err := d.SaveNetEvents([]models.NetEvent{{Ts: first.Timestamp, DeviceID: dev.ID, RawID: ptrInt64(int64(first.ID)), RawTS: &first.Timestamp}}); err != nil {
		t.Fatal(err)
	}
	job := bfQueue(t, d, nil)
	job, err := bfRun(t, d, job.ID)
	if err != nil || job.Status != NormalizeBackfillStatusDone {
		t.Fatalf("%v %+v", err, job)
	}
	if job.RowsScanned != int64(len(f.rows)) || job.RowsSkipped != 1 || job.RowsWritten != int64(f.net+f.sec-1) {
		t.Fatalf("scanned=%d skipped=%d written=%d; want %d scanned (replay out of scope), 1 skipped, %d written", job.RowsScanned, job.RowsSkipped, job.RowsWritten, len(f.rows), f.net+f.sec-1)
	}
	var n int64
	d.db.Model(&models.NetEvent{}).Where("raw_id = ?", first.ID).Count(&n)
	if n != 1 {
		t.Fatalf("raw row %d has %d net_events rows, want exactly the live one", first.ID, n)
	}
	d.db.Model(&models.NetEvent{}).Where("raw_id = ?", replay.ID).Count(&n)
	if n != 0 {
		t.Fatalf("the replayed row (created after the watermark) was backfilled")
	}
}

func ptrInt64(v int64) *int64 { return &v }

// TestNormalizeBackfill_RollupRewind: the marker a finished job leaves moves
// the closed-day cursor back on the next rollup cycle (and only back: a
// cursor already before it is left alone), clears the close-failure count
// and is consumed.
func TestNormalizeBackfill_RollupRewind(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.setSetting(d.db, netEventRollupClosedDayKey, "2026-10-02"); err != nil {
		t.Fatal(err)
	}
	if err := d.setSetting(d.db, netEventRollupCloseFailuresKey, "2026-10-02:1:2026-10-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := d.setSetting(d.db, netEventRollupRewindKey, "2026-09-29"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.runNetEventRollupCycle(rollupFixtureNow); err != nil {
		t.Fatal(err)
	}
	if v, _ := d.GetSettingValue(netEventRollupClosedDayKey); v != "2026-09-29" {
		t.Fatalf("closed day after rewind = %q, want 2026-09-29", v)
	}
	if _, ok := d.GetSettingValue(netEventRollupCloseFailuresKey); ok {
		t.Fatal("close-failure count survived the rewind")
	}
	if _, ok := d.GetSettingValue(netEventRollupRewindKey); ok {
		t.Fatal("rewind marker was not consumed")
	}
	// A marker later than the cursor does not move it forward.
	if err := d.setSetting(d.db, netEventRollupRewindKey, "2026-10-01"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.runNetEventRollupCycle(rollupFixtureNow); err != nil {
		t.Fatal(err)
	}
	if v, _ := d.GetSettingValue(netEventRollupClosedDayKey); v != "2026-09-29" {
		t.Fatalf("closed day moved forward to %q by a later marker", v)
	}
	// finishBackfillJob keeps the earlier of two markers.
	job := &models.NormalizeBackfillJob{Since: time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC), Until: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), RowsWritten: 5, Status: NormalizeBackfillStatusRunning, RunnerID: bfRunner}
	if err := d.db.Create(job).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.setSetting(d.db, netEventRollupRewindKey, "2026-09-20"); err != nil {
		t.Fatal(err)
	}
	if err := d.finishBackfillJob(job.ID, bfRunner, NormalizeBackfillStatusDone, nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := d.GetSettingValue(netEventRollupRewindKey); v != "2026-09-20" {
		t.Fatalf("marker = %q after a later job finished, want the earlier 2026-09-20 kept", v)
	}
}

// TestNormalizeBackfill_Bounds: no watermark → ErrNormalizeNotStarted; since
// is clamped to the net_events retention floor; an empty window errors.
func TestNormalizeBackfill_Bounds(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if _, _, err := d.NormalizeBackfillBounds(30, time.Now()); !errors.Is(err, ErrNormalizeNotStarted) {
		t.Fatalf("without the watermark: %v", err)
	}
	now := time.Date(2026, 10, 4, 15, 0, 0, 0, time.UTC)
	wm := now.Add(-time.Hour)
	if _, err := d.InsertSettingIfAbsent(&models.SystemSetting{Key: NormalizeIngestStartedSetting, Value: wm.Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	since, until, err := d.NormalizeBackfillBounds(30, now)
	if err != nil || !until.Equal(wm) {
		t.Fatalf("bounds: %s %s %v", since, until, err)
	}
	// 30 days back from 15:00 is before the floor (30 days back from midnight
	// UTC... the floor is utcDay(now)-30d = 2026-09-04 00:00; now-30d = 09-04
	// 15:00 is after it): since is now-30d.
	if !since.Equal(now.AddDate(0, 0, -30)) {
		t.Fatalf("since = %s, want now-30d", since)
	}
	// With the default lookback a 60-day ask is clamped to the maximum.
	if s2, _, _ := d.NormalizeBackfillBounds(60, now); !s2.Equal(since) {
		t.Fatalf("since_days 60 → %s, want clamped to %s", s2, since)
	}
	if s3, _, _ := d.NormalizeBackfillBounds(3, now); !s3.Equal(now.AddDate(0, 0, -3)) {
		t.Fatalf("since_days 3 → %s", s3)
	}
	// The floor: a watermark far in the past gives an empty window.
	d2 := NewDatabaseForTesting(t)
	if _, err := d2.InsertSettingIfAbsent(&models.SystemSetting{Key: NormalizeIngestStartedSetting, Value: now.AddDate(0, 0, -40).Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d2.NormalizeBackfillBounds(30, now); !errors.Is(err, ErrNormalizeBackfillEmpty) {
		t.Fatalf("watermark older than the floor: %v", err)
	}
}

// TestNormalizeBackfill_JobLifecycle: one active job at a time, cancel CAS
// (pending → cancelled, running → cancelling, done → not applied), resume only
// from cancelled / failed, stale requeue of running / paused rows.
func TestNormalizeBackfill_JobLifecycle(t *testing.T) {
	d := NewDatabaseForTesting(t)
	since, until := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	job := &models.NormalizeBackfillJob{Since: since, Until: until}
	if err := d.CreateNormalizeBackfillJob(job); err != nil {
		t.Fatal(err)
	}
	if job.Status != NormalizeBackfillStatusPending || job.RateRowsPerSec != NormalizeBackfillDefaultRate {
		t.Fatalf("created: %+v", job)
	}
	if err := d.CreateNormalizeBackfillJob(&models.NormalizeBackfillJob{Since: since, Until: until}); !errors.Is(err, ErrNormalizeBackfillActive) {
		t.Fatalf("second active job: %v", err)
	}
	if err := d.CreateNormalizeBackfillJob(&models.NormalizeBackfillJob{Since: until, Until: since}); !errors.Is(err, ErrNormalizeBackfillEmpty) {
		t.Fatalf("inverted window: %v", err)
	}
	if err := d.CreateNormalizeBackfillJob(&models.NormalizeBackfillJob{Since: since, Until: until, Window: "25:00-06:00"}); err == nil {
		t.Fatal("a bad run window was accepted")
	}
	st, ok, err := d.CancelNormalizeBackfillJob(job.ID)
	if err != nil || !ok || st != NormalizeBackfillStatusCancelled {
		t.Fatalf("cancel pending: %s %v %v", st, ok, err)
	}
	if _, ok, _ := d.CancelNormalizeBackfillJob(job.ID); ok {
		t.Fatal("a cancelled job was cancelled again")
	}
	if applied, err := d.ResumeNormalizeBackfillJob(job.ID); err != nil || !applied {
		t.Fatalf("resume cancelled: %v %v", applied, err)
	}
	if won, err := d.ClaimNormalizeBackfillJob(job.ID, bfRunner); err != nil || !won {
		t.Fatalf("claim: %v %v", won, err)
	}
	if won, _ := d.ClaimNormalizeBackfillJob(job.ID, bfRunner); won {
		t.Fatal("claimed twice")
	}
	if applied, _ := d.ResumeNormalizeBackfillJob(job.ID); applied {
		t.Fatal("a running job was resumed")
	}
	st, ok, err = d.CancelNormalizeBackfillJob(job.ID)
	if err != nil || !ok || st != NormalizeBackfillStatusCancelling {
		t.Fatalf("cancel running: %s %v %v", st, ok, err)
	}
	// Stale: a cancelling row with an old heartbeat is finished as cancelled.
	d.db.Model(&models.NormalizeBackfillJob{}).Where("id = ?", job.ID).Update("updated_at", time.Now().Add(-time.Hour))
	if n, err := d.RequeueStaleNormalizeBackfillJobs(normalizeBackfillStaleAfter); err != nil || n != 0 {
		t.Fatalf("requeue: %d %v", n, err)
	}
	got, _ := d.GetNormalizeBackfillJob(job.ID)
	if got.Status != NormalizeBackfillStatusCancelled {
		t.Fatalf("stale cancelling → %s, want cancelled", got.Status)
	}
	// Stale running → pending.
	j2 := &models.NormalizeBackfillJob{Since: since, Until: until}
	if err := d.CreateNormalizeBackfillJob(j2); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimNormalizeBackfillJob(j2.ID, bfRunner); err != nil {
		t.Fatal(err)
	}
	d.db.Model(&models.NormalizeBackfillJob{}).Where("id = ?", j2.ID).Update("updated_at", time.Now().Add(-time.Hour))
	if n, _ := d.RequeueStaleNormalizeBackfillJobs(normalizeBackfillStaleAfter); n != 1 {
		t.Fatalf("requeued %d, want 1", n)
	}
	next, err := d.ClaimNextNormalizeBackfillJob(bfRunner)
	if err != nil || next == nil || next.ID != j2.ID || next.Status != NormalizeBackfillStatusRunning {
		t.Fatalf("claim next: %+v %v", next, err)
	}
	if active, _ := d.GetActiveNormalizeBackfillJob(); active == nil || active.ID != j2.ID {
		t.Fatalf("active = %+v", active)
	}
	if latest, _ := d.GetLatestNormalizeBackfillJob(); latest.ID != j2.ID {
		t.Fatalf("latest = %d", latest.ID)
	}
	if list, _ := d.ListNormalizeBackfillJobs(10); len(list) != 2 || list[0].ID != j2.ID {
		t.Fatalf("list = %+v", list)
	}
}

// TestNormalizeBackfill_RunWindowPauses: outside its window the job is
// `paused` and heartbeats; once the window opens it runs to the end.
func TestNormalizeBackfill_RunWindowPauses(t *testing.T) {
	d, f, _, _ := bfSetup(t, 100)
	since, until, err := d.NormalizeBackfillBounds(30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	job := &models.NormalizeBackfillJob{Since: since, Until: until, Window: "22:00-06:00", RateRowsPerSec: NormalizeBackfillMaxRate}
	if err := d.CreateNormalizeBackfillJob(job); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local).Unix()) // noon: outside
	origNow, origStep := normalizeBackfillNow, normalizeBackfillPauseStep
	normalizeBackfillNow = func() time.Time { return time.Unix(clock.Load(), 0) }
	normalizeBackfillPauseStep = 20 * time.Millisecond
	t.Cleanup(func() { normalizeBackfillNow, normalizeBackfillPauseStep = origNow, origStep })

	if _, err := d.ClaimNormalizeBackfillJob(job.ID, bfRunner); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var runErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr = d.RunNormalizeBackfill(context.Background(), job.ID, bfRunner)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := d.GetNormalizeBackfillJob(job.ID)
		if got.Status == NormalizeBackfillStatusPaused {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job never paused: %+v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n, _, _ := bfCounts(t, d); n != 0 {
		t.Fatalf("%d rows written while outside the run window", n)
	}
	clock.Store(time.Date(2026, 10, 4, 23, 0, 0, 0, time.Local).Unix()) // 23:00: inside
	wg.Wait()
	if runErr != nil {
		t.Fatalf("run: %v", runErr)
	}
	got, _ := d.GetNormalizeBackfillJob(job.ID)
	if got.Status != NormalizeBackfillStatusDone || got.RowsWritten != int64(f.net+f.sec) {
		t.Fatalf("after the window opened: %+v", got)
	}
}

// TestNormalizeBackfill_ShutdownRequeues: a cancelled context between
// batches puts the job back to pending with its cursor, and the next run
// resumes from there.
func TestNormalizeBackfill_ShutdownRequeues(t *testing.T) {
	d, f, _, _ := bfSetup(t, 200)
	job := bfQueue(t, d, nil)
	ctx, cancel := context.WithCancel(context.Background())
	normalizeBackfillBatchHook = func(_ *models.NormalizeBackfillJob, batch int) error {
		if batch == 2 {
			cancel()
		}
		return nil
	}
	t.Cleanup(func() { normalizeBackfillBatchHook = nil; cancel() })
	if _, err := d.ClaimNormalizeBackfillJob(job.ID, bfRunner); err != nil {
		t.Fatal(err)
	}
	if err := d.RunNormalizeBackfill(ctx, job.ID, bfRunner); !errors.Is(err, context.Canceled) {
		t.Fatalf("run under a cancelled ctx: %v", err)
	}
	got, _ := d.GetNormalizeBackfillJob(job.ID)
	if got.Status != NormalizeBackfillStatusPending || got.RowsScanned != 100 || got.CursorTs == nil {
		t.Fatalf("after shutdown: %+v (want pending, 100 scanned, cursor kept)", got)
	}
	normalizeBackfillBatchHook = nil
	got, err := bfRun(t, d, job.ID)
	if err != nil || got.Status != NormalizeBackfillStatusDone || got.RowsWritten != int64(f.net+f.sec) || got.RowsSkipped != 0 {
		t.Fatalf("resumed after shutdown: %v %+v", err, got)
	}
}

func TestBackfillPace(t *testing.T) {
	if p := backfillPace(5000, 2000, 500*time.Millisecond); p != 2*time.Second {
		t.Fatalf("5000 rows at 2000/s after 0.5 s: sleep %s, want 2s", p)
	}
	if p := backfillPace(5000, 2000, 3*time.Second); p != 0 {
		t.Fatalf("a slow batch must not sleep: %s", p)
	}
	if p := backfillPace(0, 2000, 0); p != 0 {
		t.Fatalf("no rows: %s", p)
	}
	if p := backfillPace(100, 0, 0); p != 0 {
		t.Fatalf("no rate: %s", p)
	}
	if p := backfillPace(100, 100000, 0); p != time.Millisecond {
		t.Fatalf("100 rows at 100k/s: %s, want 1ms", p)
	}
}

func TestParseRunWindow(t *testing.T) {
	if _, ok, err := parseRunWindow(""); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	for _, bad := range []string{"22:00", "22:00-", "25:00-06:00", "22:00-22:00", "10pm-6am", "22:00-06:00-07:00"} {
		if _, _, err := parseRunWindow(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	w, ok, err := parseRunWindow(" 22:00-06:00 ")
	if !ok || err != nil {
		t.Fatal(err)
	}
	at := func(h, m int) time.Time { return time.Date(2026, 10, 4, h, m, 0, 0, time.Local) }
	for _, c := range []struct {
		t    time.Time
		want bool
	}{{at(21, 59), false}, {at(22, 0), true}, {at(23, 30), true}, {at(0, 0), true}, {at(5, 59), true}, {at(6, 0), false}, {at(12, 0), false}} {
		if got := w.contains(c.t); got != c.want {
			t.Errorf("22:00-06:00 contains %s = %v, want %v", c.t.Format("15:04"), got, c.want)
		}
	}
	day, _, _ := parseRunWindow("09:00-17:00")
	if !day.contains(at(12, 0)) || day.contains(at(17, 0)) || day.contains(at(8, 59)) {
		t.Fatal("09:00-17:00 bounds")
	}
}

func TestSinceDaysArg(t *testing.T) {
	for in, want := range map[string]int{"30d": 30, "7": 7, " 1d ": 1} {
		if got, err := SinceDaysArg(in); err != nil || got != want {
			t.Errorf("%q → %d %v, want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"0", "31", "-1", "x", "", "30h"} {
		if _, err := SinceDaysArg(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestSecEventsCopyColumns_MatchModel pins the sec_events COPY pair to the
// model, like TestNetEventsCopyColumns_MatchModel.
func TestSecEventsCopyColumns_MatchModel(t *testing.T) {
	var cache sync.Map
	sch, err := schema.Parse(&models.SecEvent{}, &cache, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, f := range sch.Fields {
		if f.DBName != "" && f.DBName != "id" {
			want = append(want, f.DBName)
		}
	}
	if !reflect.DeepEqual(secEventsCopyColumns, want) {
		t.Fatalf("secEventsCopyColumns =\n%v\nwant (model order, no id)\n%v", secEventsCopyColumns, want)
	}
	if row := secEventCopyRow(&models.SecEvent{}); len(row) != len(secEventsCopyColumns) {
		t.Fatalf("secEventCopyRow renders %d values for %d columns", len(row), len(secEventsCopyColumns))
	}
}

// TestParsePartitionBound: both bound markers, every rendering.
func TestParsePartitionBound(t *testing.T) {
	b := "FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00')"
	lo, ok := parsePartitionBound(b, "FROM ('")
	if !ok || lo.Format("2006-01-02") != "2026-09-01" {
		t.Fatalf("lower = %s %v", lo, ok)
	}
	hi, ok := parsePartitionUpperBound(b)
	if !ok || hi.Format("2006-01-02") != "2026-10-01" {
		t.Fatalf("upper = %s %v", hi, ok)
	}
	if _, ok := parsePartitionBound("DEFAULT", "FROM ('"); ok {
		t.Fatal("DEFAULT parsed as a range")
	}
}

// TestBackfillResumePosition: a resumed job continues in its partition after
// its cursor; when that partition was dropped it continues at the first LEAF
// starting after the cursor — which is ranges[0] when there is no DEFAULT
// child (a dropped-partition resume used to skip it), never a DEFAULT child.
func TestBackfillResumePosition(t *testing.T) {
	oct, nov, dec := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	sep20 := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	leaves := []backfillRange{{table: "syslog_messages_2026_10", lo: oct, hi: nov}, {table: "syslog_messages_2026_11", lo: nov, hi: dec}}
	withDefault := append([]backfillRange{{table: "syslog_messages_default", lo: sep20, hi: dec, isDefault: true}}, leaves...)

	if i, ts, id := backfillResumePosition(leaves, "", nil, 0); i != 0 || !ts.Equal(oct) || id != 0 {
		t.Fatalf("fresh: %d %s %d", i, ts, id)
	}
	c := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	if i, ts, id := backfillResumePosition(leaves, "syslog_messages_2026_11", &c, 42); i != 1 || !ts.Equal(c) || id != 42 {
		t.Fatalf("in its partition: %d %s %d", i, ts, id)
	}
	// The September leaf the cursor was in has been dropped; no DEFAULT child.
	if i, ts, id := backfillResumePosition(leaves, "syslog_messages_2026_09", &sep20, 7); i != 0 || !ts.Equal(oct) || id != 0 {
		t.Fatalf("dropped partition, no DEFAULT: idx %d ts %s id %d, want 0 (the October leaf) from its start", i, ts, id)
	}
	// Same with a DEFAULT child first: it is not walked again.
	if i, ts, _ := backfillResumePosition(withDefault, "syslog_messages_2026_09", &sep20, 7); i != 1 || !ts.Equal(oct) {
		t.Fatalf("dropped partition, DEFAULT first: idx %d ts %s, want 1 (the October leaf)", i, ts)
	}
	// Past every leaf: nothing left.
	late := dec.Add(time.Hour)
	if i, _, _ := backfillResumePosition(leaves, "syslog_messages_2026_12", &late, 1); i != len(leaves) {
		t.Fatalf("past the end: idx %d, want %d", i, len(leaves))
	}
}

// TestNormalizeBackfill_OwnerTokenGuardsCommit: a runner whose job was
// requeued and claimed by another runner cannot commit a batch — the status
// alone (running again) would let it.
func TestNormalizeBackfill_OwnerTokenGuardsCommit(t *testing.T) {
	d, f, dev, _ := bfSetup(t, 10)
	job := bfQueue(t, d, nil)
	if won, err := d.ClaimNormalizeBackfillJob(job.ID, "runner-a"); err != nil || !won {
		t.Fatalf("claim a: %v %v", won, err)
	}
	// A's heartbeat is lost: requeued, then B claims it.
	d.db.Model(&models.NormalizeBackfillJob{}).Where("id = ?", job.ID).Update("updated_at", time.Now().Add(-time.Hour))
	if n, err := d.RequeueStaleNormalizeBackfillJobs(normalizeBackfillStaleAfter); err != nil || n != 1 {
		t.Fatalf("requeue: %d %v", n, err)
	}
	if won, err := d.ClaimNormalizeBackfillJob(job.ID, "runner-b"); err != nil || !won {
		t.Fatalf("claim b: %v %v", won, err)
	}
	m := f.rows[1]
	nets := []models.NetEvent{{Ts: m.Timestamp, DeviceID: dev.ID, RawID: ptrInt64(int64(m.ID)), RawTS: &m.Timestamp}}
	p := backfillProgress{partition: "syslog_messages", cursorTs: m.Timestamp, cursorID: int64(m.ID), scanned: 2, written: 1}
	if err := d.commitBackfillBatch(context.Background(), job.ID, "runner-a", 1, nil, nets, nil, nil, p); !errors.Is(err, errBackfillJobLost) {
		t.Fatalf("stale runner's commit: %v, want errBackfillJobLost", err)
	}
	if n, _, _ := bfCounts(t, d); n != 0 {
		t.Fatalf("the stale runner's batch committed %d net_events rows", n)
	}
	if got, _ := d.GetNormalizeBackfillJob(job.ID); got.RunnerID != "runner-b" || got.CursorTs != nil || got.RowsScanned != 0 {
		t.Fatalf("job after the refused commit: %+v", got)
	}
	// The owner commits.
	if err := d.commitBackfillBatch(context.Background(), job.ID, "runner-b", 1, nil, nets, nil, nil, p); err != nil {
		t.Fatalf("owner's commit: %v", err)
	}
	// And the stale runner cannot finish the job either.
	if err := d.finishBackfillJob(job.ID, "runner-a", NormalizeBackfillStatusFailed, errors.New("x")); !errors.Is(err, errBackfillJobLost) {
		t.Fatalf("stale runner's finish: %v, want errBackfillJobLost", err)
	}
	if got, _ := d.GetNormalizeBackfillJob(job.ID); got.Status != NormalizeBackfillStatusRunning {
		t.Fatalf("stale runner's finish changed the status to %s", got.Status)
	}
}

// TestNormalizeBackfill_CancelWakesPaceSleep: at a low rate the pace sleep
// after a batch is long; a cancel must end the run within about one
// normalizeBackfillCancelPoll, not after the sleep.
func TestNormalizeBackfill_CancelWakesPaceSleep(t *testing.T) {
	d, _, _, _ := bfSetup(t, 600)
	normalizeBackfillBatchSize = 300 // 300 rows at 100 rows/s: a 3 s pace sleep
	origPoll := normalizeBackfillCancelPoll
	normalizeBackfillCancelPoll = 20 * time.Millisecond
	t.Cleanup(func() { normalizeBackfillCancelPoll = origPoll })
	since, until, err := d.NormalizeBackfillBounds(30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	job := &models.NormalizeBackfillJob{Since: since, Until: until, RateRowsPerSec: NormalizeBackfillMinRate}
	if err := d.CreateNormalizeBackfillJob(job); err != nil {
		t.Fatal(err)
	}
	var cancelledAt time.Time
	normalizeBackfillBatchHook = func(j *models.NormalizeBackfillJob, batch int) error {
		if batch == 1 {
			cancelledAt = time.Now()
			_, _, err := d.CancelNormalizeBackfillJob(j.ID)
			return err
		}
		return nil
	}
	t.Cleanup(func() { normalizeBackfillBatchHook = nil })
	got, err := bfRun(t, d, job.ID)
	latency := time.Since(cancelledAt)
	if err != nil || got.Status != NormalizeBackfillStatusCancelled || got.RowsScanned != 300 {
		t.Fatalf("after cancel: %v %+v", err, got)
	}
	if latency > time.Second {
		t.Fatalf("cancel took %s to land during a 3 s pace sleep, want well under 1 s", latency)
	}
}

// TestEstimateNormalizeBackfill_IgnoresStaleSample: a server_metrics sample
// older than normalizeBackfillMetricMaxAge does not count — free space is
// unknown — while a recent one decides.
func TestEstimateNormalizeBackfill_IgnoresStaleSample(t *testing.T) {
	d := NewDatabaseForTesting(t)
	until := time.Now().UTC().Truncate(time.Hour)
	since := until.Add(-48 * time.Hour)
	if err := d.db.Create(&models.SyslogIngestHourly{Timestamp: since.Add(time.Hour), Severity: 5, RowCount: 1_000_000}).Error; err != nil {
		t.Fatal(err)
	}
	tiny := uint64(1 << 20)
	if err := d.db.Create(&models.ServerMetric{Timestamp: time.Now().Add(-time.Hour), DataDiskFreeBytes: &tiny}).Error; err != nil {
		t.Fatal(err)
	}
	est, err := d.EstimateNormalizeBackfill(since, until)
	if err != nil {
		t.Fatal(err)
	}
	if est.FreeKnown || !est.Enough || est.Rows != 1_000_000 {
		t.Fatalf("with only an hour-old sample: %+v, want free unknown (not refused on a stale figure)", est)
	}
	if err := d.db.Create(&models.ServerMetric{Timestamp: time.Now().Add(-time.Minute), DataDiskFreeBytes: &tiny}).Error; err != nil {
		t.Fatal(err)
	}
	if est, _ = d.EstimateNormalizeBackfill(since, until); !est.FreeKnown || est.Enough {
		t.Fatalf("with a recent sample: %+v, want known and refused", est)
	}
	// The remaining window of a resumed job starts at its cursor.
	cur := since.Add(24 * time.Hour)
	if from, to := NormalizeBackfillRemaining(&models.NormalizeBackfillJob{Since: since, Until: until, CursorTs: &cur}); !from.Equal(cur) || !to.Equal(until) {
		t.Fatalf("remaining = [%s, %s)", from, to)
	}
}

// TestNormalizeBackfill_StopsAtUnindexedRelation: a raw relation the keyset
// page cannot be served from by index is never seq-scanned: the job stops
// failed (resumable) with its cursor parked at the start of that relation
// and the reason in its error; once the index exists, resume continues there
// and completes — no new job over the whole window.
func TestNormalizeBackfill_StopsAtUnindexedRelation(t *testing.T) {
	d, f, _, _ := bfSetup(t, 100)
	orig := backfillLeafIndexProbe
	indexed := false
	var probed []string
	backfillLeafIndexProbe = func(_ *Database, table string, _ bool) (bool, error) {
		probed = append(probed, table)
		return indexed, nil
	}
	t.Cleanup(func() { backfillLeafIndexProbe = orig })
	job, err := bfRun(t, d, bfQueue(t, d, nil).ID)
	if err == nil || !strings.Contains(err.Error(), "no usable (timestamp) index") {
		t.Fatalf("run: %v, want the missing-index failure", err)
	}
	if job.Status != NormalizeBackfillStatusFailed || job.RowsScanned != 0 || job.RowsWritten != 0 ||
		!strings.Contains(job.Error, "syslog_messages") || !strings.Contains(job.Error, "resume") {
		t.Fatalf("job: %+v, want failed with the reason", job)
	}
	if job.CurrentPartition != "syslog_messages" || job.CursorTs == nil || !job.CursorTs.Equal(job.Since) || job.CursorID != 0 {
		t.Fatalf("cursor %s/%v/%d, want parked at the relation's start %s/0", job.CurrentPartition, job.CursorTs, job.CursorID, job.Since)
	}
	if ok, hint := NormalizeBackfillResumable(job); !ok || !strings.Contains(hint, "resume") {
		t.Fatalf("resumable=%v hint=%q", ok, hint)
	}
	// The operator creates the index and resumes: the run continues there.
	indexed = true
	if applied, err := d.ResumeNormalizeBackfillJob(job.ID); err != nil || !applied {
		t.Fatalf("resume: %v %v", applied, err)
	}
	if job, err = bfRun(t, d, job.ID); err != nil || job.Status != NormalizeBackfillStatusDone ||
		job.RowsScanned != int64(len(f.rows)) || job.RowsWritten != int64(f.net+f.sec) {
		t.Fatalf("resumed: %v %+v", err, job)
	}
	if n, s, distinct := bfCounts(t, d); n != int64(f.net) || s != int64(f.sec) || distinct != int64(f.net+f.sec) {
		t.Fatalf("after resume net=%d sec=%d distinct=%d", n, s, distinct)
	}
	if len(probed) != 2 {
		t.Fatalf("index probe calls = %v, want one per run", probed)
	}
}

// TestNormalizeBackfill_ObservedCountsOnlyCommittedBatches: a batch whose
// transaction rolls back adds nothing to device_field_observed — it is
// counted once, when the resumed run commits it — so a failed-then-resumed
// job ends with exactly the counts of a clean run.
func TestNormalizeBackfill_ObservedCountsOnlyCommittedBatches(t *testing.T) {
	total := func(d *Database) int64 {
		var n int64
		if err := d.db.Raw("SELECT COALESCE(SUM(count), 0) FROM device_field_observed").Scan(&n).Error; err != nil {
			t.Fatal(err)
		}
		return n
	}
	clean, _, _, _ := bfSetup(t, 200)
	if job, err := bfRun(t, clean, bfQueue(t, clean, nil).ID); err != nil || job.Status != NormalizeBackfillStatusDone {
		t.Fatalf("clean run: %v %+v", err, job)
	}
	want := total(clean)
	if want == 0 {
		t.Fatal("the clean run observed no fields")
	}

	d, _, _, _ := bfSetup(t, 200)
	normalizeBackfillTxHook = func(batch int) error {
		if batch == 3 {
			return errors.New("injected crash")
		}
		return nil
	}
	t.Cleanup(func() { normalizeBackfillTxHook = nil })
	job, err := bfRun(t, d, bfQueue(t, d, nil).ID)
	if err == nil || job.Status != NormalizeBackfillStatusFailed || job.RowsScanned != 100 {
		t.Fatalf("injected failure: %v %+v", err, job)
	}
	normalizeBackfillTxHook = nil
	if applied, err := d.ResumeNormalizeBackfillJob(job.ID); err != nil || !applied {
		t.Fatalf("resume: %v %v", applied, err)
	}
	if job, err = bfRun(t, d, job.ID); err != nil || job.Status != NormalizeBackfillStatusDone {
		t.Fatalf("resumed: %v %+v", err, job)
	}
	if got := total(d); got != want {
		t.Fatalf("device_field_observed total = %d after fail + resume, want %d (the clean run's): the rolled-back batch was counted", got, want)
	}
}

// TestBackfillProbe_ScopedAndBounded: the dedup probe of a device-scoped job
// reads only that device's normalized rows, and returns only the batch's own
// raw_ids — never the other rows its ts range happens to hold.
func TestBackfillProbe_ScopedAndBounded(t *testing.T) {
	d, f, dev, until := bfSetup(t, 30) // 30 rows over 71 h: a sparse batch
	other := &models.Device{Name: "fw-example-02", IPAddress: "192.0.2.2", Vendor: "fortigate"}
	if err := d.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	// Normalized rows already present: two of dev's batch rows (must be
	// found), the other device's rows at the same instants (scope), and dev
	// rows between the batch's instants whose raw rows are not in the batch
	// (bound).
	var pre []models.NetEvent
	for _, i := range []int{3, 6} {
		m := f.rows[i]
		pre = append(pre, models.NetEvent{Ts: m.Timestamp, DeviceID: dev.ID, RawID: ptrInt64(int64(m.ID)), RawTS: &m.Timestamp})
	}
	for i := 0; i < 20; i++ {
		ts := f.rows[i].Timestamp
		pre = append(pre, models.NetEvent{Ts: ts, DeviceID: other.ID, RawID: ptrInt64(int64(900000 + i)), RawTS: &ts})
		mid := ts.Add(time.Minute)
		pre = append(pre, models.NetEvent{Ts: mid, DeviceID: dev.ID, RawID: ptrInt64(int64(800000 + i)), RawTS: &mid})
	}
	if err := d.SaveNetEvents(pre); err != nil {
		t.Fatal(err)
	}
	r := backfillRange{table: "syslog_messages", lo: f.first, hi: until}
	rows, existing, err := d.fetchBackfillBatch(context.Background(), r, f.first.Add(-time.Second), 0, until, &dev.ID, 30)
	if err != nil || len(rows) != 30 {
		t.Fatalf("fetch: %d rows, %v", len(rows), err)
	}
	want := map[int64]struct{}{int64(f.rows[3].ID): {}, int64(f.rows[6].ID): {}}
	if !reflect.DeepEqual(existing, want) {
		t.Fatalf("probe returned %d raw_ids (%v), want exactly the batch's two already-normalized rows", len(existing), existing)
	}
}

// TestNormalizeBackfill_FwRulesCommitWithBatch: the batch's fw_rules upsert
// is part of the batch transaction. When it fails, the batch rolls back and
// the job fails resumable — never a committed cursor with the catalog rows
// lost (they used to be upserted after the commit, with a failure only
// logged). After the fault clears, resume completes with every rule present.
func TestNormalizeBackfill_FwRulesCommitWithBatch(t *testing.T) {
	d, f, _, _ := bfSetup(t, 150)
	if err := d.db.Exec(`CREATE TRIGGER bf_block_fw_rules BEFORE INSERT ON fw_rules BEGIN SELECT RAISE(ABORT, 'injected fw_rules failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	job, err := bfRun(t, d, bfQueue(t, d, nil).ID)
	if err == nil || job.Status != NormalizeBackfillStatusFailed || job.CursorTs != nil || job.RowsWritten != 0 {
		t.Fatalf("with fw_rules failing: %v %+v, want failed before any batch committed", err, job)
	}
	if n, s, _ := bfCounts(t, d); n != 0 || s != 0 {
		t.Fatalf("the failed batch committed net=%d sec=%d rows", n, s)
	}
	if err := d.db.Exec(`DROP TRIGGER bf_block_fw_rules`).Error; err != nil {
		t.Fatal(err)
	}
	if applied, err := d.ResumeNormalizeBackfillJob(job.ID); err != nil || !applied {
		t.Fatalf("resume: %v %v", applied, err)
	}
	if job, err = bfRun(t, d, job.ID); err != nil || job.Status != NormalizeBackfillStatusDone || job.RowsWritten != int64(f.net+f.sec) {
		t.Fatalf("resumed: %v %+v", err, job)
	}
	var rules int64
	d.db.Model(&models.FwRule{}).Count(&rules)
	if rules != 3 {
		t.Fatalf("fw_rules rows = %d, want the fixture's 3 policies", rules)
	}
}

// TestNormalizeBackfill_UsesStoredFormat (v74): the backfill normalizes a row
// the way the live ingest did. Two generic RFC 5424 rows whose structured
// data carries `src=`: with a stored format (a framing-contract row) the body
// is tokenized alone, so the event has no source; without one the re-framing
// join folds the structured data in and the source appears. Before v74 the
// backfill re-framed both.
func TestNormalizeBackfill_UsesStoredFormat(t *testing.T) {
	d, f, _, _ := bfSetup(t, 30)
	gen := &models.Device{Name: "fw-example-09", IPAddress: "192.0.2.9", Vendor: "generic"}
	if err := d.db.Create(gen).Error; err != nil {
		t.Fatal(err)
	}
	ts := f.first.Add(time.Hour)
	mk := func(dst string, stored *int16) models.SyslogMessage {
		return models.SyslogMessage{Timestamp: ts, DeviceID: gen.ID, ProbeID: 1, Hostname: "fw-example-09", AppName: "fwd", ProcessID: "-", MessageID: "-",
			StructuredData: `[meta src="198.51.100.66"]`, Message: "action=deny proto=tcp dst=" + dst, Severity: 4, Facility: 16, CreatedAt: ts, StoredFormat: stored}
	}
	framed, legacy := mk("203.0.113.5", models.SyslogFormatCode("rfc5424")), mk("203.0.113.6", nil)
	for _, m := range []*models.SyslogMessage{&framed, &legacy} {
		if err := d.db.Create(m).Error; err != nil {
			t.Fatal(err)
		}
	}
	job := bfQueue(t, d, &gen.ID)
	if job, err := bfRun(t, d, job.ID); err != nil || job.Status != NormalizeBackfillStatusDone || job.RowsWritten != 2 {
		t.Fatalf("job: err=%v %+v; want done with 2 rows written", err, job)
	}
	src := func(raw uint) string {
		var ev models.NetEvent
		if err := d.db.Where("raw_id = ?", raw).First(&ev).Error; err != nil {
			t.Fatalf("net_events for raw row %d: %v", raw, err)
		}
		if ev.SrcIP == nil {
			return ""
		}
		return *ev.SrcIP
	}
	if got := src(framed.ID); got != "" {
		t.Errorf("stored-format row: src_ip %q, want none — a framed row's structured data is not the body (NormalizeFramed)", got)
	}
	if got := src(legacy.ID); got != "198.51.100.66" {
		t.Errorf("format-less row: src_ip %q, want 198.51.100.66 from the re-framing join", got)
	}
}
