//go:build integration

// S-5 (v0.11.297) on a real PostgreSQL: the per-leaf keyset walk over the
// partitioned syslog_messages, the COPY path inside the batch transaction,
// the dedup probe against the daily net_events leaves, cancel / resume with
// no duplicate, and the rollup rewind the finished job queues.
package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestNormalizeBackfill_PG seeds 30 000 synthetic FortiGate rows over three
// days (RFC 5737 addresses, fw-example-01, alice) and runs the job as the
// poller worker would.
func TestNormalizeBackfill_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if d.pgxPool == nil {
		t.Fatal("the integration Database must have a pgx pool, or the COPY path is not under test")
	}
	d.netEventRetentionDays = 30
	if !pgIsPartitioned(t, d, "syslog_messages") {
		t.Fatal("syslog_messages is not partitioned on the fresh-install path")
	}
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	dev := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate"}
	if err := d.db.Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	const n = 30000
	f := seedBackfillRows(t, d, dev.ID, now.Add(-72*time.Hour), 71*time.Hour, n)
	until := now.Add(-30 * time.Minute)
	if _, err := d.InsertSettingIfAbsent(&models.SystemSetting{Key: NormalizeIngestStartedSetting, Value: until.Format(time.RFC3339), Type: "string"}); err != nil {
		t.Fatal(err)
	}
	// The live ingest's share: the traffic rows among the newest 50 of the
	// window were normalized live (the batch that wrote the watermark). The
	// backfill must skip them, not duplicate them.
	var live []models.NetEvent
	for i := n - 50; i < n; i++ {
		if i%25 == 0 || i%10 == 0 {
			continue // unparsed / sec-class fixture rows: the live ingest stored no net_events row
		}
		m := f.rows[i]
		live = append(live, models.NetEvent{Ts: m.Timestamp, DeviceID: dev.ID, RawID: ptrInt64(int64(m.ID)), RawTS: &m.Timestamp})
	}
	if err := d.SaveNetEvents(live); err != nil {
		t.Fatal(err)
	}
	nLive := int64(len(live))
	// A spool replay received after the watermark: out of scope.
	replay := models.SyslogMessage{Timestamp: f.first.Add(2 * time.Hour), DeviceID: dev.ID, ProbeID: 1, Hostname: "fw-example-01", AppName: "traffic", Severity: 5, Facility: 20,
		CreatedAt: until.Add(time.Minute), Message: fmt.Sprintf(bfTraffic, 50000, 3000000, 10, 0, 0)}
	if err := d.db.Create(&replay).Error; err != nil {
		t.Fatal(err)
	}
	// Pretend the rollup had closed through yesterday, so the rewind is observable.
	closedBefore := utcDay(now).AddDate(0, 0, -1).Format("2006-01-02")
	if err := d.setSetting(d.db, netEventRollupClosedDayKey, closedBefore); err != nil {
		t.Fatal(err)
	}
	// Leaves and ranges: the DEFAULT child first, then the overlapping months.
	since, _, err := d.NormalizeBackfillBounds(30, now)
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := d.backfillRanges(since, until)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) < 2 || !strings.HasSuffix(ranges[0].table, "_default") {
		t.Fatalf("ranges = %+v, want the default child first then the month leaves", ranges)
	}
	for i := 2; i < len(ranges); i++ {
		if !ranges[i].lo.Equal(ranges[i-1].hi) {
			t.Fatalf("leaf ranges are not contiguous: %+v", ranges)
		}
	}

	orig := normalizeBackfillBatchSize
	normalizeBackfillBatchSize = 5000
	t.Cleanup(func() { normalizeBackfillBatchSize = orig })

	// Cancel after the second batch, then resume: exact totals, no duplicate.
	job := &models.NormalizeBackfillJob{RequestedBy: "test", Since: since, Until: until, RateRowsPerSec: NormalizeBackfillMaxRate}
	if err := d.CreateNormalizeBackfillJob(job); err != nil {
		t.Fatal(err)
	}
	normalizeBackfillBatchHook = func(j *models.NormalizeBackfillJob, batch int) error {
		if batch == 2 {
			_, _, err := d.CancelNormalizeBackfillJob(j.ID)
			return err
		}
		return nil
	}
	t.Cleanup(func() { normalizeBackfillBatchHook = nil })
	job, err = bfRun(t, d, job.ID)
	if err != nil || job.Status != NormalizeBackfillStatusCancelled || job.RowsScanned != 10000 {
		t.Fatalf("after cancel: %v %+v", err, job)
	}
	partial, _, _ := bfCounts(t, d)
	if partial <= nLive {
		t.Fatalf("partial net_events = %d", partial)
	}
	normalizeBackfillBatchHook = nil
	if applied, err := d.ResumeNormalizeBackfillJob(job.ID); err != nil || !applied {
		t.Fatalf("resume: %v %v", applied, err)
	}
	start := time.Now()
	job, err = bfRun(t, d, job.ID)
	if err != nil || job.Status != NormalizeBackfillStatusDone {
		t.Fatalf("resumed run: %v %+v", err, job)
	}
	t.Logf("resumed run of %d rows took %s", n-10000, time.Since(start))
	if job.RowsScanned != n || job.RowsSkipped != nLive || job.RowsUnparsed != int64(f.unp) || job.RowsWritten != int64(f.net+f.sec)-nLive {
		t.Fatalf("counters: %+v; want scanned %d, skipped %d, unparsed %d, written %d", job, n, nLive, f.unp, int64(f.net+f.sec)-nLive)
	}
	net, sec, distinct := bfCounts(t, d)
	if net != int64(f.net) || sec != int64(f.sec) || distinct != int64(f.net+f.sec) {
		t.Fatalf("net=%d sec=%d distinct raw=%d; want %d/%d/%d", net, sec, distinct, f.net, f.sec, f.net+f.sec)
	}
	// Every backfilled row sits in a day leaf, none in the default child.
	var inDefault int64
	if err := d.db.Raw("SELECT COUNT(*) FROM ONLY net_events_default").Scan(&inDefault).Error; err != nil {
		t.Fatal(err)
	}
	if inDefault != 0 {
		t.Fatalf("%d net_events rows landed in the default child", inDefault)
	}
	var replayed int64
	d.db.Model(&models.NetEvent{}).Where("raw_id = ?", replay.ID).Count(&replayed)
	if replayed != 0 {
		t.Fatal("the spool-replayed row (created after the watermark) was backfilled")
	}
	// Types survived the COPY: inet / macaddr / jsonb round-trip.
	var probe struct {
		Src    string
		Action int16
	}
	if err := d.db.Raw("SELECT host(src_ip) AS src, action FROM net_events WHERE raw_id = ?", f.rows[1].ID).Scan(&probe).Error; err != nil {
		t.Fatal(err)
	}
	if probe.Src != "192.0.2.10" {
		t.Fatalf("src_ip round-trip = %q", probe.Src)
	}

	// Rollup rewind: the marker names the day before the window; the next
	// cycle rewinds the closed-day cursor and recomputes those days.
	wantDay := utcDay(since).AddDate(0, 0, -1).Format("2006-01-02")
	if v, _ := d.GetSettingValue(netEventRollupRewindKey); v != wantDay {
		t.Fatalf("rewind marker = %q, want %q", v, wantDay)
	}
	if _, days, err := d.runNetEventRollupCycle(now); err != nil {
		t.Fatalf("rollup cycle: %v (%d days)", err, days)
	}
	if v, _ := d.GetSettingValue(netEventRollupClosedDayKey); v == closedBefore {
		t.Fatalf("closed-day cursor stayed at %s after the rewind", v)
	}
	if _, ok := d.GetSettingValue(netEventRollupRewindKey); ok {
		t.Fatal("rewind marker not consumed")
	}
	// Run the cycle until the backfilled days are closed again; the rollup
	// hits must equal the net_events rows of each closed day.
	for i := 0; i < 20; i++ {
		if _, _, err := d.runNetEventRollupCycle(now); err != nil {
			t.Fatal(err)
		}
	}
	type dayCount struct {
		Day   time.Time
		Hits  int64
		Exact bool
	}
	var rolled []dayCount
	if err := d.db.Raw("SELECT day, SUM(hits) AS hits, BOOL_AND(distinct_src_exact) AS exact FROM net_event_rollups GROUP BY day ORDER BY day").Scan(&rolled).Error; err != nil {
		t.Fatal(err)
	}
	if len(rolled) < 3 {
		t.Fatalf("rollup days after the rewind: %+v, want the three fixture days and the open one", rolled)
	}
	closedDays := 0
	for _, r := range rolled {
		day := r.Day.UTC()
		var raw int64
		d.db.Model(&models.NetEvent{}).Where("ts >= ? AND ts < ?", day, day.AddDate(0, 0, 1)).Count(&raw)
		if !day.Before(utcDay(now)) {
			// The current UTC day is still open: folds only, never more than the rows.
			if r.Hits > raw {
				t.Fatalf("open day %s: rollup hits %d exceed its %d rows", day.Format("2006-01-02"), r.Hits, raw)
			}
			continue
		}
		closedDays++
		if r.Hits != raw || !r.Exact {
			closed, _ := d.GetSettingValue(netEventRollupClosedDayKey)
			t.Fatalf("closed day %s: rollup hits %d (exact=%v), net_events rows %d (double counted or missed); closed_day=%s", day.Format("2006-01-02"), r.Hits, r.Exact, raw, closed)
		}
	}
	if closedDays < 2 {
		t.Fatalf("only %d complete fixture days were re-closed after the rewind", closedDays)
	}

	// A second job over the same window writes nothing.
	job2 := &models.NormalizeBackfillJob{RequestedBy: "test", Since: since, Until: until, RateRowsPerSec: NormalizeBackfillMaxRate}
	if err := d.CreateNormalizeBackfillJob(job2); err != nil {
		t.Fatal(err)
	}
	job2, err = bfRun(t, d, job2.ID)
	if err != nil || job2.Status != NormalizeBackfillStatusDone || job2.RowsWritten != 0 || job2.RowsSkipped != int64(f.net+f.sec) {
		t.Fatalf("second job: %v %+v", err, job2)
	}

	// The transaction: a failure injected inside batch 2 rolls its rows back.
	if err := d.db.Exec("TRUNCATE net_events, sec_events, normalize_backfill_jobs").Error; err != nil {
		t.Fatal(err)
	}
	job3 := &models.NormalizeBackfillJob{RequestedBy: "test", Since: since, Until: until, RateRowsPerSec: NormalizeBackfillMaxRate}
	if err := d.CreateNormalizeBackfillJob(job3); err != nil {
		t.Fatal(err)
	}
	normalizeBackfillTxHook = func(batch int) error {
		if batch == 2 {
			return errors.New("injected crash")
		}
		return nil
	}
	t.Cleanup(func() { normalizeBackfillTxHook = nil })
	job3, err = bfRun(t, d, job3.ID)
	if err == nil || job3.Status != NormalizeBackfillStatusFailed || job3.RowsScanned != 5000 {
		t.Fatalf("injected failure: %v %+v", err, job3)
	}
	net1, sec1, _ := bfCounts(t, d)
	wantNet, wantSec := 0, 0
	for i := 0; i < 5000; i++ {
		switch {
		case i%25 == 0:
		case i%10 == 0:
			wantSec++
		default:
			wantNet++
		}
	}
	if net1 != int64(wantNet) || sec1 != int64(wantSec) {
		t.Fatalf("after the rolled-back batch: net=%d sec=%d, want exactly batch one %d/%d", net1, sec1, wantNet, wantSec)
	}
	normalizeBackfillTxHook = nil
	if applied, err := d.ResumeNormalizeBackfillJob(job3.ID); err != nil || !applied {
		t.Fatal(err)
	}
	if job3, err = bfRun(t, d, job3.ID); err != nil || job3.Status != NormalizeBackfillStatusDone {
		t.Fatalf("%v %+v", err, job3)
	}
	if net, sec, distinct := bfCounts(t, d); net != int64(f.net) || sec != int64(f.sec) || distinct != int64(f.net+f.sec) {
		t.Fatalf("after resume net=%d sec=%d distinct=%d", net, sec, distinct)
	}
	_ = context.Background
}
