//go:build integration

// S-5 (v0.11.297) on a real PostgreSQL: the per-leaf keyset walk over the
// partitioned syslog_messages, the COPY path inside the batch transaction,
// the dedup probe against the daily net_events leaves, cancel / resume with
// no duplicate, and the rollup rewind the finished job queues.
package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"

	"gorm.io/gorm"
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

	// The keyset page's plan on every populated leaf, all devices and
	// device-scoped: an index walk, never a Seq Scan that costs anything
	// (an EMPTY leaf's zero-cost seq scan is free and allowed).
	if err := d.db.Exec("ANALYZE syslog_messages").Error; err != nil {
		t.Fatal(err)
	}
	populated := 0
	for _, r := range ranges {
		var n int64
		if err := d.db.Raw(fmt.Sprintf("SELECT COUNT(*) FROM ONLY %s", r.table)).Scan(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			continue
		}
		populated++
		for _, dev := range []*uint{nil, &dev.ID} {
			stmt := backfillPageQuery(d.db.Session(&gorm.Session{DryRun: true}), r, r.lo, 0, until, dev, normalizeBackfillBatchSize).Find(&[]models.SyslogMessage{}).Statement
			plan := assertBackfillPlan(t, d, fmt.Sprintf("page %s device=%v", r.table, dev != nil), stmt)
			if !strings.Contains(plan, "Index Scan") {
				t.Fatalf("page %s: no index scan in the plan:\n%s", r.table, plan)
			}
		}
	}
	if populated == 0 {
		t.Fatal("no populated syslog_messages leaf to check the page plan on")
	}

	// fw_rules: the live ingest has already seen one of the fixture's rules
	// under a NEWER name (last_seen after every backfilled row). The backfill
	// replays older sightings of it inside its batch transaction (the pgx
	// upsert): the live name must survive, the NULL ruleset be filled, and
	// first_seen move back to the oldest sighting.
	ev, out := normalize.Normalize("fortigate", &f.rows[1])
	liveRule, ok := FwRuleFromEvent(&ev, now)
	if out.Kind != normalize.OutcomeOK || !ok || liveRule.Ruleset == nil {
		t.Fatalf("fixture row 1 yields no rule with a ruleset: %v %+v", out.Kind, liveRule)
	}
	liveName := "LAN-to-WAN-renamed-live"
	liveRule.RuleName, liveRule.Ruleset = &liveName, nil
	if err := d.UpsertFwRules([]models.FwRule{liveRule}); err != nil {
		t.Fatal(err)
	}

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
	var rule models.FwRule
	if err := d.db.Where("device_id = ? AND rule_key = ?", dev.ID, liveRule.RuleKey).First(&rule).Error; err != nil {
		t.Fatal(err)
	}
	if rule.RuleName == nil || *rule.RuleName != liveName || rule.Ruleset == nil || !rule.LastSeen.Equal(now) || !rule.FirstSeen.Before(f.first.Add(time.Hour)) {
		t.Fatalf("fw_rules after the backfill: name=%v ruleset=%v first=%s last=%s; want the live name kept, the ruleset filled, last_seen %s, first_seen the oldest sighting",
			rule.RuleName, rule.Ruleset, rule.FirstSeen, rule.LastSeen, now)
	}

	// The dedup probe's plans on the populated net_events / sec_events day
	// leaves, all devices and device-scoped: index only.
	if err := d.db.Exec("ANALYZE net_events; ANALYZE sec_events").Error; err != nil {
		t.Fatal(err)
	}
	// The batch: 200 rows from the middle of the fixture — on production a
	// 5000-row batch is a sliver of a day leaf holding millions; here the
	// leaves hold ~10 000 rows, so a 200-row batch keeps the same "small
	// fraction of the leaf" shape (a 5000-row one would cover half a leaf,
	// where a seq scan is legitimately the cheaper plan).
	var batch []models.SyslogMessage
	if err := d.db.Table("syslog_messages").Where("timestamp >= ?", f.rows[n/2].Timestamp).Order("timestamp, id").Limit(200).Find(&batch).Error; err != nil || len(batch) != 200 {
		t.Fatalf("probe batch: %d rows, %v", len(batch), err)
	}
	for _, table := range []string{"net_events", "sec_events"} {
		for _, dv := range []*uint{nil, &dev.ID} {
			stmt := backfillProbeQuery(d.db.Session(&gorm.Session{DryRun: true}), table, batch, dv).Find(&[]map[string]any{}).Statement
			plan := assertBackfillPlan(t, d, fmt.Sprintf("probe %s device=%v", table, dv != nil), stmt)
			if table == "net_events" && !strings.Contains(plan, "Index") {
				t.Fatalf("probe on net_events: no index in the plan:\n%s", plan)
			}
		}
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

// planNode is one node of an EXPLAIN (FORMAT JSON) plan.
type planNode struct {
	Type      string     `json:"Node Type"`
	Relation  string     `json:"Relation Name"`
	Index     string     `json:"Index Name"`
	TotalCost float64    `json:"Total Cost"`
	Plans     []planNode `json:"Plans"`
}

// assertBackfillPlan EXPLAINs a dry-run statement exactly as the run would
// send it (same SQL, same bound values, so the same partition pruning) and
// fails on any Seq Scan with a cost above zero — the lesson: an EMPTY leaf's
// seq scan is a free zero-page read, a populated one's is the defect. Returns
// the plan, one node per line, for the caller's checks and the log.
func assertBackfillPlan(t *testing.T, d *Database, label string, stmt *gorm.Statement) string {
	t.Helper()
	var raw string
	if err := d.pgxPool.QueryRow(context.Background(), "EXPLAIN (FORMAT JSON) "+stmt.SQL.String(), stmt.Vars...).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN %s: %v\n%s", label, err, stmt.SQL.String())
	}
	var top []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(raw), &top); err != nil || len(top) != 1 {
		t.Fatalf("EXPLAIN %s JSON: %v", label, err)
	}
	var b strings.Builder
	var walk func(n planNode, depth int)
	walk = func(n planNode, depth int) {
		fmt.Fprintf(&b, "%s%s %s %s (cost %.2f)\n", strings.Repeat("  ", depth), n.Type, n.Relation, n.Index, n.TotalCost)
		if n.Type == "Seq Scan" && n.TotalCost > 0 {
			t.Errorf("EXPLAIN %s: Seq Scan on %s costing %.2f — the backfill must read populated relations by index", label, n.Relation, n.TotalCost)
		}
		for _, c := range n.Plans {
			walk(c, depth+1)
		}
	}
	walk(top[0].Plan, 0)
	t.Logf("EXPLAIN %s:\n%s", label, b.String())
	return b.String()
}

// TestLeafHasUsableIndex_PG: the pre-scan index check on real catalogs — a
// populated relation with no index is refused, an empty one passes, a
// (timestamp) index serves every job, a (device_id, timestamp) one only a
// device-scoped job, and a partial index serves none.
func TestLeafHasUsableIndex_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	for _, q := range []string{
		`CREATE TABLE bf_idx_none (id bigint, "timestamp" timestamptz, device_id bigint)`,
		`CREATE TABLE bf_idx_ts (LIKE bf_idx_none)`,
		`CREATE TABLE bf_idx_dev (LIKE bf_idx_none)`,
		`CREATE TABLE bf_idx_partial (LIKE bf_idx_none)`,
		`CREATE TABLE bf_idx_empty (LIKE bf_idx_none)`,
		`CREATE INDEX ON bf_idx_ts ("timestamp")`,
		`CREATE INDEX ON bf_idx_dev (device_id, "timestamp")`,
		`CREATE INDEX ON bf_idx_partial ("timestamp") WHERE device_id = 1`,
	} {
		if err := d.db.Exec(q).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, tb := range []string{"bf_idx_none", "bf_idx_ts", "bf_idx_dev", "bf_idx_partial"} {
		if err := d.db.Exec(fmt.Sprintf(`INSERT INTO %s SELECT g, now() - g * interval '1 second', 1 FROM generate_series(1, 1000) g`, tb)).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		table  string
		scoped bool
		want   bool
	}{
		{"bf_idx_none", false, false}, {"bf_idx_none", true, false},
		{"bf_idx_ts", false, true}, {"bf_idx_ts", true, true},
		{"bf_idx_dev", false, false}, {"bf_idx_dev", true, true},
		{"bf_idx_partial", false, false}, {"bf_idx_partial", true, false},
		{"bf_idx_empty", false, true},
	} {
		got, err := d.leafHasUsableIndex(c.table, c.scoped)
		if err != nil || got != c.want {
			t.Errorf("leafHasUsableIndex(%s, scoped=%v) = %v, %v; want %v", c.table, c.scoped, got, err, c.want)
		}
	}
	// Every fresh-install syslog_messages leaf passes.
	since := time.Now().UTC().AddDate(0, 0, -20)
	ranges, err := d.backfillRanges(since, time.Now().UTC())
	if err != nil || len(ranges) == 0 {
		t.Fatalf("ranges: %v %v", ranges, err)
	}
	for _, r := range ranges {
		if ok, err := d.leafHasUsableIndex(r.table, false); err != nil || !ok {
			t.Errorf("fresh-install leaf %s: usable=%v err=%v", r.table, ok, err)
		}
	}
}

// TestNormalizeBackfill_PG_DeviceScoped: a device-scoped job for a SPARSE
// device (1 500 rows over three days) beside a DENSE one (300 000 raw rows,
// all already normalized). The page and the dedup probe must be served by
// the per-leaf (device_id, ...) indexes — a probe over the sparse batch's
// ts range without the device scope would read the dense device's rows of
// the whole span — and the job writes exactly the sparse device's rows.
func TestNormalizeBackfill_PG_DeviceScoped(t *testing.T) {
	d := NewIntegrationDB(t)
	d.netEventRetentionDays = 30
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	sparse := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate"}
	dense := &models.Device{Name: "fw-example-02", IPAddress: "192.0.2.2", Vendor: "fortigate"}
	for _, dv := range []*models.Device{sparse, dense} {
		if err := d.db.Create(dv).Error; err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	start, span := now.Add(-72*time.Hour), 71*time.Hour
	f := seedBackfillRows(t, d, sparse.ID, start, span, 1500)
	const denseRows = 300000
	if err := d.db.Exec(`INSERT INTO syslog_messages (timestamp, device_id, probe_id, hostname, app_name, message, severity, facility, created_at, source_ip)
		SELECT t, ?, 1, 'fw-example-02', 'traffic', 'dense fixture row', 5, 20, t, '192.0.2.2'
		FROM (SELECT ?::timestamptz + g * (?::bigint * interval '1 microsecond') AS t FROM generate_series(1, ?) g) s`,
		dense.ID, start, span.Microseconds()/denseRows, denseRows).Error; err != nil {
		t.Fatalf("seed dense syslog: %v", err)
	}
	// The dense device's rows were all normalized (live, or by an earlier job).
	if err := d.db.Exec(`INSERT INTO net_events (ts, device_id, probe_id, activity, action, raw_id, raw_ts)
		SELECT timestamp, device_id, 1, 1, 1, id, timestamp FROM syslog_messages WHERE device_id = ?`, dense.ID).Error; err != nil {
		t.Fatalf("seed dense net_events: %v", err)
	}
	until := now.Add(-30 * time.Minute)
	if _, err := d.InsertSettingIfAbsent(&models.SystemSetting{Key: NormalizeIngestStartedSetting, Value: until.Format(time.RFC3339), Type: "string"}); err != nil {
		t.Fatal(err)
	}
	if err := d.db.Exec("ANALYZE syslog_messages; ANALYZE net_events; ANALYZE sec_events").Error; err != nil {
		t.Fatal(err)
	}
	since, _, err := d.NormalizeBackfillBounds(30, now)
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := d.backfillRanges(since, until)
	if err != nil {
		t.Fatal(err)
	}
	orig := normalizeBackfillBatchSize
	normalizeBackfillBatchSize = 5000
	t.Cleanup(func() { normalizeBackfillBatchSize = orig })

	// The page, device-scoped, on every leaf holding the sparse device.
	checked := 0
	for _, r := range ranges {
		var n int64
		if err := d.db.Raw(fmt.Sprintf("SELECT COUNT(*) FROM ONLY %s WHERE device_id = ?", r.table), sparse.ID).Scan(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			continue
		}
		checked++
		stmt := backfillPageQuery(d.db.Session(&gorm.Session{DryRun: true}), r, r.lo, 0, until, &sparse.ID, normalizeBackfillBatchSize).Find(&[]models.SyslogMessage{}).Statement
		if plan := assertBackfillPlan(t, d, "device-scoped page "+r.table, stmt); !strings.Contains(plan, "device") {
			t.Fatalf("device-scoped page on %s does not use the (device_id, timestamp) index:\n%s", r.table, plan)
		}
	}
	if checked == 0 {
		t.Fatal("no leaf holds the sparse device's rows")
	}
	// The probe of a sparse batch (its 5 000-row batch is the whole device,
	// spanning ~71 h of the dense device's traffic): (device_id, ts) only.
	var batch []models.SyslogMessage
	if err := d.db.Table("syslog_messages").Where("device_id = ?", sparse.ID).Order("timestamp, id").Limit(normalizeBackfillBatchSize).Find(&batch).Error; err != nil || len(batch) != len(f.rows) {
		t.Fatalf("sparse batch: %d rows, %v", len(batch), err)
	}
	stmt := backfillProbeQuery(d.db.Session(&gorm.Session{DryRun: true}), "net_events", batch, &sparse.ID).Find(&[]map[string]any{}).Statement
	if plan := assertBackfillPlan(t, d, "device-scoped probe net_events", stmt); !strings.Contains(plan, "device_id_ts") {
		t.Fatalf("device-scoped probe does not use the (device_id, ts) index:\n%s", plan)
	}

	// The job writes exactly the sparse device's rows; the dense device's
	// normalized rows are untouched.
	job := &models.NormalizeBackfillJob{RequestedBy: "test", Since: since, Until: until, DeviceID: &sparse.ID, RateRowsPerSec: NormalizeBackfillMaxRate}
	if err := d.CreateNormalizeBackfillJob(job); err != nil {
		t.Fatal(err)
	}
	job, err = bfRun(t, d, job.ID)
	if err != nil || job.Status != NormalizeBackfillStatusDone || job.RowsScanned != int64(len(f.rows)) || job.RowsWritten != int64(f.net+f.sec) || job.RowsSkipped != 0 {
		t.Fatalf("device-scoped job: %v %+v; want scanned %d written %d", err, job, len(f.rows), f.net+f.sec)
	}
	var denseNet int64
	d.db.Model(&models.NetEvent{}).Where("device_id = ?", dense.ID).Count(&denseNet)
	if denseNet != denseRows {
		t.Fatalf("dense device net_events = %d, want %d untouched", denseNet, denseRows)
	}
}
