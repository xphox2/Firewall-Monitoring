//go:build integration

// v72 (Phase 1, S-3) on a real PostgreSQL: the daily leaves, COPY routing into
// them, partition-drop retention, the per-class sec_events window, and the
// rollup math on the fixture the SQLite lane also runs.
package database

import (
	"fmt"
	"net"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
)

// pgLeaves lists a partitioned parent's child relations.
func pgLeaves(t *testing.T, d *Database, parent string) []string {
	t.Helper()
	var names []string
	if err := d.Gorm().Raw(`SELECT c.relname FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = ? ORDER BY c.relname`, parent).Scan(&names).Error; err != nil {
		t.Fatalf("leaves of %s: %v", parent, err)
	}
	return names
}

func pgRows(t *testing.T, d *Database, table string) int64 {
	t.Helper()
	var n int64
	if err := d.Gorm().Raw("SELECT COUNT(*) FROM " + table).Scan(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestNormalizedTables_PG(t *testing.T) {
	d := NewIntegrationDB(t) // migrations incl. v72 on an empty schema
	if d.pgxPool == nil {
		t.Fatal("the integration Database must have a pgx pool, or the COPY path is not under test")
	}
	// What Connect records from RETENTION_NET_EVENT_DAYS (the harness builds
	// its config without retention knobs).
	d.netEventRetentionDays = 30
	ret := config.RetentionConfig{DefaultDays: 90, NetEventDays: 30, SecEventDays: 365, NetEventRollupDays: 365}

	t.Run("ParentsPartitionedByV72", func(t *testing.T) {
		for _, tbl := range []string{"net_events", "sec_events"} {
			if !pgIsPartitioned(t, d, tbl) {
				t.Errorf("%s is not a partitioned parent after migrations", tbl)
			}
		}
		for _, tbl := range []string{"net_event_rollups", "fw_rules", "device_field_observed"} {
			if pgIsPartitioned(t, d, tbl) || !d.Gorm().Migrator().HasTable(tbl) {
				t.Errorf("%s should be a plain table", tbl)
			}
		}
	})

	t.Run("EnsurePartitionsCreatesDailyLeavesWithLookback", func(t *testing.T) {
		if err := d.EnsurePartitions(); err != nil {
			t.Fatalf("EnsurePartitions: %v", err)
		}
		today := utcDay(time.Now())
		leaves := pgLeaves(t, d, "net_events")
		// 30 lookback + today + 7 lead = 38 daily leaves, plus the DEFAULT child.
		if len(leaves) != 39 {
			t.Fatalf("net_events has %d children, want 39 (38 daily leaves + default): %v", len(leaves), leaves)
		}
		for _, want := range []string{
			"net_events_default",
			"net_events_" + today.AddDate(0, 0, -30).Format("20060102"),
			"net_events_" + today.Format("20060102"),
			"net_events_" + today.AddDate(0, 0, 7).Format("20060102"),
		} {
			if !contains(leaves, want) {
				t.Errorf("missing child %s", want)
			}
		}
		// Daily bounds render as full timestamps and parse back to the next
		// UTC midnight — what dropPartitionsOlderThan keys on.
		var bound string
		if err := d.Gorm().Raw(`SELECT pg_get_expr(c.relpartbound, c.oid) FROM pg_class c WHERE c.relname = ?`,
			"net_events_"+today.Format("20060102")).Scan(&bound).Error; err != nil {
			t.Fatal(err)
		}
		if upper, ok := parsePartitionUpperBound(bound); !ok || !upper.Equal(today.AddDate(0, 0, 1)) {
			t.Fatalf("today's leaf bound %q parses to %v %v, want %s", bound, upper, ok, today.AddDate(0, 0, 1))
		}
		// Monthly table: current month + 6 + default, as for every other table.
		if sec := pgLeaves(t, d, "sec_events"); len(sec) != 8 {
			t.Fatalf("sec_events has %d children, want 8 (7 monthly + default): %v", len(sec), sec)
		}
		// Every leaf (and the default) carries the five-index plan.
		for _, leaf := range []string{"net_events_" + today.Format("20060102"), "net_events_default"} {
			idx := childNonUniqueIndexCols(t, d, leaf)
			for _, want := range []string{"device_id,ts", "ts", "rule_key,ts", "src_ip,ts", "dst_ip,ts"} {
				found := false
				for _, cols := range idx {
					if joinCols(cols) == want {
						found = true
					}
				}
				if !found {
					t.Errorf("%s lacks the (%s) index; has %v", leaf, want, idx)
				}
			}
		}
		// Idempotent: a second pass creates nothing and fails nothing.
		if err := d.EnsurePartitionsForCron(); err != nil {
			t.Fatalf("EnsurePartitionsForCron: %v", err)
		}
		if again := pgLeaves(t, d, "net_events"); len(again) != 39 {
			t.Fatalf("second pass changed the leaf set: %d", len(again))
		}
	})

	t.Run("CopyRoutes10kRowsIntoDayLeaves", func(t *testing.T) {
		today := utcDay(time.Now())
		const perDay = 3334
		var rows []models.NetEvent
		id := int64(1)
		for day := 0; day < 3; day++ {
			base := today.AddDate(0, 0, -day).Add(6 * time.Hour)
			for i := 0; i < perDay; i++ {
				ev := normalize.Event{Class: normalize.ClassNetwork, Activity: normalize.ActivityTraffic, Action: normalize.ActionAllow,
					Ts: base.Add(time.Duration(i) * time.Second), DeviceID: 1, ProbeID: 1,
					SrcIP: net4(fmt.Sprintf("192.0.2.%d", i%200+1)), DstIP: net4("203.0.113.7"), RuleKey: "u:a", Ruleset: "root",
					SrcCountry: "NL", Extra: map[string]string{"service": "HTTPS"}}
				ev.SrcMAC = mac("00:00:5e:00:53:01")
				rows = append(rows, NetEventFromEvent(&ev, id, ev.Ts))
				id++
			}
		}
		rows = rows[:10000]
		if err := d.SaveNetEvents(rows); err != nil {
			t.Fatalf("SaveNetEvents (COPY): %v", err)
		}
		if n := pgRows(t, d, "net_events"); n != 10000 {
			t.Fatalf("net_events rows = %d, want 10000", n)
		}
		want := map[int]int64{0: perDay, 1: perDay, 2: 10000 - 2*perDay}
		for day, w := range want {
			leaf := "net_events_" + today.AddDate(0, 0, -day).Format("20060102")
			if n := pgRows(t, d, leaf); n != w {
				t.Errorf("%s holds %d rows, want %d", leaf, n, w)
			}
		}
		if n := pgRows(t, d, "net_events_default"); n != 0 {
			t.Errorf("net_events_default holds %d rows, want 0", n)
		}
		// Typed columns round-trip through the binary COPY encoders.
		var back struct {
			SrcIP, SrcMac, SrcCountry, Extra string
			RuleKey                          string
		}
		if err := d.Gorm().Raw(`SELECT host(src_ip) AS src_ip, src_mac::text AS src_mac, src_country, extra::text AS extra, rule_key FROM net_events ORDER BY ts LIMIT 1`).Scan(&back).Error; err != nil {
			t.Fatal(err)
		}
		if back.SrcIP != "192.0.2.1" || back.SrcMac != "00:00:5e:00:53:01" || back.SrcCountry != "NL" || back.Extra != `{"service": "HTTPS"}` || back.RuleKey != "u:a" {
			t.Fatalf("typed columns: %+v", back)
		}
		// A row older than the lookback lands in the DEFAULT child, never fails the batch.
		stray := rows[0]
		stray.Ts = today.AddDate(0, 0, -40)
		if err := d.SaveNetEvents([]models.NetEvent{stray}); err != nil {
			t.Fatalf("stray row: %v", err)
		}
		if n := pgRows(t, d, "net_events_default"); n != 1 {
			t.Fatalf("net_events_default holds %d rows after the stray, want 1", n)
		}
	})

	t.Run("RetentionDropsLeavesTrimsDefaultNeverRowDeletes", func(t *testing.T) {
		if err := d.Gorm().Exec(`CREATE TABLE net_events_20000101 PARTITION OF net_events FOR VALUES FROM ('2000-01-01 00:00:00+00') TO ('2000-01-02 00:00:00+00')`).Error; err != nil {
			t.Fatal(err)
		}
		old, _ := rollupFixture()
		old[0].Ts = time.Date(2000, 1, 1, 12, 0, 0, 0, time.UTC)
		if err := d.SaveNetEvents(old[:1]); err != nil {
			t.Fatal(err)
		}
		if n := pgRows(t, d, "net_events_20000101"); n != 1 {
			t.Fatalf("old leaf holds %d rows, want 1", n)
		}
		before := pgRows(t, d, "net_events")
		if errs := d.cleanupNormalizedEventTables(ret); len(errs) > 0 {
			t.Fatalf("cleanup: %v", errs)
		}
		if d.Gorm().Migrator().HasTable("net_events_20000101") {
			t.Fatal("the expired daily leaf was not dropped")
		}
		if n := pgRows(t, d, "net_events_default"); n != 0 {
			t.Fatalf("net_events_default still holds %d stray row(s) older than the window", n)
		}
		// Everything inside the window survived: only the leaf's row and the stray went.
		if after := pgRows(t, d, "net_events"); after != before-2 {
			t.Fatalf("net_events rows %d -> %d, want exactly 2 fewer (one dropped leaf row, one trimmed stray)", before, after)
		}
		today := utcDay(time.Now())
		if !d.Gorm().Migrator().HasTable("net_events_" + today.AddDate(0, 0, -30).Format("20060102")) {
			t.Fatal("the oldest in-window leaf (today-30) must survive: its range reaches past the cutoff")
		}
	})

	t.Run("SecEventsPerClass", func(t *testing.T) {
		if err := d.Gorm().Exec(`CREATE TABLE sec_events_200001 PARTITION OF sec_events FOR VALUES FROM ('2000-01-01 00:00:00+00') TO ('2000-02-01 00:00:00+00')`).Error; err != nil {
			t.Fatal(err)
		}
		old := time.Date(2000, 1, 15, 0, 0, 0, 0, time.UTC)
		if err := d.SaveSecEvents([]models.SecEvent{
			{Ts: old, DeviceID: 1, Class: int16(normalize.ClassFinding)},
			{Ts: old, DeviceID: 1, Class: int16(normalize.ClassConfigChange)},
			{Ts: time.Now().UTC().Add(-time.Hour), DeviceID: 1, Class: int16(normalize.ClassAuth)},
		}); err != nil {
			t.Fatal(err)
		}
		if errs := d.cleanupNormalizedEventTables(ret); len(errs) > 0 {
			t.Fatalf("cleanup: %v", errs)
		}
		// config_change kept forever: the leaf must survive and hold exactly it.
		if !d.Gorm().Migrator().HasTable("sec_events_200001") {
			t.Fatal("sec_events leaf dropped while config_change is kept forever")
		}
		var classes []int16
		d.Gorm().Raw(`SELECT class FROM sec_events ORDER BY ts`).Scan(&classes)
		if len(classes) != 2 || classes[0] != int16(normalize.ClassConfigChange) || classes[1] != int16(normalize.ClassAuth) {
			t.Fatalf("surviving classes = %v, want [config_change (2000), auth (now)]", classes)
		}
		// With a finite config_change window the whole expired leaf goes.
		finite := ret
		finite.SecConfigChangeDays = 400
		if errs := d.cleanupNormalizedEventTables(finite); len(errs) > 0 {
			t.Fatalf("cleanup 2: %v", errs)
		}
		if d.Gorm().Migrator().HasTable("sec_events_200001") {
			t.Fatal("expired sec_events leaf not dropped once both windows passed it")
		}
		if n := pgRows(t, d, "sec_events"); n != 1 {
			t.Fatalf("sec_events rows = %d, want 1 (the recent auth row)", n)
		}
	})

	t.Run("RollupMath", func(t *testing.T) {
		if err := d.Gorm().Exec(`TRUNCATE net_events, net_event_rollups`).Error; err != nil {
			t.Fatal(err)
		}
		d.Gorm().Exec(`DELETE FROM system_settings WHERE "key" IN (?, ?)`, netEventRollupWatermarkKey, netEventRollupClosedDayKey)
		// The fixture's days (2026-10-01..03) need leaves; they are older than
		// the lookback once this test is run later than November 2026, so the
		// rows would land in net_events_default — which the rollup reads through
		// the parent anyway. Nothing to arrange.
		runRollupScenario(t, d)
	})

	t.Run("V72ConvertsAnEmptyPlainTableLeftBehind", func(t *testing.T) {
		if err := d.Gorm().Exec(`DROP TABLE net_events`).Error; err != nil {
			t.Fatal(err)
		}
		if err := d.Gorm().AutoMigrate(&models.NetEvent{}); err != nil {
			t.Fatal(err)
		}
		if pgIsPartitioned(t, d, "net_events") {
			t.Fatal("precondition: plain table")
		}
		if err := d.migrateNormalizedEventTables(); err != nil {
			t.Fatalf("v72 re-run: %v", err)
		}
		if !pgIsPartitioned(t, d, "net_events") {
			t.Fatal("v72 re-run must convert an empty plain net_events left by an interrupted run")
		}
		if err := d.migrateNormalizedEventTables(); err != nil {
			t.Fatalf("v72 third run: %v", err)
		}
		// The existing-install path: no table at all when v72 runs (v1/v2 ran
		// long before the model existed) — created and converted in one go.
		if err := d.Gorm().Exec(`DROP TABLE sec_events`).Error; err != nil {
			t.Fatal(err)
		}
		if err := d.migrateNormalizedEventTables(); err != nil {
			t.Fatalf("v72 on an install without sec_events: %v", err)
		}
		if !pgIsPartitioned(t, d, "sec_events") {
			t.Fatal("v72 must create sec_events as a partitioned parent on an existing install")
		}
		if err := d.EnsurePartitions(); err != nil {
			t.Fatalf("EnsurePartitions after the fresh parent: %v", err)
		}
		if sec := pgLeaves(t, d, "sec_events"); len(sec) != 8 {
			t.Fatalf("fresh sec_events parent has %d children, want 8", len(sec))
		}
	})
}

func net4(s string) net.IP { return net.ParseIP(s) }

func mac(s string) net.HardwareAddr {
	m, _ := net.ParseMAC(s)
	return m
}

func joinCols(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += ","
		}
		out += c
	}
	return out
}
