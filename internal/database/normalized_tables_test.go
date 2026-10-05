package database

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm/schema"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
)

// v72 (Phase 1, S-3) unit tests on the SQLite lane. The Postgres-only pieces —
// daily leaves actually created, COPY routing, partition drops — are in
// normalized_pg_integration_test.go; the fixture and the rollup expectations
// below are shared with it so both backends are held to the same numbers.

// TestPartitionWindows pins the leaf plan: a daily table gets lookback..+7
// days of contiguous one-day leaves named <table>_YYYYMMDD; a monthly table
// keeps exactly the pre-v72 shape (current month + 6, <table>_YYYYMM).
func TestPartitionWindows(t *testing.T) {
	now := time.Date(2026, 10, 3, 15, 30, 0, 0, time.FixedZone("east", 12*3600))
	daily := partitionWindows(partitionDef{"net_events", "ts"}, now, 30)
	if len(daily) != 38 {
		t.Fatalf("daily windows = %d, want 38 (30 lookback + today + 7 lead)", len(daily))
	}
	// The anchor is the UTC day: 15:30 at +12 is 03:30Z on the 3rd.
	if daily[0].name != "net_events_20260903" || daily[30].name != "net_events_20261003" || daily[37].name != "net_events_20261010" {
		t.Fatalf("daily names = %s .. %s .. %s, want net_events_20260903 .. net_events_20261003 .. net_events_20261010",
			daily[0].name, daily[30].name, daily[37].name)
	}
	for i, w := range daily {
		if w.end.Sub(w.start) != 24*time.Hour || w.start.Location() != time.UTC || w.start.Hour() != 0 {
			t.Errorf("window %d [%s, %s) is not one UTC day", i, w.start, w.end)
		}
		if i > 0 && !daily[i-1].end.Equal(w.start) {
			t.Errorf("gap between %s and %s", daily[i-1].name, w.name)
		}
	}
	monthly := partitionWindows(partitionDef{"syslog_messages", "timestamp"}, now, 30)
	if len(monthly) != 7 || monthly[0].name != "syslog_messages_202610" || monthly[6].name != "syslog_messages_202704" {
		t.Fatalf("monthly windows = %d (%s .. %s), want 7 (syslog_messages_202610 .. syslog_messages_202704); a lookback must not apply to a monthly table",
			len(monthly), monthly[0].name, monthly[len(monthly)-1].name)
	}
	if !monthly[0].start.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || !monthly[0].end.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("first monthly window [%s, %s)", monthly[0].start, monthly[0].end)
	}
}

// TestPartitionLookbackDays pins that the daily lookback IS the net_events
// retention window Connect recorded (so the backfill never lands in the
// DEFAULT partition), 30 when nothing was recorded, and 0 for monthly tables.
func TestPartitionLookbackDays(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if got := d.partitionLookbackDays(partitionDef{"net_events", "ts"}); got != 30 {
		t.Fatalf("default lookback = %d, want 30", got)
	}
	d.netEventRetentionDays = 45
	if got := d.partitionLookbackDays(partitionDef{"net_events", "ts"}); got != 45 {
		t.Fatalf("lookback = %d, want the recorded retention 45", got)
	}
	if got := d.partitionLookbackDays(partitionDef{"sec_events", "ts"}); got != 0 {
		t.Fatalf("monthly lookback = %d, want 0", got)
	}
	ret := config.RetentionConfig{DefaultDays: 90}
	if ret.NetEventWindow() != 30 {
		t.Fatalf("NetEventWindow with 0 = %d, want 30 (never DefaultDays)", ret.NetEventWindow())
	}
	ret.NetEventDays = 14
	if ret.NetEventWindow() != 14 {
		t.Fatalf("NetEventWindow = %d, want 14", ret.NetEventWindow())
	}
}

// TestRegisteredMigrations_V72IsLast pins the version number the plan and
// CHANGELOG cite.
func TestRegisteredMigrations_V72IsLast(t *testing.T) {
	last := registeredMigrations[len(registeredMigrations)-1]
	if last.version != 72 || last.name != "normalized_event_tables" {
		t.Fatalf("last migration = {%d %q}, want {72 normalized_event_tables}", last.version, last.name)
	}
}

// TestMigrateV72_Idempotent (SQLite): the migration creates the five tables
// and a re-run changes nothing.
func TestMigrateV72_Idempotent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	for _, tbl := range []string{"net_events", "sec_events", "net_event_rollups", "fw_rules", "device_field_observed"} {
		if err := d.db.Exec("DROP TABLE IF EXISTS " + tbl).Error; err != nil {
			t.Fatal(err)
		}
	}
	for run := 1; run <= 2; run++ {
		if err := d.migrateNormalizedEventTables(); err != nil {
			t.Fatalf("v72 run %d: %v", run, err)
		}
		for _, m := range []interface{}{&models.NetEvent{}, &models.SecEvent{}, &models.NetEventRollup{}, &models.FwRule{}, &models.DeviceFieldObserved{}} {
			if !d.db.Migrator().HasTable(m) {
				t.Fatalf("run %d: table for %T missing", run, m)
			}
		}
	}
	// The partition machinery knows both event tables and the LC-19 plan
	// derives the five net_events leaf indexes from the model tags.
	plan, err := partitionIndexPlan(partitionDef{"net_events", "ts"})
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	for _, p := range plan {
		cols = append(cols, strings.Join(p.cols, ","))
	}
	want := []string{"device_id,ts", "ts", "rule_key,ts", "src_ip,ts", "dst_ip,ts"}
	if !reflect.DeepEqual(cols, want) {
		t.Fatalf("net_events leaf index plan = %v, want %v", cols, want)
	}
}

// TestNetEventsCopyColumns_MatchModel pins the COPY column list and the row
// renderer against the NetEvent model's own schema: every column but id, in
// field order, and one value slot per column. A column added to the model
// without a slot here fails this test rather than the first production COPY.
func TestNetEventsCopyColumns_MatchModel(t *testing.T) {
	var cache sync.Map
	sch, err := schema.Parse(&models.NetEvent{}, &cache, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, f := range sch.Fields {
		if f.DBName != "" && f.DBName != "id" {
			want = append(want, f.DBName)
		}
	}
	if !reflect.DeepEqual(netEventsCopyColumns, want) {
		t.Fatalf("netEventsCopyColumns =\n%v\nwant (model order, no id)\n%v", netEventsCopyColumns, want)
	}
	row := netEventCopyRow(&models.NetEvent{})
	if len(row) != len(netEventsCopyColumns) {
		t.Fatalf("netEventCopyRow renders %d values for %d columns", len(row), len(netEventsCopyColumns))
	}
}

// TestNetEventFromEvent_NullDiscipline pins NULL = not supplied, 0 = supplied
// zero, for every kind of column, plus the address renderings and the extra
// JSON cap.
func TestNetEventFromEvent_NullDiscipline(t *testing.T) {
	ts := time.Date(2026, 10, 1, 10, 5, 0, 0, time.UTC)
	bare := normalize.Event{Class: normalize.ClassNetwork, Activity: normalize.ActivityTraffic, Action: normalize.ActionDeny, Ts: ts, DeviceID: 7, ProbeID: 3}
	row := NetEventFromEvent(&bare, 0, time.Time{})
	if row.SrcIP != nil || row.SrcPort != nil || row.BytesIn != nil || row.RuleKey != nil || row.Direction != nil ||
		row.SrcRole != nil || row.Extra != nil || row.RawID != nil || row.RawTS != nil || row.SrcCountry != nil {
		t.Fatalf("unsupplied fields must be NULL: %+v", row)
	}
	if row.Action != int16(normalize.ActionDeny) || row.Activity != int16(normalize.ActivityTraffic) || row.DeviceID != 7 || row.ProbeID != 3 || !row.Ts.Equal(ts) {
		t.Fatalf("value columns: %+v", row)
	}

	zero := int64(0)
	port := int32(0)
	role := normalize.RoleWAN
	dir := normalize.DirectionInbound
	full := bare
	full.SrcIP = net.ParseIP("192.0.2.10")
	full.DstIP = net.ParseIP("2001:db8::7")
	full.SrcMAC, _ = net.ParseMAC("00:00:5e:00:53:0a")
	full.SrcPort = &port
	full.BytesIn = &zero
	full.SrcRole = &role
	full.Direction = &dir
	full.RuleKey = "u:4b5c6d7e-0000-0000-0000-00000000000c"
	full.Ruleset = "root"
	full.SrcCountry = "NL"
	full.Extra = map[string]string{"service": "HTTPS", "srccountry_raw": "Reserved"}
	row = NetEventFromEvent(&full, 4242, ts.Add(time.Second))
	if row.SrcIP == nil || *row.SrcIP != "192.0.2.10" || row.DstIP == nil || *row.DstIP != "2001:db8::7" || row.SrcMAC == nil || *row.SrcMAC != "00:00:5e:00:53:0a" {
		t.Fatalf("address renderings: src=%v dst=%v mac=%v", row.SrcIP, row.DstIP, row.SrcMAC)
	}
	if row.SrcPort == nil || *row.SrcPort != 0 || row.BytesIn == nil || *row.BytesIn != 0 {
		t.Fatalf("a supplied zero must stay 0, not NULL: port=%v bytes_in=%v", row.SrcPort, row.BytesIn)
	}
	if row.SrcRole == nil || *row.SrcRole != int16(models.IntfRoleWAN) || row.Direction == nil || *row.Direction != int16(normalize.DirectionInbound) {
		t.Fatalf("enum pointers: role=%v dir=%v", row.SrcRole, row.Direction)
	}
	if row.RawID == nil || *row.RawID != 4242 || row.RawTS == nil || !row.RawTS.Equal(ts.Add(time.Second)) {
		t.Fatalf("provenance: %v %v", row.RawID, row.RawTS)
	}
	var extra map[string]string
	if row.Extra == nil {
		t.Fatal("extra must be a JSON object")
	}
	if err := json.Unmarshal([]byte(*row.Extra), &extra); err != nil || extra["service"] != "HTTPS" || extra["srccountry_raw"] != "Reserved" {
		t.Fatalf("extra = %s (%v)", *row.Extra, err)
	}

	// The cap keeps the first sorted keys that fit and never emits broken JSON.
	big := map[string]string{}
	for i := 0; i < 40; i++ {
		big[fmt.Sprintf("k%02d", i)] = strings.Repeat("v", 60)
	}
	capped := extraJSON(big)
	if capped == nil || len(*capped) > netEventExtraMax || !json.Valid([]byte(*capped)) {
		t.Fatalf("capped extra: %v", capped)
	}
	var got map[string]string
	_ = json.Unmarshal([]byte(*capped), &got)
	if _, ok := got["k00"]; !ok || len(got) >= 40 {
		t.Fatalf("cap should keep the first sorted keys and drop the rest; kept %d", len(got))
	}
}

// TestSecEventFromEvent_MessageCapAndAddresses pins the sec_events mapping
// specifics: the class column, the 512-byte message cap on a rune boundary,
// and an admin source address that is only stored when it parses.
func TestSecEventFromEvent_MessageCapAndAddresses(t *testing.T) {
	ev := normalize.Event{Class: normalize.ClassConfigChange, Activity: normalize.ActivityUpdate, Action: normalize.ActionAllow,
		Ts: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), DeviceID: 1,
		AdminUser: "alice", AdminSrcIP: "192.0.2.50", AdminMethod: "gui", ConfigPath: "firewall.policy",
		Message: strings.Repeat("é", 300)} // 600 bytes of 2-byte runes
	row := SecEventFromEvent(&ev, 0, time.Time{})
	if row.Class != int16(normalize.ClassConfigChange) || row.AdminUser == nil || *row.AdminUser != "alice" || row.AdminSrcIP == nil || *row.AdminSrcIP != "192.0.2.50" {
		t.Fatalf("mapping: %+v", row)
	}
	if row.Message == nil || len(*row.Message) != 512 || strings.Count(*row.Message, "é") != 256 {
		t.Fatalf("message cap: len=%d", len(*row.Message))
	}
	ev.AdminSrcIP = "console"
	if row := SecEventFromEvent(&ev, 0, time.Time{}); row.AdminSrcIP != nil {
		t.Fatalf("a non-address admin source must be NULL in an inet column, got %q", *row.AdminSrcIP)
	}
}

// TestSaveNetEvents_SQLiteFallback round-trips the GORM path (no pgx pool):
// the mapping's rows land and read back with their NULLs intact, and
// SaveSecEvents does the same for the other classes.
func TestSaveNetEvents_SQLiteFallback(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if d.pgxPool != nil {
		t.Fatal("test harness must have no pgx pool")
	}
	rows, _ := rollupFixture()
	if err := d.SaveNetEvents(rows); err != nil {
		t.Fatalf("SaveNetEvents: %v", err)
	}
	var got []models.NetEvent
	if err := d.db.Order("ts").Find(&got).Error; err != nil {
		t.Fatal(err)
	}
	if len(got) != len(rows) {
		t.Fatalf("read back %d rows, want %d", len(got), len(rows))
	}
	if got[0].RuleKey == nil || *got[0].RuleKey != "u:a" || got[0].Direction == nil || got[3].RuleKey != nil || got[3].Direction != nil || got[3].BytesIn != nil {
		t.Fatalf("NULLs did not survive the round trip: %+v / %+v", got[0], got[3])
	}
	if err := d.SaveSecEvents([]models.SecEvent{{Ts: time.Now().UTC(), DeviceID: 1, Class: int16(normalize.ClassAuth)}}); err != nil {
		t.Fatalf("SaveSecEvents: %v", err)
	}
	var n int64
	d.db.Model(&models.SecEvent{}).Count(&n)
	if n != 1 {
		t.Fatalf("sec_events rows = %d, want 1", n)
	}
	if err := d.SaveNetEvents(nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
}

// TestUpsertFwRules_MergeAndGreatest: duplicates in one batch merge, a
// second batch keeps first_seen, advances last_seen, fills a name learned
// later and never downgrades the source.
func TestUpsertFwRules_MergeAndGreatest(t *testing.T) {
	d := NewDatabaseForTesting(t)
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	id := int64(12)
	ev := normalize.Event{DeviceID: 1, RuleKey: "i:root/12", RuleID: &id, Ruleset: "root"}
	r1, ok := FwRuleFromEvent(&ev, t0)
	if !ok {
		t.Fatal("event with a rule key must yield a catalog row")
	}
	if _, ok := FwRuleFromEvent(&normalize.Event{DeviceID: 1}, t0); ok {
		t.Fatal("event without a rule key must not yield a catalog row")
	}
	r2, _ := FwRuleFromEvent(&ev, t0.Add(time.Hour))
	if err := d.UpsertFwRules([]models.FwRule{r1, r2, r1}); err != nil {
		t.Fatalf("UpsertFwRules: %v", err)
	}
	// Later: the API poller learns the name (source 3) with an OLDER sighting.
	name := "LAN-to-WAN"
	later := models.FwRule{DeviceID: 1, RuleKey: "i:root/12", RuleName: &name, Source: models.FwRuleSourceAPI,
		FirstSeen: t0.Add(-time.Hour), LastSeen: t0.Add(-time.Hour)}
	if err := d.UpsertFwRules([]models.FwRule{later}); err != nil {
		t.Fatalf("UpsertFwRules 2: %v", err)
	}
	// The older sighting must not move last_seen backwards (GREATEST, not
	// "last write wins") while first_seen does move earlier (LEAST).
	var mid models.FwRule
	if err := d.db.First(&mid).Error; err != nil {
		t.Fatal(err)
	}
	if !mid.LastSeen.Equal(t0.Add(time.Hour)) || !mid.FirstSeen.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("after the older API sighting: first_seen=%s last_seen=%s, want %s / %s", mid.FirstSeen, mid.LastSeen, t0.Add(-time.Hour), t0.Add(time.Hour))
	}
	// And a log sighting afterwards must not downgrade the source or lose the name.
	r3, _ := FwRuleFromEvent(&ev, t0.Add(2*time.Hour))
	if err := d.UpsertFwRules([]models.FwRule{r3}); err != nil {
		t.Fatalf("UpsertFwRules 3: %v", err)
	}
	var rows []models.FwRule
	if err := d.db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("fw_rules rows = %d, want 1 (one per device+rule_key)", len(rows))
	}
	got := rows[0]
	if !got.FirstSeen.Equal(t0.Add(-time.Hour)) || !got.LastSeen.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("first_seen=%s last_seen=%s", got.FirstSeen, got.LastSeen)
	}
	if got.RuleName == nil || *got.RuleName != name || got.Source != models.FwRuleSourceAPI || got.RuleID == nil || *got.RuleID != 12 || got.Ruleset == nil || *got.Ruleset != "root" {
		t.Fatalf("merged row: %+v", got)
	}
}

// TestFlushFieldObserved_Accumulates: counts add across flushes (and within
// one), last_seen keeps the latest.
func TestFlushFieldObserved_Accumulates(t *testing.T) {
	d := NewDatabaseForTesting(t)
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	cls := int16(normalize.ClassNetwork)
	batch := []models.DeviceFieldObserved{
		{DeviceID: 1, Class: cls, Field: "bytes_in", Count: 5, LastSeen: t0},
		{DeviceID: 1, Class: cls, Field: "bytes_in", Count: 2, LastSeen: t0.Add(time.Minute)},
		{DeviceID: 1, Class: cls, Field: "rule_uid", Count: 1, LastSeen: t0},
	}
	if err := d.FlushFieldObserved(batch); err != nil {
		t.Fatal(err)
	}
	if err := d.FlushFieldObserved([]models.DeviceFieldObserved{{DeviceID: 1, Class: cls, Field: "bytes_in", Count: 3, LastSeen: t0.Add(-time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	var rows []models.DeviceFieldObserved
	if err := d.db.Order("field").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Count != 10 || !rows[0].LastSeen.Equal(t0.Add(time.Minute)) || rows[1].Count != 1 {
		t.Fatalf("rows = %+v", rows)
	}
}

// rollupFixture is the net_events set the rollup tests on BOTH backends run
// against, with the rows the rollup must produce after a full cycle at
// rollupFixtureNow (hour folds for every complete hour, exact day close for
// 2026-10-01 and 2026-10-02). Synthetic addresses only (RFC 5737).
//
//	2026-10-01 (closed): device 1
//	  u:a / allow / outbound / Web / root: 10:05 src .1 100/10, 10:20 src .2 200/20, 11:15 src .3 300/30
//	  (no rule) / deny / - / - / -:       10:30 src .9, 10:31 src .9 (no byte counters)
//	2026-10-02 (closed): device 2
//	  i:root/12 / allow / - / - / root:    23:40 src .20 50/5
//	2026-10-03 (open): device 2
//	  i:root/12 / allow / - / - / root:    09:30 src .21 70/7   <- hour 09 is complete at 12:00, folded
//	                                       11:50 src .22 90/9   <- inside the 15-min lag, NOT folded
var rollupFixtureNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func rollupFixture() ([]models.NetEvent, []models.NetEventRollup) {
	d1 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	d2 := d1.AddDate(0, 0, 1)
	d3 := d1.AddDate(0, 0, 2)
	str := func(s string) *string { return &s }
	i64 := func(n int64) *int64 { return &n }
	dir := int16(normalize.DirectionOutbound)
	ev := func(ts time.Time, dev uint, rule *string, action normalize.Action, direction *int16, appCat, ruleset *string, src string, in, out *int64) models.NetEvent {
		return models.NetEvent{Ts: ts, DeviceID: dev, Activity: int16(normalize.ActivityTraffic), Action: int16(action),
			RuleKey: rule, Direction: direction, AppCat: appCat, Ruleset: ruleset, SrcIP: str(src), BytesIn: in, BytesOut: out}
	}
	rows := []models.NetEvent{
		ev(d1.Add(10*time.Hour+5*time.Minute), 1, str("u:a"), normalize.ActionAllow, &dir, str("Web"), str("root"), "192.0.2.1", i64(100), i64(10)),
		ev(d1.Add(10*time.Hour+20*time.Minute), 1, str("u:a"), normalize.ActionAllow, &dir, str("Web"), str("root"), "192.0.2.2", i64(200), i64(20)),
		ev(d1.Add(11*time.Hour+15*time.Minute), 1, str("u:a"), normalize.ActionAllow, &dir, str("Web"), str("root"), "192.0.2.3", i64(300), i64(30)),
		ev(d1.Add(10*time.Hour+30*time.Minute), 1, nil, normalize.ActionDeny, nil, nil, nil, "192.0.2.9", nil, nil),
		ev(d1.Add(10*time.Hour+31*time.Minute), 1, nil, normalize.ActionDeny, nil, nil, nil, "192.0.2.9", nil, nil),
		ev(d2.Add(23*time.Hour+40*time.Minute), 2, str("i:root/12"), normalize.ActionAllow, nil, nil, str("root"), "192.0.2.20", i64(50), i64(5)),
		ev(d3.Add(9*time.Hour+30*time.Minute), 2, str("i:root/12"), normalize.ActionAllow, nil, nil, str("root"), "192.0.2.21", i64(70), i64(7)),
		ev(d3.Add(11*time.Hour+50*time.Minute), 2, str("i:root/12"), normalize.ActionAllow, nil, nil, str("root"), "192.0.2.22", i64(90), i64(9)),
	}
	want := []models.NetEventRollup{
		{Day: d1, DeviceID: 1, RuleKey: "", Action: int16(normalize.ActionDeny), Direction: 0, AppCat: "", Ruleset: "",
			Hits: 2, BytesIn: 0, BytesOut: 0, DistinctSrc: 1, LastTs: d1.Add(10*time.Hour + 31*time.Minute)},
		{Day: d1, DeviceID: 1, RuleKey: "u:a", Action: int16(normalize.ActionAllow), Direction: dir, AppCat: "Web", Ruleset: "root",
			Hits: 3, BytesIn: 600, BytesOut: 60, DistinctSrc: 3, LastTs: d1.Add(11*time.Hour + 15*time.Minute)},
		{Day: d2, DeviceID: 2, RuleKey: "i:root/12", Action: int16(normalize.ActionAllow), Direction: 0, AppCat: "", Ruleset: "root",
			Hits: 1, BytesIn: 50, BytesOut: 5, DistinctSrc: 1, LastTs: d2.Add(23*time.Hour + 40*time.Minute)},
		{Day: d3, DeviceID: 2, RuleKey: "i:root/12", Action: int16(normalize.ActionAllow), Direction: 0, AppCat: "", Ruleset: "root",
			Hits: 1, BytesIn: 70, BytesOut: 7, DistinctSrc: 1, LastTs: d3.Add(9*time.Hour + 30*time.Minute)},
	}
	return rows, want
}

// checkRollups compares the rollup table with the expected rows, ignoring id.
func checkRollups(t *testing.T, d *Database, want []models.NetEventRollup) {
	t.Helper()
	var got []models.NetEventRollup
	if err := d.db.Order("day, device_id, rule_key").Find(&got).Error; err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("rollup rows = %d, want %d:\n%s", len(got), len(want), dumpRollups(got))
	}
	for i := range want {
		g, w := got[i], want[i]
		if !g.Day.Equal(w.Day) || g.DeviceID != w.DeviceID || g.RuleKey != w.RuleKey || g.Action != w.Action || g.Direction != w.Direction ||
			g.AppCat != w.AppCat || g.Ruleset != w.Ruleset || g.Hits != w.Hits || g.BytesIn != w.BytesIn || g.BytesOut != w.BytesOut ||
			g.DistinctSrc != w.DistinctSrc || !g.LastTs.Equal(w.LastTs) {
			t.Errorf("rollup row %d:\n got %s\nwant %s", i, dumpRollups([]models.NetEventRollup{g}), dumpRollups([]models.NetEventRollup{w}))
		}
	}
}

func dumpRollups(rows []models.NetEventRollup) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "  %s dev=%d rule=%q action=%d dir=%d app=%q ruleset=%q hits=%d in=%d out=%d distinct=%d last=%s\n",
			r.Day.Format("2006-01-02"), r.DeviceID, r.RuleKey, r.Action, r.Direction, r.AppCat, r.Ruleset, r.Hits, r.BytesIn, r.BytesOut, r.DistinctSrc, r.LastTs.UTC().Format(time.RFC3339))
	}
	return b.String()
}

// runRollupScenario drives the fixture through the rollup on whichever
// backend d is: additive hour folds first (while the day is still open), then
// the exact day close, idempotency, and the S-5 rewind. Shared with the
// Postgres integration test.
func runRollupScenario(t *testing.T, d *Database) {
	t.Helper()
	rows, want := rollupFixture()
	if err := d.SaveNetEvents(rows); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Force the multi-statement upsert path: one INSERT per group.
	orig := netEventRollupInsertBatch
	netEventRollupInsertBatch = 1
	defer func() { netEventRollupInsertBatch = orig }()

	// Still inside 2026-10-01: only the hour folds run (limit 12:00), and the
	// two folded hours ADD into one day row; distinct_src is the per-hour max.
	hours, days, err := d.runNetEventRollupCycle(time.Date(2026, 10, 1, 12, 20, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if hours != 2 || days != 0 {
		t.Fatalf("cycle 1 folded %d hours, closed %d days; want 2 / 0", hours, days)
	}
	open := []models.NetEventRollup{want[0], want[1]}
	open[1].DistinctSrc = 2 // hours 10 (2 sources) and 11 (1 source): the lower bound
	checkRollups(t, d, open)
	if wm, ok, _ := d.netEventRollupWatermark(); !ok || !wm.Equal(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("watermark after cycle 1 = %v %v, want 2026-10-01T12:00Z", wm, ok)
	}

	// Two days later: the empty hours are jumped, every complete hour is
	// folded, and the two complete days are recomputed exactly.
	if _, days, err = d.runNetEventRollupCycle(rollupFixtureNow); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if days != 2 {
		t.Fatalf("cycle 2 closed %d days, want 2", days)
	}
	checkRollups(t, d, want)
	if wm, _, _ := d.netEventRollupWatermark(); !wm.Equal(time.Date(2026, 10, 3, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("watermark after cycle 2 = %s, want 2026-10-03T11:00Z (the 11:50 row is inside the lag)", wm)
	}
	if closed, ok, _ := d.netEventRollupClosedDay(); !ok || closed.Format("2006-01-02") != "2026-10-02" {
		t.Fatalf("closed day = %v %v, want 2026-10-02", closed, ok)
	}

	// Idempotent: the same instant again changes nothing.
	if hours, days, err = d.runNetEventRollupCycle(rollupFixtureNow); err != nil || hours != 0 || days != 0 {
		t.Fatalf("cycle 3 (repeat): hours=%d days=%d err=%v, want 0/0/nil", hours, days, err)
	}
	checkRollups(t, d, want)

	// A row arriving late for a closed day is not folded by the hour step (the
	// watermark is past it); the S-5 rewind of the closed-day marker makes the
	// next cycle recompute that day exactly.
	late := rows[0]
	late.ID = 0 // SaveNetEvents filled the ids on the GORM path
	late.Ts = late.Ts.Add(2 * time.Minute)
	late.SrcIP = nil
	if err := d.SaveNetEvents([]models.NetEvent{late}); err != nil {
		t.Fatal(err)
	}
	if err := d.setSetting(d.db, netEventRollupClosedDayKey, "2026-09-30"); err != nil {
		t.Fatal(err)
	}
	if _, days, err = d.runNetEventRollupCycle(rollupFixtureNow); err != nil || days != 2 {
		t.Fatalf("cycle 4 (rewind): days=%d err=%v, want 2", days, err)
	}
	rewound := make([]models.NetEventRollup, len(want))
	copy(rewound, want)
	rewound[1].Hits = 4
	rewound[1].BytesIn = 700
	rewound[1].BytesOut = 70
	checkRollups(t, d, rewound)
}

// TestNetEventRollup_SQLite runs the shared scenario on the SQLite lane.
func TestNetEventRollup_SQLite(t *testing.T) {
	runRollupScenario(t, NewDatabaseForTesting(t))
}

// TestNetEventRollup_EmptyTableIsQuiet: no events, no settings written.
func TestNetEventRollup_EmptyTableIsQuiet(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if h, dd, err := d.runNetEventRollupCycle(rollupFixtureNow); err != nil || h != 0 || dd != 0 {
		t.Fatalf("hours=%d days=%d err=%v", h, dd, err)
	}
	if _, ok, _ := d.netEventRollupWatermark(); ok {
		t.Fatal("an empty table must not create a watermark")
	}
}

// TestCleanupSecEvents_ConfigChangeKeptForever: with the default
// RETENTION_SEC_CONFIG_CHANGE_DAYS=0 the per-class delete removes the expired
// finding and keeps the equally old config_change; a finite window removes it.
func TestCleanupSecEvents_ConfigChangeKeptForever(t *testing.T) {
	d := NewDatabaseForTesting(t)
	old := time.Now().UTC().AddDate(0, 0, -400)
	seed := []models.SecEvent{
		{Ts: old, DeviceID: 1, Class: int16(normalize.ClassFinding)},
		{Ts: old, DeviceID: 1, Class: int16(normalize.ClassConfigChange)},
		{Ts: time.Now().UTC().AddDate(0, 0, -10), DeviceID: 1, Class: int16(normalize.ClassFinding)},
	}
	if err := d.SaveSecEvents(seed); err != nil {
		t.Fatal(err)
	}
	if err := d.db.Create(&models.NetEventRollup{Day: utcDay(old), DeviceID: 1, Hits: 1, LastTs: old}).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.db.Create(&models.NetEventRollup{Day: utcDay(time.Now().UTC().AddDate(0, 0, -10)), DeviceID: 1, Hits: 1, LastTs: old}).Error; err != nil {
		t.Fatal(err)
	}
	ret := config.RetentionConfig{SecEventDays: 365, NetEventRollupDays: 365}
	if errs := d.cleanupNormalizedEventTables(ret); len(errs) > 0 {
		t.Fatalf("cleanup: %v", errs)
	}
	var classes []int16
	if err := d.db.Model(&models.SecEvent{}).Order("ts").Pluck("class", &classes).Error; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(classes, []int16{int16(normalize.ClassConfigChange), int16(normalize.ClassFinding)}) {
		t.Fatalf("surviving classes = %v, want [config_change (old), finding (recent)]", classes)
	}
	var rollups int64
	d.db.Model(&models.NetEventRollup{}).Count(&rollups)
	if rollups != 1 {
		t.Fatalf("rollup rows after cleanup = %d, want 1 (the 400-day row dropped)", rollups)
	}

	ret.SecConfigChangeDays = 30
	if errs := d.cleanupNormalizedEventTables(ret); len(errs) > 0 {
		t.Fatalf("cleanup 2: %v", errs)
	}
	classes = nil
	d.db.Model(&models.SecEvent{}).Pluck("class", &classes)
	if !reflect.DeepEqual(classes, []int16{int16(normalize.ClassFinding)}) {
		t.Fatalf("with a finite config_change window, surviving classes = %v, want [finding (recent)]", classes)
	}
}

// TestCleanupOldData_NeverRowDeletesNetEvents: net_events retention is
// partition-drop only, so on a backend without partitions (SQLite here; a
// plain, unconverted table on Postgres) CleanupOldData leaves the rows alone
// rather than running a batched DELETE over the biggest table.
func TestCleanupOldData_NeverRowDeletesNetEvents(t *testing.T) {
	d := NewDatabaseForTesting(t)
	old := time.Now().UTC().AddDate(0, 0, -400)
	if err := d.SaveNetEvents([]models.NetEvent{{Ts: old, DeviceID: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := d.CleanupOldData(config.RetentionConfig{DefaultDays: 90, NetEventDays: 30}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}
	var n int64
	d.db.Model(&models.NetEvent{}).Count(&n)
	if n != 1 {
		t.Fatalf("net_events rows = %d, want 1 (no row DELETE on net_events)", n)
	}
}
