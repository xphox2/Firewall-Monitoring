package database

import (
	"errors"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Helpers for seeding the SQLite test lane with a minimal device/site/probe
// and net_events rows.

func seedNetEventSite(t *testing.T, db *Database, name string) *models.Site {
	t.Helper()
	site := &models.Site{Name: name}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	return site
}

func seedNetEventDevice(t *testing.T, db *Database, name string, siteID *uint) *models.Device {
	t.Helper()
	dev := &models.Device{Name: name, IPAddress: "10.0.0.1", Vendor: "fortigate", SiteID: siteID}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return dev
}

func seedNetEventProbe(t *testing.T, db *Database, name string) *models.Probe {
	t.Helper()
	probe := &models.Probe{Name: name, RegistrationKey: "k-" + name, ApprovalStatus: "approved", Status: "online"}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	return probe
}

// seedNetEventRow inserts one net_events row with the given identity/verdict.
// Most pointer columns are left nil (the "vendor did not supply it" case),
// which is what the read path must tolerate.
func seedNetEventRow(t *testing.T, db *Database, devID, probeID uint, ts time.Time, activity, action int16) {
	t.Helper()
	row := &models.NetEvent{
		Ts:       ts,
		DeviceID: devID,
		ProbeID:  probeID,
		Activity: activity,
		Action:   action,
	}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed net_event: %v", err)
	}
}

func TestListNetEvents_OrdersNewestFirst(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()
	for i := 0; i < 5; i++ {
		seedNetEventRow(t, db, dev.ID, 0, now.Add(-time.Duration(i)*time.Minute), 3, 1)
	}

	rows, total, capped, err := db.ListNetEvents(NetEventFilter{Hours: 24}, 0, 100)
	if err != nil {
		t.Fatalf("ListNetEvents: %v", err)
	}
	if capped {
		t.Fatalf("capped = true for 5 rows")
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5", total)
	}
	if len(rows) != 5 {
		t.Fatalf("len(rows) = %d, want 5", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Ts.Before(rows[i].Ts) {
			t.Fatalf("rows not ordered newest-first at index %d (%v before %v)", i, rows[i-1].Ts, rows[i].Ts)
		}
	}
	// Enrichment resolved the device name/vendor.
	if rows[0].DeviceName != "fw-1" || rows[0].Vendor != "fortigate" {
		t.Fatalf("enrichment = %q/%q, want fw-1/fortigate", rows[0].DeviceName, rows[0].Vendor)
	}
}

func TestListNetEvents_TsBounded(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()
	seedNetEventRow(t, db, dev.ID, 0, now.Add(-1*time.Hour), 3, 1)  // inside 24h
	seedNetEventRow(t, db, dev.ID, 0, now.Add(-48*time.Hour), 3, 1) // outside 24h

	rows, total, _, err := db.ListNetEvents(NetEventFilter{Hours: 24}, 0, 100)
	if err != nil {
		t.Fatalf("ListNetEvents: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("24h window = %d rows (total %d), want 1: the older row must be excluded by ts >= cutoff", len(rows), total)
	}

	rows72, total72, _, err := db.ListNetEvents(NetEventFilter{Hours: 72}, 0, 100)
	if err != nil {
		t.Fatalf("ListNetEvents 72h: %v", err)
	}
	if total72 != 2 || len(rows72) != 2 {
		t.Fatalf("72h window = %d rows (total %d), want 2", len(rows72), total72)
	}
}

func TestListNetEvents_Filters(t *testing.T) {
	db := NewDatabaseForTesting(t)
	siteA := seedNetEventSite(t, db, "site-a")
	siteB := seedNetEventSite(t, db, "site-b")
	devA := seedNetEventDevice(t, db, "fw-a", &siteA.ID)
	devB := seedNetEventDevice(t, db, "fw-b", &siteB.ID)
	probe1 := seedNetEventProbe(t, db, "probe-1")
	probe2 := seedNetEventProbe(t, db, "probe-2")
	now := time.Now()

	// devA: probe1, activity=open(1), action=allow(1)
	seedNetEventRow(t, db, devA.ID, probe1.ID, now, 1, 1)
	// devA: probe1, activity=traffic(3), action=deny(2)
	seedNetEventRow(t, db, devA.ID, probe1.ID, now.Add(-time.Minute), 3, 2)
	// devB: probe2, activity=open(1), action=allow(1)
	seedNetEventRow(t, db, devB.ID, probe2.ID, now.Add(-2*time.Minute), 1, 1)

	activity := int16(1)
	action := int16(2)

	cases := []struct {
		name   string
		filter NetEventFilter
		want   int64
	}{
		{"device", NetEventFilter{Hours: 24, DeviceID: devA.ID}, 2},
		{"probe", NetEventFilter{Hours: 24, ProbeID: probe2.ID}, 1},
		{"site", NetEventFilter{Hours: 24, SiteID: siteB.ID}, 1},
		{"activity", NetEventFilter{Hours: 24, Activity: &activity}, 2},
		{"action", NetEventFilter{Hours: 24, Action: &action}, 1},
		{"device+activity", NetEventFilter{Hours: 24, DeviceID: devA.ID, Activity: &activity}, 1},
	}
	for _, tc := range cases {
		_, total, _, err := db.ListNetEvents(tc.filter, 0, 100)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if total != tc.want {
			t.Fatalf("%s: total = %d, want %d", tc.name, total, tc.want)
		}
	}
}

func TestListNetEvents_EndpointAndRuleFilters(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()

	srcA, srcB := "10.0.0.5", "10.0.0.6"
	dstA := "192.168.1.10"
	ruleA, ruleB := "u:a", "u:b"

	seed := func(ts time.Time, src, dst, rule string) {
		row := &models.NetEvent{
			Ts: ts, DeviceID: dev.ID, ProbeID: 0, Activity: 3, Action: 1,
			SrcIP: &src, DstIP: &dst, RuleKey: &rule,
		}
		if err := db.Gorm().Create(row).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(now, srcA, dstA, ruleA)
	seed(now.Add(-time.Minute), srcA, dstA, ruleB)
	seed(now.Add(-2*time.Minute), srcB, dstA, ruleA)
	seed(now.Add(-3*time.Minute), srcA, dstA, ruleA)

	// On the SQLite lane inet is text, so a CIDR filter is an octet-aligned
	// prefix SUPERSET (10.0.0.0/24 matches every 10.0.0.*); exact equality is
	// the same on both lanes. Postgres uses exact containment instead (the
	// integration test covers it).
	cases := []struct {
		name   string
		filter NetEventFilter
		want   int64
	}{
		{"src_ip exact", NetEventFilter{Hours: 24, SrcIP: "10.0.0.5"}, 3},
		{"src_ip /24 superset", NetEventFilter{Hours: 24, SrcIP: "10.0.0.0/24"}, 4},
		{"dst_ip exact", NetEventFilter{Hours: 24, DstIP: "192.168.1.10"}, 4},
		{"dst_ip absent", NetEventFilter{Hours: 24, DstIP: "192.168.1.11"}, 0},
		{"rule_key exact", NetEventFilter{Hours: 24, RuleKey: "u:a"}, 3},
		{"rule_key other", NetEventFilter{Hours: 24, RuleKey: "u:b"}, 1},
		{"src+rule", NetEventFilter{Hours: 24, SrcIP: "10.0.0.5", RuleKey: "u:a"}, 2},
	}
	for _, tc := range cases {
		_, total, _, err := db.ListNetEvents(tc.filter, 0, 100)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if total != tc.want {
			t.Fatalf("%s: total = %d, want %d", tc.name, total, tc.want)
		}
	}
}

func TestListNetEvents_PageBounds(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()
	for i := 0; i < 10; i++ {
		seedNetEventRow(t, db, dev.ID, 0, now.Add(-time.Duration(i)*time.Minute), 3, 1)
	}

	rows, total, _, err := db.ListNetEvents(NetEventFilter{Hours: 24}, 3, 4)
	if err != nil {
		t.Fatalf("ListNetEvents: %v", err)
	}
	if total != 10 {
		t.Fatalf("total = %d, want 10 (offset/limit must not affect the count)", total)
	}
	if len(rows) != 4 {
		t.Fatalf("page len = %d, want 4", len(rows))
	}
	if rows[0].Ts.After(now) || rows[0].Ts.Before(now.Add(-10*time.Minute)) {
		t.Fatalf("unexpected first page row ts %v", rows[0].Ts)
	}
	// Offset 3 skips the three newest; the page holds the 4th..7th newest.
	if rows[0].Ts.Before(rows[3].Ts) {
		t.Fatalf("page not ordered newest-first")
	}
}

func TestListNetEvents_CountCapped(t *testing.T) {
	db := NewDatabaseForTesting(t)
	// Shrink the cap so the test seeds a handful of rows instead of 10,001
	// (the production value). Mirrors the package-var shrink pattern in
	// net_event_index_trim.go.
	old := netEventPagerCountCap
	netEventPagerCountCap = 10
	t.Cleanup(func() { netEventPagerCountCap = old })

	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()
	for i := 0; i < 15; i++ {
		seedNetEventRow(t, db, dev.ID, 0, now.Add(-time.Duration(i)*time.Minute), 3, 1)
	}

	_, total, capped, err := db.ListNetEvents(NetEventFilter{Hours: 24}, 0, 100)
	if err != nil {
		t.Fatalf("ListNetEvents: %v", err)
	}
	if !capped {
		t.Fatalf("capped = false with 15 rows over a 10-row cap")
	}
	if total != int64(netEventPagerCountCap) {
		t.Fatalf("capped total = %d, want %d", total, netEventPagerCountCap)
	}
}

// sec class ids from internal/normalize/enums.go (mirrored in
// cmd/api/static/js/enums.js). Literal here so the test does not import the
// normalize package.
const (
	secClassFinding      = int16(2004)
	secClassAuth         = int16(3002)
	secClassConfigChange = int16(5019)
	secClassVPNSession   = int16(4014)
	secClassDeviceHealth = int16(5001)
)

// seedSecEventRow inserts one sec_events row with the given identity/class and
// an optional severity. Pointer columns are left nil unless the caller seeds
// them inline, which is the "vendor did not supply it" case the read path must
// tolerate.
func seedSecEventRow(t *testing.T, db *Database, devID, probeID uint, ts time.Time, class int16, severity *int16) {
	t.Helper()
	row := &models.SecEvent{Ts: ts, DeviceID: devID, ProbeID: probeID, Class: class, Severity: severity}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed sec_event: %v", err)
	}
}

func TestListSecEvents_OrdersNewestFirst(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()
	sev := int16(7)
	for i := 0; i < 5; i++ {
		seedSecEventRow(t, db, dev.ID, 0, now.Add(-time.Duration(i)*time.Minute), secClassFinding, &sev)
	}

	rows, total, capped, err := db.ListSecEvents(SecEventFilter{Hours: 24}, 0, 100)
	if err != nil {
		t.Fatalf("ListSecEvents: %v", err)
	}
	if capped {
		t.Fatalf("capped = true for 5 rows")
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5", total)
	}
	if len(rows) != 5 {
		t.Fatalf("len(rows) = %d, want 5", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Ts.Before(rows[i].Ts) {
			t.Fatalf("rows not ordered newest-first at index %d (%v before %v)", i, rows[i-1].Ts, rows[i].Ts)
		}
	}
	// Enrichment resolved the device name/vendor, and the class/severity columns
	// round-tripped through the explicit SELECT.
	if rows[0].DeviceName != "fw-1" || rows[0].Vendor != "fortigate" {
		t.Fatalf("enrichment = %q/%q, want fw-1/fortigate", rows[0].DeviceName, rows[0].Vendor)
	}
	if rows[0].Class != secClassFinding || rows[0].Severity == nil || *rows[0].Severity != 7 {
		t.Fatalf("row class/severity = %d/%v, want 2004/7", rows[0].Class, rows[0].Severity)
	}
}

func TestListSecEvents_TsBounded(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()
	seedSecEventRow(t, db, dev.ID, 0, now.Add(-1*time.Hour), secClassAuth, nil)  // inside 24h
	seedSecEventRow(t, db, dev.ID, 0, now.Add(-48*time.Hour), secClassAuth, nil) // outside 24h

	rows, total, _, err := db.ListSecEvents(SecEventFilter{Hours: 24}, 0, 100)
	if err != nil {
		t.Fatalf("ListSecEvents: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("24h window = %d rows (total %d), want 1: the older row must be excluded by ts >= cutoff", len(rows), total)
	}

	rows72, total72, _, err := db.ListSecEvents(SecEventFilter{Hours: 72}, 0, 100)
	if err != nil {
		t.Fatalf("ListSecEvents 72h: %v", err)
	}
	if total72 != 2 || len(rows72) != 2 {
		t.Fatalf("72h window = %d rows (total %d), want 2", len(rows72), total72)
	}
}

func TestListSecEvents_Filters(t *testing.T) {
	db := NewDatabaseForTesting(t)
	devA := seedNetEventDevice(t, db, "fw-a", nil)
	devB := seedNetEventDevice(t, db, "fw-b", nil)
	probe1 := seedNetEventProbe(t, db, "probe-1")
	probe2 := seedNetEventProbe(t, db, "probe-2")
	now := time.Now()
	sevHigh, sevLow := int16(9), int16(2)

	// devA/probe1: finding severity 9; auth severity 2.
	seedSecEventRow(t, db, devA.ID, probe1.ID, now, secClassFinding, &sevHigh)
	seedSecEventRow(t, db, devA.ID, probe1.ID, now.Add(-time.Minute), secClassAuth, &sevLow)
	// devB/probe2: finding severity 9.
	seedSecEventRow(t, db, devB.ID, probe2.ID, now.Add(-2*time.Minute), secClassFinding, &sevHigh)

	class := secClassFinding
	activity := int16(0)

	cases := []struct {
		name   string
		filter SecEventFilter
		want   int64
	}{
		{"device", SecEventFilter{Hours: 24, DeviceID: devA.ID}, 2},
		{"probe", SecEventFilter{Hours: 24, ProbeID: probe2.ID}, 1},
		{"class", SecEventFilter{Hours: 24, Class: &class}, 2},
		{"severity", SecEventFilter{Hours: 24, Severity: &sevHigh}, 2},
		{"severity low", SecEventFilter{Hours: 24, Severity: &sevLow}, 1},
		{"activity 0 (real value)", SecEventFilter{Hours: 24, Activity: &activity}, 3},
		{"device+class", SecEventFilter{Hours: 24, DeviceID: devA.ID, Class: &class}, 1},
	}
	for _, tc := range cases {
		_, total, _, err := db.ListSecEvents(tc.filter, 0, 100)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if total != tc.want {
			t.Fatalf("%s: total = %d, want %d", tc.name, total, tc.want)
		}
	}
}

func TestListSecEvents_TextFilters(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()

	seed := func(ts time.Time, class int16, adminUser, sigName, tunnelName, wanName *string) {
		row := &models.SecEvent{Ts: ts, DeviceID: dev.ID, Class: class, AdminUser: adminUser, SigName: sigName, TunnelName: tunnelName, WANName: wanName}
		if err := db.Gorm().Create(row).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	admin := "admin-ops"
	sig := "MALWARE-Foo.ABC"
	tunnel := "tunnel-east"
	wan := "wan1"

	seed(now, secClassAuth, &admin, nil, nil, nil)
	seed(now.Add(-time.Minute), secClassFinding, nil, &sig, nil, nil)
	seed(now.Add(-2*time.Minute), secClassVPNSession, nil, nil, &tunnel, nil)
	seed(now.Add(-3*time.Minute), secClassDeviceHealth, nil, nil, nil, &wan)

	cases := []struct {
		name   string
		filter SecEventFilter
		want   int64
	}{
		{"admin_user substring", SecEventFilter{Hours: 24, AdminUser: "adm"}, 1},
		{"admin_user absent", SecEventFilter{Hours: 24, AdminUser: "nobody"}, 0},
		{"sig_name substring", SecEventFilter{Hours: 24, SigName: "MALWARE"}, 1},
		{"sig_name absent", SecEventFilter{Hours: 24, SigName: "exploit"}, 0},
		{"tunnel_name substring", SecEventFilter{Hours: 24, TunnelName: "east"}, 1},
		{"wan_name substring", SecEventFilter{Hours: 24, WanName: "wan1"}, 1},
	}
	for _, tc := range cases {
		_, total, _, err := db.ListSecEvents(tc.filter, 0, 100)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if total != tc.want {
			t.Fatalf("%s: total = %d, want %d", tc.name, total, tc.want)
		}
	}
}

func TestListSecEvents_PageBounds(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()
	for i := 0; i < 10; i++ {
		seedSecEventRow(t, db, dev.ID, 0, now.Add(-time.Duration(i)*time.Minute), secClassFinding, nil)
	}

	rows, total, _, err := db.ListSecEvents(SecEventFilter{Hours: 24}, 3, 4)
	if err != nil {
		t.Fatalf("ListSecEvents: %v", err)
	}
	if total != 10 {
		t.Fatalf("total = %d, want 10 (offset/limit must not affect the count)", total)
	}
	if len(rows) != 4 {
		t.Fatalf("page len = %d, want 4", len(rows))
	}
	if rows[0].Ts.Before(rows[3].Ts) {
		t.Fatalf("page not ordered newest-first")
	}
}

func TestListSecEvents_CountCapped(t *testing.T) {
	db := NewDatabaseForTesting(t)
	old := secEventPagerCountCap
	secEventPagerCountCap = 10
	t.Cleanup(func() { secEventPagerCountCap = old })

	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()
	for i := 0; i < 15; i++ {
		seedSecEventRow(t, db, dev.ID, 0, now.Add(-time.Duration(i)*time.Minute), secClassFinding, nil)
	}

	_, total, capped, err := db.ListSecEvents(SecEventFilter{Hours: 24}, 0, 100)
	if err != nil {
		t.Fatalf("ListSecEvents: %v", err)
	}
	if !capped {
		t.Fatalf("capped = false with 15 rows over a 10-row cap")
	}
	if total != int64(secEventPagerCountCap) {
		t.Fatalf("capped total = %d, want %d", total, secEventPagerCountCap)
	}
}

// ---------------------------------------------------------------------------
// net_event_rollups analytics (Phase 2, PR 4)
// ---------------------------------------------------------------------------

// Rollup action/direction literals: allow=1, deny=2, reject=3; inbound=1,
// outbound=2 (internal/normalize/enums.go — literal here so this test does not
// import the normalize package, matching the sec-event class literals above).
func seedRollupRow(t *testing.T, db *Database, day time.Time, devID uint, ruleKey string, action, direction int16, appCat, ruleset string, hits, bytesIn, bytesOut int64) {
	t.Helper()
	row := &models.NetEventRollup{
		Day: day, DeviceID: devID, RuleKey: ruleKey, Action: action, Direction: direction,
		AppCat: appCat, Ruleset: ruleset, Hits: hits, BytesIn: bytesIn, BytesOut: bytesOut,
	}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed rollup row: %v", err)
	}
}

// TestNetEventRollupStats_PolicyBytesRetrofitFloor: the optional
// net_event_rollup_bytes_valid_from marker starts the byte series at the first
// repaired day while the other series keep the full window.
func TestNetEventRollupStats_PolicyBytesRetrofitFloor(t *testing.T) {
	db := NewDatabaseForTesting(t)
	today := utcDay(time.Now())
	old := today.AddDate(0, 0, -10)

	seedRollupRow(t, db, old, 1, "u:old", 1, 2, "Web", "root", 10, 1000, 2000)
	seedRollupRow(t, db, today, 1, "u:new", 1, 2, "Web", "root", 5, 500, 1000)
	if err := db.UpsertSetting(&models.SystemSetting{
		Key: netEventRollupBytesValidFromKey, Value: today.Format(time.DateOnly),
		Category: "system", Type: "string",
	}); err != nil {
		t.Fatalf("store marker: %v", err)
	}

	stats, err := db.NetEventRollupStats(NetEventRollupFilter{Days: 30})
	if err != nil {
		t.Fatalf("NetEventRollupStats: %v", err)
	}
	if stats.PolicyBytesFrom != today.Format(time.DateOnly) {
		t.Fatalf("PolicyBytesFrom = %q, want %q", stats.PolicyBytesFrom, today.Format(time.DateOnly))
	}
	if len(stats.PolicyBytes) != 1 || stats.PolicyBytes[0].Day != today.Format(time.DateOnly) {
		t.Fatalf("policy_bytes = %+v, want only today", stats.PolicyBytes)
	}
	// The ranking (hits) is not clamped: both rules remain, but the byte
	// columns obey the floor too (the pre-floor rule reports zeros, not the
	// old inflated sum).
	if len(stats.PolicyHits) != 2 {
		t.Fatalf("policy_hits = %+v, want both rules (counts are not affected by the byte bug)", stats.PolicyHits)
	}
	if r := stats.PolicyHits[0]; r.RuleKey != "u:old" || r.Hits != 10 || r.BytesIn != 0 || r.BytesOut != 0 {
		t.Fatalf("policy_hits[0] = %+v, want u:old (10 hits, byte columns clamped to 0)", r)
	}
	if r := stats.PolicyHits[1]; r.RuleKey != "u:new" || r.Hits != 5 || r.BytesIn != 500 || r.BytesOut != 1000 {
		t.Fatalf("policy_hits[1] = %+v, want u:new 5/500/1000", r)
	}
}

// TestNetEventRollupStats_GroupingAndSums seeds a small rollup across two days
// and two devices and asserts every series' sums and grouping.
func TestNetEventRollupStats_GroupingAndSums(t *testing.T) {
	db := NewDatabaseForTesting(t)
	day0 := utcDay(time.Now())
	day1 := day0.AddDate(0, 0, -1)

	// Device 1, day0.
	seedRollupRow(t, db, day0, 1, "u:a", 1, 2, "Web", "root", 100, 1000, 2000) // allow
	seedRollupRow(t, db, day0, 1, "u:b", 2, 1, "Mail", "root", 30, 300, 600)   // deny
	seedRollupRow(t, db, day0, 1, "u:b", 3, 1, "Mail", "root", 20, 200, 400)   // reject
	// Device 1, day1.
	seedRollupRow(t, db, day1, 1, "u:a", 1, 2, "Web", "root", 50, 500, 1000)  // allow
	seedRollupRow(t, db, day1, 1, "u:c", 2, 1, "Mail", "guest", 10, 100, 200) // deny
	// Device 2, day0.
	seedRollupRow(t, db, day0, 2, "u:a", 1, 2, "Web", "root", 5, 50, 100) // allow

	stats, err := db.NetEventRollupStats(NetEventRollupFilter{Days: 30})
	if err != nil {
		t.Fatalf("NetEventRollupStats: %v", err)
	}

	// policy_hits: top rules by SUM(hits) across the window, '' excluded.
	// u:a = 100+50+5 = 155; u:b = 30+20 = 50; u:c = 10.
	if len(stats.PolicyHits) != 3 {
		t.Fatalf("policy_hits = %d rows, want 3: %+v", len(stats.PolicyHits), stats.PolicyHits)
	}
	if r := stats.PolicyHits[0]; r.RuleKey != "u:a" || r.Hits != 155 || r.BytesIn != 1550 || r.BytesOut != 3100 {
		t.Fatalf("policy_hits[0] = %+v, want u:a 155/1550/3100", r)
	}
	if r := stats.PolicyHits[1]; r.RuleKey != "u:b" || r.Hits != 50 || r.BytesIn != 500 || r.BytesOut != 1000 {
		t.Fatalf("policy_hits[1] = %+v, want u:b 50/500/1000", r)
	}
	if r := stats.PolicyHits[2]; r.RuleKey != "u:c" || r.Hits != 10 {
		t.Fatalf("policy_hits[2] = %+v, want u:c 10", r)
	}

	// policy_bytes: per-day bytes across every action, oldest-first.
	if len(stats.PolicyBytes) != 2 {
		t.Fatalf("policy_bytes = %d buckets, want 2: %+v", len(stats.PolicyBytes), stats.PolicyBytes)
	}
	if b := stats.PolicyBytes[0]; b.Day != day1.Format("2006-01-02") || b.Hits != 60 || b.BytesIn != 600 || b.BytesOut != 1200 {
		t.Fatalf("policy_bytes[0] = %+v, want day1 60/600/1200", b)
	}
	if b := stats.PolicyBytes[1]; b.Day != day0.Format("2006-01-02") || b.Hits != 155 || b.BytesIn != 1550 || b.BytesOut != 3100 {
		t.Fatalf("policy_bytes[1] = %+v, want day0 155/1550/3100", b)
	}

	// deny: only deny/reject actions, per day.
	if len(stats.Deny) != 2 {
		t.Fatalf("deny = %d buckets, want 2: %+v", len(stats.Deny), stats.Deny)
	}
	if b := stats.Deny[0]; b.Day != day1.Format("2006-01-02") || b.Hits != 10 || b.BytesIn != 100 || b.BytesOut != 200 {
		t.Fatalf("deny[0] = %+v, want day1 10/100/200", b)
	}
	if b := stats.Deny[1]; b.Day != day0.Format("2006-01-02") || b.Hits != 50 || b.BytesIn != 500 || b.BytesOut != 1000 {
		t.Fatalf("deny[1] = %+v, want day0 50/500/1000 (deny 30 + reject 20)", b)
	}

	// app_categories: SUM(hits) by app_cat, count desc.
	if len(stats.AppCategories) != 2 {
		t.Fatalf("app_categories = %d, want 2: %+v", len(stats.AppCategories), stats.AppCategories)
	}
	if c := stats.AppCategories[0]; c.Key != "Web" || c.Count != 155 {
		t.Fatalf("app_categories[0] = %+v, want Web 155", c)
	}
	if c := stats.AppCategories[1]; c.Key != "Mail" || c.Count != 60 {
		t.Fatalf("app_categories[1] = %+v, want Mail 60", c)
	}

	// directions: SUM(hits) by direction, id asc (inbound=1 before outbound=2).
	if len(stats.Directions) != 2 {
		t.Fatalf("directions = %d, want 2: %+v", len(stats.Directions), stats.Directions)
	}
	if d := stats.Directions[0]; d.Direction != 1 || d.Hits != 60 {
		t.Fatalf("directions[0] = %+v, want inbound 60", d)
	}
	if d := stats.Directions[1]; d.Direction != 2 || d.Hits != 155 {
		t.Fatalf("directions[1] = %+v, want outbound 155", d)
	}

	// rulesets: SUM(hits) by ruleset, count desc.
	if len(stats.Rulesets) != 2 {
		t.Fatalf("rulesets = %d, want 2: %+v", len(stats.Rulesets), stats.Rulesets)
	}
	if c := stats.Rulesets[0]; c.Key != "root" || c.Count != 205 {
		t.Fatalf("rulesets[0] = %+v, want root 205", c)
	}
	if c := stats.Rulesets[1]; c.Key != "guest" || c.Count != 10 {
		t.Fatalf("rulesets[1] = %+v, want guest 10", c)
	}
}

// TestNetEventRollupStats_DayFilter asserts rows older than the window are
// excluded: a 40-day-old row is outside the default 30-day bound.
func TestNetEventRollupStats_DayFilter(t *testing.T) {
	db := NewDatabaseForTesting(t)
	day0 := utcDay(time.Now())
	old := day0.AddDate(0, 0, -40)

	seedRollupRow(t, db, day0, 1, "u:new", 1, 2, "Web", "root", 5, 50, 100)
	seedRollupRow(t, db, old, 1, "u:old", 1, 2, "Web", "root", 999, 999, 999)

	stats, err := db.NetEventRollupStats(NetEventRollupFilter{Days: 30})
	if err != nil {
		t.Fatalf("NetEventRollupStats: %v", err)
	}
	if len(stats.PolicyHits) != 1 || stats.PolicyHits[0].RuleKey != "u:new" {
		t.Fatalf("policy_hits = %+v, want only u:new (u:old is outside the window)", stats.PolicyHits)
	}
	if len(stats.PolicyBytes) != 1 || stats.PolicyBytes[0].Day != day0.Format("2006-01-02") {
		t.Fatalf("policy_bytes = %+v, want only day0", stats.PolicyBytes)
	}
}

// TestNetEventRollupStats_DeviceAndSiteFilter asserts the device and site
// filters narrow the series through the (day, device_id, …) key prefix.
func TestNetEventRollupStats_DeviceAndSiteFilter(t *testing.T) {
	db := NewDatabaseForTesting(t)
	siteA := seedNetEventSite(t, db, "site-a")
	siteB := seedNetEventSite(t, db, "site-b")
	devA := seedNetEventDevice(t, db, "fw-a", &siteA.ID)
	devB := seedNetEventDevice(t, db, "fw-b", &siteB.ID)
	day0 := utcDay(time.Now())

	seedRollupRow(t, db, day0, devA.ID, "u:a", 1, 2, "Web", "root", 10, 100, 200)
	seedRollupRow(t, db, day0, devB.ID, "u:a", 1, 2, "Web", "root", 7, 70, 140)

	all, err := db.NetEventRollupStats(NetEventRollupFilter{Days: 30})
	if err != nil {
		t.Fatalf("NetEventRollupStats(all): %v", err)
	}
	if len(all.PolicyHits) != 1 || all.PolicyHits[0].Hits != 17 {
		t.Fatalf("all policy_hits = %+v, want u:a 17 (both devices)", all.PolicyHits)
	}

	byDevice, err := db.NetEventRollupStats(NetEventRollupFilter{Days: 30, DeviceID: devA.ID})
	if err != nil {
		t.Fatalf("NetEventRollupStats(device): %v", err)
	}
	if len(byDevice.PolicyHits) != 1 || byDevice.PolicyHits[0].Hits != 10 {
		t.Fatalf("device policy_hits = %+v, want u:a 10 (device A only)", byDevice.PolicyHits)
	}

	bySite, err := db.NetEventRollupStats(NetEventRollupFilter{Days: 30, SiteID: siteA.ID})
	if err != nil {
		t.Fatalf("NetEventRollupStats(site): %v", err)
	}
	if len(bySite.PolicyHits) != 1 || bySite.PolicyHits[0].Hits != 10 {
		t.Fatalf("site policy_hits = %+v, want u:a 10 (site A only)", bySite.PolicyHits)
	}
}

// ---------------------------------------------------------------------------
// net_events — short-window analytics (Phase 2, PR 5)
// ---------------------------------------------------------------------------

// statStr / statI64 are tiny pointer helpers so a seed row can carry a
// NULL-able dimension column (nil = "vendor did not supply it").
func statStr(s string) *string { return &s }
func statI64(v int64) *int64   { return &v }

// statRow is the seed shape for the NetEventStats tests: the dimension columns
// the series group on, all pointers so nil seeds the skipped (NULL) case.
type statRow struct {
	devID                          uint
	ts                             time.Time
	srcCountry, dstCountry         *string
	srcIP, srcMAC                  *string
	user, app, appCat, webCat, dns *string
	natSrc, natDst                 *string
	bytesIn, bytesOut              *int64
}

func seedNetEventStatRow(t *testing.T, db *Database, r statRow) {
	t.Helper()
	row := &models.NetEvent{
		Ts:         r.ts,
		DeviceID:   r.devID,
		Activity:   3,
		Action:     1,
		SrcCountry: r.srcCountry,
		DstCountry: r.dstCountry,
		SrcIP:      r.srcIP,
		SrcMAC:     r.srcMAC,
		UserName:   r.user,
		App:        r.app,
		AppCat:     r.appCat,
		WebCat:     r.webCat,
		DNSQName:   r.dns,
		NatSrcIP:   r.natSrc,
		NatDstIP:   r.natDst,
		BytesIn:    r.bytesIn,
		BytesOut:   r.bytesOut,
	}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed net_event stat row: %v", err)
	}
}

// findKeyCount returns the count for a key in a KeyCount series, or 0 when the
// key is absent (the series is ordered by count desc, so absent means below the
// top-N cut or skipped).
func findKeyCount(series []KeyCount, key string) int64 {
	for _, c := range series {
		if c.Key == key {
			return c.Count
		}
	}
	return 0
}

// TestNetEventStats_GroupingAndSums seeds a handful of rows and asserts every
// series' grouping and sums: two rows for one (device, identity, user, app,
// web, dns, nat) tuple and one for a second, so each count and the geo bytes
// are exercised.
func TestNetEventStats_GroupingAndSums(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()

	seedNetEventStatRow(t, db, statRow{
		devID: dev.ID, ts: now,
		srcCountry: statStr("US"), dstCountry: statStr("CA"),
		srcIP: statStr("10.0.0.1"), srcMAC: statStr("aa:bb:cc:dd:ee:01"),
		user: statStr("alice"), app: statStr("web"), appCat: statStr("Web"), webCat: statStr("Shopping"), dns: statStr("example.com"),
		natSrc: statStr("10.0.0.1"), natDst: statStr("1.2.3.4"),
		bytesIn: statI64(100), bytesOut: statI64(200),
	})
	seedNetEventStatRow(t, db, statRow{
		devID: dev.ID, ts: now.Add(-time.Minute),
		srcCountry: statStr("US"), dstCountry: statStr("CA"),
		srcIP: statStr("10.0.0.1"), srcMAC: statStr("aa:bb:cc:dd:ee:01"),
		user: statStr("alice"), app: statStr("web"), appCat: statStr("Web"), webCat: statStr("Shopping"), dns: statStr("example.com"),
		natSrc: statStr("10.0.0.1"), natDst: statStr("1.2.3.4"),
		bytesIn: statI64(100), bytesOut: statI64(200),
	})
	seedNetEventStatRow(t, db, statRow{
		devID: dev.ID, ts: now.Add(-2 * time.Minute),
		srcCountry: statStr("US"), dstCountry: statStr("GB"),
		srcIP: statStr("10.0.0.2"), srcMAC: statStr("aa:bb:cc:dd:ee:02"),
		user: statStr("bob"), app: statStr("mail"), appCat: statStr("Mail"), webCat: statStr("News"), dns: statStr("example.net"),
		natSrc: statStr("10.0.0.2"), natDst: statStr("5.6.7.8"),
		bytesIn: statI64(300), bytesOut: statI64(400),
	})

	stats, err := db.NetEventStats(NetEventStatsFilter{Hours: 24})
	if err != nil {
		t.Fatalf("NetEventStats: %v", err)
	}

	// geo_src: US=3 with bytes 500/800 (the two 100/200 rows plus 300/400).
	if len(stats.GeoSrc) != 1 {
		t.Fatalf("geo_src = %d rows, want 1: %+v", len(stats.GeoSrc), stats.GeoSrc)
	}
	if g := stats.GeoSrc[0]; g.Country != "US" || g.Hits != 3 || g.BytesIn != 500 || g.BytesOut != 800 {
		t.Fatalf("geo_src[0] = %+v, want US 3/500/800", g)
	}

	// geo_dst: CA=2, GB=1 (ordered hits desc).
	if len(stats.GeoDst) != 2 {
		t.Fatalf("geo_dst = %d rows, want 2: %+v", len(stats.GeoDst), stats.GeoDst)
	}
	if g := stats.GeoDst[0]; g.Country != "CA" || g.Hits != 2 {
		t.Fatalf("geo_dst[0] = %+v, want CA 2", g)
	}
	if g := stats.GeoDst[1]; g.Country != "GB" || g.Hits != 1 {
		t.Fatalf("geo_dst[1] = %+v, want GB 1", g)
	}

	// identity: (10.0.0.1, aa:..01)=2 then (10.0.0.2, aa:..02)=1.
	if len(stats.Identity) != 2 {
		t.Fatalf("identity = %d rows, want 2: %+v", len(stats.Identity), stats.Identity)
	}
	if id := stats.Identity[0]; id.SrcIP != "10.0.0.1" || id.SrcMAC != "aa:bb:cc:dd:ee:01" || id.Hits != 2 {
		t.Fatalf("identity[0] = %+v, want 10.0.0.1/aa:..01 2", id)
	}
	if id := stats.Identity[1]; id.SrcIP != "10.0.0.2" || id.Hits != 1 {
		t.Fatalf("identity[1] = %+v, want 10.0.0.2 1", id)
	}

	if findKeyCount(stats.Users, "alice") != 2 || findKeyCount(stats.Users, "bob") != 1 {
		t.Fatalf("users = %+v, want alice 2 / bob 1", stats.Users)
	}
	if findKeyCount(stats.Apps, "web") != 2 || findKeyCount(stats.Apps, "mail") != 1 {
		t.Fatalf("apps = %+v, want web 2 / mail 1", stats.Apps)
	}
	if findKeyCount(stats.AppCategories, "Web") != 2 || findKeyCount(stats.AppCategories, "Mail") != 1 {
		t.Fatalf("app_categories = %+v, want Web 2 / Mail 1", stats.AppCategories)
	}
	if findKeyCount(stats.WebCategories, "Shopping") != 2 || findKeyCount(stats.WebCategories, "News") != 1 {
		t.Fatalf("web_categories = %+v, want Shopping 2 / News 1", stats.WebCategories)
	}
	if findKeyCount(stats.DNS, "example.com") != 2 || findKeyCount(stats.DNS, "example.net") != 1 {
		t.Fatalf("dns = %+v, want example.com 2 / example.net 1", stats.DNS)
	}

	// nat: (10.0.0.1 → 1.2.3.4)=2 then (10.0.0.2 → 5.6.7.8)=1.
	if len(stats.NAT) != 2 {
		t.Fatalf("nat = %d rows, want 2: %+v", len(stats.NAT), stats.NAT)
	}
	if n := stats.NAT[0]; n.SrcIP != "10.0.0.1" || n.DstIP != "1.2.3.4" || n.Hits != 2 {
		t.Fatalf("nat[0] = %+v, want 10.0.0.1 → 1.2.3.4 2", n)
	}
	if n := stats.NAT[1]; n.SrcIP != "10.0.0.2" || n.DstIP != "5.6.7.8" || n.Hits != 1 {
		t.Fatalf("nat[1] = %+v, want 10.0.0.2 → 5.6.7.8 1", n)
	}
}

// TestNetEventStats_TsBounded asserts rows older than the window are excluded:
// a 48-hour-old row is outside the default 24 h bound.
func TestNetEventStats_TsBounded(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()

	seedNetEventStatRow(t, db, statRow{devID: dev.ID, ts: now, srcCountry: statStr("US"), user: statStr("alice"), srcIP: statStr("10.0.0.1"), natSrc: statStr("10.0.0.1")})
	seedNetEventStatRow(t, db, statRow{devID: dev.ID, ts: now.Add(-48 * time.Hour), srcCountry: statStr("DE"), user: statStr("eve"), srcIP: statStr("10.0.0.9"), natSrc: statStr("10.0.0.9")})

	stats, err := db.NetEventStats(NetEventStatsFilter{Hours: 24})
	if err != nil {
		t.Fatalf("NetEventStats: %v", err)
	}
	if len(stats.GeoSrc) != 1 || stats.GeoSrc[0].Country != "US" {
		t.Fatalf("geo_src = %+v, want only US (DE is outside the 24 h window)", stats.GeoSrc)
	}
	if len(stats.Users) != 1 || stats.Users[0].Key != "alice" {
		t.Fatalf("users = %+v, want only alice", stats.Users)
	}
	if len(stats.Identity) != 1 || stats.Identity[0].SrcIP != "10.0.0.1" {
		t.Fatalf("identity = %+v, want only 10.0.0.1", stats.Identity)
	}
	if len(stats.NAT) != 1 || stats.NAT[0].SrcIP != "10.0.0.1" {
		t.Fatalf("nat = %+v, want only 10.0.0.1", stats.NAT)
	}
}

// TestNetEventStats_DeviceAndSiteFilter asserts the device and site filters
// narrow every series through the (device_id, ts) index.
func TestNetEventStats_DeviceAndSiteFilter(t *testing.T) {
	db := NewDatabaseForTesting(t)
	siteA := seedNetEventSite(t, db, "site-a")
	siteB := seedNetEventSite(t, db, "site-b")
	devA := seedNetEventDevice(t, db, "fw-a", &siteA.ID)
	devB := seedNetEventDevice(t, db, "fw-b", &siteB.ID)
	now := time.Now()

	seedNetEventStatRow(t, db, statRow{devID: devA.ID, ts: now, srcCountry: statStr("US"), user: statStr("alice"), srcIP: statStr("10.0.0.1"), natSrc: statStr("10.0.0.1")})
	seedNetEventStatRow(t, db, statRow{devID: devB.ID, ts: now, srcCountry: statStr("GB"), user: statStr("bob"), srcIP: statStr("10.0.0.2"), natSrc: statStr("10.0.0.2")})

	byDevice, err := db.NetEventStats(NetEventStatsFilter{Hours: 24, DeviceID: devA.ID})
	if err != nil {
		t.Fatalf("NetEventStats(device): %v", err)
	}
	if len(byDevice.GeoSrc) != 1 || byDevice.GeoSrc[0].Country != "US" {
		t.Fatalf("device geo_src = %+v, want only US", byDevice.GeoSrc)
	}
	if len(byDevice.Users) != 1 || byDevice.Users[0].Key != "alice" {
		t.Fatalf("device users = %+v, want only alice", byDevice.Users)
	}

	bySite, err := db.NetEventStats(NetEventStatsFilter{Hours: 24, SiteID: siteB.ID})
	if err != nil {
		t.Fatalf("NetEventStats(site): %v", err)
	}
	if len(bySite.GeoSrc) != 1 || bySite.GeoSrc[0].Country != "GB" {
		t.Fatalf("site geo_src = %+v, want only GB", bySite.GeoSrc)
	}
	if len(bySite.Users) != 1 || bySite.Users[0].Key != "bob" {
		t.Fatalf("site users = %+v, want only bob", bySite.Users)
	}
}

// TestNetEventStats_EmptySkipped asserts NULL and empty-string dimension values
// are skipped: a row that supplies none of the grouped columns contributes no
// groups, and a row whose src_ip/nat_src_ip is NULL contributes no identity/NAT
// pair. A present src_ip with a NULL src_mac reads back as an empty MAC.
func TestNetEventStats_EmptySkipped(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()

	// Nothing supplied: every grouped column is NULL.
	seedNetEventStatRow(t, db, statRow{devID: dev.ID, ts: now})
	// Empty strings: the "vendor supplied empty" case the queries skip.
	seedNetEventStatRow(t, db, statRow{
		devID: dev.ID, ts: now.Add(-time.Minute),
		srcCountry: statStr(""), dstCountry: statStr(""),
		user: statStr(""), app: statStr(""), appCat: statStr(""), webCat: statStr(""), dns: statStr(""),
	})
	// src_ip present with no MAC: an identity whose MAC reads back as ''.
	seedNetEventStatRow(t, db, statRow{devID: dev.ID, ts: now.Add(-2 * time.Minute), srcIP: statStr("10.0.0.7")})

	stats, err := db.NetEventStats(NetEventStatsFilter{Hours: 24})
	if err != nil {
		t.Fatalf("NetEventStats: %v", err)
	}

	if len(stats.GeoSrc) != 0 {
		t.Fatalf("geo_src = %+v, want empty (NULL and '' codes skipped)", stats.GeoSrc)
	}
	if len(stats.GeoDst) != 0 {
		t.Fatalf("geo_dst = %+v, want empty", stats.GeoDst)
	}
	if len(stats.Users) != 0 || len(stats.Apps) != 0 || len(stats.AppCategories) != 0 || len(stats.WebCategories) != 0 || len(stats.DNS) != 0 {
		t.Fatalf("key-count series not empty: users=%+v apps=%+v app_categories=%+v web_categories=%+v dns=%+v",
			stats.Users, stats.Apps, stats.AppCategories, stats.WebCategories, stats.DNS)
	}
	// Only the row with a src_ip (and no MAC) yields an identity; its MAC is ''.
	if len(stats.Identity) != 1 || stats.Identity[0].SrcIP != "10.0.0.7" || stats.Identity[0].SrcMAC != "" || stats.Identity[0].Hits != 1 {
		t.Fatalf("identity = %+v, want exactly [10.0.0.7 '' 1]", stats.Identity)
	}
	// No row supplied a nat_src_ip, so no NAT pair.
	if len(stats.NAT) != 0 {
		t.Fatalf("nat = %+v, want empty", stats.NAT)
	}
}

// ---------------------------------------------------------------------------
// sec_events — class-scoped analytics (Phase 2, PR 6)
// ---------------------------------------------------------------------------

// statF64 is a tiny pointer helper so a seed row can carry a NULL-able
// metric_value (nil = "vendor did not supply it").
func statF64(v float64) *float64 { return &v }

// secStatRow is the seed shape for the SecEventStats tests: the class-specific
// columns each series groups on, all pointers so nil seeds the skipped (NULL)
// case.
type secStatRow struct {
	devID      uint
	ts         time.Time
	class      int16
	severity   *int16
	sigName    *string
	adminUser  *string
	adminSrcIP *string
	configPath *string
	tunnelName *string
	tunnelPeer *string
	wanName    *string
	metric     *float64
}

func seedSecStatRow(t *testing.T, db *Database, r secStatRow) {
	t.Helper()
	row := &models.SecEvent{
		Ts:          r.ts,
		DeviceID:    r.devID,
		Class:       r.class,
		Severity:    r.severity,
		SigName:     r.sigName,
		AdminUser:   r.adminUser,
		AdminSrcIP:  r.adminSrcIP,
		ConfigPath:  r.configPath,
		TunnelName:  r.tunnelName,
		TunnelPeer:  r.tunnelPeer,
		WANName:     r.wanName,
		MetricValue: r.metric,
	}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed sec_event stat row: %v", err)
	}
}

// TestSecEventStats_GroupingAndSums seeds one or two rows per class across two
// UTC days and asserts every series' day buckets, sums and top-N ordering.
func TestSecEventStats_GroupingAndSums(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	day0 := utcDay(time.Now())
	day1 := day0.AddDate(0, 0, -1)
	sevHigh, sevLow := int16(9), int16(2)

	// findings: day0 MALWARE-A twice (sev 9 and 2), day1 MALWARE-B once (sev 2).
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(9 * time.Hour), class: secClassFinding, severity: &sevHigh, sigName: statStr("MALWARE-A")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(10 * time.Hour), class: secClassFinding, severity: &sevLow, sigName: statStr("MALWARE-A")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day1.Add(9 * time.Hour), class: secClassFinding, severity: &sevLow, sigName: statStr("MALWARE-B")})

	// auth: day0 admin-ops from 10.0.0.5 and 10.0.0.6, day1 root from 10.0.0.7.
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(8 * time.Hour), class: secClassAuth, adminUser: statStr("admin-ops"), adminSrcIP: statStr("10.0.0.5")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(9 * time.Hour), class: secClassAuth, adminUser: statStr("admin-ops"), adminSrcIP: statStr("10.0.0.6")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day1.Add(8 * time.Hour), class: secClassAuth, adminUser: statStr("root"), adminSrcIP: statStr("10.0.0.7")})

	// config_change: day0 two paths by admin-ops, day1 one path by root.
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(7 * time.Hour), class: secClassConfigChange, configPath: statStr("/system/global"), adminUser: statStr("admin-ops")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(8 * time.Hour), class: secClassConfigChange, configPath: statStr("/system/interface"), adminUser: statStr("admin-ops")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day1.Add(7 * time.Hour), class: secClassConfigChange, configPath: statStr("/system/global"), adminUser: statStr("root")})

	// vpn_session: day0 tunnel-east twice (peer 198.51.100.1 and 198.51.100.2), day1 tunnel-west once.
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(6 * time.Hour), class: secClassVPNSession, tunnelName: statStr("tunnel-east"), tunnelPeer: statStr("198.51.100.1")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(7 * time.Hour), class: secClassVPNSession, tunnelName: statStr("tunnel-east"), tunnelPeer: statStr("198.51.100.2")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day1.Add(6 * time.Hour), class: secClassVPNSession, tunnelName: statStr("tunnel-west"), tunnelPeer: statStr("203.0.113.1")})

	// device_health: day0 wan1 reads 10 then 20 (avg 15, last 20), day1 wan1 reads 5.
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(8 * time.Hour), class: secClassDeviceHealth, wanName: statStr("wan1"), metric: statF64(10)})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day0.Add(9 * time.Hour), class: secClassDeviceHealth, wanName: statStr("wan1"), metric: statF64(20)})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: day1.Add(8 * time.Hour), class: secClassDeviceHealth, wanName: statStr("wan1"), metric: statF64(5)})

	stats, err := db.SecEventStats(SecEventStatsFilter{Days: 30})
	if err != nil {
		t.Fatalf("SecEventStats: %v", err)
	}

	// findings trend: day1 = 1, day0 = 2, oldest-first.
	if len(stats.Findings) != 2 {
		t.Fatalf("findings = %d buckets, want 2: %+v", len(stats.Findings), stats.Findings)
	}
	if b := stats.Findings[0]; b.Day != day1.Format("2006-01-02") || b.Count != 1 {
		t.Fatalf("findings[0] = %+v, want day1 1", b)
	}
	if b := stats.Findings[1]; b.Day != day0.Format("2006-01-02") || b.Count != 2 {
		t.Fatalf("findings[1] = %+v, want day0 2", b)
	}

	// top_signatures: MALWARE-A (count 2, worst severity 9) then MALWARE-B (1, 2).
	if len(stats.TopSignatures) != 2 {
		t.Fatalf("top_signatures = %d, want 2: %+v", len(stats.TopSignatures), stats.TopSignatures)
	}
	if s := stats.TopSignatures[0]; s.SigName != "MALWARE-A" || s.Count != 2 || s.Severity != 9 {
		t.Fatalf("top_signatures[0] = %+v, want MALWARE-A 2/9", s)
	}
	if s := stats.TopSignatures[1]; s.SigName != "MALWARE-B" || s.Count != 1 || s.Severity != 2 {
		t.Fatalf("top_signatures[1] = %+v, want MALWARE-B 1/2", s)
	}

	// admin_logins trend + top admin users + top admin source IPs.
	if len(stats.AdminLogins) != 2 || stats.AdminLogins[1].Count != 2 || stats.AdminLogins[0].Count != 1 {
		t.Fatalf("admin_logins = %+v, want day1 1 / day0 2", stats.AdminLogins)
	}
	if findKeyCount(stats.TopAdminUsers, "admin-ops") != 2 || findKeyCount(stats.TopAdminUsers, "root") != 1 {
		t.Fatalf("top_admin_users = %+v, want admin-ops 2 / root 1", stats.TopAdminUsers)
	}
	// Three distinct source /32s, each seen once (the count tie makes the order
	// non-deterministic, so assert membership rather than position).
	if findKeyCount(stats.TopAdminSrcIPs, "10.0.0.5") != 1 || findKeyCount(stats.TopAdminSrcIPs, "10.0.0.6") != 1 || findKeyCount(stats.TopAdminSrcIPs, "10.0.0.7") != 1 {
		t.Fatalf("top_admin_src_ips = %+v, want the three distinct /32s", stats.TopAdminSrcIPs)
	}

	// config_changes trend + top config paths + top config admins.
	if len(stats.ConfigChanges) != 2 || stats.ConfigChanges[1].Count != 2 || stats.ConfigChanges[0].Count != 1 {
		t.Fatalf("config_changes = %+v, want day1 1 / day0 2", stats.ConfigChanges)
	}
	if findKeyCount(stats.TopConfigPaths, "/system/global") != 2 || findKeyCount(stats.TopConfigPaths, "/system/interface") != 1 {
		t.Fatalf("top_config_paths = %+v, want /system/global 2 / /system/interface 1", stats.TopConfigPaths)
	}
	if findKeyCount(stats.TopConfigAdmins, "admin-ops") != 2 || findKeyCount(stats.TopConfigAdmins, "root") != 1 {
		t.Fatalf("top_config_admins = %+v, want admin-ops 2 / root 1", stats.TopConfigAdmins)
	}

	// vpn_sessions trend + top tunnels + top tunnel peers.
	if len(stats.VPNSessions) != 2 || stats.VPNSessions[1].Count != 2 || stats.VPNSessions[0].Count != 1 {
		t.Fatalf("vpn_sessions = %+v, want day1 1 / day0 2", stats.VPNSessions)
	}
	if findKeyCount(stats.TopTunnels, "tunnel-east") != 2 || findKeyCount(stats.TopTunnels, "tunnel-west") != 1 {
		t.Fatalf("top_tunnels = %+v, want tunnel-east 2 / tunnel-west 1", stats.TopTunnels)
	}
	if findKeyCount(stats.TopTunnelPeers, "198.51.100.1") != 1 || findKeyCount(stats.TopTunnelPeers, "198.51.100.2") != 1 || findKeyCount(stats.TopTunnelPeers, "203.0.113.1") != 1 {
		t.Fatalf("top_tunnel_peers = %+v, want the three distinct peers", stats.TopTunnelPeers)
	}

	// wan_health: day1 (avg 5, last 5) then day0 (avg 15, last 20).
	if len(stats.WanHealth) != 2 {
		t.Fatalf("wan_health = %d rows, want 2: %+v", len(stats.WanHealth), stats.WanHealth)
	}
	if w := stats.WanHealth[0]; w.Day != day1.Format("2006-01-02") || w.WanName != "wan1" || w.Avg != 5 || w.Last != 5 {
		t.Fatalf("wan_health[0] = %+v, want day1 wan1 5/5", w)
	}
	if w := stats.WanHealth[1]; w.Day != day0.Format("2006-01-02") || w.Avg != 15 || w.Last != 20 {
		t.Fatalf("wan_health[1] = %+v, want day0 wan1 15/20 (avg of 10,20; last 20)", w)
	}
}

// TestSecEventStats_TsBounded asserts rows older than the window are excluded:
// a 48-hour-old finding is outside a 24 h bound.
func TestSecEventStats_TsBounded(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()

	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: now, class: secClassFinding, sigName: statStr("RECENT")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: now.Add(-48 * time.Hour), class: secClassFinding, sigName: statStr("OLD")})

	stats, err := db.SecEventStats(SecEventStatsFilter{Hours: 24})
	if err != nil {
		t.Fatalf("SecEventStats: %v", err)
	}
	if len(stats.Findings) != 1 || stats.Findings[0].Count != 1 {
		t.Fatalf("findings = %+v, want one bucket of 1 (the 48 h-old row is outside the 24 h window)", stats.Findings)
	}
	if len(stats.TopSignatures) != 1 || stats.TopSignatures[0].SigName != "RECENT" {
		t.Fatalf("top_signatures = %+v, want only RECENT", stats.TopSignatures)
	}
}

// TestSecEventStats_DeviceAndSiteFilter asserts the device and site filters
// narrow every series through the (device_id, ts) index.
func TestSecEventStats_DeviceAndSiteFilter(t *testing.T) {
	db := NewDatabaseForTesting(t)
	siteA := seedNetEventSite(t, db, "site-a")
	siteB := seedNetEventSite(t, db, "site-b")
	devA := seedNetEventDevice(t, db, "fw-a", &siteA.ID)
	devB := seedNetEventDevice(t, db, "fw-b", &siteB.ID)
	now := time.Now()

	seedSecStatRow(t, db, secStatRow{devID: devA.ID, ts: now, class: secClassFinding, sigName: statStr("A")})
	seedSecStatRow(t, db, secStatRow{devID: devB.ID, ts: now, class: secClassFinding, sigName: statStr("B")})

	byDevice, err := db.SecEventStats(SecEventStatsFilter{Hours: 24, DeviceID: devA.ID})
	if err != nil {
		t.Fatalf("SecEventStats(device): %v", err)
	}
	if len(byDevice.TopSignatures) != 1 || byDevice.TopSignatures[0].SigName != "A" {
		t.Fatalf("device top_signatures = %+v, want only A", byDevice.TopSignatures)
	}

	bySite, err := db.SecEventStats(SecEventStatsFilter{Hours: 24, SiteID: siteB.ID})
	if err != nil {
		t.Fatalf("SecEventStats(site): %v", err)
	}
	if len(bySite.TopSignatures) != 1 || bySite.TopSignatures[0].SigName != "B" {
		t.Fatalf("site top_signatures = %+v, want only B", bySite.TopSignatures)
	}
}

// TestSecEventStats_EmptySkipped asserts NULL and empty-string dimension values
// are skipped: a row that supplies none of a class's grouped columns
// contributes no groups (the per-day trend still counts the row).
func TestSecEventStats_EmptySkipped(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	now := time.Now()

	// A finding with no sig_name/severity: counts in the trend but no signature.
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: now, class: secClassFinding})
	// Empty-string text columns (the "vendor supplied empty" case the queries
	// skip) and NULL inet columns (an inet column can never hold '' in
	// production, so NULL is the only skip case there).
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: now.Add(-time.Minute), class: secClassAuth, adminUser: statStr("")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: now.Add(-2 * time.Minute), class: secClassConfigChange, configPath: statStr(""), adminUser: statStr("")})
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: now.Add(-3 * time.Minute), class: secClassVPNSession, tunnelName: statStr("")})
	// A health row with no wan_name/metric: skipped entirely from wan_health.
	seedSecStatRow(t, db, secStatRow{devID: dev.ID, ts: now.Add(-4 * time.Minute), class: secClassDeviceHealth})

	stats, err := db.SecEventStats(SecEventStatsFilter{Hours: 24})
	if err != nil {
		t.Fatalf("SecEventStats: %v", err)
	}

	if len(stats.Findings) != 1 || stats.Findings[0].Count != 1 {
		t.Fatalf("findings = %+v, want the trend to count the no-signature row", stats.Findings)
	}
	if len(stats.TopSignatures) != 0 {
		t.Fatalf("top_signatures = %+v, want empty (NULL sig_name skipped)", stats.TopSignatures)
	}
	if len(stats.TopAdminUsers) != 0 || len(stats.TopAdminSrcIPs) != 0 {
		t.Fatalf("top admin series = %+v / %+v, want empty", stats.TopAdminUsers, stats.TopAdminSrcIPs)
	}
	if len(stats.TopConfigPaths) != 0 || len(stats.TopConfigAdmins) != 0 {
		t.Fatalf("top config series = %+v / %+v, want empty", stats.TopConfigPaths, stats.TopConfigAdmins)
	}
	if len(stats.TopTunnels) != 0 || len(stats.TopTunnelPeers) != 0 {
		t.Fatalf("top vpn series = %+v / %+v, want empty", stats.TopTunnels, stats.TopTunnelPeers)
	}
	if len(stats.WanHealth) != 0 {
		t.Fatalf("wan_health = %+v, want empty (no wan_name/metric)", stats.WanHealth)
	}
}

// ---------------------------------------------------------------------------
// Single-row detail getters (Phase 2, PR 8)
// ---------------------------------------------------------------------------

// TestGetNetEvent_Found seeds one net_event (with provenance) and asserts the
// getter returns the same column set as the list — enrichment plus the
// raw_id/raw_ts provenance the "View raw syslog" link reads.
func TestGetNetEvent_Found(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	ts := time.Date(2026, 10, 1, 10, 5, 0, 0, time.UTC)
	rawID := int64(4242)
	src := "10.0.0.5"
	row := &models.NetEvent{Ts: ts, DeviceID: dev.ID, Activity: 3, Action: 2, SrcIP: &src, RawID: &rawID, RawTS: &ts}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := db.GetNetEvent(row.ID)
	if err != nil {
		t.Fatalf("GetNetEvent: %v", err)
	}
	if got.ID != row.ID || !got.Ts.Equal(ts) {
		t.Fatalf("identity = %+v, want id %d ts %v", got, row.ID, ts)
	}
	if got.DeviceName != "fw-1" || got.Vendor != "fortigate" {
		t.Fatalf("enrichment = %q/%q, want fw-1/fortigate", got.DeviceName, got.Vendor)
	}
	if got.Action != 2 || got.SrcIP == nil || *got.SrcIP != src {
		t.Fatalf("columns = action %d src %v, want 2/10.0.0.5", got.Action, got.SrcIP)
	}
	if got.RawID == nil || *got.RawID != 4242 || got.RawTS == nil || !got.RawTS.Equal(ts) {
		t.Fatalf("provenance = %v/%v, want 4242/%v", got.RawID, got.RawTS, ts)
	}
}

// TestGetNetEvent_NotFound asserts an unknown id is gorm.ErrRecordNotFound (the
// handler maps it to a 404), not a nil row.
func TestGetNetEvent_NotFound(t *testing.T) {
	db := NewDatabaseForTesting(t)
	if _, err := db.GetNetEvent(999999); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("GetNetEvent(999999) err = %v, want ErrRecordNotFound", err)
	}
}

// TestGetSecEvent_Found mirrors TestGetNetEvent_Found for sec_events: the class
// and severity columns round-trip and the provenance is present.
func TestGetSecEvent_Found(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := seedNetEventDevice(t, db, "fw-1", nil)
	ts := time.Date(2026, 10, 1, 10, 5, 0, 0, time.UTC)
	rawID := int64(99)
	sev := int16(7)
	sig := "MALWARE-Foo"
	row := &models.SecEvent{Ts: ts, DeviceID: dev.ID, Class: secClassFinding, Severity: &sev, SigName: &sig, RawID: &rawID, RawTS: &ts}
	if err := db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := db.GetSecEvent(row.ID)
	if err != nil {
		t.Fatalf("GetSecEvent: %v", err)
	}
	if got.ID != row.ID || !got.Ts.Equal(ts) {
		t.Fatalf("identity = %+v, want id %d ts %v", got, row.ID, ts)
	}
	if got.DeviceName != "fw-1" || got.Vendor != "fortigate" {
		t.Fatalf("enrichment = %q/%q, want fw-1/fortigate", got.DeviceName, got.Vendor)
	}
	if got.Class != secClassFinding || got.Severity == nil || *got.Severity != 7 || got.SigName == nil || *got.SigName != sig {
		t.Fatalf("columns = class %d sev %v sig %v, want 2004/7/MALWARE-Foo", got.Class, got.Severity, got.SigName)
	}
	if got.RawID == nil || *got.RawID != 99 || got.RawTS == nil || !got.RawTS.Equal(ts) {
		t.Fatalf("provenance = %v/%v, want 99/%v", got.RawID, got.RawTS, ts)
	}
}

// TestGetSecEvent_NotFound asserts an unknown id is gorm.ErrRecordNotFound.
func TestGetSecEvent_NotFound(t *testing.T) {
	db := NewDatabaseForTesting(t)
	if _, err := db.GetSecEvent(999999); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("GetSecEvent(999999) err = %v, want ErrRecordNotFound", err)
	}
}
