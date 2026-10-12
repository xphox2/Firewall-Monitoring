package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
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
