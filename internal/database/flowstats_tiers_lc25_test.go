package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetFlowStats_WindowSpansAllRollupTiers pins the LC-25 fix: the rollup
// lifecycle keeps each age band in exactly ONE tier (promotion deletes the
// source rows), so a query window must union EVERY tier whose band it
// intersects. Pre-fix a 7d window read only the "1h" tier and silently
// dropped the (1h,48h] band, and a 90d window dropped (1h,30d].
func TestGetFlowStats_WindowSpansAllRollupTiers(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()

	// One row per lifecycle tier, each in the age band the ladder actually
	// keeps it in: raw <1h, 5m in (1h,48h], 1h in (48h,30d], 1d beyond 30d.
	raw := models.FlowSample{
		Timestamp: now.Add(-30 * time.Minute), DeviceID: 1, Protocol: 6,
		SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", SrcPort: 50000, DstPort: 443,
		Bytes: 100, Packets: 1,
	}
	if err := db.Gorm().Create(&raw).Error; err != nil {
		t.Fatalf("seed raw: %v", err)
	}
	mkRollup := func(interval string, age time.Duration, bytes uint64) models.FlowRollup {
		return models.FlowRollup{
			Timestamp: now.Add(-age), DeviceID: 1, IntervalType: interval,
			SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: bytes, PacketsSum: 1, FlowCount: 1,
		}
	}
	rollups := []models.FlowRollup{
		mkRollup("5m", 23*time.Hour, 200), // 23h, not 24h: keep clear of the 24h-case cutoff edge
		mkRollup("1h", 5*24*time.Hour, 400),
		mkRollup("1d", 40*24*time.Hour, 800),
	}
	if err := db.Gorm().Create(&rollups).Error; err != nil {
		t.Fatalf("seed rollups: %v", err)
	}

	cases := []struct {
		hours     int
		wantBytes uint64
		wantFlows int64
		desc      string
	}{
		{24, 300, 2, "24h = raw + 5m tier"},
		{168, 700, 3, "7d = raw + 5m + 1h tiers (pre-fix: raw + 1h only)"},
		{720, 700, 3, "30d = raw + 5m + 1h tiers"},
		{2160, 1500, 4, "90d = raw + all three rollup tiers (pre-fix: raw + 1d only)"},
	}
	for _, tc := range cases {
		res, err := db.GetFlowStats(tc.hours, FlowStatsFilter{})
		if err != nil {
			t.Fatalf("GetFlowStats(%d): %v", tc.hours, err)
		}
		if res.TotalBytes != tc.wantBytes || res.TotalFlows != tc.wantFlows {
			t.Errorf("%s: bytes=%d flows=%d, want %d/%d",
				tc.desc, res.TotalBytes, res.TotalFlows, tc.wantBytes, tc.wantFlows)
		}
	}
}

// The tier-selection tests below replace TestRollupIntervalsForWindow, which
// asserted that a 48h window reads only the 5m tier and a 720h window excludes
// the 1d tier. Those assertions were true, but they pinned the READER to the
// LADDER's promotion ages — the very coupling that made the reader breakable —
// so the test enshrined the hazard instead of guarding against it.
//
// These assert the property that actually matters: a reader's answer does not
// depend on where the ladder happens to promote.

// seedTierLadder lays down raw-adjacent 5m rollups across a window and returns
// the total bytes seeded.
//
// Local-zone time deliberately, NOT .UTC(): GetFlowStats renders its cutoff in
// the local zone and the SQLite lane compares timestamps as text, so a UTC seed
// silently falls outside every window on a machine that is not on UTC.
func seedTierLadder(t *testing.T, d *Database, hoursAgo []int, each uint64) uint64 {
	t.Helper()
	var total uint64
	for _, h := range hoursAgo {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: time.Now().Add(-time.Duration(h) * time.Hour),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: each, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed %dh ago: %v", h, err)
		}
		total += each
	}
	return total
}

// TestFlowStats_SurvivesAn5mTo1hPromotionAtAnyAge pins that the reader does not
// depend on the 5m→1h promotion happening at 48 hours.
//
// aggregateRollupsUp takes its cutoff as a PARAMETER, so this age is one edit
// away from changing. Against the old tier selection — which added the 1h tier
// only when the window exceeded 48h — promoting earlier stranded every promoted
// row outside a 48h query: 4,000 of 7,000 seeded bytes.
func TestFlowStats_SurvivesAn5mTo1hPromotionAtAnyAge(t *testing.T) {
	d := NewDatabaseForTesting(t)
	want := seedTierLadder(t, d, []int{4, 10, 20, 30, 40, 44, 46}, 1000)

	// Move the ladder's own age, which is what a future change would do, and
	// promote accordingly. The reader must follow the constant, not a literal of
	// its own.
	orig := flowPromote5mTo1hAge
	flowPromote5mTo1hAge = 24 * time.Hour
	defer func() { flowPromote5mTo1hAge = orig }()
	d.aggregateRollupsUp("5m", "1h", time.Now().Add(-flowPromote5mTo1hAge))

	var promoted int64
	d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", "1h").Count(&promoted)
	if promoted == 0 {
		t.Fatal("precondition: nothing was promoted, so the test proves nothing")
	}

	res, err := d.GetFlowStats(48, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats(48): %v", err)
	}
	if res.TotalBytes != want {
		t.Errorf("a 48h window reports %d bytes against %d seeded. The reader derives its tier "+
			"list from flowPromote5mTo1hAge; if it carried its own literal instead, moving the "+
			"ladder strands every promoted row outside the window.", res.TotalBytes, want)
	}
}

// TestFlowStats_SurvivesA1hTo1dPromotionAtAnyAge is the same property one rung
// up, and it matters more: 720h IS a range pill, so this is the 30-day view.
func TestFlowStats_SurvivesA1hTo1dPromotionAtAnyAge(t *testing.T) {
	d := NewDatabaseForTesting(t)
	want := seedTierLadder(t, d, []int{24, 24 * 5, 24 * 12, 24 * 18, 24 * 22, 24 * 26, 24 * 28}, 1000)

	// Move the ladder's own age and promote accordingly.
	orig5m := flowPromote5mTo1hAge
	orig1h := flowPromote1hTo1dAge
	flowPromote5mTo1hAge = 12 * time.Hour
	flowPromote1hTo1dAge = 10 * 24 * time.Hour
	defer func() {
		flowPromote5mTo1hAge = orig5m
		flowPromote1hTo1dAge = orig1h
	}()
	d.aggregateRollupsUp("5m", "1h", time.Now().Add(-flowPromote5mTo1hAge))
	d.aggregateRollupsUp("1h", "1d", time.Now().Add(-flowPromote1hTo1dAge))

	var promoted int64
	d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", "1d").Count(&promoted)
	if promoted == 0 {
		t.Fatal("precondition: nothing reached the 1d tier, so the test proves nothing")
	}

	res, err := d.GetFlowStats(720, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats(720): %v", err)
	}
	if res.TotalBytes != want {
		t.Errorf("the 30-day window reports %d bytes against %d seeded; rows promoted to the 1d "+
			"tier earlier than 30 days were dropped", res.TotalBytes, want)
	}
}

// TestFlowStats_TrimsTheLeadingPartialBucket pins the chart defect this work
// uncovered. The window's cutoff lands inside a bucket and `timestamp > cutoff`
// keeps only that bucket's post-cutoff slice — which was then drawn at full
// bucket width, so the first plotted point read anywhere from 8% to 100% of its
// true rate depending on the wall-clock minute. v0.11.247 fixed the same defect
// at the trailing end and missed this one because it only looked at the newest
// bucket.
func TestFlowStats_TrimsTheLeadingPartialBucket(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	cutoffHour := now.Add(-24 * time.Hour).Truncate(time.Hour)

	// A full hour's worth of 5m rows spanning the cutoff hour: some before the
	// 24h cutoff (outside the window) and some after (inside it). The bucket is
	// therefore partial however the clock falls.
	// Every minute, not every five: seeding only :00-:55 made this a silent no-op
	// whenever GetFlowStats's own cutoff landed at :55 or later, because then
	// every seeded row is below it, series[0] is a different hour, and the
	// assertion passes on unfixed code too. 5 minutes in every 60.
	for m := 0; m < 60; m++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: cutoffHour.Add(time.Duration(m) * time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed cutoff hour +%dm: %v", m, err)
		}
	}
	// And a whole, unambiguously-inside hour so the series is not empty after
	// the trim.
	fullHour := now.Add(-12 * time.Hour).Truncate(time.Hour)
	for m := 0; m < 60; m += 5 {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: fullHour.Add(time.Duration(m) * time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.2", DstAddr: "8.8.4.4", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed full hour +%dm: %v", m, err)
		}
	}

	res, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats(24): %v", err)
	}
	if len(res.BytesOverTime) == 0 {
		t.Fatal("the series is empty; the trim removed everything")
	}

	cutLabel := bucketLabelAt(now.Add(-24*time.Hour), "hour")
	if first := res.BytesOverTime[0].Bucket; first == cutLabel {
		t.Errorf("the first plotted bucket is %q, the one the 24h cutoff falls inside. It holds "+
			"only its post-cutoff slice but is drawn at full width, so the chart opens on a "+
			"point that under-reads its own rate.", first)
	}
}
