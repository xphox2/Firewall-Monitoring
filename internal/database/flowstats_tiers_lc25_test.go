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

// TestRollupIntervalsForWindow pins the tier-band arithmetic at the exact
// boundaries: 48h still reads only the 5m tier (the 1h tier starts strictly
// past 48h), 720h still excludes the 1d tier.
func TestRollupIntervalsForWindow(t *testing.T) {
	cases := []struct {
		hours int
		want  []string
	}{
		{2, []string{"5m"}},
		{48, []string{"5m"}},
		{49, []string{"5m", "1h"}},
		{168, []string{"5m", "1h"}},
		{720, []string{"5m", "1h"}},
		{721, []string{"5m", "1h", "1d"}},
		{2160, []string{"5m", "1h", "1d"}},
	}
	for _, tc := range cases {
		got := rollupIntervalsForWindow(tc.hours)
		if len(got) != len(tc.want) {
			t.Errorf("rollupIntervalsForWindow(%d) = %v, want %v", tc.hours, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("rollupIntervalsForWindow(%d) = %v, want %v", tc.hours, got, tc.want)
				break
			}
		}
	}
}
