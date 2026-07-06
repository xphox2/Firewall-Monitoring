package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func hasKey(kcs []KeyCount, key string) bool {
	for _, kc := range kcs {
		if kc.Key == key {
			return true
		}
	}
	return false
}

// TestGetFlowStatsScopeLocalRaw pins the raw-sample path (hours=1): portless
// ROUTED protocols (ESP) appear in the top-talker charts, scope-local noise
// (fe80->ff02) is excluded from them but counted in LocalTraffic, and TotalBytes
// includes everything.
func TestGetFlowStatsScopeLocalRaw(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)

	samples := []models.FlowSample{
		// portless ESP between routed hosts -> visible in top-talkers.
		{Timestamp: now, DeviceID: 1, Protocol: 50, SrcAddr: "10.0.0.20", DstAddr: "198.51.100.7", SrcPort: 0, DstPort: 0, Bytes: 12000, Packets: 12, ScopeLocal: false},
		// normal TCP -> visible.
		{Timestamp: now, DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", SrcPort: 5000, DstPort: 443, Bytes: 8000, Packets: 8, ScopeLocal: false},
		// scope-local link-local -> multicast noise -> excluded from charts, counted as LocalTraffic.
		{Timestamp: now, DeviceID: 1, Protocol: 58, SrcAddr: "fe80::1", DstAddr: "ff02::1", SrcPort: 0, DstPort: 0, Bytes: 7000, Packets: 7, ScopeLocal: true},
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed flow samples: %v", err)
	}

	res, err := db.GetFlowStats(1, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}

	if !hasKey(res.TopSources, "10.0.0.20") {
		t.Errorf("TopSources missing portless ESP src 10.0.0.20 (must be visible): %+v", res.TopSources)
	}
	if hasKey(res.TopSources, "fe80::1") {
		t.Errorf("TopSources contains scope-local src fe80::1 (must be excluded): %+v", res.TopSources)
	}
	if hasKey(res.TopDestinations, "ff02::1") {
		t.Errorf("TopDestinations contains multicast dst ff02::1 (must be excluded): %+v", res.TopDestinations)
	}
	for _, c := range res.TopConversations {
		if c.SrcAddr == "fe80::1" || c.DstAddr == "ff02::1" {
			t.Errorf("TopConversations contains scope-local flow: %+v", c)
		}
	}

	if res.LocalTraffic.Bytes != 7000 || res.LocalTraffic.Flows != 1 {
		t.Errorf("LocalTraffic = %d bytes / %d flows, want 7000 / 1 (scope-local row only)", res.LocalTraffic.Bytes, res.LocalTraffic.Flows)
	}
	if res.TotalBytes != 27000 {
		t.Errorf("TotalBytes = %d, want 27000 (all rows including scope-local)", res.TotalBytes)
	}
}

// TestGetFlowStatsScopeLocalRollup pins the rollup path (hours>1): the same
// scope-local exclusion applies to flow_rollups via the symmetric scope_local
// filter (the old port-0 filter used a different predicate on rollups).
func TestGetFlowStatsScopeLocalRollup(t *testing.T) {
	db := NewDatabaseForTesting(t)
	ts := time.Now().Add(-2 * time.Hour)

	rollups := []models.FlowRollup{
		{Timestamp: ts, DeviceID: 1, IntervalType: "5m", Protocol: 50, SrcAddr: "10.0.0.30", DstAddr: "198.51.100.8", DstPort: 0, BytesSum: 15000, PacketsSum: 15, FlowCount: 3, ScopeLocal: false},
		{Timestamp: ts, DeviceID: 1, IntervalType: "5m", Protocol: 58, SrcAddr: "fe80::2", DstAddr: "ff02::fb", DstPort: 0, BytesSum: 9000, PacketsSum: 9, FlowCount: 2, ScopeLocal: true},
	}
	if err := db.Gorm().Create(&rollups).Error; err != nil {
		t.Fatalf("seed flow rollups: %v", err)
	}

	res, err := db.GetFlowStats(6, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}

	if !hasKey(res.TopSources, "10.0.0.30") {
		t.Errorf("TopSources missing routed rollup src 10.0.0.30: %+v", res.TopSources)
	}
	if hasKey(res.TopSources, "fe80::2") {
		t.Errorf("TopSources contains scope-local rollup src fe80::2 (must be excluded): %+v", res.TopSources)
	}
	if res.LocalTraffic.Bytes != 9000 || res.LocalTraffic.Flows != 2 {
		t.Errorf("LocalTraffic = %d bytes / %d flows, want 9000 / 2 (scope-local rollup only)", res.LocalTraffic.Bytes, res.LocalTraffic.Flows)
	}
}
