package database

import (
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// TestGetFlowStatsByCategoryAndDirection verifies that GetFlowStats surfaces the
// ingest-time classification columns (app_category, direction) as the
// ByCategory / ByDirection breakdowns. The handler stamps these at ingest; here
// we seed them directly to exercise the aggregation path.
func TestGetFlowStatsByCategoryAndDirection(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)

	mk := func(proto uint8, src, dst string, sp, dp uint16, bytes uint64) models.FlowSample {
		return models.FlowSample{
			Timestamp:   now,
			DeviceID:    1,
			Protocol:    proto,
			SrcAddr:     src,
			DstAddr:     dst,
			SrcPort:     sp,
			DstPort:     dp,
			Bytes:       bytes,
			Packets:     1,
			AppCategory: uint8(classify.Classify(proto, sp, dp, 0)),
			Direction:   classify.Direction(src, dst, 0, 0),
		}
	}

	samples := []models.FlowSample{
		// Two outbound web flows (internal → public, dst 443).
		mk(6, "10.0.0.5", "8.8.8.8", 50000, 443, 1000),
		mk(6, "10.0.0.6", "1.1.1.1", 50001, 443, 2000),
		// One internal DNS flow.
		mk(17, "10.0.0.5", "10.0.0.1", 40000, 53, 300),
		// One inbound remote-access flow (public → internal, dst 22).
		mk(6, "203.0.113.9", "10.0.0.5", 51000, 22, 400),
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed flow samples: %v", err)
	}

	res, err := db.GetFlowStats(1, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}

	cat := map[string]int64{}
	for _, kc := range res.ByCategory {
		cat[kc.Key] = kc.Count
	}
	if cat["Web"] != 2 {
		t.Errorf("ByCategory[Web] = %d, want 2. got=%v", cat["Web"], res.ByCategory)
	}
	if cat["DNS"] != 1 {
		t.Errorf("ByCategory[DNS] = %d, want 1. got=%v", cat["DNS"], res.ByCategory)
	}
	if cat["Remote Access"] != 1 {
		t.Errorf("ByCategory[Remote Access] = %d, want 1. got=%v", cat["Remote Access"], res.ByCategory)
	}

	dir := map[string]int64{}
	for _, kc := range res.ByDirection {
		dir[kc.Key] = kc.Count
	}
	if dir["Outbound"] != 2 {
		t.Errorf("ByDirection[Outbound] = %d, want 2. got=%v", dir["Outbound"], res.ByDirection)
	}
	if dir["Internal"] != 1 {
		t.Errorf("ByDirection[Internal] = %d, want 1. got=%v", dir["Internal"], res.ByDirection)
	}
	if dir["Inbound"] != 1 {
		t.Errorf("ByDirection[Inbound] = %d, want 1. got=%v", dir["Inbound"], res.ByDirection)
	}
}

// TestGetFlowStatsCategoryDirectionFilter verifies the By-Application /
// By-Direction click-to-filter narrows the aggregates server-side.
func TestGetFlowStatsCategoryDirectionFilter(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)
	mk := func(cat, dir uint8, bytes uint64) models.FlowSample {
		return models.FlowSample{
			Timestamp: now, DeviceID: 1, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", SrcPort: 50000, DstPort: 443,
			Bytes: bytes, Packets: 1, AppCategory: cat, Direction: dir,
		}
	}
	// 2 Web/Outbound, 1 DNS/Internal.
	samples := []models.FlowSample{
		mk(1, 2, 1000), mk(1, 2, 2000), mk(2, 3, 500),
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	web := uint8(1)
	res, err := db.GetFlowStats(1, FlowStatsFilter{AppCategory: &web})
	if err != nil {
		t.Fatalf("GetFlowStats(cat=Web): %v", err)
	}
	if res.TotalFlows != 2 {
		t.Errorf("AppCategory=Web TotalFlows = %d, want 2", res.TotalFlows)
	}

	internal := uint8(3)
	res, err = db.GetFlowStats(1, FlowStatsFilter{Direction: &internal})
	if err != nil {
		t.Fatalf("GetFlowStats(dir=Internal): %v", err)
	}
	if res.TotalFlows != 1 {
		t.Errorf("Direction=Internal TotalFlows = %d, want 1", res.TotalFlows)
	}
}

// TestGetFlowStatsTopCountriesAndASNs verifies the geo/ASN breakdowns aggregate
// by destination bytes and exclude unmapped (empty country / asn 0) rows.
func TestGetFlowStatsTopCountriesAndASNs(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)

	mk := func(dst, country string, asn uint32, bytes uint64) models.FlowSample {
		return models.FlowSample{
			Timestamp: now, DeviceID: 1, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: dst, SrcPort: 50000, DstPort: 443,
			Bytes: bytes, Packets: 1,
			DstCountry: country, DstASN: asn,
		}
	}
	samples := []models.FlowSample{
		mk("8.8.8.8", "US", 15169, 5000),
		mk("8.8.4.4", "US", 15169, 3000),
		mk("1.1.1.1", "AU", 13335, 1000),
		// Internal/unmapped: no country, asn 0 — must be excluded.
		mk("10.0.0.9", "", 0, 9999),
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := db.GetFlowStats(1, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}

	country := map[string]int64{}
	for _, kc := range res.TopCountries {
		country[kc.Key] = kc.Count
	}
	if country["US"] != 8000 {
		t.Errorf("TopCountries[US] = %d, want 8000. got=%v", country["US"], res.TopCountries)
	}
	if country["AU"] != 1000 {
		t.Errorf("TopCountries[AU] = %d, want 1000. got=%v", country["AU"], res.TopCountries)
	}
	if _, ok := country[""]; ok {
		t.Errorf("TopCountries must exclude empty country. got=%v", res.TopCountries)
	}

	asn := map[string]int64{}
	for _, kc := range res.TopASNs {
		asn[kc.Key] = kc.Count
	}
	if asn["AS15169"] != 8000 {
		t.Errorf("TopASNs[AS15169] = %d, want 8000. got=%v", asn["AS15169"], res.TopASNs)
	}
	if asn["AS13335"] != 1000 {
		t.Errorf("TopASNs[AS13335] = %d, want 1000. got=%v", asn["AS13335"], res.TopASNs)
	}
	if _, ok := asn["AS0"]; ok {
		t.Errorf("TopASNs must exclude asn 0. got=%v", res.TopASNs)
	}
}
