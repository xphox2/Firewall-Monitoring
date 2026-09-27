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

	// Count is BYTES, Records the sampled-record count (FlowKeyCount).
	check := func(name string, list []FlowKeyCount, want map[string][2]int64) {
		t.Helper()
		got := map[string][2]int64{}
		for _, kc := range list {
			got[kc.Key] = [2]int64{kc.Count, kc.Records}
		}
		for k, w := range want {
			if got[k] != w {
				t.Errorf("%s[%s] = bytes %d records %d, want bytes %d records %d. got=%v",
					name, k, got[k][0], got[k][1], w[0], w[1], list)
			}
		}
	}
	check("ByCategory", res.ByCategory, map[string][2]int64{
		"Web": {3000, 2}, "DNS": {300, 1}, "Remote Access": {400, 1},
	})
	check("ByDirection", res.ByDirection, map[string][2]int64{
		"Outbound": {3000, 2}, "Internal": {300, 1}, "Inbound": {400, 1},
	})
}

// TestGetFlowStats_DistributionsRankByBytes pins the production defect: one
// server showed "Unknown" first on Applications (938k records, 49 MB) while Web
// carried 400 GB, and Protocols printed the record count as if it were bytes.
// Many small records must lose to a few large ones on every distribution panel,
// on the raw side AND the rolled-up side.
func TestGetFlowStats_DistributionsRankByBytes(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	// Raw: twenty tiny UDP/unknown-category/inbound records ...
	for i := 0; i < 20; i++ {
		if err := db.Gorm().Create(&models.FlowSample{
			Timestamp: now.Add(-20 * time.Minute), DeviceID: 1, Protocol: 17,
			SrcAddr: "203.0.113.9", DstAddr: "10.0.0.5", SrcPort: 40000, DstPort: 40001,
			Bytes: 10, Packets: 1,
			AppCategory: uint8(classify.Unknown), Direction: classify.DirInbound,
		}).Error; err != nil {
			t.Fatalf("seed raw: %v", err)
		}
	}
	// ... and one rolled-up TCP web outbound row carrying almost all the bytes
	// in only three records.
	if err := db.Gorm().Create(&models.FlowRollup{
		Timestamp: now.Add(-20 * time.Hour), DeviceID: 1, IntervalType: "5m",
		SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
		BytesSum: 5_000_000, PacketsSum: 4000, FlowCount: 3, SamplingRateAvg: 1,
		AppCategory: uint8(classify.Web), Direction: classify.DirOutbound,
	}).Error; err != nil {
		t.Fatalf("seed rollup: %v", err)
	}

	res, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	for _, c := range []struct {
		name      string
		list      []FlowKeyCount
		wantFirst string
		bytes     int64
		records   int64
	}{
		{"ByProtocol", res.ByProtocol, "TCP", 5_000_000, 3},
		{"ByCategory", res.ByCategory, classify.CategoryName(uint8(classify.Web)), 5_000_000, 3},
		{"ByDirection", res.ByDirection, classify.DirectionName(classify.DirOutbound), 5_000_000, 3},
	} {
		if len(c.list) < 2 {
			t.Errorf("%s = %v, want both values", c.name, c.list)
			continue
		}
		top := c.list[0]
		if top.Key != c.wantFirst || top.Count != c.bytes || top.Records != c.records {
			t.Errorf("%s[0] = %+v, want {%s bytes=%d records=%d} — the panel must rank by bytes, "+
				"not by how many records a value produced", c.name, top, c.wantFirst, c.bytes, c.records)
		}
		if second := c.list[1]; second.Count != 200 || second.Records != 20 {
			t.Errorf("%s[1] = %+v, want bytes=200 records=20", c.name, second)
		}
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

// TestGetFlowStatsGeoFilter verifies the Top Countries / Top ASNs click-to-filter
// narrows the aggregates by destination country and ASN.
func TestGetFlowStatsGeoFilter(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)
	mk := func(dst, country string, asn uint32, bytes uint64) models.FlowSample {
		return models.FlowSample{
			Timestamp: now, DeviceID: 1, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: dst, SrcPort: 50000, DstPort: 443,
			Bytes: bytes, Packets: 1, DstCountry: country, DstASN: asn,
		}
	}
	samples := []models.FlowSample{
		mk("8.8.8.8", "US", 15169, 5000),
		mk("8.8.4.4", "US", 15169, 3000),
		mk("1.1.1.1", "AU", 13335, 1000),
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := db.GetFlowStats(1, FlowStatsFilter{DstCountry: "US"})
	if err != nil {
		t.Fatalf("GetFlowStats(country=US): %v", err)
	}
	if res.TotalFlows != 2 {
		t.Errorf("DstCountry=US TotalFlows = %d, want 2", res.TotalFlows)
	}

	asn := uint32(13335)
	res, err = db.GetFlowStats(1, FlowStatsFilter{DstASN: &asn})
	if err != nil {
		t.Fatalf("GetFlowStats(asn=13335): %v", err)
	}
	if res.TotalFlows != 1 {
		t.Errorf("DstASN=13335 TotalFlows = %d, want 1", res.TotalFlows)
	}
}
