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
