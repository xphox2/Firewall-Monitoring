package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetFlowInterfaceChartWindow verifies the sFlow interface bandwidth query
// buckets flow_if_counters and exposes cumulative octets as in_bytes/out_bytes
// (the frontend deltas them into a rate), scoped to the device+ifIndex+window.
func TestGetFlowInterfaceChartWindow(t *testing.T) {
	db := NewDatabaseForTesting(t)
	base := time.Now().Add(-30 * time.Minute)
	mk := func(off time.Duration, ifIdx uint32, in, out uint64) models.FlowInterfaceCounter {
		return models.FlowInterfaceCounter{
			Timestamp: base.Add(off), DeviceID: 1, IfIndex: ifIdx,
			IfSpeed: 1_000_000_000, InOctets: in, OutOctets: out,
		}
	}
	rows := []models.FlowInterfaceCounter{
		mk(0, 7, 1000, 5000),
		mk(1*time.Minute, 7, 126000, 255000), // +125000 in / +250000 out over 60s
		mk(2*time.Minute, 7, 251000, 505000),
		mk(1*time.Minute, 9, 1, 2), // different interface — must be excluded
	}
	if err := db.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	from := base.Add(-time.Minute)
	to := base.Add(10 * time.Minute)
	buckets, err := db.GetFlowInterfaceChartWindow(1, 7, from, to)
	if err != nil {
		t.Fatalf("GetFlowInterfaceChartWindow: %v", err)
	}
	if len(buckets) < 2 {
		t.Fatalf("got %d buckets, want >=2 (need consecutive points for a rate)", len(buckets))
	}
	// Cumulative octets are surfaced as in_bytes/out_bytes (monotonic here).
	for i := 1; i < len(buckets); i++ {
		if buckets[i].InBytes < buckets[i-1].InBytes || buckets[i].OutBytes < buckets[i-1].OutBytes {
			t.Errorf("cumulative octets should be non-decreasing across buckets: %+v", buckets)
		}
		if buckets[i].BucketMs == 0 {
			t.Errorf("bucket_ms not populated at %d", i)
		}
	}

	// A window with no data returns empty, not an error (frontend falls back).
	empty, err := db.GetFlowInterfaceChartWindow(1, 7, to, to.Add(time.Hour))
	if err != nil {
		t.Fatalf("empty window: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected no buckets outside the data window, got %d", len(empty))
	}
}
