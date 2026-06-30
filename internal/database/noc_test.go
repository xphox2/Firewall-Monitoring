package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetNOCSnapshot verifies the live snapshot aggregates recent flows over the
// window (throughput, top talkers, threat-flow count) and excludes flows older
// than the window.
func TestGetNOCSnapshot(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	recent := now.Add(-1 * time.Minute)
	old := now.Add(-30 * time.Minute) // outside a 5-min window

	mk := func(ts time.Time, src, dst string, bytes uint64, threat uint8) models.FlowSample {
		return models.FlowSample{
			Timestamp: ts, DeviceID: 1, Protocol: 6, SrcAddr: src, DstAddr: dst,
			SrcPort: 40000, DstPort: 443, Bytes: bytes, Packets: 1,
			AppCategory: 1, Direction: 2, ThreatFlag: threat,
		}
	}
	rows := []models.FlowSample{
		mk(recent, "10.0.0.5", "8.8.8.8", 1000, 0),
		mk(recent, "10.0.0.5", "8.8.4.4", 2000, 2), // threat-flagged dst
		mk(recent, "10.0.0.6", "1.1.1.1", 500, 0),
		mk(old, "10.0.0.9", "9.9.9.9", 999999, 0), // outside window — must be excluded
	}
	if err := db.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	snap, err := db.GetNOCSnapshot(5 * time.Minute)
	if err != nil {
		t.Fatalf("GetNOCSnapshot: %v", err)
	}
	if snap.TotalFlows != 3 {
		t.Errorf("TotalFlows = %d, want 3 (old flow excluded)", snap.TotalFlows)
	}
	if snap.TotalBytes != 3500 {
		t.Errorf("TotalBytes = %d, want 3500 (1000+2000+500)", snap.TotalBytes)
	}
	if snap.ThreatFlows != 1 {
		t.Errorf("ThreatFlows = %d, want 1", snap.ThreatFlows)
	}
	if snap.UniqueSources != 2 {
		t.Errorf("UniqueSources = %d, want 2", snap.UniqueSources)
	}
	if snap.BitsPerSecond <= 0 {
		t.Errorf("BitsPerSecond = %v, want > 0", snap.BitsPerSecond)
	}
	if len(snap.TopSources) == 0 || snap.TopSources[0].Key != "10.0.0.5" {
		t.Errorf("TopSources[0] = %+v, want 10.0.0.5 first", snap.TopSources)
	}
	if snap.WindowSeconds != 300 {
		t.Errorf("WindowSeconds = %d, want 300", snap.WindowSeconds)
	}
}
