package handlers

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestUpdatePingStatsBatch_FoldsCorrectly is the regression for the 2026-06-23
// audit M4 finding: ping-stat aggregation now folds a whole batch per
// (device,target) with one read + one write, instead of a serial
// read-modify-write per result. The folded min/max/avg/sample-count must be
// identical to applying the samples one at a time.
func TestUpdatePingStatsBatch_FoldsCorrectly(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)
	if err := db.Gorm().AutoMigrate(&models.PingStats{}); err != nil {
		t.Fatalf("migrate ping_stats: %v", err)
	}

	// First batch: 3 samples for one target + 1 for another.
	h.updatePingStatsBatch(probe.ID, []models.PingResult{
		{DeviceID: device.ID, TargetIP: "8.8.8.8", Latency: 10, PacketLoss: 0},
		{DeviceID: device.ID, TargetIP: "8.8.8.8", Latency: 20, PacketLoss: 0},
		{DeviceID: device.ID, TargetIP: "8.8.8.8", Latency: 30, PacketLoss: 5}, // last → packet loss
		{DeviceID: device.ID, TargetIP: "1.1.1.1", Latency: 100, PacketLoss: 0},
	})

	s1, err := db.GetPingStatsByTarget(device.ID, "8.8.8.8")
	if err != nil || s1 == nil {
		t.Fatalf("no stats for 8.8.8.8 (err=%v)", err)
	}
	if s1.Samples != 3 {
		t.Errorf("samples = %d, want 3", s1.Samples)
	}
	if s1.MinLatency != 10 || s1.MaxLatency != 30 {
		t.Errorf("min/max = %v/%v, want 10/30", s1.MinLatency, s1.MaxLatency)
	}
	if s1.AvgLatency != 20 { // (10+20+30)/3
		t.Errorf("avg = %v, want 20", s1.AvgLatency)
	}
	if s1.PacketLoss != 5 {
		t.Errorf("packetLoss = %v, want 5 (last-writer)", s1.PacketLoss)
	}

	// Grouping: the second target got its own row.
	if s2, _ := db.GetPingStatsByTarget(device.ID, "1.1.1.1"); s2 == nil || s2.Samples != 1 {
		t.Errorf("1.1.1.1 stats wrong: %+v", s2)
	}

	// Second batch folds into the existing running series.
	h.updatePingStatsBatch(probe.ID, []models.PingResult{
		{DeviceID: device.ID, TargetIP: "8.8.8.8", Latency: 40, PacketLoss: 0},
	})
	s1b, _ := db.GetPingStatsByTarget(device.ID, "8.8.8.8")
	if s1b.Samples != 4 {
		t.Errorf("samples = %d, want 4 after second batch", s1b.Samples)
	}
	if s1b.AvgLatency != 25 { // (20*3 + 40)/4
		t.Errorf("avg = %v, want 25 (folded into existing)", s1b.AvgLatency)
	}
	if s1b.MaxLatency != 40 {
		t.Errorf("max = %v, want 40", s1b.MaxLatency)
	}
}

// TestGetDeviceIDsByProbe is the regression for the 2026-06-23 audit M3 finding:
// the ingestion allow-list check now pulls just device IDs (no Site preload, no
// per-device secret decryption).
func TestGetDeviceIDsByProbe(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	// A device owned by a different (nil) probe must not appear.
	other := &models.Device{Name: "other", IPAddress: "10.0.0.9"}
	db.Gorm().Create(other)

	ids, err := db.GetDeviceIDsByProbe(probe.ID)
	if err != nil {
		t.Fatalf("GetDeviceIDsByProbe: %v", err)
	}
	if len(ids) != 1 || ids[0] != device.ID {
		t.Errorf("ids = %v, want [%d] (only the probe's own device)", ids, device.ID)
	}

	// And the handler's allow-list set agrees.
	set := h.probeDeviceIDs(probe.ID)
	if !set[device.ID] || set[other.ID] {
		t.Errorf("probeDeviceIDs set wrong: own=%v other=%v", set[device.ID], set[other.ID])
	}
}
