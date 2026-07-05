package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetFlowStatsFlowSourceFilter pins the Tranche 3 source filter: it
// narrows aggregates to one exporting protocol, and 0 (sFlow) is a real
// filter value, not "no filter".
func TestGetFlowStatsFlowSourceFilter(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)
	mk := func(src uint8, bytes uint64) models.FlowSample {
		return models.FlowSample{
			Timestamp: now, DeviceID: 1, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", SrcPort: 50000, DstPort: 443,
			Bytes: bytes, Packets: 1, FlowSource: src,
		}
	}
	samples := []models.FlowSample{
		mk(models.FlowSourceSFlow, 1000),
		mk(models.FlowSourceNetFlowV9, 2000),
		mk(models.FlowSourceNetFlowV9, 3000),
		mk(models.FlowSourceIPFIX, 500),
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	v9 := uint8(models.FlowSourceNetFlowV9)
	res, err := db.GetFlowStats(1, FlowStatsFilter{FlowSource: &v9})
	if err != nil {
		t.Fatalf("GetFlowStats(v9): %v", err)
	}
	if res.TotalFlows != 2 || res.TotalBytes != 5000 {
		t.Errorf("v9 filter: flows=%d bytes=%d, want 2/5000", res.TotalFlows, res.TotalBytes)
	}

	sf := uint8(models.FlowSourceSFlow)
	res, err = db.GetFlowStats(1, FlowStatsFilter{FlowSource: &sf})
	if err != nil {
		t.Fatalf("GetFlowStats(sflow): %v", err)
	}
	if res.TotalFlows != 1 {
		t.Errorf("sFlow(0) filter: flows=%d, want 1 — zero must act as a real filter", res.TotalFlows)
	}
}

// TestFlowRollup_GroupsByFlowSource pins that the rollup pipeline carries
// flow_source: identical 5-tuples from different sources land in DISTINCT
// rollup groups, and the source filter still resolves after raw rows are
// rolled up.
func TestFlowRollup_GroupsByFlowSource(t *testing.T) {
	db := NewDatabaseForTesting(t)
	old := time.Now().Add(-3 * time.Hour) // older than the 1h raw window
	mk := func(src uint8, bytes uint64) models.FlowSample {
		return models.FlowSample{
			Timestamp: old, DeviceID: 1, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", SrcPort: 50000, DstPort: 443,
			Bytes: bytes, Packets: 1, SamplingRate: 1, FlowSource: src,
		}
	}
	samples := []models.FlowSample{
		mk(models.FlowSourceSFlow, 1000),
		mk(models.FlowSourceNetFlowV9, 2000),
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	db.RunFlowRollupCycle()

	var rollups []models.FlowRollup
	if err := db.Gorm().Where("interval_type = ?", "5m").Find(&rollups).Error; err != nil {
		t.Fatalf("query rollups: %v", err)
	}
	if len(rollups) != 2 {
		t.Fatalf("got %d 5m rollup groups, want 2 (one per flow_source)", len(rollups))
	}
	seen := map[uint8]uint64{}
	for _, r := range rollups {
		seen[r.FlowSource] = r.BytesSum
	}
	if seen[models.FlowSourceSFlow] != 1000 || seen[models.FlowSourceNetFlowV9] != 2000 {
		t.Errorf("rollup groups wrong: %v", seen)
	}

	// The filter must resolve from rollups (24h window > 1h raw window).
	v9 := uint8(models.FlowSourceNetFlowV9)
	res, err := db.GetFlowStats(24, FlowStatsFilter{FlowSource: &v9})
	if err != nil {
		t.Fatalf("GetFlowStats from rollups: %v", err)
	}
	if res.TotalBytes != 2000 {
		t.Errorf("rollup-window v9 bytes = %d, want 2000", res.TotalBytes)
	}
}

// TestGetMixedFlowSourceDevices pins the dual-export warning query: a device
// reporting via two protocols in the last hour is flagged; single-source
// devices are not.
func TestGetMixedFlowSourceDevices(t *testing.T) {
	db := NewDatabaseForTesting(t)
	devices := []models.Device{
		{Name: "fw-dual", IPAddress: "192.0.2.1"},
		{Name: "fw-single", IPAddress: "192.0.2.2"},
	}
	if err := db.Gorm().Create(&devices).Error; err != nil {
		t.Fatalf("seed devices: %v", err)
	}
	now := time.Now().Add(-5 * time.Minute)
	mk := func(dev uint, src uint8) models.FlowSample {
		return models.FlowSample{
			Timestamp: now, DeviceID: dev, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", Bytes: 100, Packets: 1, FlowSource: src,
		}
	}
	samples := []models.FlowSample{
		mk(devices[0].ID, models.FlowSourceSFlow),
		mk(devices[0].ID, models.FlowSourceNetFlowV9),
		mk(devices[1].ID, models.FlowSourceNetFlowV9),
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed flows: %v", err)
	}

	got := db.GetMixedFlowSourceDevices()
	if len(got) != 1 || got[0] != "fw-dual" {
		t.Errorf("GetMixedFlowSourceDevices = %v, want [fw-dual]", got)
	}
}

// TestGetMixedFlowSourceDevices_UnattributedSampler pins the LC-00 follow-up:
// dual-export detection must not depend on device resolution. Covers the two
// pre-fix blind spots — a fully unattributed exporter (labeled by sampler
// address) and a device whose second flow family failed device resolution
// (device_id split across 5 and 0 for the same sampler IP).
func TestGetMixedFlowSourceDevices_UnattributedSampler(t *testing.T) {
	db := NewDatabaseForTesting(t)
	dev := models.Device{Name: "fw-split", IPAddress: "192.0.2.10"}
	if err := db.Gorm().Create(&dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	now := time.Now().Add(-5 * time.Minute)
	mk := func(devID uint, sampler string, src uint8) models.FlowSample {
		return models.FlowSample{
			Timestamp: now, DeviceID: devID, SamplerAddress: sampler, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", Bytes: 100, Packets: 1, FlowSource: src,
		}
	}
	samples := []models.FlowSample{
		// Fully unattributed dual exporter — both families failed resolution.
		mk(0, "203.0.113.7", models.FlowSourceSFlow),
		mk(0, "203.0.113.7", models.FlowSourceNetFlowV9),
		// Split-attribution dual exporter: sFlow resolved, NetFlow didn't.
		// Neither the device_id group nor the device_id=0 rows alone see two
		// sources — only the sampler_address grouping catches it.
		mk(dev.ID, "192.0.2.10", models.FlowSourceSFlow),
		mk(0, "192.0.2.10", models.FlowSourceNetFlowV9),
		// Single-source unattributed exporter — must NOT be flagged.
		mk(0, "203.0.113.99", models.FlowSourceIPFIX),
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed flows: %v", err)
	}

	got := db.GetMixedFlowSourceDevices()
	if len(got) != 2 || got[0] != "203.0.113.7" || got[1] != "fw-split" {
		t.Errorf("GetMixedFlowSourceDevices = %v, want [203.0.113.7 fw-split]", got)
	}
}
