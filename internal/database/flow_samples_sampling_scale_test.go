package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestMigrateFlowSamplesSamplingRateScale_ScalesAndIsIdempotent is the
// regression for the CTO-loop audit (2026-06-22, taocp [critical] #2):
// the v7 migration must backfill existing flow_samples rows so bytes
// becomes `frame_length * sampling_rate` and packets becomes
// `sampling_rate`. Without this migration, new inserts are scaled (per
// the internal/sflow parser change) but historical rows remain unscaled,
// so SUM(bytes) mixes apples and oranges.
//
// Three checks:
//  1. After run, an unmigrated row (bytes=frameLength, packets=1,
//     sampling_rate=512) becomes (bytes=frameLength*sampling_rate,
//     packets=sampling_rate).
//  2. A row with sampling_rate=1 is left alone (scaling by 1 is identity).
//  3. A re-run is a no-op (idempotency — the WHERE clause selects only
//     rows that haven't been migrated yet).
func TestMigrateFlowSamplesSamplingRateScale_ScalesAndIsIdempotent(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)

	// Seed three rows representing three pre-migration cases:
	//  - high sampling rate (will be scaled)
	//  - sampling rate of 1 (no-op for the WHERE clause; left alone)
	//  - already-migrated (packets != 1; left alone — covers the
	//    idempotency check)
	samples := []models.FlowSample{
		{
			Timestamp: now, DeviceID: 1, ProbeID: 1, Protocol: 6,
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcPort: 5000, DstPort: 443,
			Bytes: 1500, Packets: 1, SamplingRate: 512,
		},
		{
			Timestamp: now.Add(-1 * time.Minute), DeviceID: 1, ProbeID: 1, Protocol: 6,
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcPort: 5001, DstPort: 80,
			Bytes: 1500, Packets: 1, SamplingRate: 1, // no scaling needed
		},
		{
			Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, ProbeID: 1, Protocol: 6,
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcPort: 5002, DstPort: 22,
			Bytes: 1500 * 256, Packets: 256, SamplingRate: 256, // already migrated
		},
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Run the migration.
	if err := db.migrateFlowSamplesSamplingRateScale(); err != nil {
		t.Fatalf("migrateFlowSamplesSamplingRateScale: %v", err)
	}

	// Check 1: the high-sampling-rate row was scaled.
	var scaled models.FlowSample
	if err := db.Gorm().Where("src_port = 5000").First(&scaled).Error; err != nil {
		t.Fatalf("read scaled row: %v", err)
	}
	if scaled.Bytes != 1500*512 {
		t.Errorf("Bytes = %d, want %d (= 1500 * 512)", scaled.Bytes, 1500*512)
	}
	if scaled.Packets != 512 {
		t.Errorf("Packets = %d, want 512 (= sampling_rate)", scaled.Packets)
	}

	// Check 2: the sampling_rate=1 row was left alone.
	var noScale models.FlowSample
	if err := db.Gorm().Where("src_port = 5001").First(&noScale).Error; err != nil {
		t.Fatalf("read no-scale row: %v", err)
	}
	if noScale.Bytes != 1500 {
		t.Errorf("Bytes = %d, want 1500 (sampling_rate=1: identity, not scaled)", noScale.Bytes)
	}
	if noScale.Packets != 1 {
		t.Errorf("Packets = %d, want 1 (sampling_rate=1: identity, not scaled)", noScale.Packets)
	}

	// Check 3: the already-migrated row was left alone (idempotency).
	var alreadyScaled models.FlowSample
	if err := db.Gorm().Where("src_port = 5002").First(&alreadyScaled).Error; err != nil {
		t.Fatalf("read already-scaled row: %v", err)
	}
	if alreadyScaled.Bytes != 1500*256 {
		t.Errorf("Bytes = %d, want %d (already-migrated row should not be re-scaled; idempotency)", alreadyScaled.Bytes, 1500*256)
	}
	if alreadyScaled.Packets != 256 {
		t.Errorf("Packets = %d, want 256 (already-migrated row should not be re-scaled)", alreadyScaled.Packets)
	}

	// Re-run: must be a no-op. All three rows unchanged.
	if err := db.migrateFlowSamplesSamplingRateScale(); err != nil {
		t.Fatalf("migrateFlowSamplesSamplingRateScale (re-run): %v", err)
	}
	var check models.FlowSample
	if err := db.Gorm().Where("src_port = 5000").First(&check).Error; err != nil {
		t.Fatalf("read after re-run: %v", err)
	}
	if check.Bytes != 1500*512 {
		t.Errorf("re-run altered Bytes: %d, want %d (idempotency violated)", check.Bytes, 1500*512)
	}
	if check.Packets != 512 {
		t.Errorf("re-run altered Packets: %d, want 512 (idempotency violated)", check.Packets)
	}
}

// TestMigrateFlowSamplesSamplingRateScale_FreshInstallNoOp verifies that
// a fresh install (zero rows in flow_samples) doesn't error and is a
// no-op. The schema_migrations row is still recorded by the runner.
func TestMigrateFlowSamplesSamplingRateScale_FreshInstallNoOp(t *testing.T) {
	db := NewDatabaseForTesting(t)
	if err := db.migrateFlowSamplesSamplingRateScale(); err != nil {
		t.Fatalf("migrateFlowSamplesSamplingRateScale on empty table: %v", err)
	}
	var count int64
	if err := db.Gorm().Model(&models.FlowSample{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 (fresh install has no flow_samples)", count)
	}
}
