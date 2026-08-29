package detect

import (
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// AUDIT-273: the c2_beacon byte gate compared AVG(bytes) against a per-FRAME
// ceiling (BeaconMaxAvgBytes=1500), but `bytes` is PRE-MULTIPLIED by
// sampling_rate at ingest. On sampled sFlow (rate 512) a small 300-byte beacon
// frame stores as 300*512=153600, so the un-normalized gate demanded an average
// frame <= ~2.9 bytes — unreachable — and no sampled beacon could ever fire even
// though c2_beacon is classified ValiditySampledOK. The fix divides each row's
// bytes by its own effective sampling rate before averaging.
func TestC2Beacon_SampledFramesPassByteGate_AUDIT273(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	base := time.Now().Add(-30 * time.Minute)

	// Beacon over SAMPLED sFlow: 12 small callouts every 60s at rate 512, stored
	// pre-multiplied (300-byte frame -> 153600 stored bytes).
	for i := 0; i < 12; i++ {
		seedFlow(t, db, models.FlowSample{
			Timestamp: base.Add(time.Duration(i) * 60 * time.Second),
			DeviceID:  1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9",
			DstPort: 8443, Direction: classify.DirOutbound,
			Bytes: 300 * 512, Packets: 512, SamplingRate: 512,
		})
	}

	// Bulk transfer over the SAME sampling rate: large 2000-byte frames
	// (2000 > 1500 per-frame ceiling) must still FAIL the byte gate, even though
	// it is just as periodic as the beacon.
	for i := 0; i < 12; i++ {
		seedFlow(t, db, models.FlowSample{
			Timestamp: base.Add(time.Duration(i) * 60 * time.Second),
			DeviceID:  1, Protocol: 6, SrcAddr: "10.0.0.6", DstAddr: "203.0.113.10",
			DstPort: 443, Direction: classify.DirOutbound,
			Bytes: 2000 * 512, Packets: 512, SamplingRate: 512,
		})
	}

	w := Window{Start: base.Add(-time.Minute), End: time.Now(), DB: db.Gorm()}
	got, err := c2BeaconDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("c2_beacon = %+v, want exactly 1 (the sampled small-frame beacon)", got)
	}
	if got[0].DstAddr != "203.0.113.9" {
		t.Errorf("beacon dst = %q, want 203.0.113.9 (bulk 203.0.113.10 must fail the per-frame byte gate)", got[0].DstAddr)
	}
}

// TestC2Beacon_UnsampledUnaffected_AUDIT273 pins the rate=1/rate=0 (unsampled)
// path: dividing by max(sampling_rate,1) is a no-op, so a small-frame beacon
// still passes and a large-frame source still fails. This is what a naive "just
// raise the constant" fix would have broken.
func TestC2Beacon_UnsampledUnaffected_AUDIT273(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	base := time.Now().Add(-30 * time.Minute)

	// Unsampled small-frame beacon (rate 0 => stored verbatim).
	for i := 0; i < 12; i++ {
		seedFlow(t, db, models.FlowSample{
			Timestamp: base.Add(time.Duration(i) * 60 * time.Second),
			DeviceID:  1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "198.51.100.9",
			DstPort: 8443, Direction: classify.DirOutbound,
			Bytes: 300, Packets: 1, SamplingRate: 0,
		})
	}
	// Unsampled bulk source: 2000-byte frames must still fail the byte gate.
	for i := 0; i < 12; i++ {
		seedFlow(t, db, models.FlowSample{
			Timestamp: base.Add(time.Duration(i) * 60 * time.Second),
			DeviceID:  1, Protocol: 6, SrcAddr: "10.0.0.7", DstAddr: "198.51.100.11",
			DstPort: 443, Direction: classify.DirOutbound,
			Bytes: 2000, Packets: 1, SamplingRate: 1,
		})
	}

	w := Window{Start: base.Add(-time.Minute), End: time.Now(), DB: db.Gorm()}
	got, err := c2BeaconDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].DstAddr != "198.51.100.9" {
		t.Fatalf("c2_beacon = %+v, want exactly the unsampled small-frame beacon 198.51.100.9", got)
	}
}
