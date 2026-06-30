package detect

import (
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

func TestCleartextDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	mk := func(dport uint16, n int) {
		for i := 0; i < n; i++ {
			s := models.FlowSample{
				Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, Protocol: 6,
				SrcAddr: "10.0.0.5", DstAddr: "10.0.0.9", SrcPort: 40000, DstPort: dport,
				Bytes: 1000, Packets: 1,
			}
			if err := db.Gorm().Create(&s).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	mk(23, 5)  // Telnet — should fire
	mk(443, 5) // HTTPS — must NOT fire (encrypted)
	mk(21, 2)  // FTP — below minFlows, must NOT fire

	w := Window{Start: now.Add(-1 * time.Hour), End: now.Add(time.Minute), DB: db.Gorm()}
	got, err := cleartextDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("cleartext fired %d times, want 1 (telnet only). got=%+v", len(got), got)
	}
	if got[0].DstPort != 23 || got[0].Severity != "warning" || got[0].Category != CategoryPolicy {
		t.Errorf("unexpected detection: %+v", got[0])
	}
}

func TestUnexpectedEgressDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	mk := func(dport uint16, dir uint8, n int) {
		for i := 0; i < n; i++ {
			s := models.FlowSample{
				Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, Protocol: 6,
				SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", SrcPort: 40000, DstPort: dport,
				Direction: dir, Bytes: 1000, Packets: 1,
			}
			if err := db.Gorm().Create(&s).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	mk(3389, classify.DirOutbound, 5) // RDP outbound — should fire
	mk(3389, classify.DirInternal, 5) // RDP internal — must NOT fire (not egress)
	mk(443, classify.DirOutbound, 5)  // HTTPS outbound — not an egress-watch port

	got, err := unexpectedEgressDetector{}.Detect(Window{Start: now.Add(-time.Hour), End: now.Add(time.Minute), DB: db.Gorm()})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].DstPort != 3389 {
		t.Fatalf("unexpected_egress = %+v, want exactly RDP(3389)", got)
	}
}

func TestSamplingBackoffDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	rows := []models.AgentDrops{
		{AgentAddress: "10.0.0.1", SamplingRate: 512, WindowStart: now.Add(-2 * time.Minute), DropsCount: 100},
		{AgentAddress: "10.0.0.1", SamplingRate: 512, WindowStart: now.Add(-1 * time.Minute), DropsCount: 50},
		{AgentAddress: "10.0.0.2", SamplingRate: 512, WindowStart: now.Add(-2 * time.Minute), DropsCount: 0}, // no drops
	}
	if err := db.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := samplingBackoffDetector{}.Detect(Window{Start: now.Add(-time.Hour), End: now.Add(time.Minute), DB: db.Gorm()})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].SrcAddr != "10.0.0.1" || got[0].Score != 150 {
		t.Fatalf("sampling_backoff = %+v, want agent 10.0.0.1 score 150", got)
	}
}

func TestCapacityDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// 1 Gbps link.
	if err := db.Gorm().Create(&models.InterfaceStats{
		Timestamp: now, DeviceID: 1, Index: 7, Speed: 1_000_000_000, Status: "up",
	}).Error; err != nil {
		t.Fatalf("seed iface: %v", err)
	}
	// ~900 Mbps over a 60s window => 90% utilisation. bytes = bps*secs/8.
	const secs = 60
	bytes := uint64(900_000_000) * secs / 8
	if err := db.Gorm().Create(&models.FlowSample{
		Timestamp: now.Add(-30 * time.Second), DeviceID: 1, Protocol: 6,
		SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", DstPort: 443,
		OutputIfIndex: 7, Bytes: bytes, Packets: 1,
	}).Error; err != nil {
		t.Fatalf("seed flow: %v", err)
	}
	w := Window{Start: now.Add(-secs * time.Second), End: now, DB: db.Gorm()}
	got, err := capacityDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("capacity fired %d times, want 1. got=%+v", len(got), got)
	}
	if got[0].Score < 85 || got[0].Score > 95 {
		t.Errorf("capacity pct = %.1f, want ~90", got[0].Score)
	}
}

// TestCapacityDetector_SFlowSpeedFallback verifies that when SNMP interface_stats
// has no speed for the interface (e.g. SNMP host-restricted), the capacity
// detector falls back to the sFlow-reported ifSpeed from flow_if_counters.
func TestCapacityDetector_SFlowSpeedFallback(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// No InterfaceStats row → SNMP speed unknown. sFlow counter supplies 1 Gbps.
	if err := db.Gorm().Create(&models.FlowInterfaceCounter{
		Timestamp: now.Add(-10 * time.Second), DeviceID: 1, IfIndex: 7, IfSpeed: 1_000_000_000,
	}).Error; err != nil {
		t.Fatalf("seed counter: %v", err)
	}
	const secs = 60
	bytes := uint64(900_000_000) * secs / 8 // ~90% of 1 Gbps
	if err := db.Gorm().Create(&models.FlowSample{
		Timestamp: now.Add(-30 * time.Second), DeviceID: 1, Protocol: 6,
		SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", DstPort: 443,
		OutputIfIndex: 7, Bytes: bytes, Packets: 1,
	}).Error; err != nil {
		t.Fatalf("seed flow: %v", err)
	}
	w := Window{Start: now.Add(-secs * time.Second), End: now, DB: db.Gorm()}
	got, err := capacityDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("capacity fired %d times, want 1 (via sFlow ifSpeed). got=%+v", len(got), got)
	}
	if got[0].Score < 85 || got[0].Score > 95 {
		t.Errorf("capacity pct = %.1f, want ~90", got[0].Score)
	}
}

func TestRunAll_MapsToModel(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		db.Gorm().Create(&models.FlowSample{
			Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, Protocol: 6,
			SrcAddr: "10.0.0.5", DstAddr: "10.0.0.9", SrcPort: 40000, DstPort: 23,
			Bytes: 1000, Packets: 1,
		})
	}
	dets := RunAll(Window{Start: now.Add(-time.Hour), End: now.Add(time.Minute), DB: db.Gorm()}, now)
	if len(dets) != 1 {
		t.Fatalf("RunAll returned %d models, want 1", len(dets))
	}
	m := dets[0]
	if m.Detector != "cleartext" || m.DedupKey == "" || m.DetectedAt.IsZero() || m.Details == "" {
		t.Errorf("ToModel mapping incomplete: %+v", m)
	}
}
