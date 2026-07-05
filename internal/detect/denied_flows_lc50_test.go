package detect

import (
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// These tests pin the LC-50 fix: DENIED firewall-event rows (Tranche 3
// zero-byte NSEL/FortiGate records) must not make the forwarded-traffic
// detectors assert that blocked traffic occurred, while the scan-behavior
// detectors intentionally keep them (a blocked probe is still scan evidence).

func seedDenied(t *testing.T, db *database.Database, s models.FlowSample, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		row := s
		if err := db.Gorm().Create(&row).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func TestCleartextDetectorExcludesDenied(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	base := models.FlowSample{
		Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, Protocol: 6,
		SrcAddr: "198.51.100.7", DstAddr: "10.0.0.9", SrcPort: 40000, DstPort: 23,
		Packets: 0,
	}
	// Blocked internet background radiation: denied Telnet probes, zero bytes.
	denied := base
	denied.FirewallEvent = models.FirewallEventDenied
	seedDenied(t, db, denied, 5)

	w := Window{Start: now.Add(-time.Hour), End: now.Add(time.Minute), DB: db.Gorm()}
	got, err := cleartextDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("cleartext fired on DENIED-only Telnet probes: %+v — blocked traffic never crossed the network", got)
	}

	// Mixed: real forwarded Telnet alongside the denied probes must still fire,
	// counting only the forwarded flows.
	allowed := base
	allowed.Bytes = 1000
	allowed.Packets = 1
	seedDenied(t, db, allowed, 4)
	got, err = cleartextDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect (mixed): %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("cleartext = %d findings on mixed denied+forwarded, want 1", len(got))
	}
	if flows, _ := got[0].Details["flows"].(int64); flows != 4 {
		t.Errorf("cleartext counted %v flows, want 4 (forwarded only)", got[0].Details["flows"])
	}
}

func TestUnexpectedEgressDetectorExcludesDenied(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	denied := models.FlowSample{
		Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, Protocol: 6,
		SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", SrcPort: 40000, DstPort: 445,
		Direction: classify.DirOutbound, FirewallEvent: models.FirewallEventDenied,
	}
	seedDenied(t, db, denied, 5)

	got, err := unexpectedEgressDetector{}.Detect(Window{Start: now.Add(-time.Hour), End: now.Add(time.Minute), DB: db.Gorm()})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected_egress asserted SMB 'leaving the network' for flows the firewall DENIED: %+v", got)
	}
}

func TestThreatIntelDetectorExcludesDenied(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	denied := models.FlowSample{
		Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, Protocol: 6,
		SrcAddr: "10.0.0.5", DstAddr: "203.0.113.66", SrcPort: 40000, DstPort: 443,
		ThreatFlag: 2, FirewallEvent: models.FirewallEventDenied,
	}
	seedDenied(t, db, denied, 3)

	got, err := threatIntelDetector{}.Detect(Window{Start: now.Add(-time.Hour), End: now.Add(time.Minute), DB: db.Gorm()})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("threat_intel reported 'traffic with known-bad destination' for BLOCKED connections: %+v", got)
	}
}

func TestPortScanDetectorKeepsDeniedRows(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// A denied vertical scan: each probe blocked by policy, but the source
	// really touched every port — scan evidence the detector must keep.
	for port := uint16(1); port <= 10; port++ {
		s := models.FlowSample{
			Timestamp: now.Add(-2 * time.Minute), DeviceID: 1, Protocol: 6,
			SrcAddr: "198.51.100.9", DstAddr: "10.0.0.9", SrcPort: 40000, DstPort: port,
			FirewallEvent: models.FirewallEventDenied,
		}
		if err := db.Gorm().Create(&s).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	w := Window{
		Start: now.Add(-time.Hour), End: now.Add(time.Minute), DB: db.Gorm(),
		Config: Config{PortScanPorts: 5},
	}
	got, err := portScanDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("port_scan = %d findings on a denied scan, want 1 — blocked probes are still scan evidence", len(got))
	}
}
