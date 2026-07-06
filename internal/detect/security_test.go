package detect

import (
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

func seedFlow(t *testing.T, db *database.Database, s models.FlowSample) {
	t.Helper()
	if s.Timestamp.IsZero() {
		s.Timestamp = time.Now().Add(-2 * time.Minute)
	}
	if err := db.Gorm().Create(&s).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func fullWindow(now time.Time) Window {
	return Window{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}
}

func TestPortScanDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// Scanner: one src hitting 25 distinct ports.
	for p := 1; p <= 25; p++ {
		seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "10.0.0.9", DstPort: uint16(p), Bytes: 100, Packets: 1})
	}
	// Normal host: few ports.
	seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.6", DstAddr: "10.0.0.9", DstPort: 443, Bytes: 100, Packets: 1})

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config.PortScanPorts = 20 // override the raised default (100) so 25 ports fires
	got, err := portScanDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].SrcAddr != "10.0.0.5" || got[0].Category != CategorySecurity {
		t.Fatalf("port_scan = %+v, want exactly 10.0.0.5", got)
	}
	if got[0].Severity != "warning" {
		t.Errorf("severity = %q, want warning (source not on threat feed)", got[0].Severity)
	}
	// The detection must attribute the exporter device (was 0 → "Unknown" before).
	if got[0].DeviceID != 1 {
		t.Errorf("device attribution = %d, want 1 (no more Unknown)", got[0].DeviceID)
	}

	// With the default (100) threshold, 25 ports must NOT fire — the false-positive fix.
	wDefault := fullWindow(now)
	wDefault.DB = db.Gorm()
	gotDefault, err := portScanDetector{}.Detect(wDefault)
	if err != nil {
		t.Fatalf("Detect(default): %v", err)
	}
	if len(gotDefault) != 0 {
		t.Errorf("with default threshold 100, 25 ports must not fire; got %+v", gotDefault)
	}
}

// TestPortScanDetector_KnownBadEscalates verifies a scan from a threat-flagged
// source escalates to critical and is labelled known-bad.
func TestPortScanDetector_KnownBadEscalates(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	for p := 1; p <= 25; p++ {
		// ThreatFlag bit 0 = source is on the threat-intel feed.
		seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "203.0.113.9", DstAddr: "10.0.0.9", DstPort: uint16(p), Bytes: 100, Packets: 1, ThreatFlag: 1})
	}
	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config.PortScanPorts = 20
	got, err := portScanDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("known-bad scan = %+v, want exactly one critical finding", got)
	}
	if kb, _ := got[0].Details["known_bad"].(bool); !kb {
		t.Errorf("known_bad detail = %v, want true", got[0].Details["known_bad"])
	}
}

func TestSuperSpreaderDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// Spreader: one src reaching 100 distinct destinations.
	for i := 0; i < 100; i++ {
		seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: ipFromInt(i), DstPort: 445, Bytes: 100, Packets: 1})
	}
	// Normal host: a handful of destinations.
	for i := 0; i < 5; i++ {
		seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.6", DstAddr: ipFromInt(i), DstPort: 443, Bytes: 100, Packets: 1})
	}
	w := fullWindow(now)
	w.DB = db.Gorm()
	got, err := superSpreaderDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].SrcAddr != "10.0.0.5" {
		t.Fatalf("super_spreader = %+v, want exactly 10.0.0.5", got)
	}
}

func TestDataExfilDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	big := uint64(1) << 30 // 1 GiB in one flow
	// Outbound bulk transfer — should fire.
	seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", DstCountry: "RU", DstPort: 443, Direction: classify.DirOutbound, Bytes: big + 1, Packets: 1000})
	// Same volume but internal — must NOT fire.
	seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "10.0.0.9", DstPort: 445, Direction: classify.DirInternal, Bytes: big + 1, Packets: 1000})
	// Outbound but small — must NOT fire.
	seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.6", DstAddr: "203.0.113.10", DstPort: 443, Direction: classify.DirOutbound, Bytes: 1000, Packets: 1})

	w := fullWindow(now)
	w.DB = db.Gorm()
	got, err := dataExfilDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].DstAddr != "203.0.113.9" {
		t.Fatalf("data_exfil = %+v, want exactly →203.0.113.9", got)
	}
}

func TestThreatIntelDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// Flows flagged at ingest (threat_flag bit 1 = dst bad).
	seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", DstPort: 443, Bytes: 5000, Packets: 5, ThreatFlag: 2})
	seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", DstPort: 443, Bytes: 3000, Packets: 3, ThreatFlag: 2})
	// Clean flow — must NOT contribute.
	seedFlow(t, db, models.FlowSample{DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", DstPort: 443, Bytes: 9000, Packets: 9, ThreatFlag: 0})

	w := fullWindow(now)
	w.DB = db.Gorm()
	got, err := threatIntelDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].DstAddr != "203.0.113.9" || got[0].Category != CategorySecurity {
		t.Fatalf("threat_intel = %+v, want exactly →203.0.113.9", got)
	}
	if got[0].Details["flows"].(int64) != 2 {
		t.Errorf("expected 2 flows aggregated, got %v", got[0].Details["flows"])
	}
}

func TestC2BeaconDetector(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	base := time.Now().Add(-30 * time.Minute)
	// Regular beacon: 12 small callouts every 60s (CV ~ 0).
	for i := 0; i < 12; i++ {
		seedFlow(t, db, models.FlowSample{
			Timestamp: base.Add(time.Duration(i) * 60 * time.Second),
			DeviceID:  1, Protocol: 6, SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9",
			DstPort: 8443, Direction: classify.DirOutbound, Bytes: 300, Packets: 1,
		})
	}
	// Irregular chatter to another dst: jittery gaps, should not look periodic.
	jitter := []int{0, 5, 90, 95, 400, 410, 800, 1200}
	for _, off := range jitter {
		seedFlow(t, db, models.FlowSample{
			Timestamp: base.Add(time.Duration(off) * time.Second),
			DeviceID:  1, Protocol: 6, SrcAddr: "10.0.0.6", DstAddr: "203.0.113.10",
			DstPort: 8443, Direction: classify.DirOutbound, Bytes: 300, Packets: 1,
		})
	}

	w := Window{Start: base.Add(-time.Minute), End: time.Now(), DB: db.Gorm()}
	got, err := c2BeaconDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].DstAddr != "203.0.113.9" || got[0].Severity != "info" {
		t.Fatalf("c2_beacon = %+v, want exactly →203.0.113.9 (info)", got)
	}
}

// ipFromInt builds a deterministic distinct IP per index (10.10.x.y).
func ipFromInt(i int) string {
	return "10.10." + itoa(i/256) + "." + itoa(i%256)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}
