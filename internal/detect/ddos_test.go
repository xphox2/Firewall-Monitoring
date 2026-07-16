package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// ddosTestConfig returns test-friendly thresholds so fixtures stay small:
// 1 Mb/s, 100 pps, 10 fps.
func ddosTestConfig() Config {
	return Config{DDoSBps: 1_000_000, DDoSPps: 100, DDoSFps: 10}
}

// seedBurst seeds n inbound flow rows to dst inside one minute, each carrying
// the given bytes/packets and source metadata.
func seedBurst(t *testing.T, db *database.Database, dst string, n int, bytes, packets uint64, flowSource uint8, samplingRate uint32, at time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		seedFlow(t, db, models.FlowSample{
			DeviceID: 1, Protocol: 6,
			SrcAddr: fmt.Sprintf("203.0.113.%d", i%250+1), DstAddr: dst, DstPort: 443,
			Bytes: bytes, Packets: packets,
			Direction: uint8(classify.DirInbound), FlowSource: flowSource, SamplingRate: samplingRate,
			SrcCountry: "CN",
			Timestamp:  at.Add(time.Duration(i%50) * time.Millisecond),
		})
	}
}

// TestDDoSVolumetric_PpsFiresNotBps: a packet flood (high pps, low bytes) must
// fire the pps threshold and not bps.
func TestDDoSVolumetric_PpsFiresNotBps(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// 120 rows × 60 packets in one minute = 7200 packets/min = 120 pps peak
	// (>100 threshold); bytes stay tiny.
	seedBurst(t, db, "192.0.2.10", 120, 60, 60, models.FlowSourceNetFlowV9, 1, now.Add(-3*time.Minute))

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = ddosTestConfig()
	got, err := ddosVolumetricDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("detections = %d, want 1", len(got))
	}
	d := got[0]
	if d.DstAddr != "192.0.2.10" || d.DedupKey != "ddosvol_192.0.2.10" {
		t.Errorf("victim/dedup wrong: %+v", d)
	}
	crossed := fmt.Sprintf("%v", d.Details["crossed"])
	if !strings.Contains(crossed, "pps") || strings.Contains(crossed, "bps") {
		t.Errorf("crossed = %s, want pps only", crossed)
	}
	if !strings.Contains(d.Message, "distinct sources") {
		t.Errorf("message missing source enrichment: %s", d.Message)
	}
}

// TestDDoSVolumetric_SampledRowsFirePpsButNeverFps: sFlow rows (pre-multiplied
// packets) are valid for pps but must never count toward fps.
func TestDDoSVolumetric_SampledRowsFirePpsButNeverFps(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// sFlow: 20 rows, each representing 2000 sampled packets → 40000 pkts/min
	// = 667 pps peak. Flow count 20 is far over a 0.1 fps threshold — but as
	// sampled rows they must not register as fps at all.
	seedBurst(t, db, "192.0.2.11", 20, 3000, 2000, models.FlowSourceSFlow, 2000, now.Add(-3*time.Minute))

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = Config{DDoSBps: 1_000_000_000, DDoSPps: 100, DDoSFps: 1}
	got, err := ddosVolumetricDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("detections = %d, want 1", len(got))
	}
	crossed := fmt.Sprintf("%v", got[0].Details["crossed"])
	if !strings.Contains(crossed, "pps") {
		t.Errorf("crossed = %s, want pps", crossed)
	}
	if strings.Contains(crossed, "fps") {
		t.Errorf("fps fired on sampled rows: %s (flow counts are invalid under sampling)", crossed)
	}
}

// TestDDoSVolumetric_PacketlessRowsFireFpsNotPps: ASA-NSEL-shaped rows (zero
// packets) must never fire pps, but their complete-row flow count fires fps.
func TestDDoSVolumetric_PacketlessRowsFireFpsNotPps(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// 700 complete zero-packet rows in one minute ≈ 11.7 fps (>10 threshold).
	seedBurst(t, db, "192.0.2.12", 700, 40, 0, models.FlowSourceIPFIX, 1, now.Add(-3*time.Minute))

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = ddosTestConfig()
	got, err := ddosVolumetricDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("detections = %d, want 1", len(got))
	}
	crossed := fmt.Sprintf("%v", got[0].Details["crossed"])
	if strings.Contains(crossed, "pps") {
		t.Errorf("pps fired with zero packet counters: %s", crossed)
	}
	if !strings.Contains(crossed, "fps") {
		t.Errorf("fps did not fire on complete rows: %s", crossed)
	}
}

// TestDDoSVolumetric_ElephantSmearNoFinding: one long-span NetFlow record
// whose interval average is below threshold must not fire off its end-minute
// spike.
func TestDDoSVolumetric_ElephantSmearNoFinding(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	start := now.Add(-14 * time.Minute)
	end := now.Add(-2 * time.Minute)
	// 90 MB over 12 minutes = 1 Mb/s average — at threshold boundary but the
	// unsmeared end-minute would read 12 Mb/s and false-fire.
	seedFlow(t, db, models.FlowSample{
		DeviceID: 1, Protocol: 6, SrcAddr: "198.51.100.9", DstAddr: "192.0.2.13", DstPort: 443,
		Bytes: 90_000_000, Packets: 60_000,
		Direction: uint8(classify.DirInbound), FlowSource: models.FlowSourceNetFlowV9, SamplingRate: 1,
		FlowStart: &start, FlowEnd: &end, Timestamp: end,
	})

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = Config{DDoSBps: 8_000_000, DDoSPps: 1_000_000, DDoSFps: 1_000_000} // 8 Mb/s
	got, err := ddosVolumetricDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("elephant flow false-fired: %+v", got[0].Details)
	}
}

// TestDDoSVolumetric_CriticalAtTwoTimes: ≥2x threshold escalates to critical.
func TestDDoSVolumetric_CriticalAtTwoTimes(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	// 250 pps peak vs 100 threshold = 2.5x.
	seedBurst(t, db, "192.0.2.14", 250, 60, 60, models.FlowSourceNetFlowV9, 1, now.Add(-3*time.Minute))

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = ddosTestConfig()
	got, err := ddosVolumetricDetector{}.Detect(w)
	if err != nil || len(got) != 1 {
		t.Fatalf("detect: %v / %d", err, len(got))
	}
	if got[0].Severity != "critical" {
		t.Errorf("severity = %s, want critical at 2.5x", got[0].Severity)
	}
}

// TestDDoSVolumetric_Disabled: the kill switch silences the detector.
func TestDDoSVolumetric_Disabled(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	seedBurst(t, db, "192.0.2.15", 250, 60, 60, models.FlowSourceNetFlowV9, 1, now.Add(-3*time.Minute))

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = ddosTestConfig()
	w.Config.DDoSVolumetricDisabled = true
	got, err := ddosVolumetricDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("disabled detector fired: %d", len(got))
	}
}

// TestDDoSPrefix_CarpetBombing: many hosts in one /24, each individually
// below the per-host threshold, must produce ONE prefix finding — and no
// per-host findings.
func TestDDoSPrefix_CarpetBombing(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	at := now.Add(-3 * time.Minute)
	// 60 victims × 25 packets/min each = 1500 pkts/min for the /24 → 25 pps
	// prefix peak vs prefix threshold 100×0.75=75... use bigger: 60 victims ×
	// 120 packets = 7200/min = 120 pps ≥ 75 fire line; per-host 2 pps each.
	for v := 1; v <= 60; v++ {
		seedFlow(t, db, models.FlowSample{
			DeviceID: 1, Protocol: 17,
			SrcAddr: fmt.Sprintf("203.0.113.%d", v), DstAddr: fmt.Sprintf("192.0.2.%d", v), DstPort: 53,
			Bytes: 5000, Packets: 120,
			Direction: uint8(classify.DirInbound), FlowSource: models.FlowSourceNetFlowV9, SamplingRate: 1,
			Timestamp: at,
		})
	}

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = Config{DDoSBps: 1_000_000_000, DDoSPps: 100, DDoSFps: 1_000_000}

	host, err := ddosVolumetricDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("host detect: %v", err)
	}
	if len(host) != 0 {
		t.Fatalf("per-host fired for sub-threshold victims: %+v", host)
	}

	pfx, err := ddosPrefixDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("prefix detect: %v", err)
	}
	if len(pfx) != 1 {
		t.Fatalf("prefix detections = %d, want 1", len(pfx))
	}
	if pfx[0].DstAddr != "192.0.2.0/24" || pfx[0].DedupKey != "ddospfx_192.0.2.0/24" {
		t.Errorf("prefix wrong: %+v", pfx[0])
	}
}

// TestDDoSPrefix_SuppressedWhenHostFired: a single dst over the per-host
// threshold must yield a per-host finding and NO prefix finding.
func TestDDoSPrefix_SuppressedWhenHostFired(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	seedBurst(t, db, "192.0.2.20", 200, 60, 60, models.FlowSourceNetFlowV9, 1, now.Add(-3*time.Minute))
	// A second host in the prefix keeps hosts>=2 true so only hostFired gates.
	seedBurst(t, db, "192.0.2.21", 30, 60, 60, models.FlowSourceNetFlowV9, 1, now.Add(-3*time.Minute))

	w := fullWindow(now)
	w.DB = db.Gorm()
	w.Config = ddosTestConfig()

	host, err := ddosVolumetricDetector{}.Detect(w)
	if err != nil || len(host) != 1 {
		t.Fatalf("host detect: %v / %d", err, len(host))
	}
	pfx, err := ddosPrefixDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("prefix detect: %v", err)
	}
	if len(pfx) != 0 {
		t.Errorf("prefix fired despite per-host finding: %+v", pfx)
	}
}

// TestPrefixOf covers the fold helper's shapes.
func TestPrefixOf(t *testing.T) {
	cases := map[string]string{
		"192.0.2.77":      "192.0.2.0/24",
		"2001:db8:1:2::5": "2001:db8:1:2::/64",
		"not-an-ip":       "",
	}
	for in, want := range cases {
		if got := prefixOf(in); got != want {
			t.Errorf("prefixOf(%q) = %q, want %q", in, got, want)
		}
	}
}
