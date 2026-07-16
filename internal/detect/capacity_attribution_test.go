package detect

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestCapacityDetector_TopTalkerAttribution (T4-8): a saturated interface's
// finding names the top talkers with sane shares; shares never exceed 100%.
func TestCapacityDetector_TopTalkerAttribution(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	if err := db.Gorm().Create(&models.InterfaceStats{
		Timestamp: now, DeviceID: 1, Index: 7, Speed: 1_000_000_000, Status: "up",
	}).Error; err != nil {
		t.Fatalf("seed iface: %v", err)
	}
	const secs = 60
	total := uint64(900_000_000) * secs / 8
	// Three pairs: 60% / 30% / 10% of the interface bytes.
	pairs := []struct {
		src, dst string
		share    uint64
	}{
		{"10.0.1.7", "142.250.0.1", total * 6 / 10},
		{"10.0.1.9", "34.117.0.2", total * 3 / 10},
		{"10.0.2.3", "10.0.9.1", total * 1 / 10},
	}
	for _, p := range pairs {
		seedFlow(t, db, models.FlowSample{
			Timestamp: now.Add(-30 * time.Second), DeviceID: 1, Protocol: 6,
			SrcAddr: p.src, DstAddr: p.dst, DstPort: 443,
			OutputIfIndex: 7, Bytes: p.share, Packets: 100,
		})
	}

	w := Window{Start: now.Add(-secs * time.Second), End: now, DB: db.Gorm()}
	got, err := capacityDetector{}.Detect(w)
	if err != nil || len(got) != 1 {
		t.Fatalf("Detect: %v / %d", err, len(got))
	}
	d := got[0]
	if !strings.Contains(d.Message, "top talkers") || !strings.Contains(d.Message, "10.0.1.7") {
		t.Errorf("message missing attribution: %s", d.Message)
	}
	talkers, ok := d.Details["top_talkers"].([]map[string]any)
	if !ok || len(talkers) != 3 {
		t.Fatalf("top_talkers wrong: %+v", d.Details["top_talkers"])
	}
	sum := 0.0
	for _, tk := range talkers {
		sum += tk["share_pct"].(float64)
	}
	if sum > 100.5 {
		t.Errorf("shares sum to %.1f%%, must be <= 100", sum)
	}
	if talkers[0]["src"] != "10.0.1.7" {
		t.Errorf("talkers not ranked by bytes: %+v", talkers[0])
	}
}

// TestCapacityDetector_NoAttributionBelowThreshold: non-saturated interfaces
// run no attribution query and produce no finding (the common-case cost is
// zero extra queries).
func TestCapacityDetector_NoAttributionBelowThreshold(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	now := time.Now()
	if err := db.Gorm().Create(&models.InterfaceStats{
		Timestamp: now, DeviceID: 1, Index: 7, Speed: 1_000_000_000, Status: "up",
	}).Error; err != nil {
		t.Fatalf("seed iface: %v", err)
	}
	const secs = 60
	seedFlow(t, db, models.FlowSample{
		Timestamp: now.Add(-30 * time.Second), DeviceID: 1, Protocol: 6,
		SrcAddr: "10.0.1.7", DstAddr: "8.8.8.8", DstPort: 443,
		OutputIfIndex: 7, Bytes: uint64(100_000_000) * secs / 8, Packets: 100, // 10%
	})
	w := Window{Start: now.Add(-secs * time.Second), End: now, DB: db.Gorm()}
	got, err := capacityDetector{}.Detect(w)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("fired below threshold: %+v", got)
	}
}
