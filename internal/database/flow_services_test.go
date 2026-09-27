package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestTopServices_CountsBothDirectionsUnderTheServicePort: a server's replies
// (src 443 → client ports) and its requests land under the same service, and
// the panel reports the port number it filters by.
func TestTopServices_CountsBothDirectionsUnderTheServicePort(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	seed := []models.FlowSample{
		{Timestamp: now.Add(-10 * time.Minute), DeviceID: 1, Protocol: 6, SrcAddr: "66.179.9.156", DstAddr: "198.51.100.7",
			SrcPort: 443, DstPort: 51234, ServicePort: 443, Bytes: 9000, Packets: 1},
		{Timestamp: now.Add(-10 * time.Minute), DeviceID: 1, Protocol: 6, SrcAddr: "198.51.100.7", DstAddr: "66.179.9.156",
			SrcPort: 51234, DstPort: 443, ServicePort: 443, Bytes: 1000, Packets: 1},
		{Timestamp: now.Add(-10 * time.Minute), DeviceID: 1, Protocol: 6, SrcAddr: "66.179.9.156", DstAddr: "198.51.100.8",
			SrcPort: 443, DstPort: 51235, ServicePort: 443, Bytes: 500, Packets: 1},
	}
	if err := d.Gorm().Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: now.Add(-20 * time.Hour), DeviceID: 1, IntervalType: "5m", Protocol: 6,
		SrcAddr: "66.179.9.156", DstAddr: "198.51.100.9", DstPort: 52000, ServicePort: 443,
		BytesSum: 100000, PacketsSum: 10, FlowCount: 5, SamplingRateAvg: 1,
	}).Error; err != nil {
		t.Fatalf("seed rollup: %v", err)
	}
	res, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if len(res.TopServices) != 1 {
		t.Fatalf("TopServices = %+v, want exactly one service (443), not one row per client port", res.TopServices)
	}
	top := res.TopServices[0]
	if top.Port != 443 || top.Key != "HTTPS" || top.Count != 110500 {
		t.Errorf("TopServices[0] = %+v, want {Key:HTTPS Port:443 Count:110500}", top)
	}

	svc := uint16(443)
	filtered, err := d.GetFlowStats(24, FlowStatsFilter{ServicePort: &svc})
	if err != nil {
		t.Fatalf("GetFlowStats filtered: %v", err)
	}
	if filtered.TotalBytes != 110500 {
		t.Errorf("service_port=443 filter TotalBytes = %d, want 110500", filtered.TotalBytes)
	}
	other := uint16(22)
	none, err := d.GetFlowStats(24, FlowStatsFilter{ServicePort: &other})
	if err != nil {
		t.Fatalf("GetFlowStats filtered: %v", err)
	}
	if none.TotalBytes != 0 {
		t.Errorf("service_port=22 filter TotalBytes = %d, want 0 — the filter was not applied", none.TotalBytes)
	}
}

// TestTopServices_SummaryGate pins the service-dimension boundary. Summary
// buckets written before migration v68 have no service_port tops; a window
// reaching back past flow_summary_service_since must show the raw merge marked
// PARTIAL — not Degraded, which is the page-wide "last hour only" banner — and
// a window inside it (or no boundary at all) is served from the summary.
func TestTopServices_SummaryGate(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)
	seedReadPath(t, d, base)
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}
	orig := flowSummaryMinHours
	flowSummaryMinHours = 1
	defer func() { flowSummaryMinHours = orig }()

	// No boundary: the summary serves Top services.
	res, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if len(res.PartialBlocks) != 0 || len(res.TopServices) == 0 {
		t.Fatalf("without a boundary Top services must come from the summary: partial=%v services=%v",
			res.PartialBlocks, res.TopServices)
	}

	// A boundary newer than the window's start: partial, not degraded.
	since := time.Now().Add(-2 * time.Hour).UTC()
	if err := d.Gorm().Create(&models.SystemSetting{Key: flowSummaryServiceSinceKey, Value: since.Format(time.RFC3339)}).Error; err != nil {
		t.Fatalf("set since: %v", err)
	}
	res, err = d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	// The summary path always degrades the unique-count panels (the cube cannot
	// union addresses); what matters is that top_services is not among them.
	for _, b := range res.DegradedBlocks {
		if b == "top_services" {
			t.Errorf("top_services was marked Degraded (%v); past the service boundary it is partial only", res.DegradedBlocks)
		}
	}
	if len(res.PartialBlocks) != 1 || res.PartialBlocks[0] != "top_services" || res.PartialReasons["top_services"] == "" {
		t.Errorf("PartialBlocks = %v reasons = %v, want top_services with a reason", res.PartialBlocks, res.PartialReasons)
	}

	// A window that starts after the boundary is fully covered again.
	res, err = d.GetFlowStats(1, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if len(res.PartialBlocks) != 0 {
		t.Errorf("a 1h window starting after the boundary is marked partial: %v", res.PartialBlocks)
	}
}

// TestMarkFlowSummaryServiceSince: v68 stamps the boundary only on an install
// that already has summary tops, and never moves an existing one.
func TestMarkFlowSummaryServiceSince(t *testing.T) {
	d := NewDatabaseForTesting(t)
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	if err := d.markFlowSummaryServiceSince(t0); err != nil {
		t.Fatalf("mark on empty: %v", err)
	}
	if _, ok := d.GetSettingValue(flowSummaryServiceSinceKey); ok {
		t.Fatal("a fresh install (no summary tops) got a service boundary; every bucket it writes has the dimension")
	}
	if err := d.Gorm().Create(&models.FlowSummaryTop{Timestamp: t0.Add(-time.Hour), IntervalType: "1h", DeviceID: 1,
		Dimension: "dst_port", Value: "443", BytesSum: 1}).Error; err != nil {
		t.Fatalf("seed top: %v", err)
	}
	if err := d.markFlowSummaryServiceSince(t0); err != nil {
		t.Fatalf("mark: %v", err)
	}
	v, ok := d.GetSettingValue(flowSummaryServiceSinceKey)
	if !ok || v != t0.Format(time.RFC3339) {
		t.Fatalf("boundary = %q (%v), want %s", v, ok, t0.Format(time.RFC3339))
	}
	if err := d.markFlowSummaryServiceSince(t0.Add(time.Hour)); err != nil {
		t.Fatalf("re-mark: %v", err)
	}
	if v2, _ := d.GetSettingValue(flowSummaryServiceSinceKey); v2 != v {
		t.Errorf("a re-run moved the boundary from %s to %s", v, v2)
	}
}
