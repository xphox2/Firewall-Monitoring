package database

import (
	"context"
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
		{Timestamp: now.Add(-10 * time.Minute), DeviceID: 1, Protocol: 6, SrcAddr: "198.19.9.156", DstAddr: "198.51.100.7",
			SrcPort: 443, DstPort: 51234, ServicePort: 443, Bytes: 9000, Packets: 1},
		{Timestamp: now.Add(-10 * time.Minute), DeviceID: 1, Protocol: 6, SrcAddr: "198.51.100.7", DstAddr: "198.19.9.156",
			SrcPort: 51234, DstPort: 443, ServicePort: 443, Bytes: 1000, Packets: 1},
		{Timestamp: now.Add(-10 * time.Minute), DeviceID: 1, Protocol: 6, SrcAddr: "198.19.9.156", DstAddr: "198.51.100.8",
			SrcPort: 443, DstPort: 51235, ServicePort: 443, Bytes: 500, Packets: 1},
	}
	if err := d.Gorm().Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: now.Add(-20 * time.Hour), DeviceID: 1, IntervalType: "5m", Protocol: 6,
		SrcAddr: "198.19.9.156", DstAddr: "198.51.100.9", DstPort: 52000, ServicePort: 443,
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

// TestTopServices_ServiceBoundary pins the service boundary on every path.
// Rows and summary buckets from before migration v68 carry no service port, so
// a window reaching back past flow_summary_service_since shows services from
// the boundary on — with a PARTIAL badge naming the date, never the page-wide
// Degraded banner (which means "last hour only") — and a window inside it, or
// no boundary at all, is complete.
func TestTopServices_ServiceBoundary(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)
	seedReadPath(t, d, base)
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}
	orig := flowSummaryMinHours
	defer func() { flowSummaryMinHours = orig }()
	setSince := func(v time.Time) {
		t.Helper()
		d.Gorm().Where("\"key\" = ?", flowSummaryServiceSinceKey).Delete(&models.SystemSetting{})
		if !v.IsZero() {
			if err := d.Gorm().Create(&models.SystemSetting{Key: flowSummaryServiceSinceKey, Value: v.UTC().Format(time.RFC3339)}).Error; err != nil {
				t.Fatalf("set since: %v", err)
			}
		}
	}
	notDegraded := func(res *FlowStatsResult) {
		t.Helper()
		// The summary path always degrades the unique-count panels (the cube
		// cannot union addresses); top_services must never be among them here.
		for _, b := range res.DegradedBlocks {
			if b == "top_services" {
				t.Errorf("top_services was marked Degraded (%v); past the boundary it is partial only", res.DegradedBlocks)
			}
		}
	}

	for _, path := range []struct {
		name     string
		minHours int
	}{{"summary", 1}, {"rollups", 1 << 30}} {
		flowSummaryMinHours = path.minHours

		setSince(time.Time{})
		res, err := d.GetFlowStats(24, FlowStatsFilter{})
		if err != nil {
			t.Fatalf("%s: %v", path.name, err)
		}
		if len(res.PartialBlocks) != 0 || len(res.TopServices) == 0 {
			t.Errorf("%s without a boundary: partial=%v services=%v, want complete and non-empty",
				path.name, res.PartialBlocks, res.TopServices)
		}

		// A boundary inside the window: the rows after it still show, and the
		// badge names the date.
		since := time.Now().Add(-2 * time.Hour)
		setSince(since)
		res, err = d.GetFlowStats(24, FlowStatsFilter{})
		if err != nil {
			t.Fatalf("%s: %v", path.name, err)
		}
		notDegraded(res)
		want := "since " + since.Local().Format("2006-01-02") + " only"
		if len(res.PartialBlocks) != 1 || res.PartialBlocks[0] != "top_services" || res.PartialReasons["top_services"] != want {
			t.Errorf("%s: PartialBlocks=%v reasons=%v, want top_services %q", path.name, res.PartialBlocks, res.PartialReasons, want)
		}
		if len(res.TopServices) == 0 {
			t.Errorf("%s: Top services is empty past the boundary; the rows after it must still show", path.name)
		}

		// A boundary before the window's start: complete again.
		setSince(time.Now().Add(-30 * time.Hour))
		res, err = d.GetFlowStats(24, FlowStatsFilter{})
		if err != nil {
			t.Fatalf("%s: %v", path.name, err)
		}
		if len(res.PartialBlocks) != 0 || len(res.TopServices) == 0 {
			t.Errorf("%s with the boundary before the window: partial=%v services=%v, want complete",
				path.name, res.PartialBlocks, res.TopServices)
		}
	}

	// The materialized (address-filtered) path carries the boundary too.
	setSince(time.Now().Add(-2 * time.Hour))
	res, err := d.GetFlowStats(24, FlowStatsFilter{SrcAddr: "10.0.0.1"})
	if err != nil {
		t.Fatalf("materialized: %v", err)
	}
	if res.PartialReasons["top_services"] == "" {
		t.Errorf("an address-filtered window past the boundary is not marked partial: %v", res.PartialBlocks)
	}
}

// TestMarkFlowSummaryServiceSince: v68 stamps the boundary only on an install
// that already holds flow history, and never moves an existing one.
func TestMarkFlowSummaryServiceSince(t *testing.T) {
	d := NewDatabaseForTesting(t)
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	if err := d.markFlowSummaryServiceSince(t0); err != nil {
		t.Fatalf("mark on empty: %v", err)
	}
	if _, ok := d.GetSettingValue(flowSummaryServiceSinceKey); ok {
		t.Fatal("a fresh install (no flow history) got a service boundary; every row it writes has a service port")
	}
	// History in the rollups alone (summary tables still empty, as on an
	// install upgrading across v66 and v68 at once) is enough.
	if err := d.Gorm().Create(&models.FlowRollup{Timestamp: t0.Add(-48 * time.Hour), DeviceID: 1, IntervalType: "1h",
		SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6, BytesSum: 1, FlowCount: 1}).Error; err != nil {
		t.Fatalf("seed rollup: %v", err)
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

// TestFlowStatsBudget_DegradedWinsOverPartial: a panel both partial for its own
// reason and fallen back to the last hour is reported Degraded only, so its
// badge cannot claim "since <date>" coverage it does not have.
func TestFlowStatsBudget_DegradedWinsOverPartial(t *testing.T) {
	b := newFlowStatsBudget(context.Background(), time.Minute)
	b.partial("top_services", "since 2026-09-27 only")
	b.partial("top_asns", "since 2026-09-27 only")
	b.skip("top_services")
	res := &FlowStatsResult{}
	b.stamp(res)
	if len(res.PartialBlocks) != 1 || res.PartialBlocks[0] != "top_asns" {
		t.Errorf("PartialBlocks = %v, want only top_asns", res.PartialBlocks)
	}
	if _, ok := res.PartialReasons["top_services"]; ok {
		t.Error("a degraded panel kept its partial reason")
	}
	if !res.Degraded {
		t.Error("the skipped panel did not mark the result Degraded")
	}
}
