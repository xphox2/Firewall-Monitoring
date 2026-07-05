package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestFlowRollup_GroupsByFirewallEvent pins the LC-03 fix: denied records
// (firewall_event=3, legally zero-byte) survive the 1h raw collapse as their
// own rollup group instead of being erased into an anonymous flow_count, and
// the FirewallEvent filter still resolves after raw rows are rolled up.
func TestFlowRollup_GroupsByFirewallEvent(t *testing.T) {
	db := NewDatabaseForTesting(t)
	old := time.Now().Add(-3 * time.Hour) // older than the 1h raw window
	mk := func(event uint8, bytes uint64) models.FlowSample {
		return models.FlowSample{
			Timestamp: old, DeviceID: 1, Protocol: 6,
			SrcAddr: "192.0.2.66", DstAddr: "10.0.0.4", SrcPort: 50000, DstPort: 445,
			Bytes: bytes, Packets: 0, SamplingRate: 1, FirewallEvent: event,
		}
	}
	samples := []models.FlowSample{
		mk(models.FirewallEventNone, 1000),
		mk(models.FirewallEventNone, 1000),
		mk(models.FirewallEventDenied, 0),
		mk(models.FirewallEventDenied, 0),
		mk(models.FirewallEventDenied, 0),
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
		t.Fatalf("got %d 5m rollup groups, want 2 (one per firewall_event)", len(rollups))
	}
	byEvent := map[uint8]models.FlowRollup{}
	for _, r := range rollups {
		byEvent[r.FirewallEvent] = r
	}
	if d := byEvent[models.FirewallEventDenied]; d.FlowCount != 3 || d.BytesSum != 0 {
		t.Errorf("denied group: flow_count=%d bytes_sum=%d, want 3/0", d.FlowCount, d.BytesSum)
	}
	if a := byEvent[models.FirewallEventNone]; a.FlowCount != 2 || a.BytesSum != 2000 {
		t.Errorf("allowed group: flow_count=%d bytes_sum=%d, want 2/2000", a.FlowCount, a.BytesSum)
	}

	// The denied filter must resolve from rollups (24h window > 1h raw window).
	denied := uint8(models.FirewallEventDenied)
	res, err := db.GetFlowStats(24, FlowStatsFilter{FirewallEvent: &denied})
	if err != nil {
		t.Fatalf("GetFlowStats(denied) from rollups: %v", err)
	}
	if res.TotalFlows != 3 {
		t.Errorf("denied filter from rollups: flows=%d, want 3", res.TotalFlows)
	}
}

// TestFlowRollup_PromotionCarriesFirewallEvent pins that the 5m→1h promotion
// keeps firewall_event as a group key — denied visibility survives the whole
// rollup ladder, not just the first hop.
func TestFlowRollup_PromotionCarriesFirewallEvent(t *testing.T) {
	db := NewDatabaseForTesting(t)
	old := time.Now().Add(-72 * time.Hour) // older than the 48h 5m window
	mk := func(event uint8, count int64, bytes uint64) models.FlowRollup {
		return models.FlowRollup{
			Timestamp: old, DeviceID: 1, IntervalType: "5m",
			SrcAddr: "192.0.2.66", DstAddr: "10.0.0.4", DstPort: 445, Protocol: 6,
			BytesSum: bytes, FlowCount: count, FirewallEvent: event,
		}
	}
	rollups := []models.FlowRollup{
		mk(models.FirewallEventNone, 2, 2000),
		mk(models.FirewallEventDenied, 5, 0),
	}
	if err := db.Gorm().Create(&rollups).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	db.RunFlowRollupCycle()

	var hourly []models.FlowRollup
	if err := db.Gorm().Where("interval_type = ?", "1h").Find(&hourly).Error; err != nil {
		t.Fatalf("query 1h rollups: %v", err)
	}
	if len(hourly) != 2 {
		t.Fatalf("got %d 1h rollup groups, want 2 (firewall_event must stay a group key on promotion)", len(hourly))
	}
	byEvent := map[uint8]models.FlowRollup{}
	for _, r := range hourly {
		byEvent[r.FirewallEvent] = r
	}
	if d := byEvent[models.FirewallEventDenied]; d.FlowCount != 5 {
		t.Errorf("promoted denied group flow_count=%d, want 5", d.FlowCount)
	}
}
