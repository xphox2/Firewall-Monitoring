package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// seedTieredFlows lays down one raw sample and one 5m rollup row for the same
// conversation, which is the shape every test below depends on: raw holds only
// what the rollup ladder has not yet consumed (about an hour on production),
// while the rollup tiers hold everything older. A panel that reads only the raw
// base therefore reports ~1 hour of data under whatever range the pill claims.
func seedTieredFlows(t *testing.T, db *Database, now time.Time) {
	t.Helper()
	raw := models.FlowSample{
		Timestamp: now.Add(-30 * time.Minute), DeviceID: 1, ProbeID: 7, Protocol: 6,
		SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", SrcPort: 50000, DstPort: 443,
		Bytes: 100, Packets: 10, SamplingRate: 1,
	}
	if err := db.Gorm().Create(&raw).Error; err != nil {
		t.Fatalf("seed raw: %v", err)
	}
	// Deliberately a DIFFERENT, much larger conversation so a raw-only panel
	// cannot accidentally look correct: this is the real #1 and it lives only in
	// the rollup tier, exactly like production's NFS pair.
	roll := models.FlowRollup{
		Timestamp: now.Add(-23 * time.Hour), DeviceID: 1, IntervalType: "5m",
		SrcAddr: "192.168.25.21", DstAddr: "192.168.5.25", DstPort: 2049, Protocol: 6,
		BytesSum: 999000, PacketsSum: 5000, FlowCount: 42, SamplingRateAvg: 1024,
	}
	if err := db.Gorm().Create(&roll).Error; err != nil {
		t.Fatalf("seed rollup: %v", err)
	}
}

// TestGetFlowStats_TopConversationsIncludesRollups pins the fix for the panel
// that had no rollup branch at all. On production the displayed #1 was 427 MB
// while the true #1 (NFS, 6,799 MB) was absent from the list entirely, because
// the query read newFilteredRawBase() only.
func TestGetFlowStats_TopConversationsIncludesRollups(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	seedTieredFlows(t, db, now)

	res, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if len(res.TopConversations) == 0 {
		t.Fatal("TopConversations is empty")
	}
	top := res.TopConversations[0]
	if top.DstPort != 2049 {
		t.Errorf("TopConversations[0] is %s -> %s:%d; want the rolled-up 2049 conversation. "+
			"A raw-only query ranks the small recent flow first and drops the real top talker.",
			top.SrcAddr, top.DstAddr, top.DstPort)
	}
	if top.Bytes != 999000 {
		t.Errorf("TopConversations[0].Bytes = %d, want 999000", top.Bytes)
	}
}

// TestGetFlowStats_TopPortsIncludesRollups is the same defect on the ports card:
// magnitudes ran ~19x low and port 2049 was missing.
func TestGetFlowStats_TopPortsIncludesRollups(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	seedTieredFlows(t, db, now)

	res, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	var total int64
	found := false
	for _, p := range res.TopPorts {
		total += p.Count
		if strings.Contains(p.Key, "2049") || p.Key == "nfs" || p.Key == "NFS" {
			found = true
		}
	}
	if !found {
		keys := make([]string, 0, len(res.TopPorts))
		for _, p := range res.TopPorts {
			keys = append(keys, p.Key)
		}
		t.Errorf("TopPorts %v omits the rolled-up port 2049", keys)
	}
	if total < 999000 {
		t.Errorf("TopPorts total = %d, want >= 999000 (raw-only totals run orders of magnitude low)", total)
	}
}

// TestGetFlowStats_TotalPacketsIncludesRollups pins the packets tile, which was
// raw-only: production showed 2.7% of the true 24h count and 0.05% at 90d.
func TestGetFlowStats_TotalPacketsIncludesRollups(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	seedTieredFlows(t, db, now)

	res, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if want := uint64(10 + 5000); res.TotalPackets != want {
		t.Errorf("TotalPackets = %d, want %d (raw 10 + rolled-up 5000)", res.TotalPackets, want)
	}
}

// TestGetFlowStats_SamplingRangeSpansTiers pins the sampling chip. It read the
// raw base only, so it always said 1:1 even when most of the window's bytes
// arrived at 1:1024. A single average is not the fix either: averaging across a
// sampling-regime change produces a rate that never existed.
func TestGetFlowStats_SamplingRangeSpansTiers(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	seedTieredFlows(t, db, now)

	res, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if res.SamplingRateMin != 1 {
		t.Errorf("SamplingRateMin = %v, want 1 (the raw sample)", res.SamplingRateMin)
	}
	if res.SamplingRateMax != 1024 {
		t.Errorf("SamplingRateMax = %v, want 1024 (the rolled-up rows); a raw-only read reports 1",
			res.SamplingRateMax)
	}
}

// TestGetFlowStats_ProbeFilterKeepsRollups is the worst of the set. A probe
// filter used to switch the rollup side off entirely, because flow_rollups has
// no probe_id — so choosing the single probe in the dropdown collapsed EVERY
// tile to the ~1h raw window while the range pill still said 24 hours.
// Production measured 1.7% of the true flow count, with no warning.
func TestGetFlowStats_ProbeFilterKeepsRollups(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()

	// The probe owns the device whose flows are rolled up.
	probeID := uint(7)
	if err := db.Gorm().Create(&models.Device{
		Name: "fw-1", IPAddress: "192.0.2.1", Vendor: "fortigate", ProbeID: &probeID,
	}).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	var dev models.Device
	if err := db.Gorm().Where("name = ?", "fw-1").First(&dev).Error; err != nil {
		t.Fatalf("load device: %v", err)
	}
	if err := db.Gorm().Create(&models.FlowSample{
		Timestamp: now.Add(-30 * time.Minute), DeviceID: dev.ID, ProbeID: 7, Protocol: 6,
		SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", DstPort: 443, Bytes: 100, Packets: 10,
	}).Error; err != nil {
		t.Fatalf("seed raw: %v", err)
	}
	if err := db.Gorm().Create(&models.FlowRollup{
		Timestamp: now.Add(-23 * time.Hour), DeviceID: dev.ID, IntervalType: "5m",
		SrcAddr: "10.0.0.6", DstAddr: "8.8.4.4", DstPort: 443, Protocol: 6,
		BytesSum: 5000, PacketsSum: 50, FlowCount: 9,
	}).Error; err != nil {
		t.Fatalf("seed rollup: %v", err)
	}

	unfiltered, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats unfiltered: %v", err)
	}
	filtered, err := db.GetFlowStats(24, FlowStatsFilter{ProbeID: 7})
	if err != nil {
		t.Fatalf("GetFlowStats probe-filtered: %v", err)
	}
	// Every flow belongs to a device this probe owns, so the two must agree.
	if filtered.TotalBytes != unfiltered.TotalBytes {
		t.Errorf("probe-filtered TotalBytes = %d, unfiltered = %d; they must match when the probe "+
			"owns every contributing device. A raw-only fallback drops the rolled-up tiers.",
			filtered.TotalBytes, unfiltered.TotalBytes)
	}
	if filtered.TotalFlows != unfiltered.TotalFlows {
		t.Errorf("probe-filtered TotalFlows = %d, unfiltered = %d", filtered.TotalFlows, unfiltered.TotalFlows)
	}
	if filtered.TotalBytes < 5000 {
		t.Errorf("probe-filtered TotalBytes = %d, want >= 5000 (the rolled-up row)", filtered.TotalBytes)
	}
}

// TestGetFlowStats_ProtocolCountNotCappedAtTen pins the tile that took
// len(protocols) AFTER a Limit(10), so it silently stopped counting at ten
// however many protocols the window carried.
func TestGetFlowStats_ProtocolCountNotCappedAtTen(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	protos := []uint8{1, 2, 6, 17, 47, 50, 51, 58, 89, 103, 112, 132}
	for i, p := range protos {
		if err := db.Gorm().Create(&models.FlowSample{
			Timestamp: now.Add(-30 * time.Minute), DeviceID: 1, Protocol: p,
			SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", DstPort: uint16(1000 + i),
			Bytes: uint64(100 * (i + 1)), Packets: 1,
		}).Error; err != nil {
			t.Fatalf("seed proto %d: %v", p, err)
		}
	}
	res, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if res.ProtocolCount != int64(len(protos)) {
		t.Errorf("ProtocolCount = %d, want %d; the tile used to cap at 10 because it counted the "+
			"already-truncated display slice", res.ProtocolCount, len(protos))
	}
	if len(res.ByProtocol) > 10 {
		t.Errorf("ByProtocol has %d entries; the DISPLAY list should still be capped at 10", len(res.ByProtocol))
	}
}

// TestFlowAddrFilter_WideCIDRDoesNotMatchNothing pins the filter repair that is
// engine-independent. cidrToLikePattern returns "" for any mask shorter than /8
// and for 0.0.0.0/0; the old flowAddrFilter then compared the column to that
// literal string, so a legitimate wide filter silently returned an empty page.
func TestFlowAddrFilter_WideCIDRDoesNotMatchNothing(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	if err := db.Gorm().Create(&models.FlowSample{
		Timestamp: now.Add(-30 * time.Minute), DeviceID: 1, Protocol: 6,
		SrcAddr: "10.0.0.5", DstAddr: "8.8.8.8", DstPort: 443, Bytes: 100, Packets: 1,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, cidr := range []string{"10.0.0.0/6", "0.0.0.0/0"} {
		res, err := db.GetFlowStats(24, FlowStatsFilter{SrcAddr: cidr})
		if err != nil {
			t.Fatalf("GetFlowStats(%s): %v", cidr, err)
		}
		if res.TotalFlows == 0 {
			t.Errorf("SrcAddr=%q matched nothing; a wide prefix must not silently empty the page", cidr)
		}
	}
	// A filter that cannot be a network at all must still match nothing rather
	// than falling open.
	res, err := db.GetFlowStats(24, FlowStatsFilter{SrcAddr: "not-an-address"})
	if err != nil {
		t.Fatalf("GetFlowStats(garbage): %v", err)
	}
	if res.TotalFlows != 0 {
		t.Errorf("a malformed address filter matched %d flows; it must match none", res.TotalFlows)
	}
}

// TestGetFlowStats_DegradedWhenRollupsFail pins the contract that matters most
// when a window is too wide to aggregate: the request must still RETURN, and it
// must say that what it returned covers less than the range asked for.
//
// Before this, rolled-up failures were logged and execution continued, so a 30d
// request answered with raw-only figures — about one hour of data — presented
// under a "30 days" label, and nothing in the payload distinguished that from a
// complete answer. Dropping the rollup table stands in for the statement timeout
// that causes this on production.
func TestGetFlowStats_DegradedWhenRollupsFail(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now()
	seedTieredFlows(t, db, now)

	// Sanity: a healthy window is NOT degraded. A flag that is always on tells
	// the operator nothing.
	healthy, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats healthy: %v", err)
	}
	if healthy.Degraded {
		t.Fatalf("a complete window was marked degraded (blocks: %v)", healthy.DegradedBlocks)
	}

	if err := db.Gorm().Migrator().DropTable(&models.FlowRollup{}); err != nil {
		t.Fatalf("drop flow_rollups: %v", err)
	}

	res, err := db.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats must still return when the rolled-up side fails, got: %v", err)
	}
	if !res.Degraded {
		t.Error("Degraded is false after every rolled-up query failed; the page would present " +
			"raw-only figures as though they covered the whole window")
	}
	if len(res.DegradedBlocks) == 0 {
		t.Error("DegradedBlocks is empty; the UI cannot name which panels fell back")
	}
	// The raw side must still be reported — degraded means partial, not empty.
	if res.TotalFlows == 0 {
		t.Error("TotalFlows = 0; the raw tier should still be reported when rollups fail")
	}
	// The first failure must short-circuit the rest rather than letting each
	// remaining rolled-up query run and burn its own timeout in turn.
	if n := len(res.DegradedBlocks); n < 2 {
		t.Errorf("DegradedBlocks has %d entries (%v); every skipped panel should be named, "+
			"not just the one that failed first", n, res.DegradedBlocks)
	}
}
