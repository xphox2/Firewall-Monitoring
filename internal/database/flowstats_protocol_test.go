package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetFlowStatsExcludesHOPOPT verifies the protocol breakdown drops protocol
// 0 (HOPOPT) — which is only ever an artifact of an unwalked IPv6 extension
// header or an unparseable packet — while keeping legitimate portless protocols
// like ICMP alongside TCP.
func TestGetFlowStatsExcludesHOPOPT(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)

	samples := []models.FlowSample{
		// HOPOPT noise (port 0/0) — must be excluded from the breakdown.
		{Timestamp: now, DeviceID: 1, Protocol: 0, SrcAddr: "2001:db8::1", DstAddr: "2001:db8::2", Bytes: 9000, Packets: 9},
		{Timestamp: now, DeviceID: 1, Protocol: 0, SrcAddr: "2001:db8::3", DstAddr: "2001:db8::4", Bytes: 9000, Packets: 9},
		// ICMP (portless) — must stay visible.
		{Timestamp: now, DeviceID: 1, Protocol: 1, SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", Bytes: 100, Packets: 1},
		// TCP — must stay visible.
		{Timestamp: now, DeviceID: 1, Protocol: 6, SrcAddr: "10.0.0.1", DstAddr: "10.0.0.5", SrcPort: 5000, DstPort: 443, Bytes: 500, Packets: 5},
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed flow samples: %v", err)
	}

	// hours=1 keeps the query on raw flow_samples only (no rollup path).
	res, err := db.GetFlowStats(1, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}

	keys := map[string]bool{}
	for _, kc := range res.ByProtocol {
		keys[kc.Key] = true
	}
	if keys["HOPOPT"] {
		t.Errorf("ByProtocol contains HOPOPT (protocol 0); it must be excluded. got=%v", res.ByProtocol)
	}
	if !keys["ICMP"] {
		t.Errorf("ByProtocol missing ICMP; portless protocols must be kept. got=%v", res.ByProtocol)
	}
	if !keys["TCP"] {
		t.Errorf("ByProtocol missing TCP. got=%v", res.ByProtocol)
	}
}
