package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetFlowStatsFilters verifies that GetFlowStats honors every dimension of
// FlowStatsFilter, so the Flows page's shared filter row narrows the aggregate
// views (totals + top conversations), not just the raw Flow Samples list.
func TestGetFlowStatsFilters(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)

	samples := []models.FlowSample{
		{Timestamp: now, DeviceID: 1, ProbeID: 1, Protocol: 6, SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcPort: 5000, DstPort: 443, Bytes: 1000, Packets: 10},
		{Timestamp: now, DeviceID: 2, ProbeID: 2, Protocol: 17, SrcAddr: "10.0.0.3", DstAddr: "10.0.0.4", SrcPort: 5001, DstPort: 53, Bytes: 2000, Packets: 20},
		{Timestamp: now, DeviceID: 1, ProbeID: 1, Protocol: 6, SrcAddr: "10.0.0.1", DstAddr: "192.168.1.9", SrcPort: 5002, DstPort: 80, Bytes: 500, Packets: 5},
	}
	if err := db.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed flow samples: %v", err)
	}

	proto := func(p uint8) *uint8 { return &p }
	port := func(p uint16) *uint16 { return &p }

	cases := []struct {
		name      string
		filter    FlowStatsFilter
		wantFlows int64
		wantBytes uint64
		wantConvs int // number of top conversations returned
	}{
		{"no filter", FlowStatsFilter{}, 3, 3500, 3},
		{"device 1", FlowStatsFilter{DeviceID: 1}, 2, 1500, 2},
		{"device 2", FlowStatsFilter{DeviceID: 2}, 1, 2000, 1},
		{"probe 2", FlowStatsFilter{ProbeID: 2}, 1, 2000, 1},
		{"protocol TCP", FlowStatsFilter{Protocol: proto(6)}, 2, 1500, 2},
		{"protocol UDP", FlowStatsFilter{Protocol: proto(17)}, 1, 2000, 1},
		{"dst port 443", FlowStatsFilter{DstPort: port(443)}, 1, 1000, 1},
		{"src exact", FlowStatsFilter{SrcAddr: "10.0.0.1"}, 2, 1500, 2},
		{"dst exact", FlowStatsFilter{DstAddr: "10.0.0.4"}, 1, 2000, 1},
		{"src /24 CIDR", FlowStatsFilter{SrcAddr: "10.0.0.0/24"}, 3, 3500, 3},
		{"dst /24 CIDR", FlowStatsFilter{DstAddr: "192.168.1.0/24"}, 1, 500, 1},
		{"device 1 + TCP + port 80", FlowStatsFilter{DeviceID: 1, Protocol: proto(6), DstPort: port(80)}, 1, 500, 1},
	}

	// hours=1 keeps the query on raw flow_samples only (no rollup path), which
	// is what we seeded.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := db.GetFlowStats(1, tc.filter)
			if err != nil {
				t.Fatalf("GetFlowStats: %v", err)
			}
			if res.TotalFlows != tc.wantFlows {
				t.Errorf("TotalFlows = %d, want %d", res.TotalFlows, tc.wantFlows)
			}
			if res.TotalBytes != tc.wantBytes {
				t.Errorf("TotalBytes = %d, want %d", res.TotalBytes, tc.wantBytes)
			}
			if len(res.TopConversations) != tc.wantConvs {
				t.Errorf("TopConversations count = %d, want %d", len(res.TopConversations), tc.wantConvs)
			}
		})
	}
}
