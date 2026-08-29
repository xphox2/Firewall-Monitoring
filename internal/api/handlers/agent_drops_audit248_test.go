package handlers

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestAgentDrops_DualRateAgentKeepsSeparateBaselines (AUDIT-248): sFlow agents
// commonly run several sampling instances, each exporting its OWN cumulative
// sample-pool drops counter. The baseline map keyed on the bare agent address
// folded those streams together, so a dual-rate agent's interleaved counters
// (100 vs 5 here) fabricated a bogus backward-restart or growth delta on
// nearly every batch. Per (agent, rate) baselines: two identical batches are
// both pure first-sightings/no-growth — ZERO flow_agent_drops rows — and a
// genuinely growing counter still emits its delta under its own key.
func TestAgentDrops_DualRateAgentKeepsSeparateBaselines(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().AutoMigrate(&models.AgentDrops{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	batch := []models.FlowSample{
		{SamplerAddress: "10.9.0.1", SamplingRate: 1000, Drops: 100, FlowSource: models.FlowSourceSFlow},
		{SamplerAddress: "10.9.0.1", SamplingRate: 2000, Drops: 5, FlowSource: models.FlowSourceSFlow},
	}
	h.recordAgentDrops(batch)
	h.recordAgentDrops(batch)

	var rows []models.AgentDrops
	if err := db.Gorm().Find(&rows).Error; err != nil {
		t.Fatalf("query drops: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("fabricated %d drops row(s) from a dual-rate agent's unchanged counters: %+v", len(rows), rows)
	}

	// Real growth on ONE instance still emits exactly its delta.
	h.recordAgentDrops([]models.FlowSample{
		{SamplerAddress: "10.9.0.1", SamplingRate: 1000, Drops: 150, FlowSource: models.FlowSourceSFlow},
		{SamplerAddress: "10.9.0.1", SamplingRate: 2000, Drops: 5, FlowSource: models.FlowSourceSFlow},
	})
	if err := db.Gorm().Find(&rows).Error; err != nil {
		t.Fatalf("query drops after growth: %v", err)
	}
	if len(rows) != 1 || rows[0].SamplingRate != 1000 || rows[0].DropsCount != 50 {
		t.Fatalf("want exactly one delta row {rate 1000, drops 50}, got %+v", rows)
	}
}
