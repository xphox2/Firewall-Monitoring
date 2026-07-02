package database

import (
	"time"

	"firewall-mon/internal/models"
)

// SaveAgentDrops persists one (agent, sampling_rate, window) delta row of
// sFlow sample-pool drops. Called from the flow-ingest handler
// (recordAgentDrops, M2 of the 2026-07-01 audit), which deltas each agent's
// CUMULATIVE drops counter per batch. Multiple rows per (agent, window) are
// fine — the sampling_backoff detector SUMs drops_count over the window.
func (d *Database) SaveAgentDrops(agentAddress string, samplingRate uint32, windowStart time.Time, dropsCount uint64) error {
	row := models.AgentDrops{
		AgentAddress: agentAddress,
		SamplingRate: samplingRate,
		WindowStart:  windowStart.UTC(),
		DropsCount:   dropsCount,
	}
	return d.db.Create(&row).Error
}

// GetAgentDropsRecent returns the rows in flow_agent_drops newer than
// `since` (typically now-5m), ordered newest first. Callers feed this to
// the alert policy (`SFLOW_AGENT_DROPS`) and the NOC strip widget.
// Per the audit (2026-06-22, taocp [MEDIUM] #5), this was previously
// impossible — the data wasn't persisted anywhere.
func (d *Database) GetAgentDropsRecent(since time.Time) ([]models.AgentDrops, error) {
	var rows []models.AgentDrops
	err := d.db.Where("window_start >= ?", since.UTC()).
		Order("window_start DESC").
		Limit(1000).
		Find(&rows).Error
	return rows, err
}
