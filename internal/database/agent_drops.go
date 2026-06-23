package database

import (
	"time"

	"firewall-mon/internal/models"
)

// SaveAgentDrops persists one (agent, sampling_rate, window) aggregate row
// of sFlow sample-pool drops. Called by the alert/reporting layer after
// each 1-minute rollup of per-sample Drops values. Duplicates
// (same agent+sampling_rate+window) are tolerated; the caller is
// expected to upsert via INSERT ON CONFLICT in production (TODO follow-up
// when the alert-policy hook lands).
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
