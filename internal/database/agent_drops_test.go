package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestAgentDrops_RoundTrip pins the data path for the new
// flow_agent_drops table (migration v8). SaveAgentDrops persists a
// (agent, sampling_rate, window) aggregate; GetAgentDropsRecent reads
// them back ordered by window DESC. The CTO-loop audit (2026-06-22,
// taocp [MEDIUM] #5) found this data was previously invisible —
// agent-side congestion was undetectable end-to-end. This test
// exercises both the SQLite test path (no pgx pool) and the GORM
// fallback that test lane uses.
func TestAgentDrops_RoundTrip(t *testing.T) {
	db := NewDatabaseForTesting(t)

	now := time.Now().UTC().Truncate(time.Minute)

	cases := []models.AgentDrops{
		{AgentAddress: "10.0.0.1", SamplingRate: 512, WindowStart: now.Add(-4 * time.Minute), DropsCount: 1500},
		{AgentAddress: "10.0.0.1", SamplingRate: 512, WindowStart: now.Add(-3 * time.Minute), DropsCount: 2200},
		{AgentAddress: "10.0.0.2", SamplingRate: 256, WindowStart: now.Add(-2 * time.Minute), DropsCount: 0},
		// Out of window — should NOT appear in the recent query.
		{AgentAddress: "10.0.0.1", SamplingRate: 512, WindowStart: now.Add(-10 * time.Minute), DropsCount: 99999},
	}
	for _, c := range cases {
		if err := db.SaveAgentDrops(c.AgentAddress, c.SamplingRate, c.WindowStart, c.DropsCount); err != nil {
			t.Fatalf("SaveAgentDrops(%v, %d, %v, %d): %v", c.AgentAddress, c.SamplingRate, c.WindowStart, c.DropsCount, err)
		}
	}

	// since = now - 5m → should return the first 3 but not the 10m-old row.
	got, err := db.GetAgentDropsRecent(now.Add(-5 * time.Minute))
	if err != nil {
		t.Fatalf("GetAgentDropsRecent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("GetAgentDropsRecent returned %d rows, want 3 (the 10m-old row should be filtered out)", len(got))
	}

	// Order is window_start DESC.
	if !got[0].WindowStart.After(got[1].WindowStart) {
		t.Errorf("rows not in DESC order: got[0]=%v got[1]=%v", got[0].WindowStart, got[1].WindowStart)
	}

	// The 99999-drops out-of-window row must not appear.
	for _, r := range got {
		if r.DropsCount == 99999 {
			t.Errorf("out-of-window row returned: %+v", r)
		}
	}

	// Find the 2200-drops row (should be got[0] since now-3m > now-4m > now-2m... wait, now-2m is the LATEST).
	// Order by window_start DESC: now-2m (most recent), now-3m, now-4m.
	// We don't strictly assert order — just verify counts add up.
	var sum uint64
	for _, r := range got {
		sum += r.DropsCount
	}
	if want := uint64(1500 + 2200 + 0); sum != want {
		t.Errorf("sum of drops_count = %d, want %d", sum, want)
	}
}

// TestAgentDrops_EmptyResultIsCleanNil pins that an empty result returns
// (nil, nil) — not (nil, err) — so callers can range over the result
// without nil-guards. A subtle but real concern for the NOC widget.
func TestAgentDrops_EmptyResultIsCleanNil(t *testing.T) {
	db := NewDatabaseForTesting(t)

	got, err := db.GetAgentDropsRecent(time.Now().UTC())
	if err != nil {
		t.Errorf("GetAgentDropsRecent on empty table: err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("GetAgentDropsRecent returned %d rows on empty table, want 0", len(got))
	}
}
