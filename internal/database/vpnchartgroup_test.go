package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// One logical tunnel is reported as several rows under unrelated names, so the
// per-name chart shows a fraction of the traffic — or, for a config-derived row
// with no counters, nothing at all. These pin the grouped query.

// seedTunnelSamples writes cumulative counter samples for one tunnel name.
func seedTunnelSamples(t *testing.T, d *Database, deviceID uint, name string, base time.Time, vals ...uint64) {
	t.Helper()
	rows := make([]models.VPNStatus, 0, len(vals))
	for i, v := range vals {
		rows = append(rows, models.VPNStatus{
			DeviceID: deviceID, TunnelName: name, TunnelType: "ipsec", Status: "up",
			BytesIn: v, BytesOut: v * 2,
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}
	if err := d.SaveVPNStatuses(rows); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// THE INTERLEAVING BUG. Two names in one query means LAG must be partitioned;
// without it the window walks across rows of different tunnels ordered only by
// time, so each delta is computed against the wrong predecessor.
//
// The two series are interleaved in time and rise at different rates, so an
// unpartitioned LAG produces wildly wrong deltas rather than a near-miss.
func TestGetVPNChartGroupWindow_PartitionsPerTunnel(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-30 * time.Minute).Truncate(time.Minute)

	// A climbs by 100 per sample, B by 1000, and their timestamps interleave.
	seedTunnelSamples(t, d, 1, "childA", base, 1000, 1100, 1200)
	seedTunnelSamples(t, d, 1, "childB", base.Add(30*time.Second), 50000, 51000, 52000)

	rows, err := d.GetVPNChartGroupWindow(1, []string{"childA", "childB"},
		base.Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("group window: %v", err)
	}

	var totalIn float64
	for _, r := range rows {
		totalIn += r.InBytes
	}
	// Correct: A contributes 100+100, B contributes 1000+1000 = 2200.
	// An unpartitioned LAG jumps between the two series and yields deltas in
	// the tens of thousands.
	if totalIn > 5000 {
		t.Fatalf("summed in_bytes = %.0f, want ~2200 — LAG crossed between tunnels, "+
			"so deltas were computed against the wrong predecessor", totalIn)
	}
	if totalIn == 0 {
		t.Fatalf("summed in_bytes = 0 — the group query returned no deltas at all")
	}
}

// A group of one must behave exactly as the single-tunnel query, so grouping
// cannot regress the overwhelmingly common case.
func TestGetVPNChartGroupWindow_SingleNameMatchesUngrouped(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-20 * time.Minute).Truncate(time.Minute)
	seedTunnelSamples(t, d, 1, "solo", base, 500, 700, 900)

	from, to := base.Add(-time.Minute), time.Now()
	grouped, err := d.GetVPNChartGroupWindow(1, []string{"solo"}, from, to)
	if err != nil {
		t.Fatalf("grouped: %v", err)
	}
	single, err := d.GetVPNChartWindow(1, "solo", from, to)
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	if len(grouped) != len(single) {
		t.Fatalf("bucket count differs: grouped %d, single %d", len(grouped), len(single))
	}
	for i := range grouped {
		if grouped[i].InBytes != single[i].InBytes || grouped[i].OutBytes != single[i].OutBytes {
			t.Errorf("bucket %d differs: grouped %.0f/%.0f, single %.0f/%.0f",
				i, grouped[i].InBytes, grouped[i].OutBytes, single[i].InBytes, single[i].OutBytes)
		}
	}
}

// A row carrying no counters must contribute nothing — this is what stops a
// config-derived phase1 row from rendering an empty series next to the real one.
func TestGetVPNChartGroupWindow_CounterlessRowsContributeNothing(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-20 * time.Minute).Truncate(time.Minute)
	seedTunnelSamples(t, d, 1, "real", base, 100, 200, 300)
	// The SSH-sourced sibling: present, named, and permanently zero.
	seedTunnelSamples(t, d, 1, "configOnly", base, 0, 0, 0)

	withBoth, err := d.GetVPNChartGroupWindow(1, []string{"real", "configOnly"},
		base.Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	realOnly, err := d.GetVPNChartWindow(1, "real", base.Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	var a, b float64
	for _, r := range withBoth {
		a += r.InBytes
	}
	for _, r := range realOnly {
		b += r.InBytes
	}
	if a != b {
		t.Errorf("counterless rows changed the totals: %.0f vs %.0f", a, b)
	}
}

// Empty input must not produce a query at all.
func TestGetVPNChartGroupWindow_EmptyGroupIsNoOp(t *testing.T) {
	d := NewDatabaseForTesting(t)
	rows, err := d.GetVPNChartGroupWindow(1, nil, time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("empty group: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want no buckets, got %d", len(rows))
	}
}
