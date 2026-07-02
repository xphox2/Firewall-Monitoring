package database

import (
	"math"
	"testing"
	"time"
)

// TestFoldPingStats_AtomicAccumulation_L16 pins the 2026-07-01 audit L16 fix:
// folding a batch's aggregate into the running PingStats series is a single
// INSERT … ON CONFLICT DO UPDATE, so the min/max/running-average/sample-count
// accumulate exactly whether the series is created or updated — and, because it
// is one statement, concurrent folds for the same (device,target) can no longer
// lose a whole batch to a read-modify-write last-writer race.
func TestFoldPingStats_AtomicAccumulation_L16(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Unix(1_700_000_000, 0)

	// First fold creates the row: min=10 max=20 sum=45 count=3 → avg=15.
	if err := d.FoldPingStats(7, 1, "8.8.8.8", 10, 20, 45, 3, 0.0, now); err != nil {
		t.Fatalf("fold #1: %v", err)
	}
	s, err := d.GetPingStatsByTarget(7, "8.8.8.8")
	if err != nil || s == nil {
		t.Fatalf("get after fold #1: %v (nil=%v)", err, s == nil)
	}
	if s.Samples != 3 || s.MinLatency != 10 || s.MaxLatency != 20 || math.Abs(s.AvgLatency-15) > 1e-9 {
		t.Fatalf("after fold #1: samples=%d min=%.2f max=%.2f avg=%.4f (want 3/10/20/15)",
			s.Samples, s.MinLatency, s.MaxLatency, s.AvgLatency)
	}

	// Second fold updates in place: min=5 max=30 sum=40 count=2, packet_loss=0.5.
	// Expected: samples=5, min=5, max=30, avg=(15*3+40)/5=17, packet_loss last-writer.
	if err := d.FoldPingStats(7, 2, "8.8.8.8", 5, 30, 40, 2, 0.5, now.Add(time.Minute)); err != nil {
		t.Fatalf("fold #2: %v", err)
	}
	s, err = d.GetPingStatsByTarget(7, "8.8.8.8")
	if err != nil || s == nil {
		t.Fatalf("get after fold #2: %v", err)
	}
	if s.Samples != 5 {
		t.Errorf("samples=%d, want 5 (no batch lost)", s.Samples)
	}
	if s.MinLatency != 5 || s.MaxLatency != 30 {
		t.Errorf("min/max=%.2f/%.2f, want 5/30", s.MinLatency, s.MaxLatency)
	}
	if math.Abs(s.AvgLatency-17) > 1e-9 {
		t.Errorf("avg=%.4f, want 17 (running average folded exactly)", s.AvgLatency)
	}
	if s.PacketLoss != 0.5 {
		t.Errorf("packet_loss=%.2f, want 0.5 (last-writer)", s.PacketLoss)
	}
	if s.ProbeID != 2 {
		t.Errorf("probe_id=%d, want 2 (last-writer provenance)", s.ProbeID)
	}
}

// TestFoldPingStats_ManyFoldsSumSamples_L16 folds a long run of single-sample
// batches and asserts every one is counted — the property the pre-fix
// read-modify-write violated under concurrency (each dropped fold would leave
// Samples short of the number of folds applied).
func TestFoldPingStats_ManyFoldsSumSamples_L16(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Unix(1_700_000_000, 0)

	const n = 50
	var wantSum float64
	for i := 0; i < n; i++ {
		v := float64(i + 1)
		wantSum += v
		if err := d.FoldPingStats(3, 1, "1.1.1.1", v, v, v, 1, 0, now); err != nil {
			t.Fatalf("fold %d: %v", i, err)
		}
	}
	s, err := d.GetPingStatsByTarget(3, "1.1.1.1")
	if err != nil || s == nil {
		t.Fatalf("get: %v", err)
	}
	if s.Samples != n {
		t.Errorf("samples=%d, want %d (no fold lost)", s.Samples, n)
	}
	if s.MinLatency != 1 || s.MaxLatency != n {
		t.Errorf("min/max=%.0f/%.0f, want 1/%d", s.MinLatency, s.MaxLatency, n)
	}
	if wantAvg := wantSum / n; math.Abs(s.AvgLatency-wantAvg) > 1e-9 {
		t.Errorf("avg=%.4f, want %.4f", s.AvgLatency, wantAvg)
	}
}
