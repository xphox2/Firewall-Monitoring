package report

import (
	"testing"
	"time"
)

// buildFloorProfile makes a week-long hourly seasonal profile: every hour at
// dayMean except 0-5h at nightMean.
func buildFloorProfile(dayMean, nightMean float64) *SeasonalProfile {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var bs []float64
	var bt []time.Time
	for i := 0; i < 7*24; i++ {
		ts := base.Add(time.Duration(i) * time.Hour)
		v := dayMean
		if h := ts.Hour(); h < 6 {
			v = nightMean
		}
		// Small jitter so std > 0.
		bs = append(bs, v+float64(i%5-2)*v*0.01)
		bt = append(bt, ts)
	}
	return BuildSeasonalProfile(bs, bt)
}

// TestObserve_FloorKillsDeadPortNoise is the user's exact pain case: a ~90bps
// port spiking to 800bps must NOT alert with the 1 Mbps floor, and must keep
// alerting with the floor disabled (legacy).
func TestObserve_FloorKillsDeadPortNoise(t *testing.T) {
	profile := buildFloorProfile(90, 90) // dead port: ~90bps around the clock
	now := time.Date(2026, 6, 8, 14, 0, 0, 0, time.UTC)
	minDur := 0 * time.Minute

	// Floor 1 Mbps → never fires on 800bps.
	d := NewSeasonalSpikeDetector(time.Hour, 0, func(string) *SeasonalProfile { return profile })
	for i := 0; i < 5; i++ {
		if dec := d.Observe("1:1", now.Add(time.Duration(i)*time.Minute), 800, 2.0, minDur, 1e6); dec.Fire {
			t.Fatalf("dead-port 800bps spike fired despite the 1 Mbps floor (i=%d)", i)
		}
	}
	// Floor 0 → legacy z-score fires.
	d2 := NewSeasonalSpikeDetector(time.Hour, 0, func(string) *SeasonalProfile { return profile })
	fired := false
	for i := 0; i < 5; i++ {
		if d2.Observe("1:1", now.Add(time.Duration(i)*time.Minute), 800, 2.0, minDur, 0).Fire {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("floor 0 must preserve legacy behavior (800bps fires on a 90bps baseline)")
	}
}

// TestObserve_PeakQualifierKeepsNightCoverage pins the user decision: a port
// doing 50 Mbps by day but 0.2 Mbps at night still alerts on a genuine 3am
// 50 Mbps surge — qualification is by the port's PEAK normal period, not the
// current time-of-day band.
func TestObserve_PeakQualifierKeepsNightCoverage(t *testing.T) {
	profile := buildFloorProfile(50e6, 0.2e6)
	d := NewSeasonalSpikeDetector(time.Hour, 0, func(string) *SeasonalProfile { return profile })
	night := time.Date(2026, 6, 8, 3, 0, 0, 0, time.UTC)
	if dec := d.Observe("1:1", night, 50e6, 2.0, 0, 1e6); !dec.Fire {
		t.Fatalf("3am 50 Mbps surge on a day-busy port must fire (peak qualifier); got %+v", dec)
	}
}

// TestObserve_PeakQualifierSuppressesDeadPortBigSpike: a port whose EVERY
// normal period is under the floor never alerts, even on a >floor spike (the
// user's "don't even alert if the port doesn't normally pass 1 Mbps").
func TestObserve_PeakQualifierSuppressesDeadPortBigSpike(t *testing.T) {
	profile := buildFloorProfile(90, 90)
	d := NewSeasonalSpikeDetector(time.Hour, 0, func(string) *SeasonalProfile { return profile })
	now := time.Date(2026, 6, 8, 14, 0, 0, 0, time.UTC)
	if dec := d.Observe("1:1", now, 5e6, 2.0, 0, 1e6); dec.Fire {
		t.Fatalf("dead port (peak ~90bps) must not alert even on a 5 Mbps spike; got %+v", dec)
	}
}

// TestObserve_FloorFailResolvesOngoingAlert: an alerting interface whose
// traffic drops below the floor resolves (floor-fail takes the !anomalous
// branch).
func TestObserve_FloorFailResolvesOngoingAlert(t *testing.T) {
	profile := buildFloorProfile(5e6, 5e6)
	d := NewSeasonalSpikeDetector(time.Hour, 0, func(string) *SeasonalProfile { return profile })
	now := time.Date(2026, 6, 8, 14, 0, 0, 0, time.UTC)
	if dec := d.Observe("1:1", now, 500e6, 2.0, 0, 1e6); !dec.Fire {
		t.Fatalf("qualifying 500 Mbps spike must fire; got %+v", dec)
	}
	if dec := d.Observe("1:1", now.Add(time.Minute), 800, 2.0, 0, 1e6); !dec.Resolve {
		t.Fatalf("sub-floor traffic must resolve the open spike; got %+v", dec)
	}
}

// TestMaxBandMean pins the peak qualifier's source: max per-bucket mean with
// enough samples; nil-safe.
func TestMaxBandMean(t *testing.T) {
	var nilP *SeasonalProfile
	if got := nilP.MaxBandMean(); got != 0 {
		t.Fatalf("nil profile MaxBandMean = %v, want 0", got)
	}
	p := buildFloorProfile(50e6, 0.2e6)
	got := p.MaxBandMean()
	if got < 45e6 || got > 55e6 {
		t.Fatalf("MaxBandMean = %v, want ~50e6 (the busiest period)", got)
	}
}

// TestDetectSpikesInSeries_Floor: the report fallback path applies both floor
// clauses.
func TestDetectSpikesInSeries_Floor(t *testing.T) {
	// Dead port: ~90bps with an 800bps outlier.
	var vals []float64
	var times []time.Time
	base := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		v := 90.0 + float64(i%3)
		if i == 25 {
			v = 800
		}
		vals = append(vals, v)
		times = append(times, base.Add(time.Duration(i)*time.Minute))
	}
	if got := detectSpikesInSeries(vals, times, 3.0, "dead0", 1e6); got != nil {
		t.Fatalf("dead-port series must yield no spikes with the floor, got %d", len(got))
	}
	if got := detectSpikesInSeries(vals, times, 3.0, "dead0", 0); len(got) == 0 {
		t.Fatal("floor 0 must preserve legacy series detection")
	}
	// Qualifying port: ~5 Mbps with a 50 Mbps spike — floor must not mute it.
	vals = vals[:0]
	times = times[:0]
	for i := 0; i < 30; i++ {
		v := 5e6 + float64(i%3)*1e5
		if i == 25 {
			v = 50e6
		}
		vals = append(vals, v)
		times = append(times, base.Add(time.Duration(i)*time.Minute))
	}
	if got := detectSpikesInSeries(vals, times, 3.0, "wan1", 1e6); len(got) == 0 {
		t.Fatal("qualifying 50 Mbps spike must survive the floor")
	}
}

// TestDetectSpikesTimeOfDay_Floor: the report seasonal path applies the floor.
func TestDetectSpikesTimeOfDay_Floor(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	mk := func(baseline, spike float64) ([]float64, []time.Time) {
		var vals []float64
		var times []time.Time
		for i := 0; i < 8*24; i++ { // 7 baseline days + 1 test day
			v := baseline + float64(i%5-2)*baseline*0.01
			if i >= 7*24+10 && i < 7*24+14 {
				v = spike
			}
			vals = append(vals, v)
			times = append(times, base.Add(time.Duration(i)*time.Hour))
		}
		return vals, times
	}
	vals, times := mk(90, 800)
	if got := detectSpikesTimeOfDay(vals, times, 24, 2.0, "dead0", 1e6); got != nil {
		t.Fatalf("dead-port seasonal spikes must be floored, got %d", len(got))
	}
	if got := detectSpikesTimeOfDay(vals, times, 24, 2.0, "dead0", 0); len(got) == 0 {
		t.Fatal("floor 0 must preserve legacy seasonal detection")
	}
	vals, times = mk(5e6, 50e6)
	if got := detectSpikesTimeOfDay(vals, times, 24, 2.0, "wan1", 1e6); len(got) == 0 {
		t.Fatal("qualifying seasonal spike must survive the floor")
	}
}
