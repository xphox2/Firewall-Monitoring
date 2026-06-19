package report

import (
	"testing"
	"time"
)

// TestDetectSpikesTimeOfDay verifies that a recurring nightly pattern (a backup
// at 02:00 every night) is NOT flagged, while a one-off surge at a normally
// quiet daytime hour IS — the whole point of the time-of-day baseline.
func TestDetectSpikesTimeOfDay(t *testing.T) {
	// 6 days of hourly samples. Prior days (0–4) establish the baseline:
	// 02:00 is consistently a backup (with spread), every other hour is idle
	// (small spread, mean ~100 Mbps). Day 5 is the report window under test.
	priorBackup := []float64{850e6, 870e6, 880e6, 890e6, 900e6}
	idleSet := []float64{97e6, 99e6, 101e6, 103e6, 100e6} // mean 100, nonzero stddev
	base := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)

	var series []float64
	var times []time.Time
	for d := 0; d < 6; d++ {
		for h := 0; h < 24; h++ {
			var v float64
			if d == 5 { // report window
				switch h {
				case 2:
					v = 900e6 // tonight's backup — must read as normal
				case 14:
					v = 700e6 // surge at a normally-quiet hour — anomalous
				default:
					v = 100e6 // idle, at the baseline mean
				}
			} else if h == 2 {
				v = priorBackup[d]
			} else {
				v = idleSet[d]
			}
			series = append(series, v)
			times = append(times, base.Add(time.Duration(d*24+h)*time.Hour))
		}
	}

	spikes := detectSpikesTimeOfDay(series, times, 24, 2.0, "wan1")

	if len(spikes) != 1 {
		t.Fatalf("expected exactly 1 spike (the 14:00 surge), got %d: %+v", len(spikes), spikes)
	}
	s := spikes[0]
	if s.Timestamp.Hour() != 14 {
		t.Errorf("spike at hour %d, want 14 (02:00 backup must NOT be flagged)", s.Timestamp.Hour())
	}
	if s.Interface != "wan1" {
		t.Errorf("interface = %q, want wan1", s.Interface)
	}
	if s.Severity != "critical" {
		t.Errorf("severity = %q, want critical", s.Severity)
	}
}

// TestDetectSpikesTimeOfDay_FallsBackWithoutHistory verifies that with fewer
// than 3 prior days the detector falls back to the single-window detector
// rather than silently emitting nothing.
func TestDetectSpikesTimeOfDay_FallsBackWithoutHistory(t *testing.T) {
	base := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	// Two days of hourly data; a clear ramp in the last 24h so the rolling
	// fallback has nonzero variance to fire on.
	var series []float64
	var times []time.Time
	for i := 0; i < 48; i++ {
		v := 100e6 + float64(i)*5e6 // steadily rising baseline (nonzero stddev)
		if i == 40 {
			v = 5e9 // a sharp transient in the test window
		}
		series = append(series, v)
		times = append(times, base.Add(time.Duration(i)*time.Hour))
	}

	got := detectSpikesTimeOfDay(series, times, 24, 2.0, "wan1")
	if len(got) == 0 {
		t.Fatalf("fallback path should still surface the transient spike, got none")
	}
}

// genHourly builds `days` of hourly samples ending at `end` (exclusive of the
// hour after end), using valueAt(dayIndex, weekday, hour) to pick each value.
func genHourly(end time.Time, days int, valueAt func(day, weekday, hour int) float64) ([]float64, []time.Time) {
	start := end.Add(-time.Duration(days*24-1) * time.Hour)
	n := days * 24
	series := make([]float64, 0, n)
	times := make([]time.Time, 0, n)
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(i) * time.Hour)
		series = append(series, valueAt(i/24, int(ts.Weekday()), ts.Hour()))
		times = append(times, ts)
	}
	return series, times
}

// TestDetectSpikesTimeOfDay_WeekdayAware verifies weekly periodicity: a normal
// Monday-morning workload is NOT flagged (it matches prior Mondays) even though
// weekends are quiet, while an unusual surge at a normally-quiet Monday hour IS.
func TestDetectSpikesTimeOfDay_WeekdayAware(t *testing.T) {
	// End on a Monday 23:00 so the test window (last 24h) is a Monday.
	end := time.Date(2026, 6, 15, 23, 0, 0, 0, time.UTC) // 2026-06-15 is a Monday
	if end.Weekday() != time.Monday {
		t.Fatalf("test setup: expected Monday, got %s", end.Weekday())
	}
	isToday := func(day int) bool { return day == 27 } // last of 28 days
	// idle has a small, nonzero spread (real traffic is never perfectly flat),
	// so a quiet hour's baseline has a usable stddev.
	idle := func(day, hour int) float64 { return 100e6 + float64((day*7+hour)%5-2)*1e6 }

	series, times := genHourly(end, 28, func(day, weekday, hour int) float64 {
		weekdayBusy := weekday >= int(time.Monday) && weekday <= int(time.Friday) && hour == 9
		if isToday(day) {
			switch hour {
			case 9:
				return 500e6 // normal Monday ramp
			case 3:
				return 600e6 // surge at a normally-quiet Monday hour
			default:
				return 100e6 // idle, at the baseline mean
			}
		}
		if weekdayBusy {
			return 500e6 // weekdays ramp at 09:00; weekends stay quiet
		}
		return idle(day, hour)
	})

	spikes := detectSpikesTimeOfDay(series, times, 24, 2.0, "wan1")
	if len(spikes) != 1 {
		t.Fatalf("expected exactly 1 spike (the 03:00 surge); the normal Monday 09:00 ramp must NOT flag. got %d: %+v", len(spikes), spikes)
	}
	if spikes[0].Timestamp.Hour() != 3 {
		t.Errorf("spike at hour %d, want 3", spikes[0].Timestamp.Hour())
	}
}

// TestDetectSpikesTimeOfDay_TimingTolerance verifies the ±1h tolerance: a backup
// that normally runs at 02:00 but tonight runs at 03:00 (delayed) is NOT flagged.
func TestDetectSpikesTimeOfDay_TimingTolerance(t *testing.T) {
	end := time.Date(2026, 6, 15, 23, 0, 0, 0, time.UTC)
	isToday := func(day int) bool { return day == 27 }

	series, times := genHourly(end, 28, func(day, weekday, hour int) float64 {
		if isToday(day) {
			if hour == 3 {
				return 880e6 // backup ran an hour late tonight
			}
			return 100e6 // including a quiet 02:00 (didn't run at the usual time)
		}
		if hour == 2 {
			return 880e6 // backup normally at 02:00 every prior day
		}
		return 100e6
	})

	spikes := detectSpikesTimeOfDay(series, times, 24, 2.0, "wan1")
	for _, s := range spikes {
		t.Errorf("delayed backup at %02d:00 should be tolerated (±1h), but was flagged: %+v", s.Timestamp.Hour(), s)
	}
}

func TestSeasonalProfileBandFallback(t *testing.T) {
	// Only 2 samples in any slot -> Band reports not-enough-history.
	base := time.Date(2026, 6, 1, 2, 0, 0, 0, time.UTC)
	p := BuildSeasonalProfile(
		[]float64{100e6, 110e6},
		[]time.Time{base, base.Add(24 * time.Hour)},
	)
	if _, _, ok := p.Band(base.Add(48 * time.Hour)); ok {
		t.Errorf("Band should report ok=false with < %d samples", minSeasonalSamples)
	}
}

// TestSeasonalSpikeDetector_SustainedGateAndCooldown verifies the real-time
// detector only fires after a spike is sustained ≥ minDuration, fires once per
// event, resolves when traffic normalizes, and respects the cooldown.
func TestSeasonalSpikeDetector_SustainedGateAndCooldown(t *testing.T) {
	// Baseline: a week of hourly ~100 Mbps (small jitter) across every hour.
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var bs []float64
	var bt []time.Time
	for i := 0; i < 7*24; i++ {
		bs = append(bs, 100e6+float64(i%5-2)*1e6)
		bt = append(bt, base.Add(time.Duration(i)*time.Hour))
	}
	profile := BuildSeasonalProfile(bs, bt)

	d := NewSeasonalSpikeDetector(time.Hour, 30*time.Minute, func(string) *SeasonalProfile { return profile })
	const (
		key  = "1:2"
		k    = 2.0
		high = 900e6
	)
	minDur := 15 * time.Minute
	now := time.Date(2026, 6, 8, 14, 0, 0, 0, time.UTC)

	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Minute) }

	if d.Observe(key, at(0), high, k, minDur).Fire {
		t.Fatal("must not fire immediately")
	}
	if d.Observe(key, at(10), high, k, minDur).Fire {
		t.Fatal("must not fire before 15 min sustained")
	}
	if dec := d.Observe(key, at(15), high, k, minDur); !dec.Fire {
		t.Fatalf("must fire once sustained ≥15 min; got %+v", dec)
	}
	if d.Observe(key, at(16), high, k, minDur).Fire {
		t.Fatal("must not re-fire while already alerting")
	}
	if dec := d.Observe(key, at(20), 100e6, k, minDur); !dec.Resolve {
		t.Fatalf("must resolve when traffic normalizes; got %+v", dec)
	}
	// Anomalous again from t=21; within cooldown (last alert t=15, cooldown 30m).
	for _, m := range []int{21, 30, 40} {
		if d.Observe(key, at(m), high, k, minDur).Fire {
			t.Fatalf("must not fire within cooldown (t=%dm)", m)
		}
	}
	if dec := d.Observe(key, at(50), high, k, minDur); !dec.Fire {
		t.Fatalf("must fire again after cooldown + sustained; got %+v", dec)
	}
}

// TestSeasonalSpikeDetector_RollingFallback verifies that with no seasonal
// profile, the detector still gates on the rolling fallback band (and never
// alerts before it has enough samples).
func TestSeasonalSpikeDetector_RollingFallback(t *testing.T) {
	d := NewSeasonalSpikeDetector(time.Hour, 0, func(string) *SeasonalProfile { return nil })
	base := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	minDur := 0 * time.Minute // isolate the band logic from the duration gate
	// Feed 15 normal samples to build the rolling band (no alerts — under 10 then within band).
	for i := 0; i < 15; i++ {
		if dec := d.Observe("9:9", base.Add(time.Duration(i)*time.Minute), 100e6+float64(i%3)*1e6, 2.0, minDur); dec.Fire {
			t.Fatalf("normal traffic must not fire (i=%d)", i)
		}
	}
	// Now a large sustained jump should fire via the rolling fallback band.
	if dec := d.Observe("9:9", base.Add(20*time.Minute), 5e9, 2.0, minDur); !dec.Fire {
		t.Fatalf("rolling fallback should fire on a large jump; got %+v", dec)
	}
}

func TestDistinctDays(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	times := []time.Time{
		base, base.Add(3 * time.Hour), base.Add(25 * time.Hour), base.Add(50 * time.Hour),
	}
	if got := distinctDays(times); got != 3 {
		t.Errorf("distinctDays = %d, want 3", got)
	}
}
