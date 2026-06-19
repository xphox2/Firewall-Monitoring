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

func TestDistinctDays(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	times := []time.Time{
		base, base.Add(3 * time.Hour), base.Add(25 * time.Hour), base.Add(50 * time.Hour),
	}
	if got := distinctDays(times); got != 3 {
		t.Errorf("distinctDays = %d, want 3", got)
	}
}
