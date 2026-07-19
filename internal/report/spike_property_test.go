package report

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"
)

// AUDIT-120: property-based tests for the counter-delta / spike-detect math.
// These complement the example-based tests by asserting invariants that must
// hold for *every* input, using stdlib testing/quick (no new dependency — same
// approach as the AUDIT-119 fuzz tests). The generators below deliberately
// produce only finite, non-negative throughput values (bps), which is the
// real domain: detectSpikesInSeries runs on per-bucket throughput derived from
// counter deltas (see the v0.10.236 note in spike.go), never raw octet
// counters or NaN/Inf.

// finiteNonNegSlice is a testing/quick value generator that yields a []float64
// of finite, non-negative values with a realistic length distribution.
func finiteNonNegSlice(args []reflect.Value, rng *rand.Rand) {
	n := rng.Intn(130) // 0..129 — spans below the 3-sample floor and above it
	out := make([]float64, n)
	for i := range out {
		// 0 .. ~1e10 bps, finite. Occasionally emit exact-equal values so the
		// stddev==0 branch and constant-window cases get exercised.
		if rng.Intn(4) == 0 {
			out[i] = 1000
		} else {
			out[i] = rng.Float64() * 1e10
		}
	}
	args[0] = reflect.ValueOf(out)
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// TestMeanStdDev_Invariants_AUDIT120: stddev is always a finite, non-negative
// real; mean lies within [min,max] of the inputs; the empty slice yields (0,0).
func TestMeanStdDev_Invariants_AUDIT120(t *testing.T) {
	t.Parallel()
	prop := func(vals []float64) bool {
		mean, sd := meanStdDev(vals)
		if len(vals) == 0 {
			return mean == 0 && sd == 0
		}
		if !finite(sd) || sd < 0 {
			return false
		}
		if !finite(mean) {
			return false
		}
		mn, mx := vals[0], vals[0]
		for _, v := range vals {
			if v < mn {
				mn = v
			}
			if v > mx {
				mx = v
			}
		}
		// Floating-point slack proportional to the magnitude in play.
		eps := 1e-6 * (1 + math.Abs(mn) + math.Abs(mx))
		return mean >= mn-eps && mean <= mx+eps
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 3000, Values: finiteNonNegSlice}); err != nil {
		t.Error(err)
	}
}

// TestMeanStdDev_ConstantHasZeroStdDev_AUDIT120: a constant window has stddev 0
// and mean equal to the constant — the exact precondition spike detection uses
// to skip a window (avoids a divide-by-meaning on a flat signal).
func TestMeanStdDev_ConstantHasZeroStdDev_AUDIT120(t *testing.T) {
	t.Parallel()
	prop := func(v float64, count uint8) bool {
		// Domain guard: throughput (bps) is finite and bounded — real values
		// top out around terabit/s. Magnitudes near float64-max are out of
		// domain and would make the running sum overflow to ±Inf (a float64
		// limitation, not a math bug), so skip them.
		if !finite(v) || math.Abs(v) > 1e15 {
			return true
		}
		k := int(count%50) + 1
		vals := make([]float64, k)
		for i := range vals {
			vals[i] = v
		}
		mean, sd := meanStdDev(vals)
		return math.Abs(mean-v) <= 1e-6*(1+math.Abs(v)) && sd <= 1e-6*(1+math.Abs(v))
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 3000}); err != nil {
		t.Error(err)
	}
}

// TestDetectSpikes_Invariants_AUDIT120: for any series, every reported spike is
// internally consistent — its value strictly exceeds the window mean, its
// window stddev is strictly positive (the stddev==0 windows are skipped), a
// "critical" spike clears the 2x bar, and severity is only ever one of the two
// known labels. The detector must also never panic and must return nil for
// degenerate inputs (too few points, or a non-positive threshold).
func TestDetectSpikes_Invariants_AUDIT120(t *testing.T) {
	t.Parallel()
	const threshold = 3.0
	prop := func(vals []float64) bool {
		times := make([]time.Time, len(vals))
		spikes := detectSpikesInSeries(vals, times, threshold, "eth0", 0)
		for _, s := range spikes {
			if !(s.Value > s.Mean) {
				return false
			}
			if s.StdDev <= 0 || !finite(s.StdDev) {
				return false
			}
			switch s.Severity {
			case "warning":
				// must clear the 1x bar but not the 2x bar
				if !(s.Value > s.Mean+threshold*s.StdDev) {
					return false
				}
			case "critical":
				if !(s.Value > s.Mean+threshold*2*s.StdDev) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 3000, Values: finiteNonNegSlice}); err != nil {
		t.Error(err)
	}

	// Degenerate inputs return nil regardless of content.
	if got := detectSpikesInSeries([]float64{1, 2}, make([]time.Time, 2), threshold, "x", 0); got != nil {
		t.Errorf("len<3 should yield nil, got %v", got)
	}
	if got := detectSpikesInSeries([]float64{1, 2, 3, 4, 5}, make([]time.Time, 5), 0, "x", 0); got != nil {
		t.Errorf("non-positive threshold should yield nil, got %v", got)
	}
}
