package handlers

import (
	"math"
	"strconv"
	"testing"
	"time"
)

// TestPublicChartLookback_ClampsNumericRange_AUDIT323 covers the `range` table
// for GetPublicInterfaceChart.
//
// AUDIT-323: the numeric fallback ParseFloats the value and had only a lower
// bound, so range=Inf produced a +Inf float whose int conversion is
// implementation-defined (the minimum int64 on amd64). The cutoff derived from
// it was an arbitrary instant rather than the requested window. The endpoint is
// device- and public-gated either way, so this is a correctness bug, not a
// disclosure one — but the window it served was simply wrong.
func TestPublicChartLookback_ClampsNumericRange_AUDIT323(t *testing.T) {
	const hour = time.Hour

	tests := []struct {
		name     string
		rangeStr string
		want     time.Duration
		wantPts  int
	}{
		// Presets must keep their exact pre-refactor windows and point budgets.
		{"5m preset", "5m", 5 * time.Minute, 10},
		{"15m preset", "15m", 15 * time.Minute, 20},
		{"6h preset", "6h", 6 * hour, 360},
		{"24h preset", "24h", 24 * hour, 96},
		{"7d preset", "7d", 168 * hour, 168},
		{"720 preset", "720", 720 * hour, 90},
		{"8760 preset", "8760", 8760 * hour, 365},
		{"90d preset", "90d", 2160 * hour, 90},

		// AUDIT-235 fractional public ranges.
		{"15m fractional", "0.25", 15 * time.Minute, 30},
		{"30m fractional", "0.5", 30 * time.Minute, 30},

		// Plain numeric hours inside the bound.
		{"numeric hours", "2", 2 * hour, 180},
		{"upper bound exactly", "8760.0", 8760 * hour, 180},

		// Unparseable and out-of-range both fall back to the 1h default.
		{"default 1h", "1h", hour, 60},
		{"garbage", "not-a-range", hour, 60},
		{"zero", "0", hour, 60},
		{"negative", "-5", hour, 60},

		// AUDIT-323: the values that used to produce a garbage cutoff.
		{"positive infinity", "Inf", hour, 60},
		{"infinity long form", "Infinity", hour, 60},
		{"negative infinity", "-Inf", hour, 60},
		{"NaN", "NaN", hour, 60},
		{"above the bound", "100000", hour, 60},
		{"absurdly large", "1e18", hour, 60},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, pts := publicChartLookback(tc.rangeStr)
			if got != tc.want {
				t.Errorf("publicChartLookback(%q) lookback = %v, want %v", tc.rangeStr, got, tc.want)
			}
			if pts != tc.wantPts {
				t.Errorf("publicChartLookback(%q) maxPoints = %d, want %d", tc.rangeStr, pts, tc.wantPts)
			}
		})
	}
}

// TestPublicChartLookback_NeverNonPositive_AUDIT323 states the property the
// clamp exists to guarantee: whatever the client sends, the resolved window is
// a sane positive duration no longer than the one-year bound. A non-positive
// or overflowed value would make `time.Now().Add(-lookback)` a cutoff in the
// future or in the distant past.
func TestPublicChartLookback_NeverNonPositive_AUDIT323(t *testing.T) {
	inputs := []string{
		"Inf", "-Inf", "NaN", "1e308", "-1e308", "1e18", "99999999",
		"", "0", "-1", "0.0000001", "abc", "1h", "0.25", "8760", "90d",
		strconv.FormatFloat(math.MaxFloat64, 'g', -1, 64),
	}
	const maxWindow = maxPublicChartRangeHours * time.Hour

	for _, in := range inputs {
		lookback, pts := publicChartLookback(in)
		if lookback <= 0 {
			t.Errorf("publicChartLookback(%q) = %v: a non-positive window makes the cutoff now-or-future", in, lookback)
		}
		if lookback > maxWindow {
			t.Errorf("publicChartLookback(%q) = %v exceeds the %v bound", in, lookback, maxWindow)
		}
		if pts <= 0 {
			t.Errorf("publicChartLookback(%q) maxPoints = %d: downsampling would divide by zero", in, pts)
		}
	}
}
