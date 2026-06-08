package uptime

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

// AUDIT-120: property-based tests for the uptime math, using stdlib
// testing/quick. They assert invariants that must hold for every input rather
// than spot-checking examples: the FormatUptime round-trip, and the
// UptimePercent clamp + reboot-underflow guard in GetStats.

// parseUptimeString reverses FormatUptime back into seconds. It understands the
// four shapes FormatUptime can emit ("Xd Xh Xm Xs", "Xh Xm Xs", "Xm Xs", "Xs")
// by reading each whitespace-separated token's trailing unit letter. This is an
// independent decoder (not a re-implementation of the encoder), so the
// round-trip property genuinely exercises FormatUptime's output.
func parseUptimeString(s string) (uint64, bool) {
	var total uint64
	for _, tok := range strings.Fields(s) {
		if len(tok) < 2 {
			return 0, false
		}
		n, err := strconv.ParseUint(tok[:len(tok)-1], 10, 64)
		if err != nil {
			return 0, false
		}
		switch tok[len(tok)-1] {
		case 'd':
			total += n * 86400
		case 'h':
			total += n * 3600
		case 'm':
			total += n * 60
		case 's':
			total += n
		default:
			return 0, false
		}
	}
	return total, true
}

// TestFormatUptime_RoundTrip_AUDIT120: FormatUptime renders centiseconds as a
// d/h/m/s string; decoding that string must recover the whole-seconds value
// (uptime/100) exactly, for any uint64. Implicitly proves it never panics and
// always emits a parseable, non-empty string.
func TestFormatUptime_RoundTrip_AUDIT120(t *testing.T) {
	t.Parallel()
	prop := func(u uint64) bool {
		got, ok := parseUptimeString(FormatUptime(u))
		return ok && got == u/100
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 5000}); err != nil {
		t.Error(err)
	}
	// Pin a couple of boundary values explicitly.
	for _, u := range []uint64{0, 99, 100, 8640000 /*1d*/, math.MaxUint64} {
		if got, ok := parseUptimeString(FormatUptime(u)); !ok || got != u/100 {
			t.Errorf("FormatUptime(%d) round-trip failed: got=%d ok=%v want=%d", u, got, ok, u/100)
		}
	}
}

// TestGetStats_UptimePercentBounded_AUDIT120: UptimePercent is always a finite
// value in [0,100]. A device reboot (current device uptime below the recorded
// baseline) and a not-yet-reported tracker (lastUptime==0) must both yield 0,
// never a negative number or NaN from the uint64 subtraction.
func TestGetStats_UptimePercentBounded_AUDIT120(t *testing.T) {
	t.Parallel()
	prop := func(lastUptime, startUptime uint64, elapsedSecs uint16) bool {
		// White-box construction: GetStats only reads baseline + lastUptime,
		// never config, so a zero-value tracker with fields set is sufficient.
		ut := &UptimeTracker{
			baseline: &UptimeBaseline{
				// Guarantee the baseline start is strictly in the past so
				// elapsedTime > 0 (the branch that computes a percentage).
				StartTime:   time.Now().Add(-time.Duration(elapsedSecs)*time.Second - time.Second),
				StartUptime: startUptime,
			},
			lastUptime: lastUptime,
		}
		p := ut.GetStats().UptimePercent
		if math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 100 {
			return false
		}
		if lastUptime == 0 && p != 0 {
			return false
		}
		if lastUptime < startUptime && p != 0 { // reboot → underflow guard → 0
			return false
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 5000}); err != nil {
		t.Error(err)
	}
}
