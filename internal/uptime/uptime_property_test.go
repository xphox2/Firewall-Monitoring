package uptime

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"firewall-mon/internal/models"
)

// AUDIT-120: property-based tests for the uptime math, using stdlib
// testing/quick. They assert invariants that must hold for every input rather
// than spot-checking examples: the FormatUptime round-trip, and the
// UptimePercent clamp in ComputeStats (AUDIT-318 read-time availability).

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

// TestComputeStats_UptimePercentBounded_AUDIT120: for ANY per-device sysUpTime
// series (including reboots, where the counter drops), ComputeStats yields a
// finite UptimePercent in [0,100] — never negative, never NaN/Inf from the
// downtime subtraction. Rows are built with strictly increasing timestamps
// (30s apart) so elapsed > 0.
func TestComputeStats_UptimePercentBounded_AUDIT120(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prop := func(uptimes []uint64) bool {
		if len(uptimes) == 0 {
			return true // empty series is a valid zero-value case
		}
		rows := make([]models.SystemStatus, len(uptimes))
		for i, u := range uptimes {
			rows[i] = models.SystemStatus{
				Timestamp: base.Add(time.Duration(i) * 30 * time.Second),
				Uptime:    u,
			}
		}
		p := ComputeStats(rows, rows[0].Timestamp).UptimePercent
		return !math.IsNaN(p) && !math.IsInf(p, 0) && p >= 0 && p <= 100
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 5000}); err != nil {
		t.Error(err)
	}
}
