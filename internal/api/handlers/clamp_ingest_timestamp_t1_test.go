package handlers

import (
	"testing"
	"time"
)

// TestClampIngestTimestamp is the AUDIT T1 regression: collector-supplied
// timestamps must be bounded so a future value can't become a permanent
// MAX(timestamp) "latest", suppress telemetry-stale detection, escape
// retention, or land outside every partition.
func TestClampIngestTimestamp(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{"zero → now", time.Time{}, now},
		{"far future → now", now.Add(400 * 24 * time.Hour), now},
		{"one second future → now", now.Add(time.Second), now},
		{"past preserved", now.Add(-2 * time.Hour), now.Add(-2 * time.Hour)},
		{"exactly now preserved", now, now},
		// AUDIT-204 review fix: the collector's generic BSD syslog parser
		// emits YEAR-0 timestamps (the layout has no year field); a stored
		// ancient row used to stretch the aggregation window walk across
		// millennia. Implausibly ancient → now; a deep-but-real outage
		// spool (days old) stays preserved.
		{"year-0 (BSD parser, no year) → now", time.Date(0, 8, 28, 20, 31, 12, 0, time.UTC), now},
		{"epoch 1970 → now", time.Unix(0, 0).UTC(), now},
		{"year 1999 → now", time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC), now},
		{"deep spool (30 days) preserved", now.Add(-30 * 24 * time.Hour), now.Add(-30 * 24 * time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clampIngestTimestamp(tc.in, now)
			if !got.Equal(tc.want) {
				t.Fatalf("clampIngestTimestamp(%v, %v) = %v, want %v", tc.in, now, got, tc.want)
			}
		})
	}
}
