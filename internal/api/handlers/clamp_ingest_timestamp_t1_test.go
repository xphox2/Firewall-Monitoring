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
