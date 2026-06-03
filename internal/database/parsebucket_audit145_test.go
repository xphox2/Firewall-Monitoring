package database

import (
	"testing"
	"time"
)

// TestParseBucketToMillis_AUDIT145 is the headline regression for
// the audit: pre-fix the function returned 0 (Jan 1 1970 epoch ms)
// for unparseable inputs, and the chart then rendered a literal
// "1970" datapoint. The post-fix behavior:
//
//   - Empty / whitespace input → sentinel -1
//   - Unparseable string (random text) → sentinel -1
//   - All the dialect-supported formats → real UnixMilli value
//
// The consuming code in GetSystemStatusHistory (database.go:~2158)
// filters out rows whose millis == -1, so the API response itself
// never contains a -1 bucket_ms. The test below pins the parser's
// output contract; an end-to-end test of the filter would require
// a real DB fixture (deferred).
func TestParseBucketToMillis_AUDIT145(t *testing.T) {
	// The sentinel is exposed via a getter so the test doesn't
	// need to read the unexported constant. A future agent who
	// changes the sentinel value (e.g. to math.MinInt64) would
	// fail the tests below on the "unparseable" cases anyway, so
	// we don't pin the value here.
	sentinel := BucketMillisUnparseableSentinel()
	if sentinel == 0 {
		t.Fatal("BucketMillisUnparseableSentinel() returned 0; the sentinel must NOT be 0 because 0 is a real UnixMilli value (Jan 1 1970)")
	}

	tests := []struct {
		name       string
		bucket     string
		wantMilli  int64 // use 0 to mean "we expect the sentinel" — see below
		isSentinel bool
	}{
		// Unparseable / empty inputs all return the sentinel.
		{"empty string", "", 0, true},
		{"whitespace only", "   ", 0, true},
		{"random text", "not-a-bucket", 0, true},
		{"ISO with bad month", "2026-13-01", 0, true},
		// All the documented formats parse to a real epoch ms.
		// The expected values are computed via time.Parse so the
		// test doesn't pin a literal hand-computed ms that could
		// drift in a future Go release (the parser changes are
		// rare, but the assertion would be fragile to a future
		// where the format string is interpreted slightly
		// differently). Computing the expected value the same
		// way the production code does is the more durable
		// contract: the function returns time.Parse(...).UnixMilli().
		{"sqlite datetime", "2026-06-02 12:34:56", expectedMilli(t, "2026-06-02 12:34:56", "2006-01-02 15:04:05"), false},
		{"sqlite minute", "2026-06-02 12:34", expectedMilli(t, "2026-06-02 12:34", "2006-01-02 15:04"), false},
		{"postgres ISO 8601 UTC", "2026-06-02T12:34:56Z", expectedMilli(t, "2026-06-02T12:34:56Z", "2006-01-02T15:04:05Z"), false},
		{"postgres ISO 8601 offset", "2026-06-02T05:34:56-07:00", expectedMilli(t, "2026-06-02T05:34:56-07:00", "2006-01-02T15:04:05-07:00"), false},
		{"sqlite date only", "2026-06-02", expectedMilli(t, "2026-06-02", "2006-01-02"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBucketToMillis(tc.bucket)
			if tc.isSentinel {
				if got != sentinel {
					t.Errorf("parseBucketToMillis(%q) = %d, want sentinel %d", tc.bucket, got, sentinel)
				}
				return
			}
			if got == sentinel {
				t.Errorf("parseBucketToMillis(%q) = sentinel, want real epoch ms %d", tc.bucket, tc.wantMilli)
			}
			if got != tc.wantMilli {
				t.Errorf("parseBucketToMillis(%q) = %d, want %d", tc.bucket, got, tc.wantMilli)
			}
			// Sanity: the value is positive (post-epoch) and
			// not the sentinel.
			if got <= 0 {
				t.Errorf("parseBucketToMillis(%q) = %d, must be > 0 for valid post-2000 timestamps", tc.bucket, got)
			}
		})
	}
}

// expectedMilli is a small test helper that uses the same Go
// stdlib parser the production code does. It exists so the test
// doesn't pin hand-computed ms values (which would be fragile to
// a future Go release changing how the format string is
// interpreted, or to a future agent who adjusts the format
// string subtly).
func expectedMilli(t *testing.T, value, format string) int64 {
	t.Helper()
	parsed, err := time.Parse(format, value)
	if err != nil {
		t.Fatalf("expectedMilli: %v (this would indicate a test bug, not a production bug)", err)
	}
	return parsed.UnixMilli()
}

// TestParseBucketToMillis_NeverReturnsZero_AUDIT145 is the
// defense-in-depth test: regardless of input, the function must
// never return 0. Returning 0 for unparseable inputs is exactly
// the bug AUDIT-145 was about (the chart then renders 0 as Jan 1
// 1970). Pinning "never zero" is a stronger guarantee than "always
// real epoch" because a future refactor that returns 0 for some
// new edge case would slip past the format-specific assertions
// above but fail here.
func TestParseBucketToMillis_NeverReturnsZero_AUDIT145(t *testing.T) {
	inputs := []string{
		"", "   ", "not-a-bucket", "2026-13-01",
		// A handful of valid inputs too — these all parse to
		// positive ms, so 0 is impossible.
		"2026-06-02 12:34:56", "2026-06-02 12:34", "2026-06-02",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			got := parseBucketToMillis(in)
			if got == 0 {
				t.Errorf("parseBucketToMillis(%q) returned 0 (Jan 1 1970 epoch ms); this is the AUDIT-145 bug. Return the unparseable sentinel instead.", in)
			}
		})
	}
}
