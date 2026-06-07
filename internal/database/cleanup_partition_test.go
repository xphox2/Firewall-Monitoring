package database

import (
	"testing"
	"time"
)

// TestParsePartitionUpperBound covers the partition-bound rendering formats
// Postgres actually produces. The bug fixed in v0.10.387: a timestamp-typed
// partition key renders its bound WITH a time component (and maybe a timezone),
// so the original date-only parse failed and dropPartitionsOlderThan never
// dropped any partition. These cases pin the tolerant parsing.
func TestParsePartitionUpperBound(t *testing.T) {
	want := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		bound string
		ok    bool
	}{
		{"date only", "FOR VALUES FROM ('2026-01-01') TO ('2026-02-01')", true},
		{"timestamp", "FOR VALUES FROM ('2026-01-01 00:00:00') TO ('2026-02-01 00:00:00')", true},
		{"timestamptz +00", "FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00')", true},
		{"timestamptz +00:00", "FOR VALUES FROM ('2026-01-01 00:00:00+00:00') TO ('2026-02-01 00:00:00+00:00')", true},
		{"default partition", "DEFAULT", false},
		{"no TO marker", "FOR VALUES IN ('x')", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parsePartitionUpperBound(c.bound)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (bound=%q)", ok, c.ok, c.bound)
			}
			if c.ok && !got.Equal(want) {
				t.Fatalf("upper = %s, want %s (bound=%q)", got, want, c.bound)
			}
		})
	}
}

// TestParsePartitionUpperBound_DropDecision confirms the timestamp-rendered
// bound now yields the correct keep/drop decision (the integration symptom:
// an old partition that "was not dropped").
func TestParsePartitionUpperBound_DropDecision(t *testing.T) {
	cutoff := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	old := "FOR VALUES FROM ('2000-01-01 00:00:00') TO ('2000-02-01 00:00:00')"
	cur := "FOR VALUES FROM ('2026-06-01 00:00:00') TO ('2026-07-01 00:00:00')"

	up, ok := parsePartitionUpperBound(old)
	if !ok || up.After(cutoff) {
		t.Fatalf("old partition should parse and be droppable (upper=%s ok=%v)", up, ok)
	}
	up, ok = parsePartitionUpperBound(cur)
	if !ok || !up.After(cutoff) {
		t.Fatalf("current partition should parse and be kept (upper=%s ok=%v)", up, ok)
	}
}
