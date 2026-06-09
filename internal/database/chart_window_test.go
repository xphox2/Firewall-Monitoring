package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestBucketUnitForWindow pins the adaptive bucket ladder that keeps charts
// readable (and that the drag-to-zoom re-query relies on for finer detail).
func TestBucketUnitForWindow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dur  time.Duration
		want string
	}{
		{30 * time.Minute, "minute"},
		{3 * time.Hour, "minute"},
		{3*time.Hour + time.Second, "5min"},
		{24 * time.Hour, "5min"},
		{30 * time.Hour, "5min"},
		{31 * time.Hour, "hour"},
		{7 * 24 * time.Hour, "hour"},
		{8 * 24 * time.Hour, "hour"},
		{9 * 24 * time.Hour, "6hour"},
		{30 * 24 * time.Hour, "6hour"},
		{60 * 24 * time.Hour, "6hour"},
		{61 * 24 * time.Hour, "day"},
		{365 * 24 * time.Hour, "day"},
	}
	for _, c := range cases {
		if got := bucketUnitForWindow(c.dur); got != c.want {
			t.Errorf("bucketUnitForWindow(%v) = %q, want %q", c.dur, got, c.want)
		}
	}
}

// TestGetInterfaceChartWindow verifies the windowed interface query: it honors
// the [from, to] bounds, populates bucket_ms, and returns rows ordered in time.
func TestGetInterfaceChartWindow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-90 * time.Minute).Truncate(time.Minute)

	// Cumulative octet counters, one sample per minute for 90 minutes.
	for i := 0; i < 90; i++ {
		if err := d.db.Create(&models.InterfaceStats{
			DeviceID: 1, Index: 3, Name: "wan1",
			InBytes:   uint64(i) * 1_000_000,
			OutBytes:  uint64(i) * 500_000,
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		}).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	// Full window: minute buckets (≤3h), one row per populated minute.
	rows, err := d.GetInterfaceChartWindow(1, 3, base.Add(-time.Minute), base.Add(91*time.Minute))
	if err != nil {
		t.Fatalf("GetInterfaceChartWindow full: %v", err)
	}
	if len(rows) < 80 {
		t.Fatalf("full window rows = %d, want ~90", len(rows))
	}
	for i, r := range rows {
		if r.BucketMs <= 0 {
			t.Errorf("row %d: bucket_ms not populated (%d) for bucket %q", i, r.BucketMs, r.Bucket)
		}
		if i > 0 && rows[i].BucketMs < rows[i-1].BucketMs {
			t.Errorf("rows not time-ordered at %d", i)
		}
	}

	// A 20-minute sub-window must return only buckets inside it — this is what
	// the drag-to-zoom re-query does.
	subFrom := base.Add(30 * time.Minute)
	subTo := base.Add(50 * time.Minute)
	sub, err := d.GetInterfaceChartWindow(1, 3, subFrom, subTo)
	if err != nil {
		t.Fatalf("GetInterfaceChartWindow sub: %v", err)
	}
	if len(sub) == 0 || len(sub) > 25 {
		t.Fatalf("sub-window rows = %d, want ~20", len(sub))
	}
	loMs := subFrom.UnixMilli()
	hiMs := subTo.UnixMilli()
	for _, r := range sub {
		// bucket_ms is the minute-truncated bucket; allow the boundary minute.
		if r.BucketMs < loMs-60_000 || r.BucketMs > hiMs+60_000 {
			t.Errorf("sub-window row outside bounds: bucket=%q ms=%d (window %d..%d)", r.Bucket, r.BucketMs, loMs, hiMs)
		}
	}

	// Inverted/empty window returns no rows, no error.
	empty, err := d.GetInterfaceChartWindow(1, 3, subTo, subFrom)
	if err != nil {
		t.Fatalf("inverted window err: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("inverted window rows = %d, want 0", len(empty))
	}
}

// TestGetVPNChartWindow verifies the windowed tunnel delta query populates
// bucket_ms and clamps the window, reusing the AUDIT-043 delta semantics.
func TestGetVPNChartWindow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-10 * time.Minute).Truncate(time.Minute)

	for i, b := range []uint64{100, 200, 350, 500} {
		if err := d.db.Create(&models.VPNStatus{
			DeviceID: 1, TunnelName: "t1",
			BytesIn: b, BytesOut: b / 2, PacketsIn: b / 10, PacketsOut: b / 10,
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		}).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	rows, err := d.GetVPNChartWindow(1, "t1", base.Add(-time.Minute), base.Add(11*time.Minute))
	if err != nil {
		t.Fatalf("GetVPNChartWindow: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("GetVPNChartWindow returned no rows")
	}
	var total float64
	for _, r := range rows {
		if r.BucketMs <= 0 {
			t.Errorf("bucket_ms not populated for %q", r.Bucket)
		}
		total += r.InBytes
	}
	// Deltas: 100->200->350->500 = 100+150+150 = 400 (first sample dropped).
	if total != 400 {
		t.Errorf("windowed delta sum = %v, want 400", total)
	}
}
