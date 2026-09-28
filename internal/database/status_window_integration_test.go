//go:build integration

package database

import (
	"testing"
	"time"
)

// The zoom window reader on real PostgreSQL (timestamptz bounds, bucket unit).
func TestPostgresGetSystemStatusBucketsWindow(t *testing.T) {
	d := NewIntegrationDB(t)
	now := time.Now().UTC().Truncate(time.Hour)
	seedStatusSeries(t, d, 901, now.Add(-3*time.Hour), now, time.Minute)
	b, err := d.GetSystemStatusBucketsWindow(901, now.Add(-2*time.Hour), now)
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if len(b) < 115 || len(b) > 121 {
		t.Errorf("a 2 h window gave %d buckets, want ~120 minute buckets", len(b))
	}
	if len(b) > 1 && b[1].BucketMillis-b[0].BucketMillis != 60000 {
		t.Errorf("bucket step %d ms, want 60000", b[1].BucketMillis-b[0].BucketMillis)
	}
}
