//go:build integration

package database

import (
	"testing"
	"time"
)

// The feed's episode query (window functions, MinutesBetween) and the threat
// classification (bitwise flags, CASE ladders) on real PostgreSQL.
func TestPostgresNOCFeedAndThreats(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)

	t0 := now.Add(-2 * time.Hour)
	for i := 0; i < 3; i++ {
		seedDetection(t, d, "pg-scan", t0.Add(time.Duration(i)*5*time.Minute), false, nil)
	}
	seedDetection(t, d, "pg-scan", now.Add(-30*time.Minute), false, nil)
	seedDetection(t, d, "pg-silenced", now.Add(-10*time.Minute), true, nil)
	for _, k := range []string{"pg-c", "pg-a", "pg-b"} {
		seedDetection(t, d, k, now.Add(-20*time.Minute), false, nil)
	}
	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	var keys []string
	scanEpisodes := 0
	for _, it := range feed.Detections {
		keys = append(keys, it.DedupKey)
		if it.DedupKey == "pg-scan" {
			scanEpisodes++
		}
	}
	if scanEpisodes != 2 {
		t.Errorf("pg-scan episodes = %d, want 2: %v", scanEpisodes, keys)
	}
	want := []string{"pg-a", "pg-b", "pg-c", "pg-scan", "pg-scan"} // -20m (tied, by key), -30m, -2h
	for i := range want {
		if i >= len(keys) || keys[i] != want[i] {
			t.Fatalf("order = %v, want %v", keys, want)
		}
	}
	if len(feed.Silenced) != 1 || feed.SilencedTotal != 1 {
		t.Errorf("silenced = %d (total %d), want 1", len(feed.Silenced), feed.SilencedTotal)
	}

	seedThreatRows(t, d, now,
		threatRow{dir: 1, src: bad, sport: 51000, dst: ours, dport: 22, flag: 1, age: 10 * time.Second},
		threatRow{dir: 2, src: ours, sport: 22, dst: bad, dport: 51000, flag: 2, age: 10 * time.Second},
		threatRow{dir: 2, src: "10.0.0.7", sport: 50000, dst: bad2, dport: 443, flag: 2, age: 5 * time.Second},
		threatRow{dir: 1, src: bad, sport: 443, dst: ours, dport: 51234, flag: 1, tcp: 2, age: time.Second},
		threatRow{dir: 1, src: "192.0.2.4", sport: 53, dst: ours, dport: 445, flag: 5, age: time.Second},
	)
	top, err := d.getNOCThreatTop()
	if err != nil {
		t.Fatalf("getNOCThreatTop: %v", err)
	}
	if e := findEntry(top.Inbound, bad); e == nil || e.Requests != 2 || !e.IPMatch {
		t.Errorf("inbound %s = %+v, want 2 requests (SSH + SYN), IP match", bad, e)
	}
	if e := findEntry(top.Outbound, bad2); e == nil || e.Requests != 1 || len(e.InternalHosts) != 1 {
		t.Errorf("outbound %s = %+v, want 1 request from one internal host", bad2, e)
	}
	if e := findEntry(top.Inbound, "192.0.2.4"); e == nil || !e.Inferred || e.Service != 445 {
		t.Errorf("both-known 53->445 = %+v, want inbound, inferred, service 445", e)
	}
	if top.Summary.Inbound != 3 || top.Summary.Outbound != 1 {
		t.Errorf("summary = %+v, want inbound 3, outbound 1", top.Summary)
	}
}
