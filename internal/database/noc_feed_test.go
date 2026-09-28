package database

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// feedClock pins nocNow for a test.
func feedClock(t *testing.T, now time.Time) {
	t.Helper()
	old := nocNow
	nocNow = func() time.Time { return now }
	t.Cleanup(func() { nocNow = old })
}

func seedDetection(t *testing.T, d *Database, key string, at time.Time, acked bool, alertID *uint) models.FlowDetection {
	t.Helper()
	det := models.FlowDetection{
		DetectedAt: at.UTC(), Detector: "port_scan", Category: "security", Severity: "warning",
		DeviceID: 1, SrcAddr: "203.0.113.9", DstAddr: "10.0.0.5", DstPort: 22,
		Message: "scan " + key, DedupKey: key, Acknowledged: acked, AlertID: alertID,
	}
	if err := d.db.Create(&det).Error; err != nil {
		t.Fatalf("seed detection: %v", err)
	}
	return det
}

func seedAlert(t *testing.T, d *Database, at time.Time, suppressed bool) models.Alert {
	t.Helper()
	a := models.Alert{Timestamp: at, DeviceID: 1, AlertType: "INTERFACE_DOWN", Severity: models.SeverityCritical,
		Message: "port1 down", Suppressed: suppressed}
	if err := d.db.Create(&a).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return a
}

func seedFeedDevice(t *testing.T, d *Database) {
	t.Helper()
	site := models.Site{Name: "HQ"}
	if err := d.db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	dev := models.Device{Name: "FW-HQ", IPAddress: "10.9.0.1", SiteID: &site.ID}
	if err := d.db.Create(&dev).Error; err != nil || dev.ID != 1 {
		t.Fatalf("seed device: %v (id %d)", err, dev.ID)
	}
}

// Detections outnumber alerts ~100:1 in production. Each kind is capped on its
// own, so no number of detections can push an alert out of the payload.
func TestNOCFeed_PerKindCapKeepsEveryAlert(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	for i := 0; i < 150; i++ {
		seedDetection(t, d, fmt.Sprintf("k%03d", i), now.Add(-time.Duration(10+i)*time.Minute), false, nil)
	}
	for i := 0; i < 5; i++ {
		seedAlert(t, d, now.Add(-time.Duration(3+i)*time.Hour), false)
	}
	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	if len(feed.Alerts) != 5 {
		t.Errorf("alerts = %d, want all 5", len(feed.Alerts))
	}
	if len(feed.Detections) != nocFeedDetectionLimit {
		t.Errorf("detections = %d, want the cap %d", len(feed.Detections), nocFeedDetectionLimit)
	}
	// The newest episodes survive the cap.
	if feed.Detections[0].DedupKey != "k000" {
		t.Errorf("first detection = %s, want the newest (k000)", feed.Detections[0].DedupKey)
	}
}

func TestNOCFeed_AlertsNewestUnsuppressedWithinWeek(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFeedDevice(t, d)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	for i := 0; i < 105; i++ {
		seedAlert(t, d, now.Add(-time.Duration(i+1)*time.Minute), false)
	}
	sup := seedAlert(t, d, now.Add(-30*time.Second), true)
	old := seedAlert(t, d, now.Add(-8*24*time.Hour), false)
	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	if len(feed.Alerts) != nocFeedAlertLimit {
		t.Fatalf("alerts = %d, want %d", len(feed.Alerts), nocFeedAlertLimit)
	}
	for _, a := range feed.Alerts {
		if a.ID == sup.ID {
			t.Error("a suppressed alert is in the feed")
		}
		if a.ID == old.ID {
			t.Error("an alert older than 7 days is in the feed")
		}
	}
	if !feed.Alerts[0].At.Equal(now.Add(-time.Minute)) {
		t.Errorf("first alert at %v, want the newest", feed.Alerts[0].At)
	}
	if feed.Alerts[0].DeviceName != "FW-HQ" || feed.Alerts[0].SiteName != "HQ" {
		t.Errorf("alert names = %q / %q, want FW-HQ / HQ", feed.Alerts[0].DeviceName, feed.Alerts[0].SiteName)
	}
	if feed.Alerts[0].Repeat != 1 {
		t.Errorf("alert repeat = %d, want escalation_count+1 = 1", feed.Alerts[0].Repeat)
	}
}

// Alerted detections live on the Alerts page; acknowledged (silenced) ones are
// only in the silenced list, which the browser hides by default.
func TestNOCFeed_AlertedExcludedAckedOnlySilenced(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFeedDevice(t, d)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	alertID := uint(77)
	seedDetection(t, d, "alerted", now.Add(-10*time.Minute), false, &alertID)
	seedDetection(t, d, "silenced", now.Add(-10*time.Minute), true, nil)
	seedDetection(t, d, "live", now.Add(-10*time.Minute), false, nil)
	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	if len(feed.Detections) != 1 || feed.Detections[0].DedupKey != "live" {
		t.Errorf("detections = %+v, want only 'live'", feed.Detections)
	}
	if len(feed.Silenced) != 1 || feed.Silenced[0].DedupKey != "silenced" || feed.SilencedTotal != 1 {
		t.Errorf("silenced = %+v (total %d), want only 'silenced'", feed.Silenced, feed.SilencedTotal)
	}
	if feed.Detections[0].DeviceName != "FW-HQ" {
		t.Errorf("detection device name = %q", feed.Detections[0].DeviceName)
	}
}

// The detector re-inserts an active finding every 5 minutes. Consecutive rows
// are one episode; a gap longer than two cycles starts a new one.
func TestNOCFeed_EpisodesCollapseAndSplitOnGap(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	t0 := now.Add(-2 * time.Hour)
	var newest models.FlowDetection
	for i := 0; i < 3; i++ {
		newest = seedDetection(t, d, "scan", t0.Add(time.Duration(i)*5*time.Minute), false, nil)
	}
	resumed := now.Add(-30 * time.Minute) // 80 minutes after the first run ended
	seedDetection(t, d, "scan", resumed, false, nil)

	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	if len(feed.Detections) != 2 {
		t.Fatalf("episodes = %d, want 2 (the gap splits them)", len(feed.Detections))
	}
	latest, first := feed.Detections[0], feed.Detections[1]
	if !latest.At.Equal(resumed) || latest.Repeat != 1 {
		t.Errorf("resumed episode at=%v repeat=%d, want at=%v repeat=1", latest.At, latest.Repeat, resumed)
	}
	if !first.At.Equal(t0) || first.Repeat != 3 || first.ID != newest.ID || !first.LastSeen.Equal(newest.DetectedAt) {
		t.Errorf("first episode = %+v, want at=%v repeat=3 id=%d", first, t0, newest.ID)
	}
	if first.Truncated || latest.Truncated {
		t.Error("episodes well inside the window must not be truncated")
	}
}

// The poller inserts a finding un-acknowledged, then silences it in the same
// cycle. A detection is held back from the live list until the grace passes.
func TestNOCFeed_FreshDetectionHeldBackForGrace(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	seedDetection(t, d, "fresh", now.Add(-30*time.Second), false, nil)
	seedDetection(t, d, "settled", now.Add(-100*time.Second), false, nil)
	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	if len(feed.Detections) != 1 || feed.Detections[0].DedupKey != "settled" {
		t.Errorf("detections = %+v, want only the one older than the grace", feed.Detections)
	}
}

// An episode already running when the window began is flagged, so the browser
// keys it stably while its oldest rows age out of the window.
func TestNOCFeed_EpisodeAtWindowStartIsTruncated(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	start := now.Add(-nocFeedDetectionWindow)
	for i := 0; i < 4; i++ {
		seedDetection(t, d, "edge", start.Add(2*time.Minute+time.Duration(i)*5*time.Minute), false, nil)
	}
	seedDetection(t, d, "inner", start.Add(30*time.Minute), false, nil)

	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	got := map[string]bool{}
	for _, it := range feed.Detections {
		got[it.DedupKey] = it.Truncated
	}
	if !got["edge"] {
		t.Error("an episode starting within one gap of the window start must be truncated")
	}
	if got["inner"] {
		t.Error("an episode starting well inside the window must not be truncated")
	}
}

// Every finding of a detector cycle shares one timestamp, so the order needs a
// tiebreak or the feed's bytes would change between identical frames.
func TestNOCFeed_TiedEpisodesOrderByKey(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	at := now.Add(-10 * time.Minute)
	for _, k := range []string{"c", "a", "d", "b"} {
		seedDetection(t, d, k, at, false, nil)
	}
	for run := 0; run < 3; run++ {
		feed, err := d.GetNOCFeed()
		if err != nil {
			t.Fatalf("GetNOCFeed: %v", err)
		}
		var keys string
		for _, it := range feed.Detections {
			keys += it.DedupKey
		}
		if keys != "abcd" {
			t.Fatalf("run %d: order %q, want abcd", run, keys)
		}
	}
}

// Row ids need not follow detection time (a replayed or back-filled batch is
// inserted out of order), so an episode's first and newest rows are chosen by
// time.
func TestNOCFeed_EpisodeBoundsByTimeNotID(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	var rows []models.FlowDetection
	for m := 5; m <= 60; m += 5 { // newest first: ids run backwards in time
		rows = append(rows, seedDetection(t, d, "scan", now.Add(-time.Duration(m)*time.Minute), false, nil))
	}
	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	if len(feed.Detections) != 1 {
		t.Fatalf("episodes = %d, want 1", len(feed.Detections))
	}
	it := feed.Detections[0]
	if !it.At.Equal(now.Add(-60*time.Minute)) || !it.LastSeen.Equal(now.Add(-5*time.Minute)) || it.ID != rows[0].ID || it.Repeat != 12 {
		t.Errorf("episode = at %v last_seen %v id %d repeat %d; want at -60m, last_seen -5m, id %d (the newest row), repeat 12",
			it.At, it.LastSeen, it.ID, it.Repeat, rows[0].ID)
	}
}

// The detection lists are reused for nocDetectionCacheTTL, then recomputed.
func TestNOCFeed_DetectionListsCachedForTTL(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedFeedDevice(t, d) // so enrichment writes names into the items
	d.nocDetCache = newNOCDetCache()
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	seedDetection(t, d, "first", now.Add(-10*time.Minute), false, nil)
	if feed, err := d.GetNOCFeed(); err != nil || len(feed.Detections) != 1 {
		t.Fatalf("initial feed: %v %+v", err, feed)
	}
	seedDetection(t, d, "second", now.Add(-5*time.Minute), false, nil)
	seedAlert(t, d, now.Add(-time.Minute), false)

	feedClock(t, now.Add(30*time.Second))
	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	if len(feed.Detections) != 1 {
		t.Errorf("within the TTL the cached detection list must be reused; got %d", len(feed.Detections))
	}
	if len(feed.Alerts) != 1 {
		t.Errorf("alerts are live every tick; got %d", len(feed.Alerts))
	}

	feedClock(t, now.Add(nocDetectionCacheTTL+time.Second))
	if feed, err = d.GetNOCFeed(); err != nil || len(feed.Detections) != 2 {
		t.Errorf("after the TTL the list must be recomputed: %v, %d detections", err, len(feed.Detections))
	}
	// The hub and the one-shot endpoint read the cache concurrently and each
	// enriches its copy in place; the race detector flags a shared slice.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.GetNOCFeed(); err != nil {
				t.Errorf("concurrent GetNOCFeed: %v", err)
			}
		}()
	}
	wg.Wait()
}

// The 7-day bound on alerts, separately from the 100-row cap.
func TestNOCFeed_AlertsOlderThanAWeekExcluded(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	feedClock(t, now)
	seedAlert(t, d, now.Add(-time.Hour), false)
	old := seedAlert(t, d, now.Add(-8*24*time.Hour), false)
	feed, err := d.GetNOCFeed()
	if err != nil {
		t.Fatalf("GetNOCFeed: %v", err)
	}
	if len(feed.Alerts) != 1 || feed.Alerts[0].ID == old.ID {
		t.Errorf("alerts = %+v, want only the one inside 7 days", feed.Alerts)
	}
}
