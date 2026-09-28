package handlers

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// drain returns every frame currently buffered on ch.
func drain(ch chan []byte) [][]byte {
	var out [][]byte
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

func feedFrames(frames [][]byte) int {
	n := 0
	for _, f := range frames {
		if bytes.HasPrefix(f, []byte("event: feed\n")) {
			n++
		}
	}
	return n
}

// The snapshot stays the default (unnamed) SSE event every tick, so the page's
// onmessage handler keeps working, and never carries the feed. The feed is a
// named event, re-sent only when its lists change or every
// nocFeedRefreshTicks, and replayed to a new subscriber.
func TestNOCHub_FeedIsSeparateAndSentOnChange(t *testing.T) {
	_, db := setupTestHandler(t)
	hub := newNOCHub(db, time.Hour)

	ch, latest := hub.subscribe() // 0->1 computes once
	defer hub.unsubscribe(ch)
	if !bytes.Contains(latest, []byte("event: feed\n")) || !bytes.HasPrefix(latest, []byte("data: ")) {
		t.Fatalf("new subscriber replay must be the snapshot then the feed; got %.120q", latest)
	}
	first := drain(ch)
	if len(first) != 2 || feedFrames(first) != 1 {
		t.Fatalf("first broadcast: %d frames (%d feed), want snapshot + feed", len(first), feedFrames(first))
	}
	if !bytes.HasPrefix(first[0], []byte("data: ")) || bytes.Contains(first[0], []byte(`"feed"`)) {
		t.Errorf("snapshot frame must be an unnamed event without the feed: %.200q", first[0])
	}

	// Unchanged data: the snapshot goes out every tick, the feed does not —
	// until the periodic refresh.
	for tick := 2; tick <= nocFeedRefreshTicks; tick++ {
		hub.computeAndBroadcast()
		frames := drain(ch)
		wantFeed := 0
		if tick%nocFeedRefreshTicks == 0 {
			wantFeed = 1
		}
		if len(frames) != 1+wantFeed || feedFrames(frames) != wantFeed {
			t.Fatalf("tick %d: %d frames, %d feed; want snapshot + %d feed", tick, len(frames), feedFrames(frames), wantFeed)
		}
	}

	// A new alert changes the lists: the feed goes out on the next tick.
	seedAlertForHub(t, db)
	hub.computeAndBroadcast()
	frames := drain(ch)
	if feedFrames(frames) != 1 {
		t.Fatalf("a changed feed was not sent (%d frames)", len(frames))
	}
	if !strings.Contains(string(frames[len(frames)-1]), `"generated_at"`) {
		t.Error("the feed frame must carry generated_at")
	}
}

func seedAlertForHub(t *testing.T, db *database.Database) {
	t.Helper()
	a := models.Alert{Timestamp: time.Now().UTC(), DeviceID: 1, AlertType: "INTERFACE_DOWN",
		Severity: models.SeverityCritical, Message: "port1 down"}
	if err := db.Gorm().Create(&a).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}
}

// The one-shot snapshot (the no-EventSource fallback) keeps the feed inline.
func TestGetNOCSnapshot_OneShotIncludesFeed(t *testing.T) {
	h, _ := setupTestHandler(t)
	router := gin.New()
	router.GET("/noc/snapshot", h.GetNOCSnapshot)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/noc/snapshot", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"feed":{`) || !strings.Contains(w.Body.String(), `"threat_top":{`) {
		t.Errorf("one-shot snapshot must carry feed and threat_top: %d %.300s", w.Code, w.Body.String())
	}
}
