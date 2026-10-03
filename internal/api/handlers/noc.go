package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
)

// nocSnapshotInterval is how often the broadcaster recomputes the NOC snapshot
// and pushes it to every connected dashboard. The underlying flow data refreshes
// each collector batch (~30s), so a few-second cadence keeps detections/threat
// counts feeling live without hammering the DB.
const nocSnapshotInterval = 5 * time.Second

// nocWindow is the trailing window the snapshot aggregates over (so throughput
// reflects "now", not an hourly average).
const nocWindow = 5 * time.Minute

// sseWriteTimeout bounds a single SSE flush. Armed before every write on the
// stream as a rolling deadline so an unresponsive client (stalled TCP window)
// can't pin the handler goroutine in a blocked Write forever (audit L5). A
// healthy reader resets it on each snapshot/keepalive, so it never truncates a
// live stream — it only fires when a write genuinely can't make progress.
const sseWriteTimeout = 15 * time.Second

// nocFeedRefreshTicks re-sends an unchanged live feed every Nth tick (60 s at
// the 5 s cadence). Sends are non-blocking, so a slow client can drop a feed
// frame; the feed otherwise changes only every few minutes, and this bounds how
// long such a client shows a stale one.
const nocFeedRefreshTicks = 12

// nocHub is an in-process fan-out broadcaster: a single goroutine recomputes the
// NOC snapshot on a ticker and pushes it to every subscribed SSE connection. One
// DB computation serves all viewers. Sends are non-blocking — a slow client
// drops a frame rather than stalling the broadcaster.
//
// The channels carry complete SSE frames. The snapshot is the default (unnamed)
// event, every tick. The live feed (v0.11.269) is a named "feed" event, sent
// only when its lists change or every nocFeedRefreshTicks: it is several times
// the size of the snapshot and changes on the 5-minute detector cycle.
type nocHub struct {
	db       database.Store
	interval time.Duration

	mu             sync.Mutex
	subs           map[chan []byte]struct{}
	latestSnapshot []byte    // last snapshot frame, replayed to new subscribers
	latestFeed     []byte    // last feed frame (current generated_at), replayed to new subscribers
	lastFeedLists  []byte    // the last BROADCAST feed's lists, for change detection
	ticks          int       // broadcasts since start, for the periodic feed refresh
	lastErrLog     time.Time // throttles the compute-failure log (M10); guarded by mu
}

func newNOCHub(db database.Store, interval time.Duration) *nocHub {
	return &nocHub{
		db:       db,
		interval: interval,
		subs:     make(map[chan []byte]struct{}),
	}
}

// Run computes and broadcasts a snapshot every interval until ctx is cancelled.
// Started once in a background goroutine (cmd/api).
//
// M11 of the 2026-07-01 audit: ticks compute ONLY while someone is subscribed.
// Pre-fix the hub ran its ~15 aggregate queries (including two COUNT(DISTINCT)
// over the 5-minute flow window) every 5 seconds, 24/7, whether or not any NOC
// page was open — and every ALLOW_MULTI_API follower duplicated the full load
// against the shared prod Postgres. Subscriber gating fixes both at once (an
// idle follower computes nothing) without breaking follower SSE the way
// primary-gating the hub would; the first subscriber gets a fresh snapshot via
// the compute in subscribe().
func (h *nocHub) Run(ctx context.Context) {
	if h == nil || h.db == nil {
		return
	}
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.mu.Lock()
			hasSubs := len(h.subs) > 0
			h.mu.Unlock()
			if hasSubs {
				h.computeAndBroadcast()
			}
		}
	}
}

func (h *nocHub) computeAndBroadcast() {
	snap, err := h.db.GetNOCSnapshot(nocWindow)
	if err != nil {
		// M10: keep the last good snapshot rather than blanking the dashboard —
		// and say so (rate-limited): pre-fix the snapshot function returned
		// fake nils, so this branch was dead code and DB failures broadcast
		// all-zero dashboards labeled "live" with no trace anywhere.
		h.mu.Lock()
		if time.Since(h.lastErrLog) >= time.Minute {
			h.lastErrLog = time.Now()
			log.Printf("noc-broadcaster: snapshot failed (viewers keep the last good frame): %v", err)
		}
		h.mu.Unlock()
		return
	}
	// The feed travels separately; the snapshot frame never carries it.
	feed := snap.Feed
	snap.Feed = nil
	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	frames := [][]byte{sseFrame("", b)}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.latestSnapshot = frames[0]
	h.ticks++
	if feed != nil {
		// Compare the lists only: the snapshot stamps generated_at every tick,
		// so it is cleared for the comparison and set again afterwards.
		feed.GeneratedAt = time.Time{}
		lists, lerr := json.Marshal(feed)
		feed.GeneratedAt = snap.GeneratedAt
		full, ferr := json.Marshal(feed)
		if lerr == nil && ferr == nil {
			h.latestFeed = sseFrame("feed", full)
			if !bytes.Equal(lists, h.lastFeedLists) || h.ticks%nocFeedRefreshTicks == 0 {
				h.lastFeedLists = lists
				frames = append(frames, h.latestFeed)
			}
		}
	}
	for ch := range h.subs {
		for _, f := range frames {
			select {
			case ch <- f:
			default: // subscriber buffer full — drop this frame for that client
			}
		}
	}
}

// sseFrame renders one Server-Sent Events frame; event "" is the default event.
func sseFrame(event string, data []byte) []byte {
	var b bytes.Buffer
	if event != "" {
		b.WriteString("event: ")
		b.WriteString(event)
		b.WriteByte('\n')
	}
	b.WriteString("data: ")
	b.Write(data)
	b.WriteString("\n\n")
	return b.Bytes()
}

// subscribe registers a new SSE client and returns its channel plus the latest
// frames — the snapshot, then the live feed — (nil before the first compute)
// for an immediate first paint.
// The 0→1 subscriber transition computes a fresh snapshot inline (M11): the
// hub idles while nobody watches, so whatever `latest` holds may be minutes or
// hours stale. The channel is registered only after that compute: registered
// before it, the first subscriber received the fresh snapshot and feed on the
// channel AND in `latest`, and painted them twice.
func (h *nocHub) subscribe() (chan []byte, []byte) {
	ch := make(chan []byte, 8) // a tick can carry two frames (snapshot + feed)
	h.mu.Lock()
	wasIdle := len(h.subs) == 0
	if !wasIdle {
		h.subs[ch] = struct{}{}
	}
	h.mu.Unlock()
	if wasIdle {
		h.computeAndBroadcast() // fresh first paint; delivered via latest
	}
	h.mu.Lock()
	if wasIdle {
		h.subs[ch] = struct{}{}
	}
	var latest []byte
	if h.latestSnapshot != nil {
		latest = append(append(latest, h.latestSnapshot...), h.latestFeed...)
	}
	h.mu.Unlock()
	return ch, latest
}

func (h *nocHub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// GetNOCSnapshot serves a one-shot snapshot (no streaming) — a fallback for
// clients without EventSource and the initial paint if the stream is slow.
func (h *Handler) GetNOCSnapshot(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	// site_id / device_id narrow the snapshot for the NOC drill-down panel.
	var filter database.NOCFilter
	if sid := c.Query("site_id"); sid != "" {
		if v, err := strconv.ParseUint(sid, 10, 32); err == nil {
			id := uint(v)
			filter.SiteID = &id
		}
	}
	if did := c.Query("device_id"); did != "" {
		if v, err := strconv.ParseUint(did, 10, 32); err == nil {
			id := uint(v)
			filter.DeviceID = &id
		}
	}
	snap, err := db.GetNOCSnapshotFiltered(nocWindow, filter)
	if err != nil {
		httputil.InternalError(c, "Failed to build NOC snapshot", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(snap))
}

// GetNOCStream is the Server-Sent Events endpoint feeding the live NOC dashboard.
// Authenticated by the admin cookie (EventSource sends cookies automatically).
// It subscribes to the hub, sends the latest snapshot and feed immediately, then
// streams each new frame until the client disconnects (ctx cancelled).
func (h *Handler) GetNOCStream(c *gin.Context) {
	if h.nocHub == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("NOC stream unavailable"))
		return
	}
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		httputil.InternalError(c, "streaming unsupported", nil)
		return
	}
	// This is a long-lived stream, so the server's fixed WriteTimeout (default
	// 30s) must not force-close it — but clearing the deadline outright let a
	// client that stops reading (zero TCP window) pin this handler goroutine in a
	// blocked Write forever, since there was then no deadline to unblock it
	// (audit L5). Instead each write below arms a fresh rolling deadline via rc:
	// a healthy reader keeps resetting it, while a stuck write eventually errors
	// out so the handler returns and unsubscribes.
	rc := http.NewResponseController(c.Writer)

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // don't let a reverse proxy buffer SSE
	c.Writer.WriteHeader(http.StatusOK)

	ch, latest := h.nocHub.subscribe()
	defer h.nocHub.unsubscribe(ch)

	// writeSSE writes complete SSE frames (the hub formats them).
	writeSSE := func(b []byte) bool {
		// Rolling per-write deadline (audit L5): bound how long a single flush can
		// block on an unresponsive client. Best-effort — if the writer chain has no
		// deadline support this is a no-op and the write behaves as before.
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		if _, err := c.Writer.Write(b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if latest != nil && !writeSSE(latest) {
		return
	}
	flusher.Flush()

	ctx := c.Request.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case b, ok := <-ch:
			if !ok || !writeSSE(b) {
				return
			}
		case <-keepalive.C:
			// SSE comment line keeps idle proxies/load-balancers from closing the conn.
			_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
			if _, err := c.Writer.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
