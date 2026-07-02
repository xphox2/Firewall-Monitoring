package handlers

import (
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

// nocHub is an in-process fan-out broadcaster: a single goroutine recomputes the
// NOC snapshot on a ticker and pushes the marshaled JSON to every subscribed SSE
// connection. One DB computation serves all viewers. Sends are non-blocking — a
// slow client drops a frame rather than stalling the broadcaster.
type nocHub struct {
	db       database.Store
	interval time.Duration

	mu         sync.Mutex
	subs       map[chan []byte]struct{}
	latest     []byte    // most recent marshaled snapshot, sent to new subscribers immediately
	lastErrLog time.Time // throttles the compute-failure log (M10); guarded by mu
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
	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.latest = b
	for ch := range h.subs {
		select {
		case ch <- b:
		default: // subscriber buffer full — drop this frame for that client
		}
	}
	h.mu.Unlock()
}

// subscribe registers a new SSE client and returns its channel plus the latest
// snapshot (may be nil before the first compute) for an immediate first paint.
// The 0→1 subscriber transition computes a fresh snapshot inline (M11): the
// hub idles while nobody watches, so whatever `latest` holds may be minutes or
// hours stale.
func (h *nocHub) subscribe() (chan []byte, []byte) {
	ch := make(chan []byte, 4)
	h.mu.Lock()
	wasIdle := len(h.subs) == 0
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	if wasIdle {
		h.computeAndBroadcast() // fresh first paint; delivered via ch and latest
	}
	h.mu.Lock()
	latest := h.latest
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
// It subscribes to the hub, sends the latest snapshot immediately, then streams
// each new snapshot until the client disconnects (ctx cancelled).
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
	// Clear the server's WriteTimeout for this long-lived connection — otherwise
	// the SSE stream is force-closed after SERVER_WRITE_TIMEOUT (default 30s).
	// Best-effort: if the writer chain doesn't support deadlines the stream still
	// works (it just inherits the 30s cap), so the error is ignored.
	_ = http.NewResponseController(c.Writer).SetWriteDeadline(time.Time{})

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // don't let a reverse proxy buffer SSE
	c.Writer.WriteHeader(http.StatusOK)

	ch, latest := h.nocHub.subscribe()
	defer h.nocHub.unsubscribe(ch)

	writeSSE := func(b []byte) bool {
		if _, err := c.Writer.Write([]byte("data: ")); err != nil {
			return false
		}
		if _, err := c.Writer.Write(b); err != nil {
			return false
		}
		if _, err := c.Writer.Write([]byte("\n\n")); err != nil {
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
			if _, err := c.Writer.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
