package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
)

// flowStreamSlots bounds how many LONG Flows reports run at once in this API
// process (a single process is the whole deployment unless ALLOW_MULTI_API is
// set). Only a LONG report takes a slot (FlowStatsIsLong: materialized and
// longer than a day): it holds one connection for up to a few minutes. The
// default view and short filtered views never take one.
var flowStreamSlots = make(chan struct{}, 2)

// flowStreamKeepalive is how often the stream writes a comment line while no
// event is due; well under the 60 s idle timeout of a default reverse proxy.
var flowStreamKeepalive = 15 * time.Second

// GetFlowStatsStream is GET /flows/stats as a Server-Sent Events stream, so the
// Flows page can show real progress and a long filtered report can finish
// instead of being cut at the synchronous endpoint's 20 s budget.
//
// Events: `progress` {done,total,label,elapsed_ms} before each step (also the
// keepalive); then exactly one of `result` (the synchronous endpoint's JSON
// envelope) or `fail` {message}. Not `error`: EventSource fires its own
// `error` event on a transport failure, and the page must be able to tell a
// server's answer from a dropped connection. The handler returns right after either, so
// the client closes its EventSource instead of reconnecting and re-running the
// report. Every reply is a 200 event stream — including "busy" — so a client
// can always tell a server answer from a transport failure.
func (h *Handler) GetFlowStatsStream(c *gin.Context) {
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		httputil.InternalError(c, "streaming unsupported", nil)
		return
	}
	// A long stream outlives the server's fixed WriteTimeout, so each write arms
	// its own rolling deadline instead (the NOC stream's pattern, noc.go).
	rc := http.NewResponseController(c.Writer)
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)

	// Writes come from this goroutine (events) and the keepalive below, so they
	// are serialized.
	var wmu sync.Mutex
	send := func(event string, v interface{}) bool {
		b, err := json.Marshal(v)
		if err != nil {
			return false
		}
		wmu.Lock()
		defer wmu.Unlock()
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		if _, err := c.Writer.Write([]byte("event: " + event + "\ndata: ")); err != nil {
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
	fail := func(msg string) { send("fail", gin.H{"message": msg}) }

	db := h.reqDB(c)
	if db == nil {
		fail("Database not available")
		return
	}
	hours, filter := parseFlowStatsFilter(c)
	if database.FlowStatsIsLong(hours, filter) {
		select {
		case flowStreamSlots <- struct{}{}:
			defer func() { <-flowStreamSlots }()
		default:
			fail("Another long Flows report is running — try again in a minute.")
			return
		}
	}

	// Keepalive: a report has no time limit, and a stretch with no event —
	// a day split after a statement timeout, a slow raw phase — can pass 60 s,
	// the idle timeout of a default nginx (docs/nginx.conf) or
	// nginx-proxy-manager in front of the console. An SSE comment every 15 s
	// keeps such a proxy from closing the stream, and a failed write notices a
	// client that has stopped reading (net/http then cancels the request).
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(flowStreamKeepalive)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				wmu.Lock()
				_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
				_, err := c.Writer.Write([]byte(": keepalive\n\n"))
				if err == nil {
					flusher.Flush()
				}
				wmu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}()

	start := time.Now()
	stats, err := h.buildFlowStats(db, hours, filter, database.FlowStatsOptions{
		LongRunning: true,
		// Called on this goroutine only (GetFlowStatsOpts' contract), so it may
		// write to the response.
		Progress: func(p database.FlowStatsProgress) {
			send("progress", gin.H{"done": p.Done, "total": p.Total, "label": p.Label,
				"elapsed_ms": time.Since(start).Milliseconds()})
		},
	})
	if err != nil {
		if c.Request.Context().Err() == nil {
			log.Printf("Flow stats stream: %v", err)
		}
		fail("Failed to get flow stats")
		return
	}
	send("result", response.Success(stats))
}
