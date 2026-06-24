// Package metrics exposes the API server's runtime in the Prometheus exposition
// format (AUDIT-077). Before this, the server had no /metrics endpoint and no
// way to alert on request latency, error rate, or DB connection-pool exhaustion
// from outside the log stream.
//
// Scope: this covers the **API server process** — HTTP request latency (by
// route/method/status), the database/sql connection pool, and the standard Go
// runtime + process collectors. The poller-process counters the audit also
// named (poll_cycles_total, alerts_fired_total, batcher_queue_depth) live in a
// different binary that does not serve HTTP, so they need the poller to expose
// its own /metrics — tracked as deferred follow-up work, not wired here.
package metrics

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// httpRequestDuration is the headline metric: a histogram of request latency
// labelled by the **matched route template** (not the raw path), method, and
// status code. Using the template keeps cardinality bounded — `/admin/api/
// devices/:id` is one series, not one per device id. Its `_count` child doubles
// as the total request counter, so no separate counter is needed.
var httpRequestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "fwmon",
		Subsystem: "http",
		Name:      "request_duration_seconds",
		Help:      "Latency of HTTP requests handled by the API server, by route/method/status.",
		Buckets:   prometheus.DefBuckets,
	},
	[]string{"method", "route", "status"},
)

func init() {
	// Registered on the default registry, which client_golang seeds with the Go
	// runtime + process collectors — so /metrics carries goroutines, GC, heap,
	// open FDs, and CPU for free alongside the HTTP histogram.
	prometheus.MustRegister(httpRequestDuration)
}

// Middleware records the duration of every HTTP request. Register it once,
// globally, after the request-ID/logger middleware.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			// No route matched (404). Bucket these under a single label rather
			// than emitting one series per junk path a scanner might probe.
			route = "unmatched"
		}
		httpRequestDuration.
			WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).
			Observe(time.Since(start).Seconds())
	}
}

// RegisterDBPool exposes database/sql connection-pool gauges (open / in-use /
// idle connections, wait count, wait duration, and the close counters) for the
// given pool. No-op if db is nil; idempotent — a duplicate registration is
// swallowed rather than panicking, so callers don't have to guard re-entry.
//
// A non-duplicate registration error (name collision with a different
// collector, registry corruption) is logged and skipped rather than panicking:
// /metrics is observability, and losing one pool's gauges must never take down
// the API process that the gauges exist to monitor.
func RegisterDBPool(db *sql.DB, name string) {
	if db == nil {
		return
	}
	c := collectors.NewDBStatsCollector(db, name)
	if err := prometheus.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if !errors.As(err, &already) {
			slog.Warn("metrics: failed to register DB pool collector; pool gauges unavailable",
				"pool", name, "error", err)
		}
	}
}

// Handler serves the Prometheus exposition for the default registry (the HTTP
// histogram + Go runtime + process + any registered DB pools).
//
// Per the audit, this endpoint is intentionally **unauthenticated** — the
// Prometheus convention is to protect /metrics at the network layer (bind to an
// internal interface or firewall the scrape port). It exposes no secrets, only
// aggregate timings/counters and route *templates*.
func Handler() http.Handler {
	return promhttp.Handler()
}

// StartObservabilityServer stands up a lightweight HTTP server exposing
// /metrics (Prometheus, incl. the Go runtime/process collectors), /healthz
// (liveness — 200 while the process is up), and /readyz (readiness via the
// supplied probe; 200 when ready, 503 otherwise). It exists for the daemon
// binaries (poller, trap-receiver) that have no Gin router of their own, so they
// are no longer black boxes to Prometheus and container orchestrators
// (2026-06-23 audit, M11). An empty addr returns nil (disabled). The returned
// *http.Server can be Shutdown by the caller on graceful exit. Like the API
// /metrics, this is unauthenticated by design — protect it at the network layer.
func StartObservabilityServer(addr, component string, ready func() bool) *http.Server {
	if addr == "" {
		return nil
	}
	srv := &http.Server{Addr: addr, Handler: ObservabilityHandler(ready), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		slog.Info("observability server started", "component", component, "addr", addr, "endpoints", "/metrics /healthz /readyz")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("observability server failed", "component", component, "addr", addr, "err", err)
		}
	}()
	return srv
}

// ObservabilityHandler builds the daemon observability mux: /metrics (Prometheus),
// /healthz (liveness), and /readyz (readiness via ready; nil ready ⇒ always 200).
func ObservabilityHandler(ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready == nil || ready() {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ready")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "not ready")
	})
	return mux
}
