package handlers

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// The system-health composite is built by a BACKGROUND refresher, never on a
// request. It used to be a 10s TTL + singleflight cache computed lazily by
// whichever request found it expired — but the client polls every 30s, so a
// single operator with one tab missed the cache on every poll and paid the full
// aggregation each time. On production (99M-row syslog_messages on rotational
// storage) that was a measured 32.57s per request, longer than the 30s
// WriteTimeout, so the connection died mid-flight and the dashboard sat on
// "Loading system health…" indefinitely.
//
// Now: a ticker computes the snapshot off the request path and the handler only
// ever hands back whatever is current. A request can never be slow, whatever the
// cache state.
const (
	// dashboardHealthRefreshKey is the admin-UI setting (seconds) controlling how
	// often the background refresher recomputes. Not an env var — new knobs are
	// admin settings.
	dashboardHealthRefreshKey     = "dashboard_health_refresh_seconds"
	dashboardHealthRefreshDefault = 30
	// dashboardHealthRefreshMin clamps the setting. The compute is a multi-second
	// aggregation over the biggest tables in the database; letting an operator set
	// it to 1s would turn the dashboard into a self-inflicted outage.
	dashboardHealthRefreshMin = 15
	// dashboardHealthRefreshMax bounds the other end so a typo can't park the
	// snapshot at a stale value for hours.
	dashboardHealthRefreshMax = 3600
	// dashboardHealthIdleWindow gates the ticker on recent interest, mirroring the
	// NOC hub's M11 subscriber gating: with nobody looking at the dashboard the
	// refresher computes nothing at all.
	dashboardHealthIdleWindow = 5 * time.Minute
)

// pollerFreshWindow / trapFreshWindow bound how recent the newest poll / trap
// must be for the Services module to call the poller / trap-receiver "up". These
// are activity inferences (the API can't directly see sibling processes), so a
// quiet-but-healthy system reads as "idle", never a false "down".
const (
	pollerFreshWindow = 15 * time.Minute
	trapFreshWindow   = 60 * time.Minute
	staleDeviceWindow = 60 * time.Minute
)

// dashboardHealthHub owns the background computation of the system-health
// composite. One goroutine recomputes on a cadence; every request is served from
// whatever snapshot is current, so no browser ever waits on the DB.
//
// Modelled on nocHub (noc.go) with one deliberate difference: nocHub closes its
// idle-wake gap by computing INLINE on the 0→1 subscribe, which we cannot copy —
// an inline compute is exactly the multi-second block this exists to remove. The
// wake here is a non-blocking signal to the refresher instead.
type dashboardHealthHub struct {
	h *Handler

	mu          sync.Mutex
	snap        gin.H
	generatedAt time.Time
	lastRequest time.Time
	// interval is cached from the admin setting by the refresher so the request
	// path never issues a settings query just to decide whether to nudge it.
	interval time.Duration

	// wake is a depth-1 signal channel: a request finding the snapshot missing or
	// past its interval nudges the refresher instead of waiting for the next tick.
	wake chan struct{}
}

func newDashboardHealthHub(h *Handler) *dashboardHealthHub {
	return &dashboardHealthHub{
		h:        h,
		interval: dashboardHealthRefreshDefault * time.Second,
		wake:     make(chan struct{}, 1),
	}
}

// refreshInterval reads the admin setting, clamped. Called only by the refresher
// goroutine, never on a request.
func (hub *dashboardHealthHub) refreshInterval() time.Duration {
	secs := dashboardHealthRefreshDefault
	if hub.h != nil && hub.h.db != nil {
		secs = hub.h.db.GetIntSetting(dashboardHealthRefreshKey, dashboardHealthRefreshDefault)
	}
	if secs < dashboardHealthRefreshMin {
		secs = dashboardHealthRefreshMin
	}
	if secs > dashboardHealthRefreshMax {
		secs = dashboardHealthRefreshMax
	}
	return time.Duration(secs) * time.Second
}

// Run recomputes the snapshot until ctx is cancelled.
//
// The delay is measured from compute COMPLETION, not on a fixed time.Ticker: on
// a large database the compute can exceed the interval, and a plain ticker would
// then fire back-to-back computes with no gap and pin the disk that also serves
// ingest.
func (hub *dashboardHealthHub) Run(ctx context.Context) {
	if hub == nil || hub.h == nil || hub.h.db == nil {
		return
	}
	for {
		interval := hub.refreshInterval()
		hub.mu.Lock()
		hub.interval = interval
		hub.mu.Unlock()

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-hub.wake:
			timer.Stop()
		}

		hub.mu.Lock()
		idle := hub.lastRequest.IsZero() || time.Since(hub.lastRequest) > dashboardHealthIdleWindow
		hub.mu.Unlock()
		if idle {
			continue // nobody is looking — compute nothing
		}
		hub.compute()
	}
}

// compute runs the aggregation and publishes the result. Duration is logged
// because every query inside computeDashboardHealth swallows its own error, so a
// statement killed by statement_timeout would otherwise leave no trace at all.
func (hub *dashboardHealthHub) compute() {
	start := time.Now()
	snap := hub.h.computeDashboardHealth()
	took := time.Since(start)

	hub.mu.Lock()
	hub.snap = snap
	hub.generatedAt = time.Now()
	interval := hub.interval
	hub.mu.Unlock()

	switch {
	case took > interval:
		log.Printf("dashboard-health: compute took %s — longer than the %s refresh interval; "+
			"the snapshot is now this database's steady-state load while the dashboard is open", took, interval)
	case took > 2*time.Second:
		log.Printf("dashboard-health: compute took %s", took)
	}
}

// request records interest, nudges the refresher when the snapshot is missing or
// past its interval, and returns the current snapshot without blocking. A nil
// snapshot means nothing has been computed yet.
func (hub *dashboardHealthHub) request() (gin.H, time.Time) {
	hub.mu.Lock()
	hub.lastRequest = time.Now()
	snap, generatedAt, interval := hub.snap, hub.generatedAt, hub.interval
	hub.mu.Unlock()

	if snap == nil || time.Since(generatedAt) > interval {
		select {
		case hub.wake <- struct{}{}:
		default: // a wake is already pending — one is enough
		}
	}
	return snap, generatedAt
}

// RunDashboardHealthHub runs the system-health refresher until ctx is cancelled.
// Called once from cmd/api, AFTER SetNotifier/SetIRCManager: computeDashboardHealth
// reads those to report service status.
func (h *Handler) RunDashboardHealthHub(ctx context.Context) {
	if h == nil || h.dashHub == nil {
		return
	}
	h.dashHub.Run(ctx)
}

// GetDashboardHealth serves the background-computed system-health composite that
// powers every module of the customizable dashboard. It is NOT the NOC: it
// summarizes the health of the Firewall-Mon platform + pipeline (server box, DB,
// ingestion, collectors, services) plus high-level fleet/alert rollups — it does
// not stream the real-time per-site/device view.
//
// This handler NEVER touches the database. It returns whatever the refresher last
// produced, plus age_seconds so the UI can show staleness honestly, and a
// {"status":"computing"} sentinel before the first snapshot exists. Serving a
// stale snapshot labelled with its age beats blocking a browser for 30 seconds.
func (h *Handler) GetDashboardHealth(c *gin.Context) {
	if h.db == nil || h.dashHub == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	snap, generatedAt := h.dashHub.request()
	if snap == nil {
		c.JSON(http.StatusOK, response.Success(gin.H{"status": "computing"}))
		return
	}
	// Shallow copy so age_seconds never mutates the shared snapshot. The nested
	// values are only ever read after compute publishes them.
	out := make(gin.H, len(snap)+1)
	for k, v := range snap {
		out[k] = v
	}
	out["age_seconds"] = int64(time.Since(generatedAt).Seconds())
	c.JSON(http.StatusOK, response.Success(out))
}

// computeDashboardHealth runs the (cheap) aggregate queries once. Uses the
// background store h.db so the cached value is shared across all clients — never
// the per-request store.
func (h *Handler) computeDashboardHealth() gin.H {
	db := h.db
	g := db.Gorm()

	// --- Platform + database (host CPU/mem/disk/load, runtime, DB pool/size) ---
	platform := h.buildSystemHealth(context.Background(), db)

	// --- Fleet: device counts by status (cheap GROUP BY over config table) ---
	var statusCounts []struct {
		Status string
		C      int64
	}
	_ = g.Model(&models.Device{}).Select("status, COUNT(*) AS c").Group("status").Scan(&statusCounts).Error
	var devTotal, devOnline, devOffline int64
	for _, r := range statusCounts {
		devTotal += r.C
		switch r.Status {
		case "online":
			devOnline = r.C
		case "offline":
			devOffline = r.C
		}
	}
	fleet := gin.H{"total": devTotal, "online": devOnline, "offline": devOffline}

	// --- Data freshness: newest successful poll across the fleet ---
	var newestPoll *time.Time
	_ = g.Model(&models.Device{}).Select("MAX(last_polled)").Scan(&newestPoll).Error

	// --- Ingestion: orphan-safe running telemetry totals + last-hour rates ---
	ingestion := gin.H{}
	if t, err := db.GetTelemetryTotals(); err == nil && t != nil {
		ingestion = gin.H{
			"syslog": t.Syslog, "traps": t.Traps, "flows": t.Flows, "pings": t.Pings,
			"syslog_last_hour": t.SyslogLastHr, "traps_last_hour": t.TrapsLastHr,
			"flows_last_hour": t.FlowsLastHr, "pings_last_hour": t.PingsLastHr,
			// This map is rebuilt key by key, so the approx marker has to be
			// copied explicitly or the UI silently renders estimates as exact.
			"approx": t.Approx,
		}
	}
	if newestPoll != nil {
		ingestion["freshness_seconds"] = int64(time.Since(*newestPoll).Seconds())
	}

	// --- Collectors: probe health (exclude decommissioned) ---
	collectors := gin.H{"online": 0, "offline": 0, "pending": 0, "probes": []gin.H{}}
	if probes, err := db.GetAllProbes(); err == nil {
		var online, offline, pending int
		list := make([]gin.H, 0, len(probes))
		for _, p := range probes {
			if p.DecommissionedAt != nil {
				continue
			}
			switch {
			case p.ApprovalStatus == "pending":
				pending++
			case p.Status == "online":
				online++
			default:
				offline++
			}
			siteName := ""
			if p.Site != nil {
				siteName = p.Site.Name
			}
			list = append(list, gin.H{
				"name": p.Name, "status": p.Status, "approval_status": p.ApprovalStatus,
				"last_seen": p.LastSeen, "site": siteName,
			})
		}
		collectors = gin.H{"online": online, "offline": offline, "pending": pending, "probes": list}
	}

	// --- Alerts: open counts by severity + 24h activity trend ---
	var sevRows []struct {
		Severity string
		C        int64
	}
	_ = g.Model(&models.Alert{}).Select("severity, COUNT(*) AS c").
		Where("resolved_at IS NULL AND suppressed = ? AND acknowledged = ? AND (snoozed_until IS NULL OR snoozed_until < ?)",
			false, false, time.Now()).
		Group("severity").Scan(&sevRows).Error
	openBySev := gin.H{}
	var openTotal int64
	for _, r := range sevRows {
		openBySev[r.Severity] = r.C
		openTotal += r.C
	}
	alerts := gin.H{"open_total": openTotal, "open_by_severity": openBySev}
	// Alerts-only: the dashboard renders one sparkline from trend.alerts_over_time
	// and nothing else, so the flows/syslog/traps series the full call also builds
	// were pure waste (the syslog one measured 7.0s on production).
	if ts, err := db.GetAlertsTimeSeries(24); err == nil && ts != nil {
		alerts["trend"] = ts
	}

	// --- Data quality: stale devices + noisy-device leaderboard ---
	staleCutoff := time.Now().Add(-staleDeviceWindow)
	var stale []dashboardSummaryDevice
	_ = g.Model(&models.Device{}).Select("id, name, status, last_polled").
		Where("last_polled < ? AND last_polled > ?", staleCutoff, time.Unix(1, 0)).
		Order("last_polled ASC").Limit(20).Scan(&stale).Error
	dataQuality := gin.H{
		"stale": stale,
		"noisy": noisyDevices(g, 24, 10),
	}

	// --- Services: activity-inferred component status ---
	dbReachable := false
	if dbm, ok := platform["db"].(gin.H); ok {
		if r, ok := dbm["reachable"].(bool); ok {
			dbReachable = r
		}
	}
	pollerUp := newestPoll != nil && time.Since(*newestPoll) < pollerFreshWindow
	var newestTrap *time.Time
	_ = g.Model(&models.TrapEvent{}).Select("MAX(timestamp)").Scan(&newestTrap).Error
	trapUp := newestTrap != nil && time.Since(*newestTrap) < trapFreshWindow
	svc := func(name, status string) gin.H { return gin.H{"name": name, "status": status} }
	upIdle := func(ok bool) string {
		if ok {
			return "up"
		}
		return "idle"
	}
	services := []gin.H{
		svc("API", "up"),
		svc("Database", map[bool]string{true: "up", false: "down"}[dbReachable]),
		svc("Poller", upIdle(pollerUp)),
		svc("Trap Receiver", upIdle(trapUp)),
		svc("Notifier", map[bool]string{true: "configured", false: "off"}[h.GetNotifier() != nil]),
		svc("IRC", map[bool]string{true: "configured", false: "off"}[h.GetIRCManager() != nil]),
	}

	// --- Threat feeds: enabled flag + indicator/source counts ---
	threatFeeds := gin.H{"enabled": db.GetBoolSetting("threat_feeds_enabled", false)}
	if counts, err := db.CountThreatIntelBySource(); err == nil {
		var totalIPs int64
		activeSources := 0
		for _, sc := range counts {
			totalIPs += sc.Count
			if sc.Count > 0 {
				activeSources++
			}
		}
		threatFeeds["indicator_count"] = totalIPs
		threatFeeds["active_sources"] = activeSources
	}

	return gin.H{
		"generated_at": time.Now(),
		"platform":     platform,
		"fleet":        fleet,
		"ingestion":    ingestion,
		"collectors":   collectors,
		"alerts":       alerts,
		"data_quality": dataQuality,
		"services":     services,
		"threat_feeds": threatFeeds,
	}
}
