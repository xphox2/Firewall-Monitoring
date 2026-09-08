package handlers

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/logging"
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
	dashboardHealthRefreshDefault = 60
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

	mu sync.Mutex
	// snap and summarySnap are published together from ONE compute pass and share
	// hub.generatedAt, which is what age_seconds is derived from. (Each payload
	// also carries its own inner generated_at, stamped when that half finished,
	// so the two differ by the summary compute's duration. No client reads the
	// inner key; age_seconds is the staleness contract.) The summary moved
	// here in v0.11.245: it was the last request-path aggregate, sitting behind a
	// 15s TTL cache while the client polled every 30s — so every single poll
	// missed and paid the full cost, from the vitals rail on EVERY admin page.
	// That is the same TTL-shorter-than-poll bug this hub was created to fix for
	// /health; it was simply never fixed for /summary.
	snap        gin.H
	summarySnap gin.H
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
		fresh := !hub.generatedAt.IsZero() && time.Since(hub.generatedAt) < interval
		hub.mu.Unlock()
		if idle {
			continue // nobody is looking — compute nothing
		}
		// Already fresh: drop this cycle.
		//
		// Every client poll landing DURING a compute sees a snapshot older than
		// the interval (the timer just waited one) and so sends a wake. Without
		// this check that wake fires the instant the compute finishes and runs a
		// second one back-to-back against a snapshot that is already current —
		// which under a handful of viewers converges on two computes per
		// interval, and when a compute outlasts its interval degenerates into
		// computing continuously with no gap. That is precisely what measuring
		// the delay from completion is supposed to prevent, so the wake path has
		// to honour it too.
		//
		// The timer path is unaffected: it fires exactly one interval after the
		// last publish, so the snapshot's age equals the interval and is not
		// "fresh" by this test.
		if fresh {
			continue
		}
		hub.compute()
	}
}

// compute runs the aggregation and publishes the result. Duration is logged
// because every query inside computeDashboardHealth swallows its own error, so a
// statement killed by statement_timeout would otherwise leave no trace at all.
func (hub *dashboardHealthHub) compute() {
	// Per-ITERATION recovery, not just the SafeGo wrapper around Run.
	//
	// SafeGo contains a panic to this goroutine but then lets it exit — it does
	// not restart fn. For a refresher that would be terminal: one panic anywhere
	// in the aggregation (or in gopsutil) and the console freezes for the life of
	// the process, showing either a permanent "Building the system-health
	// snapshot…" or an ever-ageing snapshot under a banner promising it is
	// refreshing. Before this endpoint moved off the request path a panic here
	// was absorbed by gin's per-request recovery and the next request simply
	// tried again; this keeps that property.
	defer logging.Recover("dashboard-health-compute")

	start := time.Now()
	// One tracker across both payloads: they are published together under a
	// single generated_at, so a failure in either makes the whole snapshot
	// partial. Sharing it also means the summary inherits the health compute's
	// honesty about dropped blocks without duplicating the plumbing.
	cs := &computeStatus{}
	snap := hub.h.computeDashboardHealth(cs)
	summary := hub.h.computeDashboardSummary(cs)
	took := time.Since(start)

	// Stamp `partial` on both maps HERE, after both computes have run, and never
	// inside them.
	//
	// The tracker is shared, so a value read inside computeDashboardHealth would
	// be provisional: the health payload is built before the summary runs, and a
	// summary-only failure would have been recorded as `false`. Doing it once at
	// the end is the only place the answer is complete for both.
	//
	// The key is always present, true or false, so a client can distinguish "this
	// snapshot is whole" from an older payload that predates the field.
	partial := cs.partial()
	snap["partial"] = partial
	summary["partial"] = partial
	if partial {
		// Name the dropped blocks so the UI can say which reading is missing
		// rather than just flagging the whole snapshot as suspect.
		snap["partial_blocks"] = cs.failed
		summary["partial_blocks"] = cs.failed
		log.Printf("dashboard compute: snapshot published PARTIAL, dropped blocks: %v", cs.failed)
	}

	hub.mu.Lock()
	hub.snap = snap
	hub.summarySnap = summary
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
func (hub *dashboardHealthHub) request() (health, summary gin.H, generatedAt time.Time) {
	hub.mu.Lock()
	hub.lastRequest = time.Now()
	snap, summarySnap, generatedAt, interval := hub.snap, hub.summarySnap, hub.generatedAt, hub.interval
	hub.mu.Unlock()

	if snap == nil || time.Since(generatedAt) > interval {
		select {
		case hub.wake <- struct{}{}:
		default: // a wake is already pending — one is enough
		}
	}
	return snap, summarySnap, generatedAt
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
	snap, _, generatedAt := h.dashHub.request()
	serveSnapshot(c, snap, generatedAt)
}

// serveSnapshot renders one published payload with its age, or the sentinel when
// nothing has been computed yet. Shared by the health and summary handlers so
// the two cannot drift apart — the {"status":"computing"} contract is load
// bearing on the client, which must branch on it rather than feeding it to a
// renderer that defaults every missing key to zero.
func serveSnapshot(c *gin.Context, snap gin.H, generatedAt time.Time) {
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

// GetDashboardSummary serves the landing-dashboard summary from the same
// background snapshot as GetDashboardHealth, and like it NEVER touches the
// database.
//
// This is the endpoint the vitals rail polls from every admin page, every 30s.
// It used to compute on the request path behind a 15s TTL cache, which meant a
// single operator with a single tab missed on every poll and paid the full cost
// (545ms median, 1.55s worst, measured on production). Serving it from the hub
// removes the last request-path aggregate in the product.
func (h *Handler) GetDashboardSummary(c *gin.Context) {
	// dashHub is only built when db != nil (NewHandler), so guard both or the
	// typed-nil-store test nil-derefs instead of proving the no-DB path.
	if h.db == nil || h.dashHub == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	_, summary, generatedAt := h.dashHub.request()
	serveSnapshot(c, summary, generatedAt)
}

// computeDashboardSummary builds the landing/vitals payload: device and probe
// counts, a bounded device list, and 24h telemetry totals.
//
// Runs on the BACKGROUND store h.db, never the request-scoped one, and that is
// asserted rather than merely intended:
// reqdb_audit032_test.go's backgroundStoreAllowed check requires this file to
// open its computes with `db := h.db` and to contain no request-scoped store
// call at all — the check is a literal substring match on the source, so even a
// comment mentioning that call by name trips it. The payload is a pure global
// aggregate with no per-user component, so every client shares one result.
func (h *Handler) computeDashboardSummary(cs *computeStatus) gin.H {
	db := h.db
	g := db.Gorm()

	// Device counts by status — a single GROUP BY over the small config table.
	var statusCounts []struct {
		Status string
		C      int64
	}
	cs.note("summary status counts",
		g.Model(&models.Device{}).Scopes(database.ActiveDevices).Select("status, COUNT(*) AS c").Group("status").Scan(&statusCounts).Error)
	var total, online, offline int64
	for _, r := range statusCounts {
		total += r.C
		switch r.Status {
		case "online":
			online = r.C
		case "offline":
			offline = r.C
		}
	}

	// Minimal device list (id/name/status/last_polled) for the stale + noisy cards.
	devices := make([]dashboardSummaryDevice, 0)
	cs.note("summary device list",
		g.Model(&models.Device{}).Scopes(database.ActiveDevices).Select("id, name, status, last_polled").Limit(1000).Scan(&devices).Error)

	// Probe counts (excluding decommissioned): active drives the stat card,
	// pending + stale drive the vitals-rail severity readout.
	probeCount := func(label, where string, args ...interface{}) int64 {
		var n int64
		q := g.Model(&models.Probe{}).Where("decommissioned_at IS NULL")
		if where != "" {
			q = q.Where(where, args...)
		}
		cs.note(label, q.Count(&n).Error)
		return n
	}
	probeActive := probeCount("probe count active", "approval_status = ? AND status = ?", "approved", "online")
	probePending := probeCount("probe count pending", "approval_status = ?", "pending")
	probeStale := probeCount("probe count stale", "approval_status = ? AND status <> ?", "approved", "online")

	// Syslog + trap 24h totals via bare bounded COUNTs. GetSyslogStats/GetTrapStats
	// also compute severity + hourly-bucket breakdowns the rail never uses, so we
	// count directly. Measured 327ms warm on production after the 2026-09-07
	// PostgreSQL tuning (649ms before it) — acceptable in a 60s background pass,
	// where it used to be paid on the request path by every poll.
	cutoff24 := time.Now().Add(-24 * time.Hour)
	var syslog24, syslogSummary24, trap24 int64
	cs.note("summary syslog 24h", g.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff24).Count(&syslog24).Error)
	cs.note("summary syslog-summary 24h", g.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff24).
		Select("COALESCE(SUM(count),0)").Scan(&syslogSummary24).Error)
	syslog24 += syslogSummary24
	cs.note("summary traps 24h", g.Model(&models.TrapEvent{}).Where("timestamp > ?", cutoff24).Count(&trap24).Error)

	return gin.H{
		"generated_at":        time.Now(),
		"device_counts":       gin.H{"total": total, "online": online, "offline": offline},
		"devices":             devices,
		"probe_count_active":  probeActive,
		"probe_count_pending": probePending,
		"probe_count_stale":   probeStale,
		"syslog_24h":          syslog24,
		"trap_24h":            trap24,
	}
}

// computeStatus records whether any block of a compute failed.
//
// Every query in both computes deliberately degrades rather than aborting: a
// failed block is dropped and the rest of the snapshot is still published. That
// is the right behaviour — one bad aggregate should not blank the console — but
// before this type there was NO trace of it in the payload, so a block killed by
// the 30s statement_timeout published a confident zero under a fresh
// generated_at and the UI rendered it as current truth. Production has already
// hit exactly that: the noisy-devices scan was killed at 30,006ms, leaving the
// leaderboard empty and indistinguishable from a genuinely quiet fleet.
//
// The stakes rose when the summary joined this hub: the vitals rail is on EVERY
// admin page, so a killed 24h COUNT would paint "0 syslog" fleet-wide for a
// whole interval. The snapshot now carries `partial: true` plus the names of the
// blocks that failed, and the UI shows a degraded state instead of a zero.
type computeStatus struct {
	failed []string
}

// note records a failure for `what` and reports whether one happened, so callers
// can both track and branch in one expression.
//
// NIL-SAFE on purpose. noisyDevices is shared between this background compute
// and the request-path GET /api/dashboard/noisy, and only the former has a
// snapshot to mark. A nil receiver still logs and still reports the failure to
// its caller; it just has nowhere to record it.
func (cs *computeStatus) note(what string, err error) bool {
	if err == nil {
		return false
	}
	if cs != nil {
		cs.failed = append(cs.failed, what)
	}
	log.Printf("dashboard compute: %s: %v (block dropped, snapshot marked partial)", what, err)
	return true
}

// partial reports whether anything was dropped.
func (cs *computeStatus) partial() bool { return cs != nil && len(cs.failed) > 0 }

// computeDashboardHealth runs the (cheap) aggregate queries once. Uses the
// background store h.db so the cached value is shared across all clients — never
// the per-request store.
//
// Returns the snapshot and the failure tracker; see computeStatus for why a
// partial result must be labelled rather than silently published.
func (h *Handler) computeDashboardHealth(cs *computeStatus) gin.H {
	db := h.db
	g := db.Gorm()

	// --- Platform + database (host CPU/mem/disk/load, runtime, DB pool/size) ---
	platform := h.buildSystemHealth(context.Background(), db)

	// --- Fleet: device counts by status (cheap GROUP BY over config table) ---
	var statusCounts []struct {
		Status string
		C      int64
	}
	cs.note("fleet status counts", g.Model(&models.Device{}).Scopes(database.ActiveDevices).Select("status, COUNT(*) AS c").Group("status").Scan(&statusCounts).Error)
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
	cs.note("newest poll", g.Model(&models.Device{}).Scopes(database.ActiveDevices).Select("MAX(last_polled)").Scan(&newestPoll).Error)

	// --- Ingestion: orphan-safe running telemetry totals + last-hour rates ---
	ingestion := gin.H{}
	t, telErr := db.GetTelemetryTotals()
	cs.note("telemetry totals", telErr)
	if telErr == nil && t != nil {
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
	probes, probeErr := db.GetAllProbes()
	cs.note("collector probes", probeErr)
	if probeErr == nil {
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
	cs.note("open alerts by severity", g.Model(&models.Alert{}).Select("severity, COUNT(*) AS c").
		Where("resolved_at IS NULL AND suppressed = ? AND acknowledged = ? AND (snoozed_until IS NULL OR snoozed_until < ?)",
			false, false, time.Now()).
		Group("severity").Scan(&sevRows).Error)
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
	ts, tsErr := db.GetAlertsTimeSeries(24)
	cs.note("alerts trend", tsErr)
	if tsErr == nil && ts != nil {
		alerts["trend"] = ts
	}

	// --- Data quality: stale devices + noisy-device leaderboard ---
	staleCutoff := time.Now().Add(-staleDeviceWindow)
	var stale []dashboardSummaryDevice
	cs.note("stale devices", g.Model(&models.Device{}).Scopes(database.ActiveDevices).Select("id, name, status, last_polled").
		Where("last_polled < ? AND last_polled > ?", staleCutoff, time.Unix(1, 0)).
		Order("last_polled ASC").Limit(20).Scan(&stale).Error)
	dataQuality := gin.H{
		"stale": stale,
		// The tracker is passed in deliberately: a killed noisy scan is the exact
		// incident computeStatus exists for, and without this it would publish an
		// empty leaderboard under partial:false — indistinguishable from a quiet
		// fleet, which is the bug, not the symptom.
		"noisy": noisyDevices(g, 24, 10, cs),
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
	cs.note("newest trap", g.Model(&models.TrapEvent{}).Select("MAX(timestamp)").Scan(&newestTrap).Error)
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
	counts, tiErr := db.CountThreatIntelBySource()
	cs.note("threat-intel counts", tiErr)
	if tiErr == nil {
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
