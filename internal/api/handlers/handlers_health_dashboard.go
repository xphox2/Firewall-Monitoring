package handlers

import (
	"context"
	"net/http"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// dashboardHealthTTL is how long a computed system-health composite is served
// from cache. Within this window every browser tab / refresh / workstation gets
// the same in-memory snapshot, so the underlying DB aggregation runs at most
// once per TTL regardless of client count (see ttlCache).
const dashboardHealthTTL = 10 * time.Second

// pollerFreshWindow / trapFreshWindow bound how recent the newest poll / trap
// must be for the Services module to call the poller / trap-receiver "up". These
// are activity inferences (the API can't directly see sibling processes), so a
// quiet-but-healthy system reads as "idle", never a false "down".
const (
	pollerFreshWindow = 15 * time.Minute
	trapFreshWindow   = 60 * time.Minute
	staleDeviceWindow = 60 * time.Minute
)

// GetDashboardHealth is the single cached composite that powers every module of
// the customizable system-health dashboard. It is NOT the NOC: it summarizes the
// health of the Firewall-Mon platform + pipeline (server box, DB, ingestion,
// collectors, services) plus high-level fleet/alert rollups — it does not stream
// the real-time per-site/device view.
//
// The whole payload is wrapped in a ~10s TTL + singleflight cache so rapid
// refreshes and many concurrent workstations collapse to one computation.
func (h *Handler) GetDashboardHealth(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	val, err := h.dashCache.get("dashboard-health", dashboardHealthTTL, func() (interface{}, error) {
		return h.computeDashboardHealth(), nil
	})
	if err != nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	c.JSON(http.StatusOK, response.Success(val))
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
	if ts, err := db.GetDashboardTimeSeries(24); err == nil && ts != nil {
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
		svc("Notifier", map[bool]string{true: "configured", false: "off"}[h.notifier != nil]),
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
