package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/detect"
	"firewall-mon/internal/logging"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/report"
	"firewall-mon/internal/secrets"
	"firewall-mon/internal/snmp"
	"firewall-mon/internal/threatfeed"
)

type Poller struct {
	cfg            *config.Config
	db             *database.Database
	alertManager   *alerts.AlertManager
	notifier       *notifier.Notifier
	spikeDetector  *report.SeasonalSpikeDetector
	prevIfaceStats map[string]*models.InterfaceStats // "deviceID_ifName" -> previous stats
	ifaceStatsMu   sync.RWMutex
	stopChan       chan struct{}

	// loopBeat is the unix-seconds timestamp of the Start() loop's last sign of
	// life (M30 of the 2026-07-01 audit). Stamped when the loop starts, before
	// each select wait, and when leader-locked work is picked up. /readyz
	// compares it against ~3x the poll interval so a halted loop (panicked and
	// awaiting supervisor restart, or wedged inside one tick's work) flips the
	// daemon to not-ready instead of staying green while polling, alerting,
	// rollups, and cleanup are dead.
	loopBeat atomic.Int64

	// feedSyncRunning guards the async threat-feed sync (M9 of the 2026-07-01
	// audit) so a slow/blackholed feed host can't (a) stall the poller's single
	// select loop — which starved SNMP polling, alert evaluation, offline
	// detection, and made shutdown hang — or (b) stack overlapping syncs when
	// an interval fires while the previous one is still running.
	feedSyncRunning atomic.Bool

	// feedEnabledSeen tracks the last-observed master + per-feed enable flags so a
	// detection cycle can notice a false→true flip (an admin re-enabling feeds in
	// the UI) and trigger an immediate resync — the API can't reach into the
	// poller's process to sync, so repopulation rides this cheap per-cycle recheck
	// (v0.11.46). nil until the first check. Accessed only from the single detect
	// goroutine (leader-locked), so it needs no mutex.
	feedMasterSeen  *bool
	feedEnabledSeen map[string]bool
}

// startThreatFeedSyncAsync runs the threat-feed sync off the poller's select
// loop (M9). It no-ops if a sync is already in flight, so intervals can't
// stack; the cross-process leader lock is acquired inside the goroutine so two
// poller processes still don't sync concurrently.
func (p *Poller) startThreatFeedSyncAsync() {
	if !p.feedSyncRunning.CompareAndSwap(false, true) {
		log.Println("threat-feeds: previous sync still running; skipping this interval")
		return
	}
	logging.SafeGo("threat-feed-sync", func() {
		defer p.feedSyncRunning.Store(false)
		p.runUnderLeaderLock("threat-feeds", p.runThreatFeedSync)
	})
}

func NewPoller(cfg *config.Config, db *database.Database, am *alerts.AlertManager, notif *notifier.Notifier) *Poller {
	p := &Poller{
		cfg:            cfg,
		db:             db,
		alertManager:   am,
		notifier:       notif,
		prevIfaceStats: make(map[string]*models.InterfaceStats),
		stopChan:       make(chan struct{}),
	}
	// M30: pre-stamp the loop heartbeat so /readyz is ready during startup,
	// before Start()'s first tick.
	p.markLoopAlive()
	// Real-time spike detector: judges live throughput against a per-interface
	// seasonal (weekday, hour) baseline, refreshed every 6h from 30 days of
	// hourly history, with a 30-minute re-fire cooldown.
	p.spikeDetector = report.NewSeasonalSpikeDetector(6*time.Hour, 30*time.Minute, func(key string) *report.SeasonalProfile {
		var deviceID uint
		var ifIndex int
		if _, err := fmt.Sscanf(key, "%d:%d", &deviceID, &ifIndex); err != nil || p.db == nil {
			return nil
		}
		buckets, err := p.db.GetInterfaceChartData(deviceID, ifIndex, "30d")
		if err != nil || len(buckets) == 0 {
			return nil
		}
		return report.BuildSeasonalProfileFromChart(buckets, 3600)
	})
	return p
}

// humanBps renders a bits-per-second value compactly for alert messages.
func humanBps(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.0f kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

// emitSpikeAlert saves and sends one sustained-spike alert.
func (p *Poller) emitSpikeAlert(device *models.Device, iface *models.InterfaceStats, dec report.SpikeDecision) {
	alert := models.Alert{
		Timestamp:    time.Now(),
		DeviceID:     iface.DeviceID,
		AlertType:    "TRAFFIC_SPIKE",
		Severity:     models.Severity(dec.Severity),
		Message:      fmt.Sprintf("Sustained traffic spike on %s: %s (typical ~%s for this time)", iface.Name, humanBps(dec.Value), humanBps(dec.Mean)),
		MetricName:   fmt.Sprintf("traffic_%s", iface.Name),
		CurrentValue: dec.Value,
		Threshold:    dec.Mean,
	}
	if p.db != nil {
		p.db.SaveAlert(&alert)
	}
	nc := notifier.SnapshotConfig(&p.cfg.Alerts)
	if err := p.notifier.SendAlert(&alert, nc); err != nil {
		log.Printf("Device %s: spike alert send error - %v", device.Name, err)
	}
}

// emitSpikeResolve records that a previously-alerted spike has cleared.
func (p *Poller) emitSpikeResolve(device *models.Device, iface *models.InterfaceStats) {
	now := time.Now()
	alert := models.Alert{
		Timestamp:  now,
		DeviceID:   iface.DeviceID,
		AlertType:  "TRAFFIC_SPIKE",
		Severity:   "info",
		Message:    fmt.Sprintf("Traffic on %s returned to normal", iface.Name),
		MetricName: fmt.Sprintf("traffic_%s", iface.Name),
		ResolvedAt: &now,
	}
	if p.db != nil {
		p.db.SaveAlert(&alert)
	}
	nc := notifier.SnapshotConfig(&p.cfg.Alerts)
	if err := p.notifier.SendAlert(&alert, nc); err != nil {
		log.Printf("Device %s: spike resolve send error - %v", device.Name, err)
	}
}

func (p *Poller) Start() error {
	if p.cfg.SNMP.PollInterval < 30*time.Second {
		p.cfg.SNMP.PollInterval = 30 * time.Second
	}

	log.Printf("Starting SNMP poller with interval: %v", p.cfg.SNMP.PollInterval)
	p.markLoopAlive()

	// Clean up stale auto-detected connections from generic interface names
	if p.db != nil {
		removed := p.db.CleanupStaleAutoConnections([]string{"ssl.root", "ssl.vdom", "naf.root", "l2t.root"})
		if removed > 0 {
			log.Printf("Cleaned up %d stale auto-detected connection(s) from generic tunnel names", removed)
		}
	}

	// Seed the interface/VPN "ever-up" set from the still-open down alerts BEFORE
	// the first cycle, so a restart during an ongoing outage keeps re-firing its
	// reminder instead of going silent. Currently-up links re-mark themselves on
	// the first cycle; enabled-but-never-cabled ports and idle tunnels stay
	// suppressed. Cheap indexed read of open alerts — no telemetry-table scan.
	if p.alertManager != nil && p.db != nil {
		if err := p.alertManager.SeedEverUpFromOpenAlerts(); err != nil {
			log.Printf("Ever-up seed failed (interface/VPN down alerts rebuild from live data): %v", err)
		}
	}

	// Run the first monitoring cycle immediately on startup
	p.runMonitoringCycle()

	ticker := time.NewTicker(p.cfg.SNMP.PollInterval)
	defer ticker.Stop()

	// Cleanup old data daily
	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()

	// L2 of the 2026-07-01 audit: prune the alert-cooldown map hourly (not just
	// on the daily cleanup). Now that prune respects each key's own cooldown,
	// running it hourly keeps the map tight without truncating any configured
	// cooldown.
	cooldownPruneTicker := time.NewTicker(1 * time.Hour)
	defer cooldownPruneTicker.Stop()

	// Roll up flow data every 5 minutes
	rollupTicker := time.NewTicker(5 * time.Minute)
	defer rollupTicker.Stop()

	// Run the sFlow detection engine every 5 minutes, over a recent window of
	// raw flow_samples (before the rollup consumes them at 1h).
	detectTicker := time.NewTicker(5 * time.Minute)
	defer detectTicker.Stop()

	// Threat-intel feed sync. v0.11.46: the ticker is created UNCONDITIONALLY so
	// the admin-UI master switch can turn feeds ON at runtime (the old
	// `if cfg.ThreatFeed.Enabled` guard made an env-off install unable to ever
	// sync). runThreatFeedSync itself gates on the master setting each run, so an
	// env-off + setting-unset install still does nothing. The initial sync fires
	// ~1 min after startup, then on the configured interval (default 12h).
	feedInterval := p.cfg.ThreatFeed.Interval
	if feedInterval <= 0 {
		feedInterval = 12 * time.Hour
	}
	feedTicker := time.NewTicker(feedInterval)
	defer feedTicker.Stop()
	feedTickC := feedTicker.C
	feedInit := time.NewTimer(1 * time.Minute)
	defer feedInit.Stop()
	feedInitC := feedInit.C
	log.Printf("threat-feeds: sync ticker armed (interval %s, ttl %dd); master switch resolved per-run from the admin UI", feedInterval, p.cfg.ThreatFeed.TTLDays)

	for {
		p.markLoopAlive() // M30: previous case completed / loop is waiting for work
		select {
		case <-ticker.C:
			// AUDIT-007: per-tick advisory lock so two poller processes
			// don't both run the same work. If another poller is active,
			// skip this tick and try again on the next one.
			p.runUnderLeaderLock("monitoring cycle", p.runMonitoringCycle)
		case <-rollupTicker.C:
			p.runUnderLeaderLock("rollup", func() {
				if p.db != nil {
					p.db.RunFlowRollupCycle()
					p.db.RunSyslogAggregationCycle(p.cfg.Retention)
				}
			})
		case <-detectTicker.C:
			p.runUnderLeaderLock("flow-detect", p.runFlowDetectionCycle)
		case <-feedInitC:
			p.startThreatFeedSyncAsync() // M9: async, off the select loop
		case <-feedTickC:
			p.startThreatFeedSyncAsync()
		case <-cooldownPruneTicker.C:
			if p.alertManager != nil {
				p.alertManager.PruneExpiredCooldowns() // L2: hourly, cheap, no lock needed
			}
		case <-cleanupTicker.C:
			p.runUnderLeaderLock("cleanup", func() {
				if p.db != nil {
					if err := p.db.CleanupOldData(p.cfg.Retention); err != nil {
						log.Printf("Data cleanup error: %v", err)
					} else {
						log.Println("Old data cleanup completed")
					}
					if err := p.db.CleanupConfigRevisions(); err != nil {
						log.Printf("Config revision cleanup error: %v", err)
					} else {
						log.Println("Config revision retention cleanup completed (top 50 + last 90d, run-collapsed)")
					}
					// Ensure future partitions exist (creates ahead partitions if needed)
					if err := p.db.EnsurePartitions(); err != nil {
						log.Printf("Partition check error: %v", err)
					}
					// Ensure autovacuum is configured (no-op if already configured)
					if err := p.db.ConfigureAutovacuum(); err != nil {
						log.Printf("Autovacuum config error: %v", err)
					}
				}
				if p.alertManager != nil {
					p.alertManager.PruneExpiredCooldowns()
				}
			})
		case <-p.stopChan:
			log.Println("Poller stopped")
			return nil
		}
	}
}

// runUnderLeaderLock acquires the AUDIT-007 cross-process advisory lock,
// runs fn while holding it, and releases on return. If the lock cannot
// be acquired (another poller is doing this work), logs a skip message
// and returns without invoking fn.
//
// SQLite (tests / single-process deployments) always acquires (no-op
// lock), so fn runs every tick.
func (p *Poller) runUnderLeaderLock(taskName string, fn func()) {
	if p.db == nil {
		// No DB to lock against; just run.
		fn()
		return
	}
	release, acquired := p.db.TryAcquirePollerWorkLock()
	if !acquired {
		log.Printf("Skipping %s: another poller holds the work lock", taskName)
		return
	}
	defer release()
	p.markLoopAlive() // M30: work picked up — a hang inside fn goes stale from here
	fn()
}

// detectConfigFromCfg maps the operator's DETECT_* config onto the detection
// engine's threshold struct. Zero values pass through and the engine substitutes
// its built-in defaults, so an operator only overrides the knobs they set.
func detectConfigFromCfg(cfg *config.Config) detect.Config {
	if cfg == nil {
		return detect.Config{}
	}
	return detect.Config{
		PortScanPorts:      cfg.Detect.PortScanPorts,
		SuperSpreaderHosts: cfg.Detect.SuperSpreaderHosts,
		DataExfilBytes:     cfg.Detect.DataExfilBytes,
		BeaconMinSamples:   cfg.Detect.BeaconMinSamples,
		BeaconMaxAvgBytes:  cfg.Detect.BeaconMaxAvgBytes,
		BeaconMaxCV:        cfg.Detect.BeaconMaxCV,
		CapacityThreshold:  cfg.Detect.CapacityThreshold,
	}
}

// detectConfig returns the effective detector thresholds for this cycle: the
// DETECT_* env baseline (detectConfigFromCfg) with any admin-UI overrides from
// system_settings layered on top. Read fresh each cycle so a Settings-page edit
// takes effect within one detection interval (~5 min) — no poller restart.
func (p *Poller) detectConfig() detect.Config {
	base := detectConfigFromCfg(p.cfg)
	if p.db == nil {
		return base
	}
	settings, err := p.db.GetAllSettings()
	if err != nil {
		log.Printf("flow-detect: load threshold settings: %v", err)
		return base
	}
	m := make(map[string]string, len(settings))
	for _, s := range settings {
		m[s.Key] = s.Value
	}
	return applyDetectSettings(base, m)
}

// applyDetectSettings overlays the detector-threshold system_settings (string
// key/value) onto a base config. A missing/blank/invalid/non-positive value
// leaves the base field untouched, so an unset setting falls back to env →
// built-in default. Pure (no DB) so it's unit-testable.
func applyDetectSettings(base detect.Config, m map[string]string) detect.Config {
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_port_scan_ports"])); err == nil && v > 0 {
		base.PortScanPorts = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_super_spreader_hosts"])); err == nil && v > 0 {
		base.SuperSpreaderHosts = v
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(m["detect_data_exfil_bytes"]), 10, 64); err == nil && v > 0 {
		base.DataExfilBytes = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_beacon_min_samples"])); err == nil && v > 0 {
		base.BeaconMinSamples = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_beacon_max_avg_bytes"])); err == nil && v > 0 {
		base.BeaconMaxAvgBytes = v
	}
	if v, err := strconv.ParseFloat(strings.TrimSpace(m["detect_beacon_max_cv"]), 64); err == nil && v > 0 {
		base.BeaconMaxCV = v
	}
	if v, err := strconv.ParseFloat(strings.TrimSpace(m["detect_capacity_threshold"]), 64); err == nil && v > 0 {
		base.CapacityThreshold = v
	}
	return base
}

// runFlowDetectionCycle runs the sFlow detection engine (internal/detect) over a
// recent window of raw flow_samples, persists every finding, and feeds each to
// the alert engine. Detections are stored regardless of whether they alert, so
// the NOC sees sub-threshold signal. The 15-minute window comfortably covers the
// 5-minute cadence with overlap; alert cooldown dedupes the overlap.
func (p *Poller) runFlowDetectionCycle() {
	if p.db == nil {
		return
	}
	// v0.11.46: repopulate feeds an admin re-enabled in the UI. The API can't
	// sync across the process boundary, so the poller detects a false→true flip on
	// its per-cycle setting read and fires an immediate resync (≤ one detect cycle
	// of latency instead of waiting for the 12h feed ticker).
	p.maybeResyncReenabledFeeds()

	end := time.Now()
	start := end.Add(-15 * time.Minute)
	detections := detect.RunAll(detect.Window{
		Start:  start,
		End:    end,
		DB:     p.db.Gorm(),
		Config: p.detectConfig(),
	}, end)
	if len(detections) == 0 {
		return
	}
	// Persist every finding first (the NOC keeps sub-threshold signal).
	saved := make([]*models.FlowDetection, 0, len(detections))
	for i := range detections {
		if err := p.db.SaveFlowDetection(&detections[i]); err != nil {
			log.Printf("flow-detect: save %s: %v", detections[i].Detector, err)
			continue
		}
		saved = append(saved, &detections[i])
	}
	if p.alertManager == nil {
		log.Printf("flow-detect: %d detection(s) persisted", len(saved))
		return
	}

	// Single feed: split into security detections (consolidated to ONE alert per
	// source) and the rest (one alert per detection). Any detection that maps to
	// an alert is linked (flow_detections.alert_id) so it drops off the sFlow
	// detections card and appears only on the Alerts page.
	securityBySrc := map[string][]*models.FlowDetection{}
	var others []*models.FlowDetection
	for _, d := range saved {
		if d.Category == string(detect.CategorySecurity) {
			securityBySrc[d.SrcAddr] = append(securityBySrc[d.SrcAddr], d)
		} else {
			others = append(others, d)
		}
	}

	link := func(ids []uint, alertID uint, what string) {
		if alertID == 0 {
			return
		}
		if err := p.db.LinkFlowDetectionsToAlert(ids, alertID); err != nil {
			log.Printf("flow-detect: link %s: %v", what, err)
		}
	}

	for _, d := range others {
		alertID, err := p.alertManager.ProcessFlowDetection(d, nil)
		if err != nil {
			log.Printf("flow-detect: alert %s: %v", d.Detector, err)
		}
		link([]uint{d.ID}, alertID, d.Detector)
	}

	// v0.11.46 — silence + cross-source storm digest, applied to the security
	// groups BEFORE the per-source loop:
	//   1. silenced sources: ack their detections (off the NOC card) and drop them
	//      so they neither alert nor count toward a storm;
	//   2. storms: bucket surviving security detections by (site, detector); any
	//      bucket over its resolved threshold collapses into ONE digest alert, and
	//      those detections are removed from the per-source groups.
	p.silenceSuppressedSources(securityBySrc)
	p.alertManager.SetStormSourcesDefault(p.db.GetIntSetting("detect_security_storm_sources", 25))
	p.rollUpSecurityStorms(securityBySrc, link)

	for src, group := range securityBySrc {
		alertID, err := p.alertManager.ProcessSecurityEvent(group, nil)
		if err != nil {
			log.Printf("flow-detect: security event %s: %v", src, err)
		}
		link(detectionIDs(group), alertID, "security "+src)
	}
	log.Printf("flow-detect: %d detection(s) persisted", len(saved))
}

// detectionIDs collects the IDs of a detection group.
func detectionIDs(group []*models.FlowDetection) []uint {
	ids := make([]uint, 0, len(group))
	for _, d := range group {
		ids = append(ids, d.ID)
	}
	return ids
}

// canonIP canonicalizes a source address for matching against the (normalized)
// suppression set, so IPv6 case/zero-compression differences don't cause a miss.
func canonIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// silenceSuppressedSources drops every currently-silenced source from the
// security groups: it acks that source's detections (so a suppressed attacker
// doesn't flood the NOC card) and removes it from securityBySrc so it neither
// fires an alert nor counts toward a storm. Fails OPEN — a load error is logged
// and treated as "none suppressed" so a transient DB blip can't silence the whole
// security pipeline. The active set is loaded ONCE (a storm has hundreds of
// distinct sources; per-source point queries would be a per-cycle read storm).
func (p *Poller) silenceSuppressedSources(securityBySrc map[string][]*models.FlowDetection) {
	sups, err := p.db.ListActiveFlowSuppressions()
	if err != nil {
		log.Printf("flow-detect: load suppressions (fail-open, none applied): %v", err)
		return
	}
	if len(sups) == 0 {
		return
	}
	set := make(map[string]struct{}, len(sups))
	for _, s := range sups {
		set[s.SrcAddr] = struct{}{}
	}
	for src, group := range securityBySrc {
		if _, ok := set[canonIP(src)]; !ok {
			continue
		}
		if err := p.db.AckFlowDetections(detectionIDs(group)); err != nil {
			log.Printf("flow-detect: ack suppressed source %s: %v", src, err)
		}
		delete(securityBySrc, src)
	}
}

// rollUpSecurityStorms detects per-(site, detector) storms in the surviving
// security groups and collapses each into ONE SFLOW_SECURITY_DIGEST alert,
// removing the consumed detections from securityBySrc so the per-source loop skips
// them. Below-threshold buckets are untouched (full backward compat when there's
// no storm).
func (p *Poller) rollUpSecurityStorms(securityBySrc map[string][]*models.FlowDetection, link func([]uint, uint, string)) {
	if len(securityBySrc) == 0 {
		return
	}
	// deviceID → siteID (0 = no site), built once per cycle.
	devSite := map[uint]uint{}
	if devs, err := p.db.GetAllDevices(); err == nil {
		for i := range devs {
			if devs[i].SiteID != nil {
				devSite[devs[i].ID] = *devs[i].SiteID
			}
		}
	} else {
		log.Printf("flow-detect: load devices for storm bucketing: %v", err)
	}

	type bucketKey struct {
		site     uint
		detector string
	}
	distinct := map[bucketKey]map[string]struct{}{}
	dets := map[bucketKey][]*models.FlowDetection{}
	for src, group := range securityBySrc {
		for _, d := range group {
			bk := bucketKey{devSite[d.DeviceID], d.Detector}
			if distinct[bk] == nil {
				distinct[bk] = map[string]struct{}{}
			}
			distinct[bk][src] = struct{}{}
			dets[bk] = append(dets[bk], d)
		}
	}

	stormDets := map[uint]struct{}{}
	for bk, srcset := range distinct {
		var siteID *uint
		if bk.site != 0 {
			s := bk.site
			siteID = &s
		}
		threshold := p.alertManager.StormThreshold(siteID)
		if threshold <= 0 || len(srcset) < threshold {
			continue // digest disabled, or below threshold → per-source path handles it
		}
		group := dets[bk]
		alertID, err := p.alertManager.ProcessSecurityDigest(siteID, bk.detector, group)
		if err != nil {
			log.Printf("flow-detect: digest %s s%d: %v", bk.detector, bk.site, err)
		}
		ids := detectionIDs(group)
		link(ids, alertID, fmt.Sprintf("digest %s s%d (%d sources)", bk.detector, bk.site, len(srcset)))
		for _, id := range ids {
			stormDets[id] = struct{}{}
		}
	}
	if len(stormDets) == 0 {
		return
	}
	// Partition: remove only the storm-consumed detections from each source group
	// (a source keeps its non-storm-detector detections), dropping now-empty groups.
	for src, group := range securityBySrc {
		kept := group[:0]
		for _, d := range group {
			if _, isStorm := stormDets[d.ID]; !isStorm {
				kept = append(kept, d)
			}
		}
		if len(kept) == 0 {
			delete(securityBySrc, src)
		} else {
			securityBySrc[src] = kept
		}
	}
}

// maybeResyncReenabledFeeds notices when the master switch or any per-feed flag
// has flipped false→true since the last detection cycle and triggers an immediate
// resync so an admin re-enabling feeds in the UI sees indicators repopulate within
// ~one cycle rather than at the next 12h ticker (v0.11.46). It only ACTS on a
// re-enable; disables are handled by runThreatFeedSync skipping them and the API
// purging rows. First call just seeds the baseline (no resync).
func (p *Poller) maybeResyncReenabledFeeds() {
	if p.db == nil {
		return
	}
	master := p.db.GetBoolSetting("threat_feeds_enabled", p.cfg.ThreatFeed.Enabled)
	perFeed := map[string]bool{}
	if statuses, err := p.db.ListThreatFeedStatus(); err == nil {
		for _, st := range statuses {
			perFeed[st.Source] = st.Enabled
		}
	}

	if p.feedMasterSeen == nil {
		// First cycle: seed the baseline without resyncing (startup already runs
		// the ~1-min initial sync).
		m := master
		p.feedMasterSeen = &m
		p.feedEnabledSeen = perFeed
		return
	}

	reenabled := false
	if master && !*p.feedMasterSeen {
		reenabled = true // master flipped off→on
	}
	if master {
		for src, en := range perFeed {
			if en && !p.feedEnabledSeen[src] {
				reenabled = true // a specific feed flipped off→on
				break
			}
		}
	}

	m := master
	p.feedMasterSeen = &m
	p.feedEnabledSeen = perFeed

	if reenabled {
		log.Printf("threat-feeds: re-enable detected in settings; triggering resync")
		p.startThreatFeedSyncAsync()
	}
}

// runThreatFeedSync fetches the configured free open-source bad-IP lists and
// upserts them into threat_intel with a TTL, then prunes expired indicators.
// Opt-in (THREAT_FEEDS_ENABLED) and leader-locked. The API process picks up the
// new indicators on its next matcher refresh (~15 min). Each feed failure is
// logged and skipped so one dead source doesn't abort the sync.
func (p *Poller) runThreatFeedSync() {
	if p.db == nil {
		return
	}
	// v0.11.46: the master switch is an admin-UI setting; the env value is only
	// the default until an operator flips it. Absent setting → follow env.
	if !p.db.GetBoolSetting("threat_feeds_enabled", p.cfg.ThreatFeed.Enabled) {
		return
	}
	var feeds []threatfeed.Feed
	if !p.cfg.ThreatFeed.DisableBundle {
		feeds = append(feeds, threatfeed.DefaultFeeds()...)
	}
	feeds = append(feeds, threatfeed.ParseExtraFeeds(p.cfg.ThreatFeed.ExtraURLs)...)
	if len(feeds) == 0 {
		return
	}
	// v0.11.46: skip feeds an admin has disabled, so their purged indicators
	// don't come back until re-enabled. Feeds with no status row yet are enabled
	// by default (first sync creates the row).
	disabled := map[string]struct{}{}
	if statuses, err := p.db.ListThreatFeedStatus(); err == nil {
		for _, st := range statuses {
			if !st.Enabled {
				disabled[st.Source] = struct{}{}
			}
		}
	}
	ttl := p.cfg.ThreatFeed.TTLDays
	if ttl <= 0 {
		ttl = 14
	}
	expires := time.Now().Add(time.Duration(ttl) * 24 * time.Hour)
	client := &http.Client{Timeout: 60 * time.Second}
	total := 0
	for _, feed := range feeds {
		if _, off := disabled[feed.Name]; off {
			continue // admin-disabled: don't refetch (rows were purged on disable)
		}
		started := time.Now()
		// recordStatus persists this feed's outcome (count or error) so the admin
		// Threat Intelligence page can show which feeds ran and when.
		recordStatus := func(count int, feedErr string) {
			st := &models.ThreatFeedStatus{
				Source: feed.Name, URL: feed.URL, Category: feed.Category,
				Severity: feed.Severity, Kind: feed.Kind, EntryCount: count,
				LastError: feedErr, LastSyncAt: started,
				LastDuration: int(time.Since(started).Milliseconds()),
			}
			if err := p.db.UpsertThreatFeedStatus(st); err != nil {
				log.Printf("threat-feeds: status %s: %v", feed.Name, err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		entries, err := threatfeed.Fetch(ctx, client, feed, p.cfg.ThreatFeed.AuthHeader)
		cancel()
		if err != nil {
			log.Printf("threat-feeds: fetch %s: %v", feed.Name, err)
			recordStatus(0, err.Error())
			continue
		}
		batch := make([]models.ThreatIntel, 0, len(entries))
		for _, e := range entries {
			ex := expires
			batch = append(batch, models.ThreatIntel{
				CIDR: e.CIDR, Category: e.Category, Source: e.Source,
				Severity: e.Severity, ExpiresAt: &ex,
			})
		}
		if err := p.db.UpsertThreatIntelBatch(batch); err != nil {
			log.Printf("threat-feeds: upsert %s: %v", feed.Name, err)
			recordStatus(0, err.Error())
			continue
		}
		total += len(batch)
		recordStatus(len(batch), "")
		log.Printf("threat-feeds: %s → %d indicators", feed.Name, len(batch))
	}
	if pruned, err := p.db.PruneExpiredThreatIntel(); err != nil {
		log.Printf("threat-feeds: prune expired: %v", err)
	} else if pruned > 0 {
		log.Printf("threat-feeds: pruned %d expired indicators", pruned)
	}
	log.Printf("threat-feeds: sync complete, %d indicators upserted (expire in %dd)", total, ttl)
}

// runMonitoringCycle is the poller's per-tick health/alert engine pass
// (formerly pollAllDevices). The server no longer polls devices over SNMP
// directly — collectors own all device polling and relay telemetry to the API
// (v0.11.74) — so each cycle evaluates DB state only: staleness sweeps,
// telemetry alert checks over the latest relayed rows, connection detection,
// alert escalations, and probe data-flow monitoring. POLL_INTERVAL remains the
// cycle cadence.
func (p *Poller) runMonitoringCycle() {
	if p.db == nil {
		log.Println("Database not connected, skipping monitoring cycle")
		return
	}

	// Refresh alert thresholds from DB so admin UI changes take effect
	if p.alertManager != nil {
		p.alertManager.RefreshThresholds(p.db.Gorm())
	}

	devices, err := p.db.GetAllDevices()
	if err != nil {
		log.Printf("Error getting devices: %v", err)
		return
	}

	if len(devices) == 0 {
		log.Println("No devices configured, skipping monitoring cycle")
		return
	}

	log.Printf("Monitoring cycle: %d device(s)", len(devices))

	// An enabled device with no collector assignment is polled by NOBODY now
	// that the server's direct SNMP loop is retired. That is a configuration
	// gap, not an outage — do NOT fire DEVICE_OFFLINE for it; surface it as one
	// summary log line per cycle instead.
	unassigned := 0
	for i := range devices {
		if devices[i].Enabled && devices[i].ProbeID == nil {
			unassigned++
		}
	}
	if unassigned > 0 {
		log.Printf("%d enabled device(s) have no collector assigned and are not monitored", unassigned)
	}

	// Drop previous-interface baselines for devices/interfaces no longer polled
	// so prevIfaceStats cannot grow without bound across the poller's lifetime
	// (a decommissioned device or a removed dynamic tunnel would otherwise leave
	// its entry behind forever). Live interfaces re-stamp their Timestamp every
	// cycle; use a generous TTL so a transient poll outage doesn't discard a
	// still-useful baseline.
	ifaceTTL := 12 * p.cfg.SNMP.PollInterval
	if ifaceTTL < time.Hour {
		ifaceTTL = time.Hour
	}
	p.pruneStaleIfaceStats(ifaceTTL)

	// Mark probe-assigned devices offline if their last_polled is stale.
	// Uses 3× poll interval as the threshold (minimum 5 minutes).
	//
	// Probe devices are polled by the remote collector, not this poller, so
	// without this sweep they would silently flip offline in the UI with NO
	// DEVICE_OFFLINE alert and NO critical email. MarkStaleProbeDevicesOffline
	// returns the devices that transitioned online -> offline, and for each we
	// fire the alert + email path. Recovery is handled by calling
	// CheckDeviceOnline on every probe device that is back to reporting fresh
	// data — sendRecovery is a no-op unless an offline alert is actually
	// active, so this clears exactly the devices that were alerted, exactly
	// once.
	staleAfter := 3 * p.cfg.SNMP.PollInterval
	if staleAfter < 5*time.Minute {
		staleAfter = 5 * time.Minute
	}
	threshold := time.Now().Add(-staleAfter)
	staleDevices, err := p.db.MarkStaleProbeDevicesOffline(threshold)
	if err != nil {
		log.Printf("Stale device check error: %v", err)
	} else if len(staleDevices) > 0 {
		log.Printf("Marked %d probe-assigned device(s) offline (no data for >%v)", len(staleDevices), staleAfter)
		for i := range staleDevices {
			dev := &staleDevices[i]
			if p.alertManager != nil {
				p.alertManager.CheckDeviceOffline(dev)
				p.sendCriticalAlertEmail(dev, "DEVICE_OFFLINE",
					fmt.Sprintf("Device %s (%s) is offline (no data from its probe for >%v)", dev.Name, dev.IPAddress, staleAfter))
			}
		}
	}

	// Same staleness sweep for the PROBES themselves. A probe's status was
	// stored and never re-derived, so a probe whose collector stopped
	// heartbeating (crash, restart into a bad state, network cut) stayed
	// "online" in the UI indefinitely — even while its devices correctly flipped
	// offline above. Flip it to offline on the same threshold so the fleet view
	// is truthful. (Its devices already drive the DEVICE_OFFLINE alerts.)
	staleProbes, perr := p.db.MarkStaleProbesOffline(threshold)
	if perr != nil {
		log.Printf("Stale probe check error: %v", perr)
	} else if len(staleProbes) > 0 {
		names := make([]string, len(staleProbes))
		for i := range staleProbes {
			names[i] = staleProbes[i].Name
		}
		log.Printf("Marked %d probe(s) offline (no heartbeat for >%v): %s", len(staleProbes), staleAfter, strings.Join(names, ", "))
	}

	// Terminally expire probe commands whose TTL passed while their probe was
	// offline or pre-v4 (ClaimProbeCommands only expires per-probe on a v4
	// heartbeat, so those would otherwise sit non-terminal forever).
	if n, cerr := p.db.ExpireStaleProbeCommands(); cerr != nil {
		log.Printf("Expire stale probe commands error: %v", cerr)
	} else if n > 0 {
		log.Printf("Expired %d stale probe command(s) past TTL", n)
	}

	// Recovery: any probe device that is reporting fresh data clears its
	// (possibly) active offline alert. CheckDeviceOnline -> sendRecovery
	// returns immediately when no offline alert is active, so iterating every
	// fresh probe device each cycle is cheap.
	if p.alertManager != nil {
		for i := range devices {
			dev := &devices[i]
			if dev.ProbeID == nil || !dev.Enabled {
				continue
			}
			if dev.LastPolled.After(threshold) {
				p.alertManager.CheckDeviceOnline(dev)
			}
		}
	}

	// Telemetry alert checks over the latest collector-relayed rows — the
	// re-home of the checks that lived inside the retired direct-poll path.
	p.checkRelayedTelemetry(devices, staleAfter)

	// Auto-detect connections — record cycle start BEFORE all detectors
	// so the stale cleanup doesn't delete connections from the first detector.
	connCycleStart := time.Now()
	vpnCount := p.detectVPNConnections(devices)
	overlayCount := p.detectOverlayConnections(devices)
	physCount := p.detectPhysicalConnections(devices)

	// Clean up auto-detected connections not refreshed by any detector.
	// Only run cleanup if at least one detector found connections — otherwise
	// a transient failure (DB error, empty data) would wipe all existing connections.
	if p.db != nil && (vpnCount+overlayCount+physCount) > 0 {
		removed := p.db.CleanupStaleAutoConnectionsBefore(connCycleStart)
		if removed > 0 {
			log.Printf("Connection cleanup: removed %d stale auto-detected connection(s)", removed)
		}
	} else if p.db != nil {
		log.Printf("Connection detection: all detectors found 0 connections, skipping stale cleanup to preserve existing data")
	}

	// Check for alert escalations and probe data flow monitoring
	if p.alertManager != nil {
		p.alertManager.CheckEscalations()
		p.alertManager.CheckProbeDataFlow()
	}
}

// checkRelayedTelemetry runs the telemetry alert checks that previously lived
// inside the retired direct device-SNMP poll (v0.11.74): CPU/memory/disk/
// session thresholds (CheckSystemStatus), interface down (CheckInterfaceStatus),
// interface error/discard deltas (CheckInterfaceErrors), VPN tunnel down
// (CheckVPNStatus), and sustained traffic-spike detection. It evaluates the
// latest collector-relayed DB rows instead of live SNMP responses; the check
// functions themselves are source-agnostic, so this is a data-plumbing change,
// not an alert-logic change.
//
// Two guards protect the delta/staleness semantics:
//   - freshness gate: rows older than staleAfter (the same 3×PollInterval /
//     5-minute-floor value the stale-device sweep uses) are skipped, so a dead
//     device's final sample can't keep re-alerting forever;
//   - same-sample guard: interfaces whose latest row timestamp equals the
//     cached prevIfaceStats entry's are excluded from the delta consumers
//     (CheckInterfaceErrors, spike detection) — the poller ticks at roughly
//     the collector's cadence, so re-reading an unchanged snapshot would feed
//     a bogus 0-delta into the spike sustain window. prevIfaceStats is
//     overwritten only AFTER processing, and spike elapsed time comes from row
//     timestamps, never time.Now().
func (p *Poller) checkRelayedTelemetry(devices []models.Device, staleAfter time.Duration) {
	if p.db == nil {
		return
	}
	cutoff := time.Now().Add(-staleAfter)

	// Only enabled devices are evaluated; rows from unknown/disabled devices
	// are skipped (deleted devices keep orphaned telemetry by design).
	devByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		if devices[i].Enabled {
			devByID[devices[i].ID] = &devices[i]
		}
	}

	// System status: CPU / memory / disk / session thresholds. The query is
	// bounded to fresh rows in SQL, so the freshness gate is implicit here.
	freshStatus := make(map[uint]bool)
	statusQueryOK := false
	if p.alertManager != nil {
		statuses, err := p.db.GetAllLatestSystemStatuses(cutoff)
		if err != nil {
			log.Printf("Telemetry check: failed to get system statuses - %v", err)
		} else {
			statusQueryOK = true
			for i := range statuses {
				dev, ok := devByID[statuses[i].DeviceID]
				if !ok {
					continue
				}
				freshStatus[statuses[i].DeviceID] = true
				if err := p.alertManager.CheckSystemStatus(&statuses[i], dev.SiteID); err != nil {
					log.Printf("Device %s: alert check error - %v", dev.Name, err)
				}
			}
		}
	}

	// Interfaces: down/error/spike checks over the latest snapshot per device.
	ifaces, err := p.db.GetAllLatestInterfaces()
	if err != nil {
		log.Printf("Telemetry check: failed to get interfaces - %v", err)
		ifaces = nil
	}
	ifacesByDevice := make(map[uint][]models.InterfaceStats)
	for _, iface := range ifaces {
		if iface.Timestamp.Before(cutoff) {
			continue // freshness gate: stale snapshot, device stopped reporting
		}
		if _, ok := devByID[iface.DeviceID]; !ok {
			continue
		}
		ifacesByDevice[iface.DeviceID] = append(ifacesByDevice[iface.DeviceID], iface)
	}
	for devID, devIfaces := range ifacesByDevice {
		device := devByID[devID]

		// Same-sample guard: exclude interfaces whose snapshot was already
		// processed (row timestamp == cached previous entry's timestamp) from
		// the delta consumers below.
		p.ifaceStatsMu.RLock()
		newSamples := make([]models.InterfaceStats, 0, len(devIfaces))
		for _, iface := range devIfaces {
			prev := p.prevIfaceStats[fmt.Sprintf("%d_%s", iface.DeviceID, iface.Name)]
			if prev != nil && prev.Timestamp.Equal(iface.Timestamp) {
				continue
			}
			newSamples = append(newSamples, iface)
		}
		p.ifaceStatsMu.RUnlock()

		if p.alertManager != nil {
			// Interface down/up is level state, not a delta — evaluate the
			// full fresh snapshot (a repeated sample can't corrupt it, and the
			// recovery path must keep seeing "up" rows).
			if err := p.alertManager.CheckInterfaceStatus(devIfaces, device.SiteID); err != nil {
				log.Printf("Device %s: interface alert check error - %v", device.Name, err)
			}
			// Check interface error/discard rates (delta vs prevIfaceStats)
			p.ifaceStatsMu.RLock()
			if err := p.alertManager.CheckInterfaceErrors(newSamples, p.prevIfaceStats, device.SiteID); err != nil {
				log.Printf("Device %s: interface error check error - %v", device.Name, err)
			}
			p.ifaceStatsMu.RUnlock()
		}

		// Real-time spike detection on interface traffic. Throughput is derived
		// from counter deltas (NOT raw cumulative counters), judged against a
		// seasonal (weekday, hour) baseline, and only alerted once it has been
		// sustained for SpikeMinDurationMinutes — so recurring/scheduled traffic
		// and momentary blips don't cause alert panic.
		if p.cfg.Alerts.SpikeAlertEnabled && p.spikeDetector != nil {
			k := p.cfg.Alerts.SpikeStdDevThreshold
			if k <= 0 {
				k = 3.0
			}
			minDur := time.Duration(p.cfg.Alerts.SpikeMinDurationMinutes) * time.Minute
			if minDur <= 0 {
				minDur = 15 * time.Minute
			}
			for i := range newSamples {
				iface := &newSamples[i]
				if iface.Status != "up" {
					continue
				}
				p.ifaceStatsMu.RLock()
				prev := p.prevIfaceStats[fmt.Sprintf("%d_%s", iface.DeviceID, iface.Name)]
				var prevBytes float64
				var prevTS time.Time
				hasPrev := prev != nil
				if hasPrev {
					prevBytes = float64(prev.InBytes + prev.OutBytes)
					prevTS = prev.Timestamp
				}
				p.ifaceStatsMu.RUnlock()
				if !hasPrev {
					continue // need a prior sample to derive throughput
				}
				elapsed := iface.Timestamp.Sub(prevTS).Seconds()
				if elapsed <= 0 {
					continue
				}
				delta := float64(iface.InBytes+iface.OutBytes) - prevBytes
				if delta < 0 {
					delta = 0 // counter reset / wrap
				}
				bps := delta * 8 / elapsed

				dec := p.spikeDetector.Observe(fmt.Sprintf("%d:%d", iface.DeviceID, iface.Index), iface.Timestamp, bps, k, minDur)
				switch {
				case dec.Fire:
					p.emitSpikeAlert(device, iface, dec)
				case dec.Resolve:
					p.emitSpikeResolve(device, iface)
				}
			}
		}

		// Store the processed samples as previous for the next cycle — AFTER
		// the delta consumers, and only for samples that were actually new, so
		// a repeated snapshot never re-stamps the baseline.
		p.ifaceStatsMu.Lock()
		for i := range newSamples {
			key := fmt.Sprintf("%d_%s", newSamples[i].DeviceID, newSamples[i].Name)
			iface := newSamples[i]
			p.prevIfaceStats[key] = &iface
		}
		p.ifaceStatsMu.Unlock()
	}

	// VPN tunnel status (down alerts + up recovery).
	if p.alertManager != nil {
		vpns, err := p.db.GetAllLatestVPNStatuses()
		if err != nil {
			log.Printf("Telemetry check: failed to get VPN statuses - %v", err)
			return
		}
		vpnsByDevice := make(map[uint][]models.VPNStatus)
		for _, vpn := range vpns {
			if vpn.Timestamp.Before(cutoff) {
				continue // freshness gate
			}
			if _, ok := devByID[vpn.DeviceID]; !ok {
				continue
			}
			vpnsByDevice[vpn.DeviceID] = append(vpnsByDevice[vpn.DeviceID], vpn)
		}
		for devID, devVPNs := range vpnsByDevice {
			p.alertManager.CheckVPNStatus(devVPNs, devByID[devID].SiteID)
		}
	}

	// Visibility: a device the server still considers online but for which no
	// fresh telemetry exists means its rows were all excluded by the freshness
	// gate — the likely cause is collector/server clock skew, which would
	// silently disable every threshold check here. Surface it once per cycle
	// rather than failing silent.
	if statusQueryOK {
		var stale int
		for id, dev := range devByID {
			if dev.Status == "online" && !freshStatus[id] {
				stale++
			}
		}
		if stale > 0 {
			log.Printf("Telemetry check: %d online device(s) had no system_status within %v — check collector NTP/clock skew", stale, staleAfter)
		}
	}
}

// pruneStaleIfaceStats removes previous-interface-stats entries that have not
// been refreshed within ttl. Live interfaces re-stamp their entry every poll
// cycle, so anything older belongs to a device or interface that is no longer
// polled and would otherwise accumulate in the map for the life of the process.
func (p *Poller) pruneStaleIfaceStats(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl)
	p.ifaceStatsMu.Lock()
	defer p.ifaceStatsMu.Unlock()
	for key, st := range p.prevIfaceStats {
		if st == nil || st.Timestamp.Before(cutoff) {
			delete(p.prevIfaceStats, key)
		}
	}
}

// detectVPNConnections matches VPN tunnel remote IPs to known device IPs
// (management IP + all interface addresses) and auto-creates/updates DeviceConnection records.
// Returns the number of connection pairs processed.
func (p *Poller) detectVPNConnections(devices []models.Device) int {
	if p.db == nil || len(devices) == 0 {
		return 0
	}

	// Build IP → Device map from management IPs
	ipToDevice := make(map[string]*models.Device, len(devices)*2)
	ipSource := make(map[string]string) // IP → "mgmt" or "interface"
	deviceByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		ipToDevice[devices[i].IPAddress] = &devices[i]
		ipSource[devices[i].IPAddress] = "mgmt"
		deviceByID[devices[i].ID] = &devices[i]
	}

	// Extend IP map with all interface addresses from IP-MIB
	ifAddrs, err := p.db.GetLatestInterfaceAddresses()
	if err != nil {
		log.Printf("VPN auto-detect: failed to get interface addresses - %v", err)
	} else {
		for _, addr := range ifAddrs {
			if _, exists := ipToDevice[addr.IPAddress]; exists {
				continue // management IP already mapped, keep it
			}
			if dev, ok := deviceByID[addr.DeviceID]; ok {
				ipToDevice[addr.IPAddress] = dev
				ipSource[addr.IPAddress] = "interface"
			}
		}
	}

	vpnStatuses, err := p.db.GetAllLatestVPNStatuses()
	if err != nil {
		log.Printf("VPN auto-detect: failed to get VPN statuses - %v", err)
		return 0
	}
	// NB: do NOT early-return when vpnStatuses is empty. Dial-up/interface-mode
	// spokes expose no fgVpnTunTable rows, so the remote-gateway strategies below
	// no-op for them — but the tunnel-overlay phase further down still maps them
	// from the IP-MIB tunnel-interface addresses, which are always present.

	// Index VPN tunnels by device ID for bidirectional checking
	vpnByDevice := make(map[uint][]models.VPNStatus)
	for _, vpn := range vpnStatuses {
		vpnByDevice[vpn.DeviceID] = append(vpnByDevice[vpn.DeviceID], vpn)
	}

	// pairKey returns a normalized key for a device pair (lower ID first)
	pairKey := func(a, b uint) string {
		if a > b {
			a, b = b, a
		}
		return fmt.Sprintf("%d:%d", a, b)
	}

	type pairInfo struct {
		sourceID    uint
		destID      uint
		tunnelNames map[string]bool
		anyUp       bool
		matchMethod string
		connType    string
		sides       int // how many sides have a matching tunnel (1=unidirectional, 2=bidirectional)
	}

	pairs := make(map[string]*pairInfo)

	for _, vpn := range vpnStatuses {
		remoteDevice, ok := ipToDevice[vpn.RemoteIP]
		if !ok {
			continue
		}
		if remoteDevice.ID == vpn.DeviceID {
			continue // skip self-referencing
		}

		key := pairKey(vpn.DeviceID, remoteDevice.ID)
		pi, exists := pairs[key]
		if !exists {
			srcID, dstID := vpn.DeviceID, remoteDevice.ID
			if srcID > dstID {
				srcID, dstID = dstID, srcID
			}
			// Determine match method based on how the IP was found
			method := "ip_match"
			if ipSource[vpn.RemoteIP] == "interface" {
				method = "interface_ip"
			}
			// Determine connection type from tunnel type
			ct := "ipsec"
			if vpn.TunnelType == "sslvpn" {
				ct = "ssl"
			}
			pi = &pairInfo{
				sourceID:    srcID,
				destID:      dstID,
				tunnelNames: make(map[string]bool),
				matchMethod: method,
				connType:    ct,
				sides:       0,
			}
			pairs[key] = pi
		}
		if vpn.TunnelName != "" {
			pi.tunnelNames[vpn.TunnelName] = true
		}
		if vpn.Status == "up" {
			pi.anyUp = true
		}
		// Upgrade connection type if we see SSL
		if vpn.TunnelType == "sslvpn" {
			pi.connType = "ssl"
		}
		// Upgrade match method if this side is via interface IP
		if ipSource[vpn.RemoteIP] == "interface" && pi.matchMethod == "ip_match" {
			pi.matchMethod = "interface_ip"
		}
	}

	// Phase 2: Indirect matching for NAT'd tunnels.
	// When a VPN tunnel's remote_ip doesn't resolve to any known device IP (common with
	// NAT'd IPSec), try matching the tunnel name against device names.
	// e.g., tunnel "NUDAY_LAN" on DC2-FW1 contains "nuday" → matches device "NUDAY-FW".
	deviceNameParts := make(map[uint][]string, len(devices))
	for i := range devices {
		name := strings.ToLower(devices[i].Name)
		parts := strings.FieldsFunc(name, func(r rune) bool {
			return r == '-' || r == '_' || r == '.' || r == ' '
		})
		for _, p := range parts {
			if len(p) >= 4 { // only meaningful parts (skip fw, gw, dc, etc.)
				deviceNameParts[devices[i].ID] = append(deviceNameParts[devices[i].ID], p)
			}
		}
	}

	for _, vpn := range vpnStatuses {
		if _, resolved := ipToDevice[vpn.RemoteIP]; resolved {
			continue // already matched in first pass
		}
		if vpn.DeviceID == 0 || vpn.TunnelName == "" {
			continue
		}
		tunnelNorm := strings.ToLower(strings.NewReplacer(" ", "", ".", "", "-", "", "_", "").Replace(vpn.TunnelName))

		for _, dev := range devices {
			if dev.ID == vpn.DeviceID {
				continue
			}
			matched := false
			for _, namePart := range deviceNameParts[dev.ID] {
				if strings.Contains(tunnelNorm, namePart) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			key := pairKey(vpn.DeviceID, dev.ID)
			pi, exists := pairs[key]
			if !exists {
				srcID, dstID := vpn.DeviceID, dev.ID
				if srcID > dstID {
					srcID, dstID = dstID, srcID
				}
				ct := "ipsec"
				if vpn.TunnelType == "sslvpn" {
					ct = "ssl"
				}
				pi = &pairInfo{
					sourceID:    srcID,
					destID:      dstID,
					tunnelNames: make(map[string]bool),
					matchMethod: "tunnel_indirect",
					connType:    ct,
				}
				pairs[key] = pi
			}
			pi.tunnelNames[vpn.TunnelName] = true
			if vpn.Status == "up" {
				pi.anyUp = true
			}
			break // found match for this tunnel, move on
		}
	}

	// Bidirectional check: for each pair, see if both sides have tunnels pointing at each other
	for _, pi := range pairs {
		srcTunnels := vpnByDevice[pi.sourceID]
		dstTunnels := vpnByDevice[pi.destID]
		srcPointsToDst := false
		dstPointsToSrc := false

		for _, t := range srcTunnels {
			if rd, ok := ipToDevice[t.RemoteIP]; ok && rd.ID == pi.destID {
				srcPointsToDst = true
				break
			}
		}
		for _, t := range dstTunnels {
			if rd, ok := ipToDevice[t.RemoteIP]; ok && rd.ID == pi.sourceID {
				dstPointsToSrc = true
				break
			}
		}

		if srcPointsToDst && dstPointsToSrc {
			pi.matchMethod = "bidirectional"
		}
	}

	// Phase 3: WAN IP inference from matched pairs.
	// For NAT'd hub-spoke VPNs, infer WAN IPs from established pairs:
	// If src has a tunnel pointing to remoteIP X and we matched it to dest,
	// then X is dest's WAN IP. Similarly in reverse. Then re-scan unmatched tunnels.
	inferredIPs := make(map[uint]map[string]bool) // deviceID → set of inferred WAN IPs
	for _, pi := range pairs {
		for _, t := range vpnByDevice[pi.sourceID] {
			// If this tunnel's remote IP resolves to the dest device, it's the dest's WAN IP
			if rd, ok := ipToDevice[t.RemoteIP]; ok && rd.ID == pi.destID {
				if inferredIPs[pi.destID] == nil {
					inferredIPs[pi.destID] = make(map[string]bool)
				}
				inferredIPs[pi.destID][t.RemoteIP] = true
			}
		}
		for _, t := range vpnByDevice[pi.destID] {
			if rd, ok := ipToDevice[t.RemoteIP]; ok && rd.ID == pi.sourceID {
				if inferredIPs[pi.sourceID] == nil {
					inferredIPs[pi.sourceID] = make(map[string]bool)
				}
				inferredIPs[pi.sourceID][t.RemoteIP] = true
			}
		}
	}

	// Also infer from indirect matches: if src tunnel matched dest by name,
	// the tunnel's remote IP is the dest's WAN, and vice versa.
	for _, pi := range pairs {
		for _, t := range vpnByDevice[pi.sourceID] {
			if pi.tunnelNames[t.TunnelName] && t.RemoteIP != "" {
				if _, known := ipToDevice[t.RemoteIP]; !known {
					if inferredIPs[pi.destID] == nil {
						inferredIPs[pi.destID] = make(map[string]bool)
					}
					inferredIPs[pi.destID][t.RemoteIP] = true
				}
			}
		}
		for _, t := range vpnByDevice[pi.destID] {
			if pi.tunnelNames[t.TunnelName] && t.RemoteIP != "" {
				if _, known := ipToDevice[t.RemoteIP]; !known {
					if inferredIPs[pi.sourceID] == nil {
						inferredIPs[pi.sourceID] = make(map[string]bool)
					}
					inferredIPs[pi.sourceID][t.RemoteIP] = true
				}
			}
		}
	}

	// Re-scan previously unmatched tunnels using inferred WAN IPs
	if len(inferredIPs) > 0 {
		for _, vpn := range vpnStatuses {
			if vpn.DeviceID == 0 || vpn.RemoteIP == "" {
				continue
			}
			// Skip if already resolved by direct IP match
			if _, resolved := ipToDevice[vpn.RemoteIP]; resolved {
				continue
			}
			// Check if remote IP matches any device's inferred WAN IP
			for devID, wanIPs := range inferredIPs {
				if devID == vpn.DeviceID {
					continue
				}
				if !wanIPs[vpn.RemoteIP] {
					continue
				}
				// This tunnel's remote IP matches an inferred WAN IP of devID
				key := pairKey(vpn.DeviceID, devID)
				pi, exists := pairs[key]
				if !exists {
					srcID, dstID := vpn.DeviceID, devID
					if srcID > dstID {
						srcID, dstID = dstID, srcID
					}
					ct := "ipsec"
					if vpn.TunnelType == "sslvpn" {
						ct = "ssl"
					}
					pi = &pairInfo{
						sourceID:    srcID,
						destID:      dstID,
						tunnelNames: make(map[string]bool),
						matchMethod: "wan_inferred",
						connType:    ct,
					}
					pairs[key] = pi
				}
				pi.tunnelNames[vpn.TunnelName] = true
				if vpn.Status == "up" {
					pi.anyUp = true
				}
				break
			}
		}
	}

	// Phase 4: tunnel-interface overlay matching.
	// The strategies above all key on a tunnel's remote-gateway IP (fgVpnTunTable),
	// which is frequently empty — interface-mode/dial-up spokes expose no rows, so
	// hub-and-spoke IPSec goes undetected. The tunnel interfaces themselves, though,
	// reliably carry an overlay IP in the standard IP-MIB (a hub e.g.
	// 192.168.255.1/24, each spoke 192.168.255.x/32). Two devices whose tunnel
	// interfaces share an overlay subnet are IPSec-connected, so match a spoke's
	// address inside a hub's tunnel network. This is cross-site by nature (no
	// same-site guard) and complements, never overrides, the pairs found above.
	if ifaces, ifErr := p.db.GetAllLatestInterfaces(); ifErr != nil {
		log.Printf("VPN auto-detect: failed to get interfaces for tunnel-overlay match - %v", ifErr)
	} else {
		type tunIf struct{ name, status string }
		tunnelIface := make(map[string]tunIf) // "deviceID:ifIndex" → tunnel interface
		for _, iface := range ifaces {
			if strings.EqualFold(iface.TypeName, "tunnel") {
				tunnelIface[fmt.Sprintf("%d:%d", iface.DeviceID, iface.Index)] = tunIf{iface.Name, iface.Status}
			}
		}
		type tunAddr struct {
			deviceID uint
			ip       net.IP
			network  *net.IPNet
			name     string
			up       bool
		}
		var tunAddrs []tunAddr
		for _, addr := range ifAddrs {
			tif, ok := tunnelIface[fmt.Sprintf("%d:%d", addr.DeviceID, addr.IfIndex)]
			if !ok || isFabricInterface("", addr.IPAddress) {
				continue
			}
			ip := net.ParseIP(addr.IPAddress)
			mask := net.ParseIP(addr.NetMask)
			if ip == nil || mask == nil {
				continue
			}
			ip4, mask4 := ip.To4(), mask.To4()
			if ip4 == nil || mask4 == nil {
				continue
			}
			tunAddrs = append(tunAddrs, tunAddr{
				deviceID: addr.DeviceID,
				ip:       ip4,
				network:  &net.IPNet{IP: ip4.Mask(net.IPMask(mask4)), Mask: net.IPMask(mask4)},
				name:     tif.name,
				up:       tif.status == "up",
			})
		}
		for i := 0; i < len(tunAddrs); i++ {
			for j := i + 1; j < len(tunAddrs); j++ {
				a, b := tunAddrs[i], tunAddrs[j]
				if a.deviceID == b.deviceID {
					continue
				}
				// Same overlay if either address sits inside the other's subnet
				// (hub /24 contains spoke /32). Two distinct /32 spokes never
				// contain each other, so they are not falsely linked to each other.
				if !a.network.Contains(b.ip) && !b.network.Contains(a.ip) {
					continue
				}
				key := pairKey(a.deviceID, b.deviceID)
				if _, exists := pairs[key]; exists {
					continue // already matched by a remote-gateway strategy
				}
				srcID, dstID := a.deviceID, b.deviceID
				if srcID > dstID {
					srcID, dstID = dstID, srcID
				}
				pi := &pairInfo{
					sourceID:    srcID,
					destID:      dstID,
					tunnelNames: make(map[string]bool),
					matchMethod: "tunnel_overlay",
					connType:    "ipsec",
					anyUp:       a.up || b.up,
				}
				if a.name != "" {
					pi.tunnelNames[a.name] = true
				}
				if b.name != "" {
					pi.tunnelNames[b.name] = true
				}
				pairs[key] = pi
			}
		}
	}

	for _, pi := range pairs {
		status := "down"
		if pi.anyUp {
			status = "up"
		}

		// Collect and sort tunnel names
		names := make([]string, 0, len(pi.tunnelNames))
		for n := range pi.tunnelNames {
			names = append(names, n)
		}
		sort.Strings(names)
		tunnelNames := strings.Join(names, ", ")

		// Build a descriptive connection name
		srcName, dstName := "?", "?"
		if d, ok := deviceByID[pi.sourceID]; ok {
			srcName = d.Name
		}
		if d, ok := deviceByID[pi.destID]; ok {
			dstName = d.Name
		}
		connName := fmt.Sprintf("%s ↔ %s", srcName, dstName)

		// Get Phase 2 subnets from peer devices
		// If a tunnel is missing subnets on one side (e.g., HUB), try to get from peer
		srcTunnels := vpnByDevice[pi.sourceID]
		dstTunnels := vpnByDevice[pi.destID]

		// Find matching tunnels by name and collect Phase 2 info from both sides
		var localSubnet, remoteSubnet string
		for _, st := range srcTunnels {
			if pi.tunnelNames[st.TunnelName] && st.LocalSubnet != "" {
				localSubnet = st.LocalSubnet
				break
			}
		}
		for _, dt := range dstTunnels {
			if pi.tunnelNames[dt.TunnelName] && dt.RemoteSubnet != "" {
				remoteSubnet = dt.RemoteSubnet
				break
			}
		}
		// If still missing, swap: get remote from source and local from dest
		if remoteSubnet == "" {
			for _, st := range srcTunnels {
				if pi.tunnelNames[st.TunnelName] && st.RemoteSubnet != "" {
					remoteSubnet = st.RemoteSubnet
					break
				}
			}
		}
		if localSubnet == "" {
			for _, dt := range dstTunnels {
				if pi.tunnelNames[dt.TunnelName] && dt.LocalSubnet != "" {
					localSubnet = dt.LocalSubnet
					break
				}
			}
		}

		if localSubnet != "" && remoteSubnet != "" {
			log.Printf("Device %s: Phase2: local=%s remote=%s for connection %s", srcName, localSubnet, remoteSubnet, connName)
		}

		if err := p.db.UpsertAutoConnection(pi.sourceID, pi.destID, status, tunnelNames, connName, pi.connType, pi.matchMethod); err != nil {
			log.Printf("VPN auto-detect: failed to upsert connection %s - %v", connName, err)
		}
	}

	if len(pairs) > 0 {
		log.Printf("VPN auto-detect: processed %d connection(s) across %d devices", len(pairs), len(devices))
	}
	return len(pairs)
}

// detectOverlayConnections finds matching overlay/local interfaces across devices and
// creates auto-detected connections. Only handles L2VLAN, L3IPVLAN, and VXLAN types.
// Tunnel/IPSec/GRE connections are handled exclusively by detectVPNConnections which
// uses actual VPN tunnel data (IPs, status) rather than name matching.
func (p *Poller) detectOverlayConnections(devices []models.Device) int {
	if p.db == nil || len(devices) == 0 {
		return 0
	}

	ifaces, err := p.db.GetAllLatestInterfaces()
	if err != nil {
		log.Printf("Overlay auto-detect: failed to get interfaces - %v", err)
		return 0
	}

	deviceByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		deviceByID[devices[i].ID] = &devices[i]
	}

	deviceVxlanInterfaces := make(map[uint]map[string]bool)
	for _, dev := range devices {
		if strings.ToLower(dev.Vendor) == "fortigate" {
			rev, err := p.db.GetLatestConfigRevision(dev.ID)
			if err == nil && rev != nil && rev.ConfigText != "" {
				vxlans := snmp.ParseFortiGateVxlanConfig(rev.ConfigText)
				if len(vxlans) > 0 {
					ifaceMap := make(map[string]bool)
					for _, v := range vxlans {
						ifaceMap[v.Name] = true
					}
					deviceVxlanInterfaces[dev.ID] = ifaceMap
				}
			}
		}
	}

	sameSite := func(devA, devB uint) bool {
		da, oa := deviceByID[devA]
		db, ob := deviceByID[devB]
		if !oa || !ob || da.SiteID == nil || db.SiteID == nil {
			return false
		}
		return *da.SiteID == *db.SiteID
	}

	// Build IP → device ID map for direct-link verification
	ipToDeviceID := make(map[string]uint, len(devices)*4)
	for i := range devices {
		if devices[i].IPAddress != "" {
			ipToDeviceID[devices[i].IPAddress] = devices[i].ID
		}
	}
	ifAddrs, _ := p.db.GetLatestInterfaceAddresses()
	for _, addr := range ifAddrs {
		if _, exists := ipToDeviceID[addr.IPAddress]; !exists {
			ipToDeviceID[addr.IPAddress] = addr.DeviceID
		}
	}

	// Load VPN tunnel data to verify direct links
	vpnStatuses, _ := p.db.GetAllLatestVPNStatuses()
	// Build set of device pairs with verified direct VPN links (remote IP points to other device)
	vpnByDevice := make(map[uint][]models.VPNStatus)
	for _, vpn := range vpnStatuses {
		vpnByDevice[vpn.DeviceID] = append(vpnByDevice[vpn.DeviceID], vpn)
	}

	hasDirectLink := func(devA, devB uint) bool {
		// Check if device A has an UP VPN tunnel pointing to device B's IP
		for _, t := range vpnByDevice[devA] {
			if t.Status != "up" {
				continue
			}
			if did, ok := ipToDeviceID[t.RemoteIP]; ok && did == devB {
				return true
			}
		}
		// Check if device B has an UP VPN tunnel pointing to device A's IP
		for _, t := range vpnByDevice[devB] {
			if t.Status != "up" {
				continue
			}
			if did, ok := ipToDeviceID[t.RemoteIP]; ok && did == devA {
				return true
			}
		}
		// Fallback: check if detectVPNConnections already created a tunnel/ipsec connection
		// that is UP (handles NAT'd tunnels matched via tunnel_indirect method)
		if p.db != nil {
			for _, ct := range []string{"ipsec", "gre", "tunnel", "ssl"} {
				conn, _ := p.db.FindConnectionByDevicePairAndType(devA, devB, ct)
				if conn != nil && conn.Status == "up" {
					return true
				}
			}
		}
		return false
	}

	// Common names to skip (too generic — present on every device).
	// Values are normalized (lowercase, no separators) to match normalizeIfName output.
	skipNames := map[string]bool{
		"loopback0": true, "lo": true, "lo0": true,
		"mgmt": true, "mgmt0": true, "management": true,
		"null0": true, "": true,
		// FortiLink (firewall <-> FortiSwitch fabric) is named identically on
		// every FortiGate, so name-matching would falsely connect any two units.
		"fortilink": true,
	}
	// FortiGate system interfaces follow *.root / *.vdom pattern — skip all of them
	isSystemIface := func(normalized string) bool {
		return strings.HasSuffix(normalized, "root") || strings.HasSuffix(normalized, "vdom")
	}

	// Only overlay and local interface types — tunnel carriers (ipsec, gre, etc.)
	// are handled exclusively by detectVPNConnections using actual VPN data.
	overlayTypes := map[string]bool{
		"l2vlan": true, "l3ipvlan": true, "vxlan": true, "bridge": true,
	}

	// Validation: ALL overlay types require a direct VPN tunnel between endpoints
	// normalizeIfName strips formatting differences so vlan500, vlan 500,
	// vlan.500, vlan-500, vlan_500, VLAN500 all match as "vlan500".
	normalizeIfName := func(name string) string {
		n := strings.ToLower(strings.TrimSpace(name))
		return strings.NewReplacer(" ", "", ".", "", "-", "", "_", "").Replace(n)
	}

	// Use device-reported type directly - if devices report different types, just use whichever
	pairConnType := func(typeA, typeB string) string {
		a := strings.ToLower(typeA)
		if a != "" {
			return a
		}
		return strings.ToLower(typeB)
	}

	type ifEntry struct {
		deviceID uint
		name     string
		typeName string
		status   string
	}
	nameGroups := make(map[string][]ifEntry)

	for _, iface := range ifaces {
		// Accept overlay/local interface types, or vxlan-prefixed names
		tn := strings.ToLower(iface.TypeName)
		isOverlayType := overlayTypes[tn]
		isVxlanName := strings.HasPrefix(strings.ToLower(iface.Name), "vxlan")
		if !isOverlayType && !isVxlanName {
			continue
		}
		normalized := normalizeIfName(iface.Name)
		if skipNames[normalized] || isSystemIface(normalized) {
			continue
		}
		effectiveType := iface.TypeName

		// Check if this is a verified VXLAN interface from config
		if vxlanMap, ok := deviceVxlanInterfaces[iface.DeviceID]; ok && vxlanMap[iface.Name] {
			// This interface is defined as a true VXLAN in FortiGate config
			effectiveType = "vxlan"
		} else if isVxlanName {
			// vxlan-prefixed name but not verified as true VXLAN from config
			// FortiGate reports these as "bridge" (ifType 209) - treat as L2VLAN extension
			effectiveType = "l2vlan"
		}

		nameGroups[normalized] = append(nameGroups[normalized], ifEntry{
			deviceID: iface.DeviceID,
			name:     iface.Name,
			typeName: effectiveType,
			status:   iface.Status,
		})
	}

	pairKey := func(a, b uint) string {
		if a > b {
			a, b = b, a
		}
		return fmt.Sprintf("%d:%d", a, b)
	}

	// Accumulator: collect all matching interface names per device-pair + connection type
	type overlayPairInfo struct {
		sourceID uint
		destID   uint
		connType string
		ifNames  map[string]bool // all matching interface names
		anyUp    bool
	}
	pairAccum := make(map[string]*overlayPairInfo)

	// Pass 1: accumulate interface names across all nameGroups
	for _, entries := range nameGroups {
		// Deduplicate by device
		seen := make(map[uint]*ifEntry)
		for i := range entries {
			if _, ok := seen[entries[i].deviceID]; !ok {
				seen[entries[i].deviceID] = &entries[i]
			}
		}
		if len(seen) < 2 {
			continue
		}

		deviceList := make([]*ifEntry, 0, len(seen))
		for _, e := range seen {
			deviceList = append(deviceList, e)
		}

		// Validation: Overlay connection requirements:
		// - L2VLAN between same-site devices: NO VPN tunnel required (can use local switching)
		// Overlay connection requirements:
		// - L2VLAN: ONLY allowed between same-site devices (never cross-site)
		// - L3IPVLAN, VXLAN: Require direct VPN tunnel between endpoints
		for i := 0; i < len(deviceList); i++ {
			for j := i + 1; j < len(deviceList); j++ {
				a, b := deviceList[i], deviceList[j]
				connType := pairConnType(a.typeName, b.typeName)

				// L2VLAN is ONLY allowed between same-site devices - never cross-site
				isSameSite := sameSite(a.deviceID, b.deviceID)
				if connType == "l2vlan" || connType == "bridge" {
					if !isSameSite {
						continue // L2VLAN/bridge cannot cross sites
					}
					// Same-site L2VLAN/bridge - no VPN tunnel needed
				} else if !hasDirectLink(a.deviceID, b.deviceID) {
					// L3IPVLAN, VXLAN require VPN tunnel
					continue
				}

				key := pairKey(a.deviceID, b.deviceID) + ":" + connType
				pi, exists := pairAccum[key]
				if !exists {
					srcID, dstID := a.deviceID, b.deviceID
					if srcID > dstID {
						srcID, dstID = dstID, srcID
					}
					pi = &overlayPairInfo{
						sourceID: srcID,
						destID:   dstID,
						connType: connType,
						ifNames:  make(map[string]bool),
					}
					pairAccum[key] = pi
				}
				// Record BOTH endpoints' interface names so the connection
				// detail can resolve and pair each side. Storing only a.name
				// (the historic behavior) left the peer's interface — and thus
				// the far end of the link — unresolvable when the two devices
				// name the interface differently (e.g. vlan100 vs VLAN-100).
				pi.ifNames[a.name] = true
				pi.ifNames[b.name] = true
				if a.status == "up" && b.status == "up" {
					pi.anyUp = true
				}
			}
		}
	}

	// Pass 2: upsert once per pair with full comma-separated interface name list
	created := 0
	for _, pi := range pairAccum {
		status := "down"
		if pi.anyUp {
			status = "up"
		}

		names := make([]string, 0, len(pi.ifNames))
		for n := range pi.ifNames {
			names = append(names, n)
		}
		sort.Strings(names)
		tunnelNames := strings.Join(names, ", ")

		srcName, dstName := "?", "?"
		if d, ok := deviceByID[pi.sourceID]; ok {
			srcName = d.Name
		}
		if d, ok := deviceByID[pi.destID]; ok {
			dstName = d.Name
		}
		connName := fmt.Sprintf("%s ↔ %s", srcName, dstName)

		if err := p.db.UpsertAutoConnection(pi.sourceID, pi.destID, status, tunnelNames, connName, pi.connType, "name_match"); err != nil {
			log.Printf("Overlay auto-detect: failed to upsert connection %s - %v", connName, err)
		} else {
			created++
		}
	}

	if created > 0 {
		log.Printf("Overlay auto-detect: upserted %d connection(s)", created)
	}
	return created
}

// isFabricInterface reports whether an interface is a device-to-fabric link that
// must never be treated as an inter-device LAN adjacency. FortiLink interfaces
// (firewall <-> FortiSwitch) are conventionally named "fortilink" and ship with
// default IPs (169.254.x, 10.255.x) that are identical on every FortiGate, so two
// same-site units would otherwise be falsely cross-connected through them. Link-
// local addresses (169.254.0.0/16, RFC 3927) are likewise never a routed
// inter-device LAN segment.
func isFabricInterface(ifName, ipAddr string) bool {
	if strings.EqualFold(strings.TrimSpace(ifName), "fortilink") {
		return true
	}
	if ip := net.ParseIP(ipAddr); ip != nil {
		if v4 := ip.To4(); v4 != nil && v4[0] == 169 && v4[1] == 254 {
			return true
		}
	}
	return false
}

// detectPhysicalConnections finds LAN-segment interfaces on same-site devices
// that share an IP subnet and creates auto-detected connections.
func (p *Poller) detectPhysicalConnections(devices []models.Device) int {
	if p.db == nil || len(devices) == 0 {
		return 0
	}

	ifaces, err := p.db.GetAllLatestInterfaces()
	if err != nil {
		log.Printf("Physical auto-detect: failed to get interfaces - %v", err)
		return 0
	}

	ifAddrs, err := p.db.GetLatestInterfaceAddresses()
	if err != nil {
		log.Printf("Physical auto-detect: failed to get interface addresses - %v", err)
		return 0
	}

	deviceByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		deviceByID[devices[i].ID] = &devices[i]
	}

	sameSite := func(devA, devB uint) bool {
		da, oa := deviceByID[devA]
		db, ob := deviceByID[devB]
		if !oa || !ob || da.SiteID == nil || db.SiteID == nil {
			return false
		}
		return *da.SiteID == *db.SiteID
	}

	// Build lookup: (DeviceID, IfIndex) → interface entry, restricted to interface
	// types that carry a LAN-segment (broadcast-domain) L3 address. On FortiGate
	// the LAN IP almost never sits on a bare Ethernet port: it lives on the
	// hardware/software switch ("internal"/"lan", reported as ifType 209 bridge)
	// or on a VLAN sub-interface (ifType 135 l2vlan); some setups use a software
	// switch/zone (ifType 53 propVirtual). All of these are valid shared-subnet
	// LAN segments, so we match on them too — not just ethernet/lag. Tunnel/GRE/
	// loopback/MPLS and the overlay-over-tunnel types (l3ipvlan, vxlan) are
	// deliberately excluded: they are point-to-point or overlay carriers, not LAN
	// segments, and are handled by the VPN/overlay detectors.
	type physIface struct {
		deviceID uint
		ifIndex  int
		name     string
		typeName string
		status   string
	}
	physicalTypes := map[string]bool{
		"ethernet":    true,
		"lag":         true,
		"bridge":      true, // FortiGate hardware/software switch (e.g. "internal")
		"l2vlan":      true, // VLAN sub-interface holding the LAN gateway IP
		"propVirtual": true, // software switch / zone
	}
	ifLookup := make(map[string]*physIface) // "deviceID:ifIndex" → entry
	for _, iface := range ifaces {
		tn := strings.ToLower(iface.TypeName)
		if !physicalTypes[tn] {
			continue
		}
		key := fmt.Sprintf("%d:%d", iface.DeviceID, iface.Index)
		ifLookup[key] = &physIface{
			deviceID: iface.DeviceID,
			ifIndex:  iface.Index,
			name:     iface.Name,
			typeName: tn,
			status:   iface.Status,
		}
	}

	// Group physical interfaces by subnet key
	type subnetEntry struct {
		iface   *physIface
		address string
	}
	subnetGroups := make(map[string][]subnetEntry)

	for _, addr := range ifAddrs {
		key := fmt.Sprintf("%d:%d", addr.DeviceID, addr.IfIndex)
		pif, ok := ifLookup[key]
		if !ok {
			continue // not a physical interface
		}
		if isFabricInterface(pif.name, addr.IPAddress) {
			continue // FortiLink/link-local fabric link, not an inter-device LAN
		}
		ip := net.ParseIP(addr.IPAddress)
		mask := net.ParseIP(addr.NetMask)
		if ip == nil || mask == nil {
			continue
		}
		ip4 := ip.To4()
		mask4 := mask.To4()
		if ip4 == nil || mask4 == nil {
			continue
		}

		// Skip /30, /31, /32 (point-to-point WAN links, not LAN segments)
		ones, bits := net.IPMask(mask4).Size()
		if bits == 32 && ones >= 30 {
			continue
		}

		network := ip4.Mask(net.IPMask(mask4))
		subnetKey := fmt.Sprintf("%s/%d", network.String(), ones)

		subnetGroups[subnetKey] = append(subnetGroups[subnetKey], subnetEntry{
			iface:   pif,
			address: addr.IPAddress,
		})
	}

	pairKey := func(a, b uint) string {
		if a > b {
			a, b = b, a
		}
		return fmt.Sprintf("%d:%d", a, b)
	}

	type physPairInfo struct {
		sourceID uint
		destID   uint
		connType string
		ifNames  map[string]bool
		anyUp    bool
	}
	pairAccum := make(map[string]*physPairInfo)

	for _, entries := range subnetGroups {
		// Deduplicate by device — collect all entries per device
		byDevice := make(map[uint][]subnetEntry)
		for _, e := range entries {
			byDevice[e.iface.deviceID] = append(byDevice[e.iface.deviceID], e)
		}
		if len(byDevice) < 2 {
			continue
		}

		deviceIDs := make([]uint, 0, len(byDevice))
		for did := range byDevice {
			deviceIDs = append(deviceIDs, did)
		}

		for i := 0; i < len(deviceIDs); i++ {
			for j := i + 1; j < len(deviceIDs); j++ {
				devA, devB := deviceIDs[i], deviceIDs[j]
				if !sameSite(devA, devB) {
					continue
				}

				// Determine connType: if either side has LAG → "lag", else "ethernet"
				connType := "ethernet"
				entriesA := byDevice[devA]
				entriesB := byDevice[devB]
				for _, e := range entriesA {
					if e.iface.typeName == "lag" {
						connType = "lag"
					}
				}
				for _, e := range entriesB {
					if e.iface.typeName == "lag" {
						connType = "lag"
					}
				}

				key := pairKey(devA, devB) + ":" + connType
				pi, exists := pairAccum[key]
				if !exists {
					srcID, dstID := devA, devB
					if srcID > dstID {
						srcID, dstID = dstID, srcID
					}
					pi = &physPairInfo{
						sourceID: srcID,
						destID:   dstID,
						connType: connType,
						ifNames:  make(map[string]bool),
					}
					pairAccum[key] = pi
				}
				for _, e := range entriesA {
					pi.ifNames[e.iface.name] = true
					if e.iface.status == "up" {
						pi.anyUp = true
					}
				}
				for _, e := range entriesB {
					pi.ifNames[e.iface.name] = true
					if e.iface.status == "up" {
						pi.anyUp = true
					}
				}
			}
		}
	}

	created := 0
	for _, pi := range pairAccum {
		status := "down"
		if pi.anyUp {
			status = "up"
		}

		names := make([]string, 0, len(pi.ifNames))
		for n := range pi.ifNames {
			names = append(names, n)
		}
		sort.Strings(names)
		tunnelNames := strings.Join(names, ", ")

		srcName, dstName := "?", "?"
		if d, ok := deviceByID[pi.sourceID]; ok {
			srcName = d.Name
		}
		if d, ok := deviceByID[pi.destID]; ok {
			dstName = d.Name
		}
		connName := fmt.Sprintf("%s ↔ %s", srcName, dstName)

		if err := p.db.UpsertAutoConnection(pi.sourceID, pi.destID, status, tunnelNames, connName, pi.connType, "subnet_match"); err != nil {
			log.Printf("Physical auto-detect: failed to upsert connection %s - %v", connName, err)
		} else {
			created++
		}
	}

	if created > 0 {
		log.Printf("Physical auto-detect: upserted %d connection(s)", created)
	}
	return created
}

// sendCriticalAlertEmail sends an HTML email for critical alerts with embedded charts.
func (p *Poller) sendCriticalAlertEmail(device *models.Device, alertType, message string) {
	if p.notifier == nil || p.db == nil {
		return
	}
	nc := notifier.SnapshotConfig(&p.cfg.Alerts)
	if !nc.EmailEnabled {
		return
	}

	alert := &models.Alert{
		Timestamp: time.Now(),
		DeviceID:  device.ID,
		AlertType: models.AlertType(alertType),
		Severity:  "critical",
		Message:   message,
	}

	recentHistory := report.GatherRecentHistory(p.db, device.ID)
	subject, htmlBody, attachments, err := report.BuildCriticalAlertEmail(alert, device, recentHistory)
	if err != nil {
		log.Printf("Device %s: failed to build critical alert email - %v", device.Name, err)
		return
	}

	recipients := p.cfg.Alerts.ReportRecipients
	if err := p.notifier.SendHTMLEmail(subject, htmlBody, attachments, nc, recipients); err != nil {
		log.Printf("Device %s: failed to send critical alert email - %v", device.Name, err)
	}
}

func (p *Poller) Stop() error {
	select {
	case <-p.stopChan:
		return nil
	default:
		close(p.stopChan)
	}
	return nil
}

// markLoopAlive stamps the Start()-loop heartbeat (M30 of the 2026-07-01 audit).
func (p *Poller) markLoopAlive() {
	p.loopBeat.Store(time.Now().Unix())
}

// LoopAliveWithin reports whether the Start() loop showed a sign of life within
// maxAge. Used by the /readyz probe so a halted loop (swallowed panic awaiting
// restart, or a wedge inside one tick's work) flips the daemon to not-ready.
func (p *Poller) LoopAliveWithin(maxAge time.Duration) bool {
	return time.Since(time.Unix(p.loopBeat.Load(), 0)) <= maxAge
}

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting SNMP Poller...")

	// AUDIT-008: load the persisted JWT secret so we derive the same AES
	// key as cmd/api and cmd/trap-receiver. Without this, the poller's
	// DB instance has a DIFFERENT encKey and cannot decrypt SNMP creds
	// / SMTP password saved through the admin UI — every poll cycle
	// against an SNMPv3 device, and every alert email, would fail with
	// the "wrong password" pattern v0.10.226 + v0.10.245 closed.
	secretsDir := os.Getenv("SECRETS_DIR")
	if secretsDir == "" {
		secretsDir = "/data"
	}
	jwtSecret, jwtSource, err := secrets.LoadOrGenerate(cfg.Server.JWTSecretKey, secretsDir, ".jwt-secret")
	if err != nil {
		log.Fatalf("JWT secret: %v (set JWT_SECRET_KEY env, or ensure %s is writable)", err, secretsDir)
	}
	cfg.Server.JWTSecretKey = jwtSecret
	if jwtSource == secrets.Generated {
		log.Printf("poller generated JWT secret to %s/.jwt-secret (chmod 600) — won race with cmd/api/cmd/trap-receiver on first start", secretsDir)
	} else if jwtSource == secrets.FromFile {
		log.Printf("poller loaded JWT secret from %s/.jwt-secret (chmod 600)", secretsDir)
	}

	// AUDIT-036: per-process DB pool default (DB_MAX_OPEN_CONNS overrides).
	if cfg.Database.MaxOpenConns == 0 {
		cfg.Database.MaxOpenConns = 10
	}
	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	// M8: a poller that can't decrypt device SNMP/SSH credentials polls with
	// empty secrets and silently marks every device offline. Fail-fast and
	// loud instead, so the misconfigured ENCRYPTION_KEY is fixed, not chased
	// for hours through "all devices offline" symptoms.
	if ok, detail := db.EncryptionVerified(); !ok {
		log.Fatalf("FATAL: %s", detail)
	}
	log.Println("Database connected")
	defer db.Close()

	// M11: expose /metrics /healthz /readyz so the poller (AlertManager +
	// polling + batchers) is observable to Prometheus/orchestrators instead of a
	// black box. POLLER_METRICS_ADDR overrides the default; "off" disables it.
	pollerMetricsAddr := os.Getenv("POLLER_METRICS_ADDR")
	if pollerMetricsAddr == "" {
		pollerMetricsAddr = ":9101"
	}
	if pollerMetricsAddr == "off" {
		pollerMetricsAddr = ""
	}
	if sqlDB, dberr := db.Gorm().DB(); dberr == nil {
		metrics.RegisterDBPool(sqlDB, "fwmon_poller")
	}
	notif := notifier.NewNotifier(cfg)
	alertManager := alerts.NewAlertManager(cfg, notif, db)

	poller := NewPoller(cfg, db, alertManager, notif)

	// M30 of the 2026-07-01 audit: /readyz must reflect whether the poller is
	// actually DOING its job, not just whether the DB answers a ping — a
	// panicked-and-halted loop previously kept green health checks forever.
	// Staleness threshold: 3x the (clamped) poll interval, floored at 10
	// minutes so legitimately long single-tick work (backlog rollups, big
	// cleanup batches) doesn't flap readiness.
	loopMaxAge := 3 * cfg.SNMP.PollInterval
	if minIv := 3 * 30 * time.Second; loopMaxAge < minIv {
		loopMaxAge = minIv // Start() clamps the interval to >=30s
	}
	if loopMaxAge < 10*time.Minute {
		loopMaxAge = 10 * time.Minute
	}
	obsSrv := metrics.StartObservabilityServer(pollerMetricsAddr, "poller", func() bool {
		// L15: bound the DB probe — an unbounded Ping() blocks forever when
		// the pool is wedged, hanging /readyz instead of answering 503.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sqlDB, derr := db.Gorm().DB()
		if derr != nil || sqlDB.PingContext(ctx) != nil {
			return false
		}
		return poller.LoopAliveWithin(loopMaxAge)
	})
	defer func() {
		if obsSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = obsSrv.Shutdown(ctx)
			cancel()
		}
	}()

	reportScheduler := report.NewReportScheduler(cfg, db, notif)
	go reportScheduler.Start()

	// M30 of the 2026-07-01 audit: REL-01's SafeGo contained a poller-loop
	// panic but never restarted the loop — the process stayed up as a zombie
	// (no polling, alerting, rollups, or cleanup) behind green health checks.
	// Supervise instead: recover per attempt, restart with capped backoff, and
	// exit only on a clean return (Stop()). The /readyz loop-heartbeat check
	// above covers the gap between crash and restart.
	go func() {
		backoff := time.Second
		for {
			clean := false
			func() {
				defer logging.Recover("poller")
				if err := poller.Start(); err != nil {
					log.Printf("Poller error: %v", err)
				}
				clean = true
			}()
			if clean {
				return // Stop() requested (or a non-panic return) — no restart
			}
			log.Printf("Poller loop crashed (panic recovered); restarting in %s", backoff)
			time.Sleep(backoff)
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down poller...")
	reportScheduler.Stop()
	poller.Stop()
	log.Println("Poller exited")
}
