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
	"firewall-mon/internal/netclass"
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
	// everUpChecked caches the interface/VPN keys whose telemetry HISTORY has
	// already been consulted for "was it ever operationally up", so the bounded
	// history query runs at most once per link/tunnel per process lifetime.
	everUpChecked map[string]bool
	everUpMu      sync.Mutex
	stopChan      chan struct{}

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

	// telemetryStaleStreak counts consecutive monitoring cycles a device has
	// satisfied the TELEMETRY_STALE condition. The alert fires only at
	// telemetryStaleCycles — the debounce that absorbs poller-restart-after-
	// outage storms (DB still says "online", rows outage-old) and re-enabled
	// devices' first cycle. (Since v0.11.105 spool replay bumps last_polled
	// with row timestamps, not now, so drain windows no longer feed this.)
	// Reset on condition-false; empty at process start by construction.
	// Accessed only from the single leader-locked monitoring cycle — no mutex.
	telemetryStaleStreak map[uint]int
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
		everUpChecked:  make(map[string]bool),
		stopChan:       make(chan struct{}),

		telemetryStaleStreak: make(map[uint]int),
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

	// The interface/VPN "ever-up" state is resolved per-link from telemetry
	// history on demand (resolveInterfaceEverUp), not seeded at startup — the old
	// open-alerts seed was circular (a stale false alert re-marked a never-up port
	// as ever-up, so it fired forever).

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

		DDoSBps:                    cfg.Detect.DDoSBps,
		DDoSPps:                    cfg.Detect.DDoSPps,
		DDoSFps:                    cfg.Detect.DDoSFps,
		DDoSPrefixBps:              cfg.Detect.DDoSPrefixBps,
		DDoSPrefixPps:              cfg.Detect.DDoSPrefixPps,
		DDoSPrefixFps:              cfg.Detect.DDoSPrefixFps,
		SampRateMinRows:            cfg.Detect.SampRateMinRows,
		DDoSVolumetricDisabled:     cfg.Detect.DDoSVolumetricDisabled,
		DDoSPrefixDisabled:         cfg.Detect.DDoSPrefixDisabled,
		SamplingRateChangeDisabled: cfg.Detect.SamplingRateChangeDisabled,

		DenyStormExternal:         cfg.Detect.DenyStormExternal,
		DenyStormInternal:         cfg.Detect.DenyStormInternal,
		DenyVictimSources:         cfg.Detect.DenyVictimSources,
		DenyVictimCount:           cfg.Detect.DenyVictimCount,
		DeniedThenAllowedMin:      cfg.Detect.DeniedThenAllowedMin,
		DenyStormDisabled:         cfg.Detect.DenyStormDisabled,
		DenyStormVictimDisabled:   cfg.Detect.DenyStormVictimDisabled,
		DeniedThenAllowedDisabled: cfg.Detect.DeniedThenAllowedDisabled,
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
	if v, err := strconv.ParseInt(strings.TrimSpace(m["detect_ddos_bps"]), 10, 64); err == nil && v > 0 {
		base.DDoSBps = v
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(m["detect_ddos_pps"]), 10, 64); err == nil && v > 0 {
		base.DDoSPps = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_ddos_fps"])); err == nil && v > 0 {
		base.DDoSFps = v
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(m["detect_ddos_prefix_bps"]), 10, 64); err == nil && v > 0 {
		base.DDoSPrefixBps = v
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(m["detect_ddos_prefix_pps"]), 10, 64); err == nil && v > 0 {
		base.DDoSPrefixPps = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_ddos_prefix_fps"])); err == nil && v > 0 {
		base.DDoSPrefixFps = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_samprate_min_rows"])); err == nil && v > 0 {
		base.SampRateMinRows = v
	}
	// Tranche 4 Phase 2 deny detectors.
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_deny_storm_min_denies"])); err == nil && v > 0 {
		base.DenyStormExternal = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_deny_storm_min_denies_internal"])); err == nil && v > 0 {
		base.DenyStormInternal = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_deny_storm_victim_min_sources"])); err == nil && v > 0 {
		base.DenyVictimSources = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_deny_storm_victim_min_denies"])); err == nil && v > 0 {
		base.DenyVictimCount = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m["detect_denied_then_allowed_min"])); err == nil && v > 0 {
		base.DeniedThenAllowedMin = v
	}
	// Per-detector enable flags need a DEDICATED three-state parse — the
	// numeric convention above treats <=0 as "fall through", which would eat
	// the 0-means-disabled semantics. Truth table: DB "0" → disabled, DB "1"
	// → enabled, DB blank/other → keep the env-derived base value.
	applyEnabledFlag := func(key string, disabled *bool) {
		switch strings.TrimSpace(m[key]) {
		case "0":
			*disabled = true
		case "1":
			*disabled = false
		}
	}
	applyEnabledFlag("detect_ddos_volumetric_enabled", &base.DDoSVolumetricDisabled)
	applyEnabledFlag("detect_ddos_prefix_enabled", &base.DDoSPrefixDisabled)
	applyEnabledFlag("detect_sampling_rate_change_enabled", &base.SamplingRateChangeDisabled)
	applyEnabledFlag("detect_deny_storm_enabled", &base.DenyStormDisabled)
	applyEnabledFlag("detect_deny_storm_victim_enabled", &base.DenyStormVictimDisabled)
	applyEnabledFlag("detect_denied_then_allowed_enabled", &base.DeniedThenAllowedDisabled)
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

	// Single feed: the flow_security suppress rules run over ALL detections —
	// security, policy AND operational — grouped by SUBJECT (the offending
	// source for src-keyed detectors, the VICTIM address for victim-keyed ones
	// per detect.VictimKeyed; e.g. ddos_volumetric — their SrcAddr is empty,
	// and grouping by it would collapse every victim into one degenerate ""
	// group). The Event-Rules hub is the single silencing surface for every
	// SFLOW_* alert class. After suppression, survivors split: src-keyed
	// SECURITY detections continue into the per-source SFLOW_SECURITY
	// consolidation + storm digest; everything else (policy/operational +
	// victim-keyed security) routes down the per-detection path (auto-derived
	// SFLOW_<DETECTOR> alert types). Any detection that maps to an alert is
	// linked (flow_detections.alert_id) so it drops off the sFlow detections
	// card.
	bySubject := map[string][]*models.FlowDetection{}
	for _, d := range saved {
		subject := d.SrcAddr
		if detect.VictimKeyed(d.Detector) {
			subject = d.DstAddr
		}
		bySubject[subject] = append(bySubject[subject], d)
	}

	p.applyFlowSecuritySuppressRules(bySubject)

	// Post-suppression split: src-keyed security stays keyed by source for
	// consolidation; the rest goes per-detection.
	securityBySrc := map[string][]*models.FlowDetection{}
	var others []*models.FlowDetection
	for subject, group := range bySubject {
		for _, d := range group {
			if d.Category == string(detect.CategorySecurity) && !detect.VictimKeyed(d.Detector) {
				securityBySrc[subject] = append(securityBySrc[subject], d)
			} else {
				others = append(others, d)
			}
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

	// Cross-source storm digest over the surviving src-keyed groups: bucket by
	// (site, detector); any bucket over its resolved threshold collapses into
	// ONE digest alert, and those detections are removed from the per-source
	// groups.
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

// applyFlowSecuritySuppressRules mutes detections (security, policy AND
// operational) matched by a flow_security SUPPRESS Event Rule — the unified
// replacement for the retired per-IP Silence-Source table. Matched PER
// DETECTION (a per-subject group spans devices + detectors): a detection whose
// first-match rule is a suppress rule is acked (off the NOC card) and removed;
// a subject is dropped from the map only when ALL its detections are
// suppressed, so it neither alerts nor counts toward a storm. Fails OPEN (nil
// manager / no matching rule → nothing muted).
func (p *Poller) applyFlowSecuritySuppressRules(securityBySrc map[string][]*models.FlowDetection) {
	if p.alertManager == nil || len(securityBySrc) == 0 {
		return
	}
	// deviceID → siteID (0/absent = no site), built once per cycle.
	devSite := map[uint]uint{}
	if devs, err := p.db.GetAllDevices(); err == nil {
		for i := range devs {
			if devs[i].SiteID != nil {
				devSite[devs[i].ID] = *devs[i].SiteID
			}
		}
	} else {
		log.Printf("flow-detect: load devices for flow_security site scope: %v", err)
	}
	siteOf := func(deviceID uint) *uint {
		if s, ok := devSite[deviceID]; ok && s != 0 {
			v := s
			return &v
		}
		return nil
	}
	var ackIDs []uint
	for src, group := range securityBySrc {
		srcCanon := canonIP(src)
		kept := group[:0] // filter in place: kept grows no faster than we read
		for _, d := range group {
			site := siteOf(d.DeviceID)
			action, ruleID, matched := p.alertManager.MatchFlowSecurityRule(alerts.FlowSecFields(d, srcCanon, site), d.DeviceID, site)
			if matched && action == "suppress" {
				p.alertManager.RecordEventRuleHit(ruleID)
				ackIDs = append(ackIDs, d.ID)
				continue
			}
			// Per-detector TOGGLE kill switch (v0.11.122). For the SRC-KEYED
			// SECURITY subset the consolidation erases sub-type identity
			// (those fire as SFLOW_SECURITY), so a toggled-off registry
			// sub-type — e.g. SFLOW_DENY_STORM → Off in the Default profile —
			// was silently inert and only a suppress rule worked. Consult the
			// detection's OWN type here, where per-detection granularity
			// still exists. Policy/operational/victim-keyed detections in
			// this same loop fire as their own SFLOW_<DETECTOR> types and
			// were already alert-gated downstream — for them this check adds
			// suppress-parity ACKING (the detection leaves the NOC card, not
			// just the alert stream). Detectors without a registry type
			// (port_scan, threat_intel, …) have no toggle row anywhere and
			// resolve ON — unchanged. The SFLOW_SECURITY MASTER toggle is
			// deliberately NOT consulted here: it gates only the consolidated
			// alert, so the card keeps sub-threshold signal.
			if !p.alertManager.EventTypeToggledOn(d.DeviceID, site,
				models.AlertType("SFLOW_"+strings.ToUpper(d.Detector))) {
				ackIDs = append(ackIDs, d.ID)
				continue
			}
			kept = append(kept, d)
		}
		if len(kept) == 0 {
			delete(securityBySrc, src)
		} else {
			securityBySrc[src] = kept
		}
	}
	if len(ackIDs) > 0 {
		if err := p.db.AckFlowDetections(ackIDs); err != nil {
			log.Printf("flow-detect: ack rule-suppressed detections: %v", err)
		}
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
	// justFlipped carries this cycle's online→offline transitions into
	// checkRelayedTelemetry: the devices slice above was loaded PRE-sweep, so
	// its Status fields still read "online" for these — without the set, a full
	// device outage would fire DEVICE_OFFLINE and TELEMETRY_STALE in the same
	// cycle.
	justFlipped := make(map[uint]struct{})
	if err != nil {
		log.Printf("Stale device check error: %v", err)
	} else if len(staleDevices) > 0 {
		log.Printf("Marked %d probe-assigned device(s) offline (no data for >%v)", len(staleDevices), staleAfter)
		for i := range staleDevices {
			dev := &staleDevices[i]
			justFlipped[dev.ID] = struct{}{}
			if p.alertManager != nil {
				p.alertManager.CheckDeviceOffline(dev)
				// DEVICE_OFFLINE supersedes a degraded-collection alert: one
				// failure, one open alert. Silent resolve (no "recovered"
				// notification at the moment of total failure).
				p.alertManager.AutoResolveTelemetryStale(dev.ID)
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
	p.checkRelayedTelemetry(devices, staleAfter, justFlipped)

	// Auto-detect connections — record cycle start BEFORE all detectors
	// so the stale cleanup doesn't delete connections from the first detector.
	connCycleStart := time.Now()
	vpnCount, vpnOK := p.detectVPNConnections(devices)
	overlayCount := p.detectOverlayConnections(devices)
	l2Count, l2OK := p.detectL2Links(devices)

	// Clean up auto-detected connections not refreshed by any detector.
	// Only run cleanup if at least one detector found connections — otherwise
	// a transient failure (DB error, empty data) would wipe all existing
	// connections. l2OK guards the same hazard one level finer: a failed L2
	// evidence READ with healthy VPN detectors would otherwise sweep every L2
	// row (their last_check untouched) and recreate them next cycle with new IDs.
	if p.db != nil && !(l2OK && vpnOK) {
		log.Printf("Connection detection: a detector read failed (l2OK=%t vpnOK=%t), skipping stale cleanup this cycle to preserve existing data", l2OK, vpnOK)
	} else if p.db != nil && (vpnCount+overlayCount+l2Count) > 0 {
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
//
// justFlipped is this cycle's set of devices the offline sweep just
// transitioned online→offline — the devices slice was loaded pre-sweep, so
// their Status fields still read "online" here; the TELEMETRY_STALE evaluation
// must skip them (DEVICE_OFFLINE supersedes).
func (p *Poller) checkRelayedTelemetry(devices []models.Device, staleAfter time.Duration, justFlipped map[uint]struct{}) {
	if p.db == nil {
		return
	}
	now := time.Now()
	cutoff := now.Add(-staleAfter)
	lookback := now.Add(-telemetryStaleLookback)

	// Only enabled devices are evaluated; rows from unknown/disabled devices
	// are skipped (deleted devices keep orphaned telemetry by design).
	devByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		if devices[i].Enabled {
			devByID[devices[i].ID] = &devices[i]
		}
	}

	// System status: CPU / memory / disk / session thresholds. The query is
	// widened to the TELEMETRY_STALE lookback so stale devices remain visible;
	// only rows past the cutoff feed the threshold checks (same split the
	// interface/VPN sections below have always used), so CheckSystemStatus and
	// its no-data recovery guard never see a stale row. staleVitals records the
	// last-seen timestamp of devices whose newest vitals row is stale.
	freshStatus := make(map[uint]bool)
	staleVitals := make(map[uint]time.Time)
	statusQueryOK := false
	if p.alertManager != nil {
		statuses, err := p.db.GetAllLatestSystemStatuses(lookback)
		if err != nil {
			log.Printf("Telemetry check: failed to get system statuses - %v", err)
		} else {
			statusQueryOK = true
			for i := range statuses {
				dev, ok := devByID[statuses[i].DeviceID]
				if !ok {
					continue
				}
				if statuses[i].Timestamp.Before(cutoff) {
					staleVitals[statuses[i].DeviceID] = statuses[i].Timestamp
					continue // freshness gate: stale row, threshold checks skip it
				}
				freshStatus[statuses[i].DeviceID] = true
				if err := p.alertManager.CheckSystemStatus(&statuses[i], dev.SiteID); err != nil {
					log.Printf("Device %s: alert check error - %v", dev.Name, err)
				}
			}
		}
	}

	// Interfaces: down/error/spike checks over the latest snapshot per device.
	// latestIface additionally records each device's newest interface-stats
	// timestamp within the lookback — TELEMETRY_STALE's second signal (SNMP
	// dying kills interface stats on every vendor, even when a FortiGate's SSH
	// perf writer keeps system_status fresh).
	ifaces, err := p.db.GetAllLatestInterfaces()
	ifaceQueryOK := err == nil
	if err != nil {
		log.Printf("Telemetry check: failed to get interfaces - %v", err)
		ifaces = nil
	}
	latestIface := make(map[uint]time.Time)
	ifacesByDevice := make(map[uint][]models.InterfaceStats)
	for _, iface := range ifaces {
		if _, ok := devByID[iface.DeviceID]; !ok {
			continue
		}
		if !iface.Timestamp.Before(lookback) && iface.Timestamp.After(latestIface[iface.DeviceID]) {
			latestIface[iface.DeviceID] = iface.Timestamp
		}
		if iface.Timestamp.Before(cutoff) {
			continue // freshness gate: stale snapshot, device stopped reporting
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
			// Resolve "was this interface ever operationally up" from telemetry
			// history BEFORE the down check, so INTERFACE_DOWN fires only for a
			// real link (an outage) and never for an enabled-but-never-cabled
			// port — without relying on the operator admin-downing it.
			p.resolveInterfaceEverUp(devIfaces, device.SiteID)
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
		if p.cfg.Alerts.SpikeAlertEnabled && p.spikeDetector != nil && p.alertManager != nil {
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

				// Phase 4b: the detector params come from the matching spike rule (or
				// the live spike settings), and fire/resolve route through the rule
				// engine (scope/suppress/severity/policy + proper open/resolve).
				k, minDur, minFloorBps := p.alertManager.SpikeParamsFor(iface.DeviceID, device.SiteID, iface.Name)
				dec := p.spikeDetector.Observe(fmt.Sprintf("%d:%d", iface.DeviceID, iface.Index), iface.Timestamp, bps, k, minDur, minFloorBps)
				switch {
				case dec.Fire:
					msg := fmt.Sprintf("Sustained traffic spike on %s: %s (typical ~%s for this time)", iface.Name, humanBps(dec.Value), humanBps(dec.Mean))
					p.alertManager.ProcessSpike(device, iface, dec.Severity, dec.Value, dec.Mean, msg, device.SiteID)
				case dec.Resolve:
					p.alertManager.ProcessSpikeResolve(device, iface, fmt.Sprintf("Traffic on %s returned to normal", iface.Name), device.SiteID)
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
			p.resolveVPNEverUp(devVPNs, devByID[devID].SiteID)
			p.alertManager.CheckVPNStatus(devVPNs, devByID[devID].SiteID)
		}
	}

	// TELEMETRY_STALE: reachable-but-degraded detection over the signal
	// timestamps collected above, plus the clock-skew visibility log for
	// devices with no vitals row at all. See telemetrystale.go.
	p.evaluateTelemetryStale(telemetryStaleInputs{
		devByID:       devByID,
		justFlipped:   justFlipped,
		freshStatus:   freshStatus,
		staleVitals:   staleVitals,
		latestIface:   latestIface,
		statusQueryOK: statusQueryOK,
		ifaceQueryOK:  ifaceQueryOK,
		staleAfter:    staleAfter,
		now:           now,
	})
}

// maxEverUpChecked caps the once-per-link dedup set so a churn of ephemeral
// dial-up tunnel names can't grow it unbounded across the process lifetime
// (mirrors the AlertManager's everUp cap).
const maxEverUpChecked = 50000

// everUpAlreadyChecked records (once) that a link/tunnel key has been resolved
// this process, so the mark/auto-resolve below runs at most once per key. Bounded.
func (p *Poller) everUpAlreadyChecked(key string) bool {
	p.everUpMu.Lock()
	defer p.everUpMu.Unlock()
	if p.everUpChecked == nil {
		p.everUpChecked = make(map[string]bool)
	}
	if p.everUpChecked[key] {
		return true
	}
	if len(p.everUpChecked) < maxEverUpChecked {
		p.everUpChecked[key] = true
	}
	return false
}

// resolveInterfaceEverUp decides, from the CURRENT snapshot's traffic counters,
// whether a down interface is a real link (an outage) or an enabled-but-never-
// cabled dark port — WITHOUT any history query (which on prod's high-volume,
// partitioned interface_stats would risk the startup statement-timeout crash).
// A never-cabled port has literally zero in/out octets; a real link that was
// ever up has nonzero counters that persist across link-down. So:
//   - nonzero counters → mark ever-up (a genuine outage still alerts, including
//     across a poller restart, since counters live in the snapshot);
//   - zero counters AND not already known ever-up → a dark port: silently clear
//     any stale/false INTERFACE_DOWN and leave it un-marked so it can't fire.
//
// Runs at most once per interface per process. Currently-up interfaces are
// marked live by CheckInterfaceStatus and skipped here.
func (p *Poller) resolveInterfaceEverUp(ifaces []models.InterfaceStats, siteID *uint) {
	if p.alertManager == nil {
		return
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Status != "down" || iface.AdminStatus != "up" {
			continue
		}
		if p.everUpAlreadyChecked(fmt.Sprintf("%d_%s", iface.DeviceID, iface.Name)) {
			continue
		}
		if iface.InBytes+iface.OutBytes > 0 {
			p.alertManager.MarkInterfaceEverUp(iface.DeviceID, iface.Name)
		} else if !p.alertManager.IsInterfaceEverUp(iface.DeviceID, iface.Name) {
			p.alertManager.AutoResolveInterfaceDown(iface.DeviceID, iface.Name, siteID)
		}
	}
}

// resolveVPNEverUp is the VPN-tunnel counterpart of resolveInterfaceEverUp, but
// SUPPRESS-ONLY: a tunnel that has carried bytes or accrued uptime is marked
// ever-up (so a real tunnel outage still alerts), but a zero-counter down tunnel
// is NEVER auto-resolved. Unlike vendor-independent IF-MIB interface octets,
// FortiGate VPN counters are per-SA (fgVpnTunEntInOctets/UpTime) and may read 0
// for a down phase2 — so auto-resolving on zero counters could silently close a
// genuine FortiGate tunnel outage across a poller restart. The ever-up gate
// alone stops the idle-tunnel flood; a lingering false VPN alert is left for the
// operator to clear once (it can't re-fire).
func (p *Poller) resolveVPNEverUp(vpns []models.VPNStatus, _ *uint) {
	if p.alertManager == nil {
		return
	}
	for i := range vpns {
		vpn := &vpns[i]
		if vpn.Status != "down" {
			continue
		}
		if p.everUpAlreadyChecked("vpn_" + fmt.Sprintf("%d_%s", vpn.DeviceID, vpn.TunnelName)) {
			continue
		}
		if vpn.BytesIn+vpn.BytesOut > 0 || vpn.TunnelUptime > 0 {
			p.alertManager.MarkVPNEverUp(vpn.DeviceID, vpn.TunnelName)
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
// detectVPNConnections returns the number of connections it upserted and whether
// the detection READ succeeded. The ok flag mirrors l2OK: a failed read must not
// be mistaken for "this device pair no longer exists", or the cycle's stale sweep
// would delete every VPN edge and recreate it with new IDs next cycle.
func (p *Poller) detectVPNConnections(devices []models.Device) (int, bool) {
	if p.db == nil || len(devices) == 0 {
		return 0, true
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
		return 0, false
	}
	// Rows past the grace horizon never arrive here — GetAllLatestVPNStatuses
	// drops them — so a tunnel the device has stopped reporting simply stops
	// being upserted and the cycle's stale sweep reaps its connection. What
	// remains is the fresh/stale split: evidence older than the fresh window
	// still identifies a real device pair, but is too old to assert up/down, so
	// the connection is HELD as "stale" (amber) instead of being trusted.
	freshCutoff := time.Now().Add(-database.VPNEvidenceFresh)
	isFresh := func(vpn models.VPNStatus) bool { return !vpn.Timestamp.Before(freshCutoff) }
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
		anyFresh    bool // at least one row inside the fresh window backs this pair
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
		if isFresh(vpn) {
			pi.anyFresh = true
			if vpn.Status == "up" {
				pi.anyUp = true
			}
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
			if isFresh(vpn) {
				pi.anyFresh = true
				if vpn.Status == "up" {
					pi.anyUp = true
				}
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
				if isFresh(vpn) {
					pi.anyFresh = true
					if vpn.Status == "up" {
						pi.anyUp = true
					}
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
			if !ok || netclass.IsFabricInterface("", addr.IPAddress) {
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
					anyFresh:    true, // interface-derived evidence, not vpn_status
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

	held := 0
	for _, pi := range pairs {
		// No fresh evidence => hold the connection as "stale" (amber) rather than
		// asserting a status we can no longer justify. The upsert still advances
		// last_check, so the ID stays stable and the sweep leaves it alone; once
		// the evidence ages past grace it stops arriving entirely and the sweep
		// reaps it. Same up -> stale -> deleted staircase the L2 detector uses.
		status := "down"
		switch {
		case !pi.anyFresh:
			status = "stale"
			held++
		case pi.anyUp:
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
		log.Printf("VPN auto-detect: processed %d connection(s) across %d devices%s", len(pairs), len(devices), heldNote(held))
	}
	return len(pairs), true
}

// heldNote annotates the detect log when connections were held on stale evidence,
// so an operator seeing amber edges can tell it is deliberate, not a detector bug.
func heldNote(held int) string {
	if held == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d held on stale evidence)", held)
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

	// Load VPN tunnel data to verify direct links. Only FRESH rows may verify a
	// direct link: an "up" carried over from evidence that is hours old would
	// keep classifying an overlay as directly-linked long after the underlying
	// tunnel stopped being reported.
	vpnStatuses, _ := p.db.GetAllLatestVPNStatuses()
	overlayFreshCutoff := time.Now().Add(-database.VPNEvidenceFresh)
	// Build set of device pairs with verified direct VPN links (remote IP points to other device)
	vpnByDevice := make(map[uint][]models.VPNStatus)
	for _, vpn := range vpnStatuses {
		if vpn.Timestamp.Before(overlayFreshCutoff) {
			continue
		}
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

				// l2vlan/bridge are SAME-SITE DIRECT-family links. They used to
				// be created here by pure interface-NAME matching (no port
				// evidence) — which drew a spurious "L2VLAN" + "Software Switch"
				// line between any two devices sharing an interface name (e.g.
				// both FortiGates have a `bridge` "internal" and shared VLAN
				// names), duplicating the real LLDP/FDB/ARP link. Same-site
				// direct/switch links now come ONLY from the evidence-based L2
				// inference (detectL2Links), which classifies every confirmed
				// same-site link as ethernet/lag (it does not emit l2vlan/
				// bridge as distinct types) — so type fidelity is traded for
				// evidence-backing, and a same-site VLAN/switch link with NO
				// LLDP/FDB/ARP evidence is intentionally hidden (hide-
				// unconfirmed). This detector keeps only vxlan/l3ipvlan, the
				// true overlays that ride a verified VPN tunnel.
				if connType == "l2vlan" || connType == "bridge" {
					continue
				}
				if !hasDirectLink(a.deviceID, b.deviceID) {
					// L3IPVLAN, VXLAN require a verified VPN tunnel.
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

	// Theme is read from the DB at send time — p.cfg.Alerts is env-frozen
	// (never refreshed from system_settings), so a config-field read would
	// silently ignore the admin-UI choice. Critical alerts are rare; one
	// read per send is nothing. Missing/blank = light.
	themeName, _ := p.db.GetSettingValue("report_email_theme")
	recentHistory := report.GatherRecentHistory(p.db, device.ID)
	subject, htmlBody, textBody, attachments, err := report.BuildCriticalAlertEmail(alert, device, recentHistory, report.ThemeByName(themeName))
	if err != nil {
		log.Printf("Device %s: failed to build critical alert email - %v", device.Name, err)
		return
	}

	recipients := p.cfg.Alerts.ReportRecipients
	if err := p.notifier.SendHTMLEmail(subject, textBody, htmlBody, attachments, nc, recipients); err != nil {
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
