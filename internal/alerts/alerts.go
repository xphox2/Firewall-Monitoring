package alerts

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/detect"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"

	"gorm.io/gorm"
)

type AlertManager struct {
	config       *config.Config
	notifier     *notifier.Notifier
	db           *database.Database
	lastAlert    map[string]time.Time
	cooldownFor  map[string]time.Duration // L2: per-key effective cooldown, so prune evicts only past each key's OWN window
	activeAlerts map[string]bool          // tracks currently-firing alert keys for recovery detection
	// everUp records the alert keys (iface_down_/vpn_down_) of interfaces and
	// VPN tunnels known to have been operationally up. INTERFACE_DOWN/
	// VPN_TUNNEL_DOWN fire ONLY for a key in this set — a real outage is "was up,
	// now down". Enabled-but-never-cabled ports and idle/never-up tunnels (common
	// on collector-managed firewalls, alert-checked for the first time since
	// v0.11.74) are never in the set, so they can't flood. Populated from live
	// up-rows each cycle AND, for a link that is down across a poller restart,
	// from the poller's traffic-counter check (MarkInterfaceEverUp/MarkVPNEverUp)
	// — a link that ever carried traffic has nonzero counters that persist while
	// down. It is deliberately NOT seeded from open alerts, which was circular (a
	// stale false alert re-marked a never-up port as ever-up, so it fired
	// forever). mu-guarded; bounded by the fleet's interface + tunnel count.
	everUp map[string]bool
	// Flap suppression (F13): fireStart records when a key went active so
	// sendRecovery can measure how long the alert lived; flapShortResolves
	// accumulates the timestamps of short-lived (< FlapMinActiveSeconds)
	// fire→resolve cycles inside the rolling window. Once the count reaches
	// FlapMaxFires, dispatchFired saves further fires SUPPRESSED (no
	// notification) until the flapping subsides out of the window. Both maps
	// are pruned alongside the cooldown maps, sharing the M25 bound.
	fireStart         map[string]time.Time
	flapShortResolves map[string][]time.Time
	// F17 zscore baselines: per-device trailing stats, own mutex — refreshed
	// OUTSIDE am.mu so alert evaluation never holds the lock across a DB read.
	baselines  map[uint]deviceBaselines
	baselineMu sync.Mutex
	// F12: open incidents by device (mu-guarded; reloaded each poll cycle).
	openIncidents map[uint]uint
	// lastSeverity records the last-FIRED severity rank per security event key
	// (flowsec_/flowsec_digest_), so a strictly-higher severity can bypass the
	// (now 6h) cooldown on the post-ack fresh-fire path — where no open alert
	// exists to escalate (A2, v0.11.46). mu-guarded, pruned with lastAlert.
	lastSeverity map[string]int
	// stormSourcesDefault is the global cross-source digest threshold from the
	// `detect_security_storm_sources` SystemSetting (default 25; <=0 disables the
	// digest globally). Set each cycle by the poller via SetStormSourcesDefault so
	// resolveAlertConfig can seed ResolvedAlertConfig.StormSources without a DB read.
	stormSourcesDefault int
	mu                  sync.RWMutex
	alertCooldown       time.Duration
	policyCache         PolicyCache
	// Event-rule engine (migration v35; profile-partitioned since v48): the
	// compiled enabled rules bucketed by owning profile + the
	// device→(vendor,site) map, both refreshed alongside policyCache under am.mu.
	eventRules ruleEngine
	deviceMeta map[uint]database.DeviceRuleMeta
	// stateOwned is the set of event_types the rule engine owns (from the
	// `state_engine_owns` SystemSetting CSV). While a type is owned, its legacy
	// resolveAlertConfig firing path is bypassed and the per-source evaluator
	// (staterules.go / metricrules.go / traprules.go) runs. Refreshed alongside
	// eventRules under am.mu.
	stateOwned map[string]bool
	// anyMetricZScoreRule is true when a compiled metric Event Rule opts into
	// zscore mode — extends the baseline-prefetch gate (zscoreConfigured) so an
	// event-rule-only zscore still gets F17 baselines. Set in RefreshEventRules.
	anyMetricZScoreRule bool
	// ruleHits accumulates per-rule match counts in memory (H2: flushed in
	// batches by RefreshEventRules, never a per-match UPDATE). Own mutex so the
	// hot path never contends with am.mu.
	ruleHits map[uint]*ruleHit
	hitMu    sync.Mutex
	// telemetryColdSwept marks devices whose TELEMETRY_STALE recovery has run
	// its one-shot cold DB resolve this process (clears rows left open across a
	// poller restart). After that, CheckTelemetryRecovered only does DB work
	// when the alert is active in-process — keeping the healthy steady state at
	// zero writes per cycle. mu-guarded; bounded by fleet size.
	telemetryColdSwept map[uint]bool
}

// firedEntry pairs an alert with its resolved policy config for deferred
// notification. key is the in-memory alert key (cooldown/active/flap state);
// empty for event alerts that don't participate in flap suppression.
type firedEntry struct {
	alert    models.Alert
	resolved ResolvedAlertConfig
	key      string
}

func NewAlertManager(cfg *config.Config, notif *notifier.Notifier, db *database.Database) *AlertManager {
	return &AlertManager{
		config:              cfg,
		notifier:            notif,
		db:                  db,
		lastAlert:           make(map[string]time.Time),
		cooldownFor:         make(map[string]time.Duration),
		activeAlerts:        make(map[string]bool),
		everUp:              make(map[string]bool),
		fireStart:           make(map[string]time.Time),
		flapShortResolves:   make(map[string][]time.Time),
		baselines:           make(map[uint]deviceBaselines),
		openIncidents:       make(map[uint]uint),
		lastSeverity:        make(map[string]int),
		stormSourcesDefault: 25, // matches the detect_security_storm_sources code default
		alertCooldown:       5 * time.Minute,
		stateOwned:          make(map[string]bool),
		telemetryColdSwept:  make(map[uint]bool),
	}
}

// SetStormSourcesDefault updates the global cross-source digest threshold (from
// the `detect_security_storm_sources` SystemSetting). Called by the poller each
// detection cycle so an admin-UI change takes effect without a restart.
func (am *AlertManager) SetStormSourcesDefault(n int) {
	am.mu.Lock()
	am.stormSourcesDefault = n
	am.mu.Unlock()
}

// StormThreshold resolves the effective cross-source digest threshold for a site
// (v0.11.46): the global default, overridden by the site's DIGEST policy-rule /
// per-site config. Resolved with deviceID 0 (site-scoped, no per-device leak). A
// return <= 0 means the digest is disabled for that scope. Pass nil for the
// "no site" bucket.
func (am *AlertManager) StormThreshold(siteID *uint) int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.resolveAlertConfig(0, siteID, models.AlertTypeSFlowSecurityDigest).StormSources
}

// ifaceDownKey / vpnDownKey build the cooldown/active/ever-up map keys. Kept as
// helpers so the firing paths and the ever-up seed can't drift apart.
func ifaceDownKey(deviceID uint, name string) string {
	return fmt.Sprintf("iface_down_%d_%s", deviceID, name)
}

func vpnDownKey(deviceID uint, tunnelName string) string {
	return fmt.Sprintf("vpn_down_%d_%s", deviceID, tunnelName)
}

// maxEverUpEntries bounds the ever-up set the same way maxLastAlertEntries
// bounds the cooldown map: managed interfaces/tunnels can't drive it far, but a
// churn of dial-up tunnel instance names over a long-lived process shouldn't
// grow it without limit. Dropping a mark only means a subsequent live "up" row
// re-adds it, so the cap is harmless.
const maxEverUpEntries = 50000

// markEverUpLocked records that key (an iface_down_/vpn_down_ key) has been seen
// up, enforcing the size cap. Caller holds am.mu.
func (am *AlertManager) markEverUpLocked(key string) {
	if _, exists := am.everUp[key]; !exists && len(am.everUp) >= maxEverUpEntries {
		return
	}
	am.everUp[key] = true
}

// MarkInterfaceEverUp records that an interface has been observed operationally
// up — the poller calls this for a down link that has carried traffic (nonzero
// counters), so a real link that is down across a poller restart still alerts.
// Idempotent + bounded.
func (am *AlertManager) MarkInterfaceEverUp(deviceID uint, name string) {
	am.mu.Lock()
	am.markEverUpLocked(ifaceDownKey(deviceID, name))
	am.mu.Unlock()
}

// MarkVPNEverUp is the VPN counterpart of MarkInterfaceEverUp.
func (am *AlertManager) MarkVPNEverUp(deviceID uint, tunnelName string) {
	am.mu.Lock()
	am.markEverUpLocked(vpnDownKey(deviceID, tunnelName))
	am.mu.Unlock()
}

// IsInterfaceEverUp reports whether an interface is currently marked ever-up, so
// the poller can avoid auto-resolving a link it already knows was up.
func (am *AlertManager) IsInterfaceEverUp(deviceID uint, name string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.everUp[ifaceDownKey(deviceID, name)]
}

// AutoResolveInterfaceDown silently clears any OPEN INTERFACE_DOWN alert for an
// interface the poller has determined is NOT a monitored link (never
// operationally up in its history). It is a cold resolve — sendRecovery only
// touches the DB and sends no "back up" notification when the key isn't active
// in this process — so it cleans up the false alerts that the old open-alerts
// seed used to perpetuate, without notifying anyone.
func (am *AlertManager) AutoResolveInterfaceDown(deviceID uint, name string, siteID *uint) {
	am.sendRecovery(ifaceDownKey(deviceID, name), "INTERFACE_DOWN", "interface_"+name,
		"interface has never been operationally up — not a monitored link", deviceID, siteID)
}

// markActiveLocked flips a state-alert key to active and stamps when it fired
// (the flap detector measures active duration at recovery). Caller holds am.mu.
func (am *AlertManager) markActiveLocked(key string, now time.Time) {
	am.activeAlerts[key] = true
	am.fireStart[key] = now
}

// alertActive reports whether the given key is currently firing in THIS process
// (cheap RLock read). Used to gate optional recovery resolves so they don't add
// per-cycle DB writes when there's nothing open to resolve.
func (am *AlertManager) alertActive(key string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.activeAlerts[key]
}

// flapPruneLocked drops short-resolve records older than the window and
// returns the surviving count. Caller holds am.mu.
func (am *AlertManager) flapPruneLocked(key string, now time.Time) int {
	window := time.Duration(am.config.Alerts.FlapWindowMinutes) * time.Minute
	if window <= 0 {
		window = time.Hour
	}
	rs := am.flapShortResolves[key]
	keep := rs[:0]
	for _, t := range rs {
		if now.Sub(t) <= window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(am.flapShortResolves, key)
	} else {
		am.flapShortResolves[key] = keep
	}
	return len(keep)
}

// flapSuppress reports whether key is currently flapping (enough short-lived
// cycles inside the window) — the caller marks the fire suppressed.
func (am *AlertManager) flapSuppress(key string, now time.Time) bool {
	if key == "" || am.config.Alerts.FlapMaxFires <= 0 {
		return false
	}
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.flapPruneLocked(key, now) >= am.config.Alerts.FlapMaxFires
}

func (am *AlertManager) CheckSystemStatus(status *models.SystemStatus, siteID *uint) error {
	type metricCheck struct {
		alertType models.AlertType
		metricKey string
		metric    string
		current   float64
		// populated reports whether THIS row actually measured the metric, so a
		// value of 0 is a real reading (allowing recovery) rather than an absent
		// field. AUDIT AL-M2: cpu/mem/disk reduce to current>0 (a live device
		// never reports 0%); session_count can legitimately be 0 on an idle
		// device, but system_status has two writers, so a 0 is trusted only from
		// an authoritative full SNMP poll (Source=snmp) — never from the
		// supplementary SSH-perf row or a legacy (empty-Source) row.
		populated bool
	}

	sessionsMeasured := status.SessionCount > 0 || status.Source == models.SystemStatusSourceSNMP
	checks := []metricCheck{
		{models.AlertTypeCPUHigh, fmt.Sprintf("cpu_high_%d", status.DeviceID), "cpu_usage", status.CPUUsage, status.CPUUsage > 0},
		{models.AlertTypeMemoryHigh, fmt.Sprintf("memory_high_%d", status.DeviceID), "memory_usage", status.MemoryUsage, status.MemoryUsage > 0},
		{models.AlertTypeDiskHigh, fmt.Sprintf("disk_high_%d", status.DeviceID), "disk_usage", status.DiskUsage, status.DiskUsage > 0},
		{models.AlertTypeSessionsHigh, fmt.Sprintf("sessions_high_%d", status.DeviceID), "session_count", float64(status.SessionCount), sessionsMeasured},
	}

	var fired []firedEntry

	// F17: refresh this device's baseline BEFORE taking am.mu (DB read).
	// No-op unless some policy rule OR metric event rule opted into zscore mode.
	if am.zscoreConfigured() {
		am.ensureBaseline(status.DeviceID)
	}

	// Effective per-check config, resolved ONCE and reused for both the fire and
	// recovery legs (Phase 4a: previously resolved twice). When a metric event_type
	// is owned, the config is sourced from the matching metric rule (override-else-
	// inherit); a suppress rule sets skipFire (mute the fire, still recover).
	type effCheck struct {
		metricCheck
		resolved ResolvedAlertConfig
		skipFire bool
	}

	am.mu.Lock()
	now := time.Now()
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)

	effs := make([]effCheck, len(checks))
	for i, chk := range checks {
		resolved, skipFire := am.resolveMetricEffectiveLocked(status.DeviceID, siteID, chk.alertType, chk.metric, now)
		effs[i] = effCheck{chk, resolved, skipFire}
	}

	for _, e := range effs {
		if e.skipFire {
			continue // suppress rule: no fire (recovery still runs below)
		}
		chk := e.metricCheck
		resolved := e.resolved
		if !resolved.AlertEnabled {
			continue
		}
		// F17: in zscore mode the effective threshold is the device's own
		// baseline + K·σ (static Threshold acts as a floor); otherwise the
		// static threshold as always. fireAt==0 = nothing configured.
		fireAt, _, dynamic := am.zscoreFireAt(resolved, status.DeviceID, chk.metric)
		if fireAt == 0 {
			continue
		}

		if chk.current >= fireAt {
			cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
			if am.canAlertWithCooldown(chk.metricKey, now, cooldown) {
				thLabel := "threshold"
				if dynamic {
					thLabel = "baseline threshold"
				}
				msg := fmt.Sprintf("%s is %.1f (%s: %.1f)", chk.metric, chk.current, thLabel, fireAt)
				if chk.alertType == models.AlertTypeSessionsHigh {
					msg = fmt.Sprintf("Session count is %d (%s: %d)", int(chk.current), thLabel, int(fireAt))
				}
				alert := models.Alert{
					Timestamp:    now,
					DeviceID:     status.DeviceID,
					AlertType:    chk.alertType,
					Severity:     resolved.Severity,
					Message:      msg,
					MetricName:   chk.metric,
					Threshold:    fireAt,
					CurrentValue: chk.current,
					PolicyID:     resolved.PolicyID,
					Suppressed:   resolved.InMaintenance,
				}
				am.recordCooldownLocked(chk.metricKey, now, cooldown)
				am.markActiveLocked(chk.metricKey, now)
				fired = append(fired, firedEntry{alert, resolved, chk.metricKey})
			}
		}
	}
	am.mu.Unlock()

	am.dispatchFired(fired, globalNC, "system")

	// Recovery — reuse the effective config resolved above (no re-resolve). Runs
	// for every check regardless of skipFire/AlertEnabled so an already-open alert
	// still auto-resolves (sendRecovery's DB resolve is idempotent + notify-gated).
	// Maintenance no longer defers resolution here (LC-13): sendRecovery itself
	// performs the DB auto-resolve and mutes the notification while in maintenance.
	for _, rc := range effs {
		// Effective fire level (static or F17 zscore), then the recovery band:
		// F14 clear-band when configured; zscore mode gets a built-in half-σ
		// band below its dynamic threshold so baseline noise doesn't flap.
		fireAt, std, dynamic := am.zscoreFireAt(rc.resolved, status.DeviceID, rc.metric)
		recoverBelow := fireAt
		if dynamic {
			recoverBelow = fireAt - 0.5*std
		}
		if rc.resolved.ClearThreshold > 0 && rc.resolved.ClearThreshold < recoverBelow {
			recoverBelow = rc.resolved.ClearThreshold
		}
		// No-data guard (AUDIT AL-M2): recover only when THIS row actually measured
		// the metric (rc.populated). cpu/mem/disk reduce to current>0 (a live device
		// never reports 0%, and the SSH `diagnose sys performance` row carries
		// cpu/mem but disk_usage=0). session_count can legitimately be 0 on an idle
		// device, so it recovers on 0 only from an authoritative full SNMP poll
		// (Source=snmp) — a supplementary SSH-perf row or a legacy empty-Source row
		// with session_count=0 must never auto-resolve a genuine SESSIONS_HIGH.
		if fireAt > 0 && rc.populated && rc.current < recoverBelow {
			am.sendRecovery(rc.metricKey, rc.alertType, rc.metric,
				fmt.Sprintf("%s recovered to %.1f", rc.metric, rc.current), status.DeviceID, siteID)
		}
	}

	return nil
}

func (am *AlertManager) CheckInterfaceStatus(interfaces []models.InterfaceStats, siteID *uint) error {
	var fired []firedEntry
	var stateCands []stateCandidate

	am.mu.Lock()
	now := time.Now()
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	owned := am.stateOwned[StateEventInterfaceDown]

	for _, iface := range interfaces {
		key := ifaceDownKey(iface.DeviceID, iface.Name)
		// Record every interface seen up so a later down transition can fire.
		if iface.Status == "up" {
			am.markEverUpLocked(key)
			continue
		}
		if iface.Status != "down" || iface.AdminStatus != "up" {
			continue
		}
		// Only a link that was genuinely UP at some point is an outage. An
		// enabled-but-never-cabled port stays admin-up/oper-down forever and
		// must NOT alert (it would flood collector-managed firewalls, which
		// expose many dark ports). everUp is populated from LIVE up-rows here
		// AND, for a link down across a poller restart, from the poller's
		// traffic-counter check (MarkInterfaceEverUp) — so a real link that ever
		// carried traffic still alerts, while an always-down/never-cabled port
		// never does, WITHOUT the operator having to admin-down it. NOTE:
		// deliberately NOT seeded from open alerts, which was circular (a stale
		// false alert re-marked a never-up port as ever-up and it fired forever).
		if !am.everUp[key] {
			continue
		}

		// State-engine ownership: route the down-decision through enabled
		// source="state" rules (scope/suppress/severity/routing) + episode
		// dampening. A disabled/absent alert rule for an owned type means "alerts
		// off, on purpose" — no legacy fallback while owned.
		if owned {
			vendor := "generic"
			if m, ok := am.deviceMeta[iface.DeviceID]; ok && m.Vendor != "" {
				vendor = m.Vendor
			}
			fields := interfaceStateFields(iface.DeviceID, iface.Name, iface.AdminStatus, vendor)
			action, rule, matched := am.matchStateRuleLocked(fields, iface.DeviceID, siteID)
			if !matched || action == "suppress" {
				continue
			}
			cand, ok := am.buildStateCandidateLocked(
				rule, iface.DeviceID, siteID, key, "INTERFACE_DOWN",
				fmt.Sprintf("interface_%s", iface.Name),
				fmt.Sprintf("Interface %s is down", iface.Name), globalNC)
			if !ok {
				continue // alerting disabled for this device/type
			}
			stateCands = append(stateCands, cand)
			continue
		}

		resolved := am.resolveAlertConfig(iface.DeviceID, siteID, "INTERFACE_DOWN")
		if !resolved.AlertEnabled {
			continue
		}
		// Also check legacy toggle when no policy rule disables it
		if !am.config.Alerts.InterfaceDownAlert && !am.policyCache.loaded {
			continue
		}
		cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
		if am.canAlertWithCooldown(key, now, cooldown) {
			alert := models.Alert{
				Timestamp:    now,
				DeviceID:     iface.DeviceID,
				AlertType:    "INTERFACE_DOWN",
				Severity:     resolved.Severity,
				Message:      fmt.Sprintf("Interface %s is down", iface.Name),
				MetricName:   fmt.Sprintf("interface_%s", iface.Name),
				CurrentValue: 0,
				PolicyID:     resolved.PolicyID,
				Suppressed:   resolved.InMaintenance,
			}
			am.recordCooldownLocked(key, now, cooldown)
			am.markActiveLocked(key, now)
			fired = append(fired, firedEntry{alert, resolved, key})
		}
	}
	am.mu.Unlock()

	am.dispatchFired(fired, globalNC, "interface")
	am.dispatchStateCandidates(stateCands, now)

	// Recovery: interfaces that are now up, plus AL-M3 — a link an operator
	// administratively DISABLED after it alerted. The fire path requires
	// AdminStatus=="up" and the up-recovery below requires Status=="up", so an
	// open INTERFACE_DOWN on a since-disabled port (admin=down, oper=down) would
	// otherwise never resolve — it stays stuck until the port is re-enabled AND
	// comes back up. Admin-down is a deliberate operator action ending the
	// outage, so resolve it. Gated on the in-memory active flag so it adds no
	// per-cycle DB writes for the common (never-alerted) case.
	for _, iface := range interfaces {
		key := ifaceDownKey(iface.DeviceID, iface.Name)
		switch {
		case iface.Status == "up":
			am.sendRecovery(key, "INTERFACE_DOWN", fmt.Sprintf("interface_%s", iface.Name),
				fmt.Sprintf("Interface %s is back up", iface.Name), iface.DeviceID, siteID)
		case iface.AdminStatus == "down" && am.alertActive(key):
			// Strictly ADMIN-DOWN (not merely "!= up"): a partial SNMP walk that
			// returns oper-down but leaves AdminStatus empty must NOT be read as
			// "operator disabled" and false-resolve a genuine ongoing outage.
			am.sendRecovery(key, "INTERFACE_DOWN", fmt.Sprintf("interface_%s", iface.Name),
				fmt.Sprintf("Interface %s administratively disabled", iface.Name), iface.DeviceID, siteID)
		}
	}

	return nil
}

// trapMetricName scopes a trap alert's MetricName to its source IP (M24), so a
// LINK_UP recovery resolves only the same source's LINK_DOWN, never another
// device's. Falls back to the bare "snmp_trap" when the source IP is unknown.
func trapMetricName(sourceIP string) string {
	if sourceIP == "" {
		return "snmp_trap"
	}
	return "snmp_trap_" + sourceIP
}

func (am *AlertManager) ProcessTrap(trap *models.TrapEvent, siteID *uint) error {
	// M24 of the 2026-07-01 audit: the direct trap-receiver pipeline never
	// populates trap.DeviceID (parseTrap doesn't resolve it), so EVERY direct
	// trap arrived with DeviceID=0 and MetricName="snmp_trap". A LINK_UP then
	// resolved WHERE device_id=0 AND metric_name='snmp_trap', which matched ALL
	// direct-trap LINK_DOWN alerts, so firewall B's LINK_UP silently closed
	// firewall A's still-open LINK_DOWN. Fix both: resolve the device from the
	// source IP (so per-device policies apply and device_id scopes recovery),
	// and scope the trap's MetricName by source IP as defense-in-depth for
	// traps from an unknown IP that stay DeviceID=0.
	if trap.DeviceID == 0 && trap.SourceIP != "" && am.db != nil {
		trap.DeviceID = am.db.ResolveDeviceByIP(trap.SourceIP)
	}
	metricName := trapMetricName(trap.SourceIP)

	// Handle LINK_UP as recovery for any active LINK_DOWN alert on this device
	if trap.TrapType == "LINK_UP" {
		key := fmt.Sprintf("trap_LINK_DOWN_%s", trap.SourceIP)
		am.sendRecovery(key, "LINK_DOWN", metricName, trap.Message, trap.DeviceID, siteID)
		return nil
	}

	key := fmt.Sprintf("trap_%s_%s", trap.TrapType, trap.SourceIP)

	am.mu.Lock()
	now := time.Now()
	resolved := am.resolveAlertConfig(trap.DeviceID, siteID, models.AlertType(trap.TrapType))
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)

	// Phase 4a: consult a matching source="trap" Event Rule ON TOP of the policy
	// config — suppress, or override severity/cooldown/routing — for ANY trap type
	// (no ownership flag: no matching rule → the legacy path runs unchanged, so
	// consulting is always non-regressive). A matched EVENT rule also counts as
	// opt-in for the LC-14 info/notice gate (mirroring resolved.RuleMatched).
	eventRuleMatched := false
	var eventRuleSeverity models.Severity
	{
		vendor := "generic"
		effSite := siteID
		if m, ok := am.deviceMeta[trap.DeviceID]; ok {
			if m.Vendor != "" {
				vendor = m.Vendor
			}
			if effSite == nil {
				effSite = m.SiteID // site-scoped trap rules match without a per-call siteID
			}
		}
		action, rule, matched := am.matchTrapRuleLocked(trapFields(trap, vendor), trap.DeviceID, effSite)
		if matched {
			am.recordHit(rule.id, now)
			if action == "suppress" {
				am.mu.Unlock()
				return nil // trap suppressed by an operator rule
			}
			eventRuleMatched = true
			eventRuleSeverity = rule.severity
			if rule.policyID != nil {
				am.applyRulePolicy(&resolved, *rule.policyID)
			}
			if rule.cooldownMin != nil && *rule.cooldownMin > 0 {
				resolved.CooldownMinutes = *rule.cooldownMin
			}
		}
	}

	// Severity filter AFTER policy resolution (LC-14): info/notice traps stay
	// dropped by default, but an enabled policy rule OR a matched trap event rule
	// for this trap type opts it in.
	if trap.Severity != "critical" && trap.Severity != "warning" && !resolved.RuleMatched && !eventRuleMatched {
		am.mu.Unlock()
		return nil
	}
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	canSend := resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if !canSend {
		return nil
	}

	// Severity precedence (most-specific wins): a matched trap EVENT rule's
	// severity > the policy AlertRule severity (resolved.RuleSeverity) > the trap
	// parser's own severity — mirroring ProcessFlowDetection's fallback pattern.
	severity := models.Severity(trap.Severity)
	if resolved.RuleSeverity != "" {
		severity = resolved.RuleSeverity
	}
	if eventRuleSeverity != "" {
		severity = eventRuleSeverity
	}

	alert := models.Alert{
		Timestamp:  trap.Timestamp,
		DeviceID:   trap.DeviceID,
		AlertType:  models.AlertType(trap.TrapType),
		Severity:   severity,
		Message:    trap.Message,
		MetricName: metricName, // M24: source-scoped so LINK_UP recovery can't cross devices
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notify(&alert, nc); err != nil {
			return fmt.Errorf("failed to send trap alert: %w", err)
		}
	}

	return nil
}

// clampDelta returns cur-prev, clamped to 0 when the counter reset or wrapped
// (cur < prev) — unsigned subtraction would otherwise underflow to ~1.8e19.
func clampDelta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

// CheckInterfaceErrors alerts when interfaces accumulate errors or discards since last poll.
// prevMap maps "deviceID_ifName" to the previous InterfaceStats for delta computation.
func (am *AlertManager) CheckInterfaceErrors(interfaces []models.InterfaceStats, prevMap map[string]*models.InterfaceStats, siteID *uint) error {
	var fired []firedEntry
	var ruleHits []uint

	am.mu.Lock()
	now := time.Now()
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)

	for _, iface := range interfaces {
		if iface.Status != "up" || iface.AdminStatus != "up" {
			continue
		}
		mapKey := fmt.Sprintf("%d_%s", iface.DeviceID, iface.Name)
		prev, ok := prevMap[mapKey]
		if !ok {
			continue
		}

		totalErrors := iface.InErrors + iface.OutErrors + iface.InDiscards + iface.OutDiscards
		prevTotalErrors := prev.InErrors + prev.OutErrors + prev.InDiscards + prev.OutDiscards
		errorDelta := clampDelta(totalErrors, prevTotalErrors)

		if errorDelta > 0 {
			resolved := am.resolveAlertConfig(iface.DeviceID, siteID, "INTERFACE_ERRORS")
			if !resolved.AlertEnabled {
				continue
			}
			// device-source Event Rule consult (v0.11.112): rules can scope on
			// interface_name to mute one noisy port without losing the rest.
			devRule, devSuppressed := am.consultDeviceRuleLocked("INTERFACE_ERRORS", iface.DeviceID, siteID,
				string(resolved.Severity), map[string]string{"interface_name": iface.Name}, &resolved)
			if devRule != nil {
				ruleHits = append(ruleHits, devRule.id)
			}
			if devSuppressed {
				continue
			}
			alertKey := fmt.Sprintf("iface_errors_%d_%s", iface.DeviceID, iface.Name)
			cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
			if am.canAlertWithCooldown(alertKey, now, cooldown) {
				alert := models.Alert{
					Timestamp: now,
					DeviceID:  iface.DeviceID,
					AlertType: "INTERFACE_ERRORS",
					Severity:  resolved.Severity,
					// LC-28: per-counter deltas get the same reset clamp as the
					// aggregate above, so one reset counter can't print ~1.8e19.
					Message:      fmt.Sprintf("Interface %s has %d new errors/discards (in_err: %d, out_err: %d, in_disc: %d, out_disc: %d)", iface.Name, errorDelta, clampDelta(iface.InErrors, prev.InErrors), clampDelta(iface.OutErrors, prev.OutErrors), clampDelta(iface.InDiscards, prev.InDiscards), clampDelta(iface.OutDiscards, prev.OutDiscards)),
					MetricName:   fmt.Sprintf("interface_errors_%s", iface.Name),
					CurrentValue: float64(errorDelta),
					PolicyID:     resolved.PolicyID,
					Suppressed:   resolved.InMaintenance,
				}
				am.recordCooldownLocked(alertKey, now, cooldown)
				fired = append(fired, firedEntry{alert, resolved, ""})
			}
		}
	}
	am.mu.Unlock()

	for _, id := range ruleHits {
		am.RecordEventRuleHit(id)
	}
	am.dispatchFired(fired, globalNC, "interface error")
	return nil
}

// ProcessSyslog evaluates a syslog message against the unified event-rule engine
// (migration v35). The legacy "alert on severity 0-2" behavior now ships as seed
// EventRules (EnsureDefaultRules) emitting the original SYSLOG_EMERGENCY/ALERT/
// CRITICAL types, so operators can additionally build content-matching rules on
// any severity. The caller no longer pre-gates on severity — the engine's
// fast-path handles the no-rules case.
func (am *AlertManager) ProcessSyslog(msg *models.SyslogMessage, siteID *uint) error {
	return am.EvaluateSyslog(msg, siteID)
}

// securityEventLinkLookback bounds how far back FindOpenAlertForSource scans for
// a source's most-recent linked detection. Detection cycles run every few
// minutes while an event persists, so a recent linked detection always exists
// inside this window; the open+unacked filter on the alert bounds the rest.
const securityEventLinkLookback = 2 * time.Hour

// securityDetectorPriority ranks the security detectors so ProcessSecurityEvent
// can pick a single "winner" when several fire on the same source with equal
// severity. Higher = more authoritative / higher-confidence.
var securityDetectorPriority = map[string]int{
	"threat_intel":   6,
	"port_scan":      5,
	"deny_storm":     4, // blocked burst; port_scan (sees allowed probes too) outranks
	"data_exfil":     3,
	"super_spreader": 2,
	"c2_beacon":      1,
}

// severityRank maps a severity to an ordinal so escalation can compare them.
func severityRank(s models.Severity) int {
	switch s {
	case "critical":
		return 2
	case "warning":
		return 1
	default:
		return 0
	}
}

// ProcessFlowDetection fires an alert for a single, non-consolidated flow
// detection (the operational/policy detectors: cleartext, egress, capacity, …).
// Security detections are consolidated per-source by ProcessSecurityEvent
// instead. It returns the id of the alert that now represents this detection —
// freshly created, or the still-open one it folded into by cooldown — so the
// caller can stamp flow_detections.alert_id ("single feed"). Returns 0 when
// nothing represents it (alerting disabled, or cooldown-suppressed with no open
// alert to link to).
func (am *AlertManager) ProcessFlowDetection(det *models.FlowDetection, siteID *uint) (uint, error) {
	alertType := models.AlertType("SFLOW_" + strings.ToUpper(det.Detector))
	key := "flowdet_" + det.DedupKey
	metric := "sflow_" + det.Detector
	// The rule/alert subject: the offending source, or the victim for
	// victim-keyed detectors (whose SrcAddr is empty/many). Persisted on the
	// alert so flow_security rules and the suggested-rule endpoint have a
	// source to match — parity with ProcessSecurityEvent.
	subject := det.SrcAddr
	if detect.VictimKeyed(det.Detector) {
		subject = det.DstAddr
	}

	am.mu.Lock()
	now := time.Now()
	resolved := am.resolveAlertConfig(det.DeviceID, siteID, alertType)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	// flow_security customize (parity with ProcessSecurityEvent): an
	// alert-action Event Rule overrides severity/routing/cooldown; a suppress
	// match mutes defensively (the poller pass normally drops it first).
	// Consulted BEFORE the cooldown record so a suppressed detection doesn't
	// burn the cooldown window for a later unsuppressed sibling.
	effSite := siteID
	if effSite == nil {
		if m, ok := am.deviceMeta[det.DeviceID]; ok {
			effSite = m.SiteID
		}
	}
	fdRule := am.matchFlowSecurityRuleLocked(FlowSecFields(det, canonIPStr(subject), effSite), det.DeviceID, effSite)
	suppressed := fdRule != nil && fdRule.action == "suppress"
	var ruleSev models.Severity
	if fdRule != nil && fdRule.action == "alert" {
		ruleSev = fdRule.severity
		if fdRule.policyID != nil {
			resolved.PolicyID = fdRule.policyID
			am.applyRulePolicy(&resolved, *fdRule.policyID)
		}
		if fdRule.cooldownMin != nil && *fdRule.cooldownMin > 0 {
			cooldown = time.Duration(*fdRule.cooldownMin) * time.Minute
		}
	}
	// LC-12 sibling: AlertEnabled gates the cooldown recording too.
	canSend := !suppressed && resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if fdRule != nil {
		am.RecordEventRuleHit(fdRule.id)
	}
	if suppressed || !resolved.AlertEnabled {
		return 0, nil
	}
	if !canSend {
		// Cooldown-suppressed: link to the still-open alert for this
		// (device, type, metric) so the detection stays off the sFlow card.
		return am.openAlertID(det.DeviceID, alertType, metric, now, cooldown), nil
	}

	// Severity precedence (parity with ProcessSecurityEvent): the detector's
	// own, then the type default, then an explicit policy-rule severity, then
	// an explicit Event Rule severity last (the operator's most deliberate
	// re-grade wins).
	sev := models.Severity(det.Severity)
	if sev == "" {
		sev = resolved.Severity
	}
	if resolved.RuleSeverity != "" {
		sev = resolved.RuleSeverity
	}
	if ruleSev != "" {
		sev = ruleSev
	}

	alert := models.Alert{
		Timestamp:    det.DetectedAt,
		DeviceID:     det.DeviceID,
		AlertType:    alertType,
		Severity:     sev,
		Message:      det.Message,
		MetricName:   metric,
		CurrentValue: det.Score,
		PolicyID:     resolved.PolicyID,
		Suppressed:   resolved.InMaintenance,
		SourceAddr:   subject,
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notify(&alert, nc); err != nil {
			return alert.ID, fmt.Errorf("failed to send flow detection alert: %w", err)
		}
	}
	return alert.ID, nil
}

// ProcessSecurityEvent consolidates all security detections for one source in a
// detection cycle into a SINGLE alert (the "single feed"). group must be
// non-empty and every member shares the same SrcAddr. It returns the id of the
// alert representing the event so the caller can link every detection to it.
//
// Correctness (see the alerts-overhaul plan):
//   - event-level cooldown key `flowsec_<src>`, independent of which detector won
//     (so the 15-min/5-min overlapping cycles don't re-fire when the winner changes);
//   - the open-alert lookup goes through the detection→alert LINK (src-discriminating,
//     detector-agnostic) and is therefore also the restart-proof DB gate;
//   - a strictly-higher severity BREAKS the cooldown and escalates immediately, so a
//     mid-event critical is never swallowed.
func (am *AlertManager) ProcessSecurityEvent(group []*models.FlowDetection, siteID *uint) (uint, error) {
	if len(group) == 0 {
		return 0, nil
	}
	winner := group[0]
	deviceID := winner.DeviceID
	for _, d := range group {
		if d.DeviceID != 0 {
			deviceID = d.DeviceID // informational attribution; NOT part of the key
		}
		if betterSecurityWinner(d, winner) {
			winner = d
		}
	}
	src := winner.SrcAddr
	eventKey := "flowsec_" + src
	alertType := models.AlertType("SFLOW_SECURITY")
	metric := "sflow_" + winner.Detector

	now := time.Now()
	resolved := am.resolveAlertConfig(deviceID, siteID, alertType)
	if !resolved.AlertEnabled {
		return 0, nil
	}
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	// Precedence: an explicit severity on a matching policy rule wins (the
	// operator deliberately re-graded this type — same rule as the trap path,
	// LC-14), else the detector's own severity, else the type default.
	newSev := models.Severity(winner.Severity)
	if newSev == "" {
		newSev = resolved.Severity
	}
	if resolved.RuleSeverity != "" {
		newSev = resolved.RuleSeverity
	}
	// flow_security customize: a matching alert-action Event Rule overrides the
	// severity and/or notification routing (parity with the other sources). Applied
	// HERE — before the escalation compare / cooldown-bypass / lastSeverity — so the
	// override actually drives them. An explicit rule severity wins over the
	// policy-rule severity above. (Suppress rules are filtered upstream in the
	// poller; a suppress match reaching here still mutes, defensively.)
	am.mu.RLock()
	csEffSite := siteID
	if csEffSite == nil {
		if m, ok := am.deviceMeta[deviceID]; ok {
			csEffSite = m.SiteID
		}
	}
	srcCanon := src
	if ip := net.ParseIP(src); ip != nil {
		srcCanon = ip.String()
	}
	csRule := am.matchFlowSecurityRuleLocked(FlowSecFields(winner, srcCanon, csEffSite), deviceID, csEffSite)
	if csRule != nil && csRule.action == "alert" {
		if csRule.severity != "" {
			newSev = csRule.severity
		}
		// Rewrite the notify channels + cooldown from the rule's policy/knobs, not
		// just stamp the ID — else the alert routes on the device policy's channels
		// while the row names the rule's policy (attribution lie). applyRulePolicy
		// reads the policy cache, so do it under the same RLock.
		if csRule.policyID != nil {
			resolved.PolicyID = csRule.policyID
			am.applyRulePolicy(&resolved, *csRule.policyID)
		}
		if csRule.cooldownMin != nil && *csRule.cooldownMin > 0 {
			cooldown = time.Duration(*csRule.cooldownMin) * time.Minute
		}
	}
	am.mu.RUnlock()
	if csRule != nil {
		am.RecordEventRuleHit(csRule.id)
		if csRule.action == "suppress" {
			return 0, nil
		}
	}

	// Find this event's still-open alert via the detection→alert link. Look back
	// at least the cooldown (A2, v0.11.46): with a 6h cadence, a source quiet
	// 2–6h then resuming would otherwise miss its open alert AND be cooldown-
	// blocked, so it would silently drop. max(lookback, cooldown) keeps the fold-in
	// working across the whole window.
	lookback := securityEventLinkLookback
	if cooldown > lookback {
		lookback = cooldown
	}
	existing, _ := am.db.FindOpenAlertForSource(src, now.Add(-lookback))
	if existing != nil {
		if severityRank(newSev) > severityRank(existing.Severity) {
			// Escalation: raise severity and re-notify immediately (break cooldown)
			// so a mid-event critical is never lost inside a warning's window.
			existing.Severity = newSev
			existing.Message = winner.Message
			existing.MetricName = metric
			existing.SourceAddr = src
			existing.EventKey = eventKey
			if am.db != nil {
				am.db.Gorm().Model(&models.Alert{}).Where("id = ?", existing.ID).Updates(map[string]any{
					"severity":         newSev,
					"message":          winner.Message,
					"metric_name":      metric,
					"source_addr":      src,
					"timestamp":        winner.DetectedAt,
					"escalation_count": existing.EscalationCount + 1,
				})
			}
			am.mu.Lock()
			am.recordCooldownLocked(eventKey, now, cooldown)
			am.lastSeverity[eventKey] = severityRank(newSev)
			am.mu.Unlock()
			if !existing.Suppressed {
				nc := BuildNotifyConfigFromResolved(resolved, globalNC)
				if err := am.notify(existing, nc); err != nil {
					return existing.ID, fmt.Errorf("failed to send escalated sflow alert: %w", err)
				}
			}
		} else {
			// Same-or-lower recurrence of an open event: fold in silently.
			am.mu.Lock()
			am.recordCooldownLocked(eventKey, now, cooldown)
			am.mu.Unlock()
		}
		return existing.ID, nil
	}

	// No open alert for this source (e.g. the operator acked the last one). Gate
	// on the event cooldown — but a strictly-higher severity than the last fire
	// BYPASSES it (A2, v0.11.46), so a critical arriving inside the 6h window
	// after an acked warning still pages immediately.
	am.mu.Lock()
	canSend := am.canAlertWithCooldown(eventKey, now, cooldown)
	if !canSend && severityRank(newSev) > am.lastSeverity[eventKey] {
		canSend = true
	}
	if canSend {
		am.recordCooldownLocked(eventKey, now, cooldown)
		am.lastSeverity[eventKey] = severityRank(newSev)
	}
	am.mu.Unlock()
	if !canSend {
		return 0, nil
	}

	alert := models.Alert{
		Timestamp:    winner.DetectedAt,
		DeviceID:     deviceID,
		AlertType:    alertType,
		Severity:     newSev,
		Message:      winner.Message,
		MetricName:   metric,
		SourceAddr:   src,
		CurrentValue: winner.Score,
		PolicyID:     resolved.PolicyID,
		Suppressed:   resolved.InMaintenance,
		EventKey:     eventKey,
	}
	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notify(&alert, nc); err != nil {
			return alert.ID, fmt.Errorf("failed to send sflow security alert: %w", err)
		}
	}
	return alert.ID, nil
}

// betterSecurityWinner reports whether cand should replace cur as the event's
// representative detection: higher severity, else higher detector priority.
func betterSecurityWinner(cand, cur *models.FlowDetection) bool {
	cr, ur := severityRank(models.Severity(cand.Severity)), severityRank(models.Severity(cur.Severity))
	if cr != ur {
		return cr > ur
	}
	return securityDetectorPriority[cand.Detector] > securityDetectorPriority[cur.Detector]
}

// ProcessSecurityDigest collapses a STORM of distinct sources for one
// (site, detector) into a SINGLE SFLOW_SECURITY_DIGEST alert (v0.11.46), instead
// of N per-source SFLOW_SECURITY alerts (a botnet scan or known-bad ASN can flag
// hundreds of sources in one cycle). group is every storm detection for that
// (site, detector). siteID is nil for the "no site" bucket; the metric name still
// encodes s0 so the digest is stable per bucket. Returns the digest alert id so
// the caller links all storm detections to it. Mirrors ProcessSecurityEvent's
// escalate/fold/cooldown structure but is keyed on the persisted metric_name (a
// digest spans many sources, so there's no single src link to key on).
func (am *AlertManager) ProcessSecurityDigest(siteID *uint, detector string, group []*models.FlowDetection) (uint, error) {
	if len(group) == 0 {
		return 0, nil
	}
	winner := group[0]
	srcSet := make(map[string]struct{}, len(group))
	for _, d := range group {
		srcSet[d.SrcAddr] = struct{}{}
		if betterSecurityWinner(d, winner) {
			winner = d
		}
	}
	distinct := len(srcSet)

	var sid uint
	if siteID != nil {
		sid = *siteID
	}
	metric := fmt.Sprintf("sflow_digest_%s_s%d", detector, sid)
	eventKey := fmt.Sprintf("flowsec_digest_%s_s%d", detector, sid)
	alertType := models.AlertTypeSFlowSecurityDigest

	now := time.Now()
	// deviceID 0: resolve the digest from the SITE policy only — passing a
	// "representative device" would leak that device's per-device override onto
	// the whole-site rollup (see the plan C3/C4).
	resolved := am.resolveAlertConfig(0, siteID, alertType)
	if !resolved.AlertEnabled {
		return 0, nil
	}
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	newSev := models.Severity(winner.Severity)
	if newSev == "" {
		newSev = resolved.Severity
	}
	if resolved.RuleSeverity != "" {
		newSev = resolved.RuleSeverity
	}

	// Digest rule consult (v0.11.119, parity with ProcessSecurityEvent's csRule
	// block): a flow_security Event Rule matching the DEDICATED
	// "security_digest" event_type governs the rollup. deviceID 0 → site+Default
	// chain only (a whole-site rollup must not inherit one device's profile).
	// Placed BEFORE FindOpenDigestAlert so a suppress touches no DB row, no
	// cooldown state, no lastSeverity. applyRulePolicy reads the policy cache,
	// so the overlay stays under the same RLock.
	am.mu.RLock()
	dgRule := am.matchFlowSecurityRuleLocked(flowSecDigestFields(detector, siteID), 0, siteID)
	if dgRule != nil && dgRule.action == "alert" {
		if dgRule.severity != "" {
			newSev = dgRule.severity
		}
		if dgRule.policyID != nil {
			resolved.PolicyID = dgRule.policyID
			am.applyRulePolicy(&resolved, *dgRule.policyID)
		}
		if dgRule.cooldownMin != nil && *dgRule.cooldownMin > 0 {
			cooldown = time.Duration(*dgRule.cooldownMin) * time.Minute
		}
	}
	am.mu.RUnlock()
	if dgRule != nil {
		am.RecordEventRuleHit(dgRule.id)
		if dgRule.action == "suppress" {
			// Ack the storm detections (parity with the poller's per-detection
			// suppress pass): rollUpSecurityStorms already removed them from the
			// per-source path, so without the ack they'd linger unlinked and
			// unacknowledged on the sFlow card.
			ids := make([]uint, 0, len(group))
			for _, det := range group {
				ids = append(ids, det.ID)
			}
			if am.db != nil {
				if err := am.db.AckFlowDetections(ids); err != nil {
					log.Printf("digest suppress: ack %d detections: %v", len(ids), err)
				}
			}
			return 0, nil
		}
	}

	msg := buildDigestMessage(detector, distinct, group)

	lookback := securityEventLinkLookback
	if cooldown > lookback {
		lookback = cooldown
	}
	existing, _ := am.db.FindOpenDigestAlert(metric, now.Add(-lookback))
	if existing != nil {
		// Fold the new sources into the open digest: refresh count + message, and
		// escalate (re-notify) only on a strictly-higher severity.
		higher := severityRank(newSev) > severityRank(existing.Severity)
		updates := map[string]any{"message": msg, "current_value": float64(distinct), "timestamp": now}
		if higher {
			updates["severity"] = newSev
			updates["escalation_count"] = existing.EscalationCount + 1
			existing.Severity = newSev
		}
		existing.Message = msg
		existing.CurrentValue = float64(distinct)
		existing.MetricName = metric
		existing.EventKey = eventKey
		if am.db != nil {
			am.db.Gorm().Model(&models.Alert{}).Where("id = ?", existing.ID).Updates(updates)
		}
		am.mu.Lock()
		am.recordCooldownLocked(eventKey, now, cooldown)
		if higher {
			am.lastSeverity[eventKey] = severityRank(newSev)
		}
		am.mu.Unlock()
		if higher && !existing.Suppressed {
			nc := BuildNotifyConfigFromResolved(resolved, globalNC)
			if err := am.notify(existing, nc); err != nil {
				return existing.ID, fmt.Errorf("failed to send escalated sflow digest: %w", err)
			}
		}
		return existing.ID, nil
	}

	// No open digest for this bucket. Same cooldown gate + higher-severity bypass
	// as ProcessSecurityEvent (A2).
	am.mu.Lock()
	canSend := am.canAlertWithCooldown(eventKey, now, cooldown)
	if !canSend && severityRank(newSev) > am.lastSeverity[eventKey] {
		canSend = true
	}
	if canSend {
		am.recordCooldownLocked(eventKey, now, cooldown)
		am.lastSeverity[eventKey] = severityRank(newSev)
	}
	am.mu.Unlock()
	if !canSend {
		return 0, nil
	}

	alert := models.Alert{
		Timestamp:    now,
		DeviceID:     0,      // site-scoped rollup; attribution-only, not used for resolution
		SiteID:       siteID, // persist the site so the UI names it (DeviceID 0 → no device→site)
		AlertType:    alertType,
		Severity:     newSev,
		Message:      msg,
		MetricName:   metric,
		CurrentValue: float64(distinct),
		PolicyID:     resolved.PolicyID,
		Suppressed:   resolved.InMaintenance,
		EventKey:     eventKey,
	}
	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notify(&alert, nc); err != nil {
			return alert.ID, fmt.Errorf("failed to send sflow security digest: %w", err)
		}
	}
	return alert.ID, nil
}

// buildDigestMessage summarizes a storm: distinct-source count + the top-3
// sources by score, and for a threat_intel storm the shared ASN/feed when every
// source shares one (e.g. a Spamhaus ASN-DROP sweep). The full offender list
// lives in the linked detections.
func buildDigestMessage(detector string, distinct int, group []*models.FlowDetection) string {
	if detector == "threat_intel" {
		if asn := sharedASN(group); asn != "" {
			return fmt.Sprintf("%s storm: %d sources from %s", detector, distinct, asn)
		}
	}
	best := make(map[string]float64, len(group))
	for _, d := range group {
		if d.Score >= best[d.SrcAddr] {
			best[d.SrcAddr] = d.Score
		}
	}
	type ss struct {
		src   string
		score float64
	}
	arr := make([]ss, 0, len(best))
	for s, sc := range best {
		arr = append(arr, ss{s, sc})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].score != arr[j].score {
			return arr[i].score > arr[j].score
		}
		return arr[i].src < arr[j].src // stable order for equal scores
	})
	top := make([]string, 0, 3)
	for i := 0; i < len(arr) && i < 3; i++ {
		top = append(top, arr[i].src)
	}
	return fmt.Sprintf("%s storm: %d sources flagged in 15m (top: %s)", detector, distinct, strings.Join(top, ", "))
}

// sharedASN returns a "AS<n> (<name>)" label when EVERY detection in the group
// carries the same ASN in its Details JSON, else "". Best-effort: detections
// without an "asn" field (or a mixed set) yield "" and the caller falls back to
// the top-sources form.
func sharedASN(group []*models.FlowDetection) string {
	var asn, name string
	for i, d := range group {
		if d.Details == "" {
			return ""
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(d.Details), &m); err != nil {
			return ""
		}
		a := asnField(m["asn"])
		if a == "" {
			return ""
		}
		if i == 0 {
			asn = a
			name = strFromAny(m["asn_name"])
		} else if a != asn {
			return ""
		}
	}
	if asn == "" {
		return ""
	}
	label := "AS" + asn
	if name != "" {
		label += " (" + name + ")"
	}
	return label
}

// asnField normalizes an ASN pulled from JSON (it may decode as a float64 number
// or a string) to a bare digit string, else "".
func asnField(v any) string {
	switch t := v.(type) {
	case float64:
		if t <= 0 {
			return ""
		}
		return strconv.FormatInt(int64(t), 10)
	case string:
		return strings.TrimPrefix(strings.TrimPrefix(t, "AS"), "as")
	default:
		return ""
	}
}

func strFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// openAlertID returns the id of the still-open alert matching
// (device, type, metric) within the cooldown window, or 0. Used to link a
// cooldown-suppressed detection to the alert already representing it.
func (am *AlertManager) openAlertID(deviceID uint, alertType models.AlertType, metricName string, ref time.Time, cooldown time.Duration) uint {
	if am.db == nil || cooldown <= 0 {
		return 0
	}
	var a models.Alert
	if err := am.db.Gorm().
		Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NULL AND timestamp > ?",
			deviceID, alertType, metricName, ref.Add(-cooldown)).
		Order("timestamp DESC").First(&a).Error; err != nil {
		return 0
	}
	return a.ID
}

// notify enriches an alert with presentation fields (device name, site, detail
// URL) and sends it. EVERY alert notification funnels through here so all
// channels — including the escalation/recovery paths that build alerts from DB
// rows with empty transient fields — carry identity + a deep link.
func (am *AlertManager) notify(alert *models.Alert, nc notifier.NotifyConfig) error {
	am.enrichAlert(alert, nc.BaseURL)
	return am.notifier.SendAlert(alert, nc)
}

// enrichAlert populates the transient DeviceName/SiteName/DetailURL fields so an
// alert clearly identifies where it came from and links to its detail view.
func (am *AlertManager) enrichAlert(alert *models.Alert, baseURL string) {
	if alert == nil || am.db == nil {
		return
	}
	if alert.DeviceName == "" && alert.DeviceID != 0 {
		if dev, err := am.db.GetDevice(alert.DeviceID); err == nil && dev != nil {
			alert.DeviceName = dev.Name
			if dev.Site != nil {
				alert.SiteName = dev.Site.Name
			}
		}
	}
	// Probe-sourced alert with no device: fall back to the probe name.
	if alert.DeviceName == "" && alert.ProbeID != nil {
		if p, err := am.db.GetProbe(*alert.ProbeID); err == nil && p != nil {
			alert.DeviceName = p.Name
		}
	}
	if alert.DetailURL == "" && baseURL != "" && alert.ID != 0 {
		alert.DetailURL = baseURL + "/admin/#alert/" + strconv.FormatUint(uint64(alert.ID), 10)
	}
}

// canAlertWithCooldown reports whether the per-key cooldown has elapsed.
func (am *AlertManager) canAlertWithCooldown(key string, now time.Time, cooldown time.Duration) bool {
	if lastTime, exists := am.lastAlert[key]; exists {
		return now.Sub(lastTime) > cooldown
	}
	return true
}

// dbCooldownActive reports whether a still-open alert for the same
// (device, alertType, metric) already exists in the DB with a timestamp inside
// the cooldown window ending at ref. It backstops the in-memory cooldown across
// a process restart: AlertManager cooldown state (lastAlert/activeAlerts) lives
// only in memory, so after a poller/API restart every still-breaching condition
// would re-fire at once — a notification storm (one email/Slack/Discord/IRC per
// breaching condition, and a per-cycle storm under a crash-loop). Consulting the
// DB makes a restart transparent: the within-cooldown duplicate is suppressed,
// while the normal periodic reminder still fires once the window elapses (older
// open rows fall outside it). Only persistent STATE alerts (thresholds,
// interface/VPN down, device offline) are deduped here; event/transient alerts
// (traps, syslog, SSH host-key, config-change) fire on arrival and must not be
// collapsed. Queried only on the rare about-to-notify path, so it adds no cost
// to the common "condition healthy / within cooldown" cycles.
func (am *AlertManager) dbCooldownActive(deviceID uint, alertType models.AlertType, metricName string, ref time.Time, cooldown time.Duration) bool {
	if am.db == nil || cooldown <= 0 {
		return false
	}
	var cnt int64
	am.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NULL AND timestamp > ?",
			deviceID, alertType, metricName, ref.Add(-cooldown)).
		Count(&cnt)
	return cnt > 0
}

// maxLastAlertEntries hard-caps the in-memory cooldown map (M25 of the
// 2026-07-01 audit). PruneExpiredCooldowns bounds it in the poller (which runs
// a prune ticker), but the trap-receiver embeds its OWN AlertManager and never
// pruned, and its keys are "trap_<TYPE>_<sourceIP>" derived from SPOOFABLE
// source IPs, so a spoof-flood grew the map ~unbounded (hundreds of MB/day).
// This cap makes any embedding process safe by construction, independent of
// whether it runs the ticker.
const maxLastAlertEntries = 50000

// recordCooldownLocked records a cooldown timestamp for key, enforcing the
// map's size cap first. Caller holds am.mu. Replaces the raw
// `am.lastAlert[key] = now` writes so every cooldown-bearing alert path is
// bounded (M25).
func (am *AlertManager) recordCooldownLocked(key string, now time.Time, cooldown time.Duration) {
	if _, exists := am.lastAlert[key]; !exists && len(am.lastAlert) >= maxLastAlertEntries {
		// Adding a NEW key at the cap: prune expired entries first; if that
		// frees nothing (all still within cooldown), evict the oldest so the
		// map can never grow past the cap.
		am.pruneExpiredLocked(now)
		if len(am.lastAlert) >= maxLastAlertEntries {
			am.evictOldestLocked()
		}
	}
	am.lastAlert[key] = now
	// L2: remember this key's effective cooldown so prune respects it.
	if cooldown > 0 {
		am.cooldownFor[key] = cooldown
	}
}

// pruneExpiredLocked deletes cooldown entries past their OWN effective cooldown
// (L2 of the 2026-07-01 audit — the pre-fix fixed `alertCooldown*2` (10 min)
// threshold truncated any operator-set per-policy cooldown > 10 min, so the
// next detection re-alerted before the configured window elapsed). Keys with
// no recorded cooldown fall back to the base cooldown. Caller holds am.mu.
func (am *AlertManager) pruneExpiredLocked(now time.Time) {
	for key, lastTime := range am.lastAlert {
		cd := am.cooldownFor[key]
		if cd <= 0 {
			cd = am.alertCooldown
		}
		if now.Sub(lastTime) > cd {
			delete(am.lastAlert, key)
			delete(am.cooldownFor, key)
		}
	}
}

// evictOldestLocked removes the single oldest cooldown entry. Caller holds am.mu.
func (am *AlertManager) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, t := range am.lastAlert {
		if first || t.Before(oldestTime) {
			oldestKey, oldestTime, first = key, t, false
		}
	}
	if !first {
		delete(am.lastAlert, oldestKey)
		delete(am.cooldownFor, oldestKey)
	}
}

// PruneExpiredCooldowns removes expired cooldown entries to prevent unbounded map growth.
func (am *AlertManager) PruneExpiredCooldowns() {
	am.mu.Lock()
	defer am.mu.Unlock()
	now := time.Now()
	am.pruneExpiredLocked(now)
	// F13: age out flap history and orphaned fire-start stamps on the same
	// hourly cadence (fireStart entries for keys that recovered are deleted
	// in sendRecovery; ones whose recovery never came are bounded here).
	for key := range am.flapShortResolves {
		am.flapPruneLocked(key, now)
	}
	window := time.Duration(am.config.Alerts.FlapWindowMinutes) * time.Minute
	if window <= 0 {
		window = time.Hour
	}
	for key, t := range am.fireStart {
		if !am.activeAlerts[key] && now.Sub(t) > window {
			delete(am.fireStart, key)
		}
	}
}

// RefreshThresholds reads alert threshold settings from the database and updates
// the running config. This ensures admin UI changes take effect without restart.
func (am *AlertManager) RefreshThresholds(db *gorm.DB) {
	if db == nil {
		return
	}

	// Refresh policy cache alongside thresholds
	am.RefreshPolicyCache(am.db)
	am.refreshOpenIncidents()

	var settings []models.SystemSetting
	if err := db.Where("\"key\" IN ?", []string{
		"cpu_threshold", "memory_threshold", "disk_threshold", "session_threshold",
		"email_enabled", "smtp_host", "smtp_port", "smtp_username", "smtp_password",
		"smtp_from", "smtp_to", "slack_webhook", "discord_webhook", "webhook_url", "webhook_secret",
		"pagerduty_routing_key", "opsgenie_api_key", "teams_webhook",
		"report_daily_enabled", "report_daily_time", "report_weekly_enabled",
		"report_weekly_day", "report_recipients", "report_timezone",
		"spike_stddev_threshold", "spike_alert_enabled", "spike_min_duration_minutes",
		"spike_min_throughput_mbps",
	}).Find(&settings).Error; err != nil {
		log.Printf("RefreshThresholds: failed to read settings: %v", err)
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	for _, s := range settings {
		if s.Value == "" {
			continue
		}
		switch s.Key {
		case "cpu_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				am.config.Alerts.CPUThreshold = v
			}
		case "memory_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				am.config.Alerts.MemoryThreshold = v
			}
		case "disk_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				am.config.Alerts.DiskThreshold = v
			}
		case "session_threshold":
			if v, err := strconv.Atoi(s.Value); err == nil && v > 0 {
				am.config.Alerts.SessionThreshold = v
			}
		case "email_enabled":
			am.config.Alerts.EmailEnabled = s.Value == "true"
		case "smtp_host":
			am.config.Alerts.SMTPHost = s.Value
		case "smtp_port":
			if v, err := strconv.Atoi(s.Value); err == nil && v > 0 {
				am.config.Alerts.SMTPPort = v
			}
		case "smtp_username":
			am.config.Alerts.SMTPUsername = s.Value
		case "smtp_password":
			// v0.10.226: was assigning raw s.Value, which is "{enc}<base64>"
			// ciphertext for any password saved through the admin UI.
			// Result: every real alert email (CPU threshold, interface
			// down, VPN tunnel down, etc.) was sending ciphertext to the
			// SMTP server as the auth password, which never matched.
			// DecryptField is idempotent for unencrypted values, so this
			// is safe even when smtp_password was set via env var rather
			// than the admin UI.
			if am.db != nil {
				am.config.Alerts.SMTPPassword = am.db.DecryptField(s.Value)
			} else {
				am.config.Alerts.SMTPPassword = s.Value
			}
		case "smtp_from":
			am.config.Alerts.SMTPFrom = s.Value
		case "smtp_to":
			am.config.Alerts.SMTPTo = s.Value
		case "slack_webhook":
			am.config.Alerts.SlackWebhookURL = s.Value
		case "discord_webhook":
			am.config.Alerts.DiscordWebhookURL = s.Value
		case "webhook_url":
			am.config.Alerts.WebHookURL = s.Value
		case "webhook_secret":
			// Encrypted at rest like smtp_password; DecryptField is idempotent
			// for plaintext (env-sourced) values.
			if am.db != nil {
				am.config.Alerts.WebhookSecret = am.db.DecryptField(s.Value)
			} else {
				am.config.Alerts.WebhookSecret = s.Value
			}
		case "pagerduty_routing_key":
			if am.db != nil {
				am.config.Alerts.PagerDutyRoutingKey = am.db.DecryptField(s.Value)
			} else {
				am.config.Alerts.PagerDutyRoutingKey = s.Value
			}
		case "opsgenie_api_key":
			if am.db != nil {
				am.config.Alerts.OpsgenieAPIKey = am.db.DecryptField(s.Value)
			} else {
				am.config.Alerts.OpsgenieAPIKey = s.Value
			}
		case "teams_webhook":
			am.config.Alerts.TeamsWebhookURL = s.Value
		case "report_daily_enabled":
			am.config.Alerts.ReportDailyEnabled = s.Value == "true"
		case "report_daily_time":
			am.config.Alerts.ReportDailyTime = s.Value
		case "report_weekly_enabled":
			am.config.Alerts.ReportWeeklyEnabled = s.Value == "true"
		case "report_weekly_day":
			am.config.Alerts.ReportWeeklyDay = s.Value
		case "report_recipients":
			am.config.Alerts.ReportRecipients = s.Value
		case "report_timezone":
			am.config.Alerts.ReportTimezone = s.Value
		case "spike_stddev_threshold":
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v > 0 {
				am.config.Alerts.SpikeStdDevThreshold = v
			}
		case "spike_alert_enabled":
			am.config.Alerts.SpikeAlertEnabled = s.Value == "true"
		case "spike_min_duration_minutes":
			if v, err := strconv.Atoi(s.Value); err == nil && v > 0 {
				am.config.Alerts.SpikeMinDurationMinutes = v
			}
		case "spike_min_throughput_mbps":
			// >= 0, NOT the sibling > 0 pattern: a saved 0 means "disable the
			// floor" and must not be silently ignored.
			if v, err := strconv.ParseFloat(s.Value, 64); err == nil && v >= 0 {
				am.config.Alerts.SpikeMinThroughputMbps = v
			}
		}
	}
}

func (am *AlertManager) SetCooldown(duration time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alertCooldown = duration
}

// sendRecovery auto-resolves the matching OPEN alert when a condition clears and,
// if the alert was active in this process, emits a recovery notification + companion
// _RESOLVED record. Must NOT be called with am.mu held — it acquires the lock internally.
//
// metricName scopes the resolution to the SPECIFIC resource that recovered (the value
// stored in Alert.MetricName, e.g. "interface_<name>", "vpn_<tunnel>", "device_status").
// Without it, a recovery for one interface would wrongly resolve every INTERFACE_DOWN
// alert on the device.
func (am *AlertManager) sendRecovery(key string, alertType models.AlertType, metricName, message string, deviceID uint, siteID *uint) {
	am.mu.Lock()
	wasActive := am.activeAlerts[key]
	if wasActive {
		delete(am.activeAlerts, key)
	}
	// F13: measure how long this alert lived. A short-lived fire→resolve
	// cycle counts toward the flap window, and while the key is flapping the
	// recovery notification is muted too (the fire is already muted — its
	// "back to normal" pair would just double the residual noise).
	flapping := false
	if wasActive && am.config.Alerts.FlapMaxFires > 0 {
		nowF := time.Now()
		if start, ok := am.fireStart[key]; ok {
			minActive := time.Duration(am.config.Alerts.FlapMinActiveSeconds) * time.Second
			if minActive <= 0 {
				minActive = 2 * time.Minute
			}
			if nowF.Sub(start) < minActive {
				am.flapShortResolves[key] = append(am.flapShortResolves[key], nowF)
			}
		}
		flapping = am.flapPruneLocked(key, nowF) >= am.config.Alerts.FlapMaxFires
	}
	delete(am.fireStart, key)
	// LC-13/LC-42: resolve the device/type config exactly like the fire path,
	// so the recovery notification honors maintenance windows and routes
	// through the policy's channels — including the stateful PagerDuty /
	// Opsgenie resolve, which the plain global snapshot could never reach
	// (its PolicyActive/Enable* flags are always false).
	resolved := am.resolveAlertConfig(deviceID, siteID, alertType)
	nc := BuildNotifyConfigFromResolved(resolved, notifier.SnapshotConfig(&am.config.Alerts))
	am.mu.Unlock()

	// Always run the precisely-scoped DB resolve, independent of the in-memory
	// activeAlerts state (idempotent + restart-safe). Extracted so the spike
	// resolve path (ProcessSpikeResolve) can reuse the exact close semantics.
	am.resolveOpenAlertRows(deviceID, alertType, metricName, message)

	// Only notify + record the companion when the alert was active in THIS process.
	// A cold resolve (post-restart, or a redundant per-poll up signal) clears the
	// ticket silently without re-sending a "back up" email.
	if !wasActive {
		return
	}

	now := time.Now()
	alert := models.Alert{
		Timestamp:      now,
		DeviceID:       deviceID,
		AlertType:      alertType + "_RESOLVED",
		Severity:       "info",
		Message:        message,
		MetricName:     "recovery",
		Acknowledged:   true,
		AcknowledgedAt: &now,
		ResolvedAt:     &now,
		// LC-13: a recovery inside a maintenance window is muted like its fire
		// (same contract as flap muting below) — the DB auto-resolve above
		// already ran, so the ticket still clears silently.
		Suppressed: resolved.InMaintenance,
	}
	am.saveAlert(&alert)
	if flapping || alert.Suppressed {
		return
	}
	// LC-42: notify with the ORIGINAL metric name so PagerDuty's dedup_key and
	// Opsgenie's alias reproduce the fire's key and the incident auto-resolves;
	// the persisted companion row keeps the "recovery" discriminator that the
	// response stats and companion queries rely on.
	notifyAlert := alert
	notifyAlert.MetricName = metricName
	if err := am.notify(&notifyAlert, nc); err != nil {
		log.Printf("Failed to send recovery notification: %v", err)
	}
}

func (am *AlertManager) saveAlert(alert *models.Alert) {
	if am.db == nil {
		return
	}
	if err := am.db.SaveAlert(alert); err != nil {
		log.Printf("Failed to persist alert %s: %v", alert.AlertType, err)
	}
}

// resolveOpenAlertRows closes every OPEN row for (device, alertType, metricName):
// unacked rows resolve + auto-acknowledge + clear snooze; acked rows resolve
// (preserving the ack timestamp, APPENDING the auto-resolution note). Idempotent
// and restart-safe (matches only resolved_at IS NULL). Shared by sendRecovery and
// ProcessSpikeResolve.
func (am *AlertManager) resolveOpenAlertRows(deviceID uint, alertType models.AlertType, metricName, message string) {
	if am.db == nil {
		return
	}
	now := time.Now()
	base := am.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NULL", deviceID, alertType, metricName)
	base.Session(&gorm.Session{}).Where("acknowledged = ?", false).
		Updates(map[string]interface{}{
			"resolved_at":     now,
			"acknowledged":    true,
			"acknowledged_at": now,
			"notes":           "Auto-resolved: " + message,
			"snoozed_until":   nil,
			"snoozed_by":      "",
			"snoozed_reason":  "",
		})
	// AUDIT-144 + acked-recovery: also close acked rows, preserving the ack note.
	base.Session(&gorm.Session{}).Where("acknowledged = ?", true).
		Updates(map[string]interface{}{
			"resolved_at":    now,
			"notes":          gorm.Expr("CASE WHEN COALESCE(notes,'') = '' THEN ? ELSE notes || ? END", "Auto-resolved: "+message, "\nAuto-resolved: "+message),
			"snoozed_until":  nil,
			"snoozed_by":     "",
			"snoozed_reason": "",
		})
}

// dispatchFired persists each fired alert and sends it unless suppressed. The
// batch Check* methods collect alerts under am.mu and then call this AFTER
// releasing the lock, so the (potentially slow) notifier send never blocks other
// alert checks. label identifies the source in the send-failure log line.
func (am *AlertManager) dispatchFired(fired []firedEntry, globalNC notifier.NotifyConfig, label string) {
	for i := range fired {
		// Cross-restart dedup: skip the save+send if this state alert was already
		// raised (and is still open) within its cooldown window — see
		// dbCooldownActive. The in-memory cooldown set by the gate suppresses
		// duplicates only within this process; the DB check covers a restart.
		cooldown := time.Duration(fired[i].resolved.CooldownMinutes) * time.Minute
		if am.dbCooldownActive(fired[i].alert.DeviceID, fired[i].alert.AlertType, fired[i].alert.MetricName, fired[i].alert.Timestamp, cooldown) {
			continue
		}
		// F13 flap suppression: a key that has been rapid-cycling (fire →
		// resolve in under FlapMinActiveSeconds, FlapMaxFires times inside the
		// window) is saved SUPPRESSED — visible in the UI with the [FLAPPING]
		// tag, but no notification. Same contract as maintenance suppression.
		if am.flapSuppress(fired[i].key, fired[i].alert.Timestamp) {
			fired[i].alert.Suppressed = true
			fired[i].alert.Message = "[FLAPPING] " + fired[i].alert.Message
			log.Printf("flap suppression: %s notifications muted (key=%s) — ≥%d short-lived cycles within window",
				fired[i].alert.AlertType, fired[i].key, am.config.Alerts.FlapMaxFires)
		}
		// F12: while the device has an open incident, attach the alert and
		// mute its individual notification — the incident is the story.
		incidentMuted := false
		if incID := am.incidentFor(fired[i].alert.DeviceID); incID != 0 {
			fired[i].alert.IncidentID = &incID
			incidentMuted = true
			log.Printf("incident %d: attached %s for device %d (notification muted)",
				incID, fired[i].alert.AlertType, fired[i].alert.DeviceID)
		}
		am.saveAlert(&fired[i].alert)
		if !fired[i].alert.Suppressed && !incidentMuted {
			nc := BuildNotifyConfigFromResolved(fired[i].resolved, globalNC)
			if err := am.notify(&fired[i].alert, nc); err != nil {
				log.Printf("Failed to send %s alert %s: %v", label, fired[i].alert.AlertType, err)
			}
		}
	}
}

func (am *AlertManager) CheckVPNStatus(vpnStatuses []models.VPNStatus, siteID *uint) error {
	var fired []firedEntry
	var stateCands []stateCandidate

	am.mu.Lock()
	now := time.Now()
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	owned := am.stateOwned[StateEventVPNDown]
	for _, vpn := range vpnStatuses {
		key := vpnDownKey(vpn.DeviceID, vpn.TunnelName)
		if vpn.Status == "up" {
			am.markEverUpLocked(key)
			continue
		}
		if vpn.Status != "down" {
			continue
		}
		// Only a tunnel that has actually come up is an outage when down.
		// Idle/never-up tunnels (dial-up, disabled configs, unestablished
		// phase2 selectors) relay status="down" every cycle and must not
		// alert. everUp is populated from live up-rows and the poller's
		// counter/uptime check (MarkVPNEverUp), never from open alerts.
		if !am.everUp[key] {
			continue
		}

		// State-engine ownership: route through source="state" rules + episode
		// dampening (mirrors CheckInterfaceStatus).
		if owned {
			vendor := "generic"
			if m, ok := am.deviceMeta[vpn.DeviceID]; ok && m.Vendor != "" {
				vendor = m.Vendor
			}
			fields := vpnStateFields(vpn.DeviceID, vpn.TunnelName, vendor)
			action, rule, matched := am.matchStateRuleLocked(fields, vpn.DeviceID, siteID)
			if !matched || action == "suppress" {
				continue
			}
			cand, ok := am.buildStateCandidateLocked(
				rule, vpn.DeviceID, siteID, key, "VPN_TUNNEL_DOWN",
				fmt.Sprintf("vpn_%s", vpn.TunnelName),
				fmt.Sprintf("VPN tunnel %s to %s is down", vpn.TunnelName, vpn.RemoteIP), globalNC)
			if !ok {
				continue // alerting disabled for this device/type
			}
			stateCands = append(stateCands, cand)
			continue
		}

		resolved := am.resolveAlertConfig(vpn.DeviceID, siteID, "VPN_TUNNEL_DOWN")
		if !resolved.AlertEnabled {
			continue
		}
		cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
		if am.canAlertWithCooldown(key, now, cooldown) {
			alert := models.Alert{
				Timestamp:  now,
				DeviceID:   vpn.DeviceID,
				AlertType:  "VPN_TUNNEL_DOWN",
				Severity:   resolved.Severity,
				Message:    fmt.Sprintf("VPN tunnel %s to %s is down", vpn.TunnelName, vpn.RemoteIP),
				MetricName: fmt.Sprintf("vpn_%s", vpn.TunnelName),
				PolicyID:   resolved.PolicyID,
				Suppressed: resolved.InMaintenance,
			}
			am.recordCooldownLocked(key, now, cooldown)
			am.markActiveLocked(key, now)
			fired = append(fired, firedEntry{alert, resolved, key})
		}
	}
	am.mu.Unlock()

	am.dispatchFired(fired, globalNC, "VPN")
	am.dispatchStateCandidates(stateCands, now)

	// Recovery: VPN tunnels that are now up
	for _, vpn := range vpnStatuses {
		if vpn.Status == "up" {
			key := vpnDownKey(vpn.DeviceID, vpn.TunnelName)
			am.sendRecovery(key, "VPN_TUNNEL_DOWN", fmt.Sprintf("vpn_%s", vpn.TunnelName),
				fmt.Sprintf("VPN tunnel %s to %s is back up", vpn.TunnelName, vpn.RemoteIP), vpn.DeviceID, siteID)
		}
	}
	return nil
}

func (am *AlertManager) CheckDeviceOffline(device *models.Device) error {
	am.mu.Lock()
	now := time.Now()
	key := fmt.Sprintf("device_offline_%d", device.ID)
	resolved := am.resolveAlertConfig(device.ID, device.SiteID, "DEVICE_OFFLINE")
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	// device-source Event Rule consult (v0.11.112): suppress mutes the fire
	// (and skips active-marking, so no recovery notification either — a muted
	// class is fully muted); alert-action overlays severity/policy/cooldown.
	devRule, devSuppressed := am.consultDeviceRuleLocked("DEVICE_OFFLINE", device.ID, device.SiteID, string(resolved.Severity), nil, &resolved)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	// LC-12: gate on AlertEnabled BEFORE marking the key active (mirrors
	// CheckProbeDataFlow). Marking active with the rule disabled left
	// activeAlerts[key] set, so recovery still sent a "back online"
	// notification + _RESOLVED row for an alert type the operator disabled.
	canSend := !devSuppressed && resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
		am.markActiveLocked(key, now)
	}
	am.mu.Unlock()

	if devRule != nil {
		am.RecordEventRuleHit(devRule.id)
	}
	if !canSend {
		return nil
	}

	alert := models.Alert{
		Timestamp:  now,
		DeviceID:   device.ID,
		AlertType:  "DEVICE_OFFLINE",
		Severity:   resolved.Severity,
		Message:    fmt.Sprintf("Device %s (%s) is offline", device.Name, device.IPAddress),
		MetricName: "device_status",
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}

	// Cross-restart dedup (see dbCooldownActive): DEVICE_OFFLINE is the canonical
	// persistent-state alert — without this, a poller restart re-pages for every
	// device still offline. The in-memory gate above already set lastAlert[key]
	// (reusing its cooldown here), so this DB check only gates the first
	// post-restart fire.
	if am.dbCooldownActive(device.ID, "DEVICE_OFFLINE", "device_status", now, cooldown) {
		return nil
	}

	// F12: an offline device opens (or joins) its incident; everything that
	// fires for the device while it's open attaches and is muted. The
	// DEVICE_OFFLINE alert itself is the incident-opening event and DOES
	// notify.
	if inc := am.openIncident(device, alert.Severity); inc != nil {
		alert.IncidentID = &inc.ID
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notify(&alert, nc); err != nil {
			log.Printf("Failed to send device offline alert: %v", err)
		}
	}
	return nil
}

// CheckDeviceOnline sends a recovery notification if the device was previously marked offline.
func (am *AlertManager) CheckDeviceOnline(device *models.Device) {
	key := fmt.Sprintf("device_offline_%d", device.ID)
	am.sendRecovery(key, "DEVICE_OFFLINE", "device_status",
		fmt.Sprintf("Device %s (%s) is back online", device.Name, device.IPAddress), device.ID, device.SiteID)
	// F12: recovery closes the device's incident with one summary notification.
	am.closeIncident(device)
}

// CheckTelemetryStale fires when a device the collector can still reach (it
// stays "online" via ping/other bumps) has stopped producing polled telemetry
// — the silent failure mode opened by v0.11.100, where the freshness gate just
// skips stale rows and every threshold check goes quiet. detail names the
// stale signal(s) with their last-seen times (built by the poller, which holds
// the row timestamps). The message hedges the diagnosis deliberately: a skewed
// collector clock makes rows look stale while data flows, so asserting
// "credentials broken" outright would be a confident wrong answer.
func (am *AlertManager) CheckTelemetryStale(device *models.Device, detail string) error {
	am.mu.Lock()
	now := time.Now()
	key := fmt.Sprintf("telemetry_stale_%d", device.ID)
	resolved := am.resolveAlertConfig(device.ID, device.SiteID, models.AlertTypeTelemetryStale)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	// device-source Event Rule consult (v0.11.112).
	devRule, devSuppressed := am.consultDeviceRuleLocked(models.AlertTypeTelemetryStale, device.ID, device.SiteID,
		string(resolved.Severity), map[string]string{"detail": detail}, &resolved)
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	// LC-12: AlertEnabled gates the cooldown/active marking (see CheckDeviceOffline).
	canSend := !devSuppressed && resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
		am.markActiveLocked(key, now)
	}
	am.mu.Unlock()

	if devRule != nil {
		am.RecordEventRuleHit(devRule.id)
	}
	if !canSend {
		return nil
	}

	alert := models.Alert{
		Timestamp: now,
		DeviceID:  device.ID,
		AlertType: models.AlertTypeTelemetryStale,
		Severity:  resolved.Severity,
		Message: fmt.Sprintf("Polled telemetry stale for %s (%s): %s. The device is still reachable by its collector — SNMP/SSH collection may be broken (credentials, agent, ACL), or the collector's clock is skewed.",
			device.Name, device.IPAddress, detail),
		MetricName: "telemetry",
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}

	// Cross-restart dedup: like DEVICE_OFFLINE this is a persistent-state
	// alert — without the DB check a poller restart re-pages for every device
	// still degraded.
	if am.dbCooldownActive(device.ID, models.AlertTypeTelemetryStale, "telemetry", now, cooldown) {
		return nil
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notify(&alert, nc); err != nil {
			log.Printf("Failed to send telemetry stale alert: %v", err)
		}
	}
	return nil
}

// CheckTelemetryRecovered resolves an open TELEMETRY_STALE when fresh polled
// telemetry is arriving again. sendRecovery always runs two UPDATEs, so this
// gates the call: only when the alert is active in this process, plus one
// unconditional cold sweep per device per process lifetime to clear rows left
// open across a restart.
func (am *AlertManager) CheckTelemetryRecovered(device *models.Device) {
	key := fmt.Sprintf("telemetry_stale_%d", device.ID)
	am.mu.Lock()
	active := am.activeAlerts[key]
	swept := am.telemetryColdSwept[device.ID]
	am.telemetryColdSwept[device.ID] = true
	am.mu.Unlock()
	if !active && swept {
		return
	}
	am.sendRecovery(key, models.AlertTypeTelemetryStale, "telemetry",
		fmt.Sprintf("Polled telemetry recovered for %s (%s)", device.Name, device.IPAddress),
		device.ID, device.SiteID)
}

// AutoResolveTelemetryStale silently closes an open TELEMETRY_STALE when the
// device transitions to fully offline — DEVICE_OFFLINE supersedes it and one
// failure must not stay open as two alerts. Deliberately NOT sendRecovery:
// that would email "telemetry recovered" at the exact moment of total device
// failure (the key is active precisely in this scenario).
func (am *AlertManager) AutoResolveTelemetryStale(deviceID uint) {
	key := fmt.Sprintf("telemetry_stale_%d", deviceID)
	am.mu.Lock()
	delete(am.activeAlerts, key)
	delete(am.fireStart, key)
	am.mu.Unlock()
	am.resolveOpenAlertRows(deviceID, models.AlertTypeTelemetryStale, "telemetry",
		"Superseded by DEVICE_OFFLINE — the device stopped reporting entirely")
}

// CheckSSHHostKeyChanged fires a CRITICAL alert when a device's reported SSH
// host-key fingerprint differs from the one previously pinned. It is a
// transient, point-in-time alert (cooldown-gated, no recovery state): the caller
// re-pins the new fingerprint after this returns, so it fires once per change.
// oldFP/newFP are SSH host-key fingerprints (e.g. "SHA256:...").
func (am *AlertManager) CheckSSHHostKeyChanged(device *models.Device, newFP string, haFailover bool) error {
	am.mu.Lock()
	now := time.Now()
	// Cooldown keyed per (device, fingerprint) so each distinct new key alerts
	// once even if several appear in quick succession.
	key := fmt.Sprintf("ssh_host_key_%d_%s", device.ID, newFP)
	resolved := am.resolveAlertConfig(device.ID, device.SiteID, "SSH_HOST_KEY_CHANGED")
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	// A new key that correlates with a recent HA failover is an expected event
	// (cluster members present distinct host keys) — WARNING, not CRITICAL.
	// Computed BEFORE the rule consult so severity-scoped rules match the
	// severity the alert would actually carry.
	severity := resolved.Severity
	if haFailover {
		severity = "warning"
	}
	// device-source Event Rule consult (v0.11.112): rules can scope on the new
	// fingerprint (e.g. pre-approve a planned key rotation).
	devRule, devSuppressed := am.consultDeviceRuleLocked("SSH_HOST_KEY_CHANGED", device.ID, device.SiteID,
		string(severity), map[string]string{"fingerprint": newFP}, &resolved)
	if devRule != nil && devRule.action == "alert" && devRule.severity != "" {
		severity = devRule.severity // an explicit rule re-grade wins over the HA downgrade
	}
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
	// LC-12 sibling: AlertEnabled gates the cooldown recording too.
	canSend := !devSuppressed && resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if devRule != nil {
		am.RecordEventRuleHit(devRule.id)
	}
	if !canSend {
		return nil
	}

	message := fmt.Sprintf("SSH host key changed for device %s (%s): new fingerprint %s, with no matching HA failover. If this was not a planned change, treat the device admin credentials as exposed and rotate them.", device.Name, device.IPAddress, newFP)
	if haFailover {
		message = fmt.Sprintf("New SSH host key %s observed for device %s (%s), correlated with a recent HA failover — learned as a known cluster-member key.", newFP, device.Name, device.IPAddress)
	}

	alert := models.Alert{
		Timestamp:  now,
		DeviceID:   device.ID,
		AlertType:  "SSH_HOST_KEY_CHANGED",
		Severity:   severity,
		Message:    message,
		MetricName: "ssh_host_key",
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}

	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notify(&alert, nc); err != nil {
			log.Printf("Failed to send SSH host-key change alert: %v", err)
		}
	}
	return nil
}

// ConfigChangeInfo carries the semantic classification and attribution of a
// detected config change so the CONFIG_CHANGE alert can be severity-driven and
// accountable. All fields are optional — a zero value reproduces the legacy
// always-"warning", checksum-only alert. Severity uses the configdiff scale
// (info|medium|high|critical); the alerts layer maps it to info|warning|critical
// without importing configdiff.
type ConfigChangeInfo struct {
	Severity   string // configdiff severity of the most significant change
	Impact     string // human-readable "security impact" summary
	ChangedBy  string // admin user, if attributed
	Method     string // GUI | CLI(ssh) | jsconsole | API
	Attributed bool   // a matching authenticated session was found
}

// CheckConfigRevision creates a CONFIG_CHANGE alert when the config checksum
// differs from the previous. The alert severity reflects the security impact of
// the change, and the message reports who made it (or flags it as a possible
// out-of-band change when no authenticated session was found).
func (am *AlertManager) CheckConfigRevision(deviceID uint, oldChecksum, newChecksum string, info ConfigChangeInfo) {
	if am.db == nil {
		return
	}
	device, err := am.db.GetDevice(deviceID)
	if err != nil {
		return
	}
	key := fmt.Sprintf("config_change_%d", deviceID)

	// Severity is computed from the configdiff classification BEFORE the rule
	// consult so severity-scoped rules match what the alert would carry.
	severity := configSeverityToAlert(info.Severity)
	if !info.Attributed {
		// No authenticated admin session matched this change — escalate one notch
		// (message flag added below).
		severity = escalateSeverity(severity)
	}

	am.mu.Lock()
	now := time.Now()
	// v0.11.112: this path previously bypassed resolveAlertConfig entirely — no
	// maintenance suppression, no per-type disable, fixed cooldown. It now
	// resolves config for those gates; the 60-minute cooldown stays the type
	// default so behavior without rules/policies is unchanged, with a matched
	// device rule able to override it.
	resolved := am.resolveAlertConfig(deviceID, device.SiteID, "CONFIG_CHANGE")
	devRule, devSuppressed := am.consultDeviceRuleLocked("CONFIG_CHANGE", deviceID, device.SiteID,
		string(severity), map[string]string{
			"method": info.Method, "changed_by": info.ChangedBy, "impact": info.Impact,
		}, &resolved)
	if devRule != nil && devRule.action == "alert" && devRule.severity != "" {
		severity = devRule.severity
	}
	cooldown := 60 * time.Minute
	if devRule != nil && devRule.action == "alert" && devRule.cooldownMin != nil && *devRule.cooldownMin > 0 {
		cooldown = time.Duration(*devRule.cooldownMin) * time.Minute
	}
	canSend := !devSuppressed && resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if devRule != nil {
		am.RecordEventRuleHit(devRule.id)
	}
	if !canSend {
		return
	}

	oldShort, newShort := oldChecksum, newChecksum
	if len(oldChecksum) >= 8 {
		oldShort = oldChecksum[:8]
	}
	if len(newChecksum) >= 8 {
		newShort = newChecksum[:8]
	}

	who := "unknown user"
	if info.ChangedBy != "" {
		who = info.ChangedBy
		if info.Method != "" {
			who += " via " + info.Method
		}
	}
	msg := fmt.Sprintf("Config change detected on %s by %s (checksum %s → %s)", device.Name, who, oldShort, newShort)
	if info.Impact != "" {
		msg += ". Impact: " + info.Impact
	}
	if !info.Attributed {
		msg += " [no authenticated admin session found — possible out-of-band change]"
	}

	am.saveAlert(&models.Alert{
		DeviceID:   deviceID,
		AlertType:  "CONFIG_CHANGE",
		Severity:   severity,
		Message:    msg,
		Timestamp:  now,
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	})
}

// configSeverityToAlert maps a configdiff severity onto the alert vocabulary
// (info | warning | critical). Empty/unknown defaults to "warning" to preserve
// the legacy behavior.
func configSeverityToAlert(sev string) models.Severity {
	switch sev {
	case "info":
		return "info"
	case "high", "critical":
		return "critical"
	case "medium", "":
		return "warning"
	default:
		return "warning"
	}
}

// escalateSeverity bumps an alert severity one notch toward critical.
func escalateSeverity(sev models.Severity) models.Severity {
	switch sev {
	case "info":
		return "warning"
	default:
		return "critical"
	}
}

// CheckProbeDataFlow checks all approved probes and alerts if any have not sent
// data within the configured threshold (PROBE_DATA_LAG_ALERT_MINUTES).
// This catches issues like queue full, network problems, or systematic data loss
// that wouldn't be caught by heartbeat-based DEVICE_OFFLINE alerts.
func (am *AlertManager) CheckProbeDataFlow() error {
	if am.db == nil || am.config.Alerts.ProbeDataLagAlertMinutes <= 0 {
		return nil
	}

	probes, err := am.db.GetApprovedProbes()
	if err != nil {
		return fmt.Errorf("failed to get approved probes: %w", err)
	}

	now := time.Now()
	lagThreshold := time.Duration(am.config.Alerts.ProbeDataLagAlertMinutes) * time.Minute
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)

	for _, probe := range probes {
		// M28 of the 2026-07-01 audit: DecommissionProbe deliberately keeps
		// approval_status='approved' (telemetry attribution), so
		// GetApprovedProbes still returns retired probes — whose
		// LastDataReceived is frozen by design. Without this skip, the
		// documented soft-decommission path produced a PROBE_DATA_LAG alert
		// on every cooldown expiry, forever.
		if probe.DecommissionedAt != nil || !probe.Enabled {
			continue
		}
		if probe.LastDataReceived.IsZero() {
			continue
		}

		lag := now.Sub(probe.LastDataReceived)
		if lag < lagThreshold {
			key := fmt.Sprintf("probe_data_lag_%d", probe.ID)
			am.sendRecovery(key, "PROBE_DATA_LAG", "probe_data_flow",
				fmt.Sprintf("Probe %s is receiving data again (lag cleared)", probe.Name), 0, &probe.SiteID)
			continue
		}

		key := fmt.Sprintf("probe_data_lag_%d", probe.ID)

		// Resolve config, check the cooldown, and record the firing state all
		// under am.mu — these read policyCache and the lastAlert/activeAlerts
		// maps, which other goroutines mutate. This block previously ran
		// unlocked, a latent data race with concurrent alert checks.
		am.mu.Lock()
		resolved := am.resolveAlertConfig(0, &probe.SiteID, "PROBE_DATA_LAG")
		// device-source Event Rule consult (v0.11.112): device_id is 0 for
		// probe-scoped alerts; rules scope on probe_id/probe_name (or site).
		devRule, devSuppressed := am.consultDeviceRuleLocked("PROBE_DATA_LAG", 0, &probe.SiteID,
			string(resolved.Severity), map[string]string{
				"probe_id": strconv.FormatUint(uint64(probe.ID), 10), "probe_name": probe.Name,
			}, &resolved)
		cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute
		canSend := !devSuppressed && resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
		if canSend {
			am.recordCooldownLocked(key, now, cooldown)
			am.markActiveLocked(key, now)
		}
		am.mu.Unlock()
		if devRule != nil {
			am.RecordEventRuleHit(devRule.id)
		}
		if !canSend {
			continue
		}

		alert := models.Alert{
			Timestamp:  now,
			AlertType:  "PROBE_DATA_LAG",
			Severity:   resolved.Severity,
			Message:    fmt.Sprintf("Probe %s has not received data for %v (threshold: %d min)", probe.Name, lag.Round(time.Minute), am.config.Alerts.ProbeDataLagAlertMinutes),
			MetricName: "probe_data_flow",
			PolicyID:   resolved.PolicyID,
			Suppressed: resolved.InMaintenance,
			ProbeID:    &probe.ID,
		}

		am.saveAlert(&alert)
		if !alert.Suppressed {
			nc := BuildNotifyConfigFromResolved(resolved, globalNC)
			if err := am.notify(&alert, nc); err != nil {
				log.Printf("Failed to send probe data lag alert: %v", err)
			}
		}
	}

	return nil
}

// RecordProbeDataTruncation should be called when a data batch is truncated.
// It flags the probe for monitoring - frequent truncation may indicate misconfiguration.
func (am *AlertManager) RecordProbeDataTruncation(probeID uint, probeName string, totalItems, retainedItems int) {
	if am.db == nil {
		return
	}

	key := fmt.Sprintf("probe_truncation_%d", probeID)
	now := time.Now()
	cooldown := 5 * time.Minute

	// Anti-spam: at most one alert per probe per cooldown window. LC-26: the
	// previous guard read a lastAlert key nothing ever wrote and returned early
	// unless a prior alert was RECENT (inverted), so this alert could never fire.
	am.mu.Lock()
	// v0.11.112: this path previously bypassed resolveAlertConfig — no per-type
	// disable, fixed severity/cooldown. The 5-minute cooldown and "warning"
	// severity stay the type defaults so behavior without rules is unchanged.
	resolved := am.resolveAlertConfig(0, nil, "PROBE_DATA_TRUNCATED")
	severity := models.Severity("warning")
	devRule, devSuppressed := am.consultDeviceRuleLocked("PROBE_DATA_TRUNCATED", 0, nil,
		string(severity), map[string]string{
			"probe_id": strconv.FormatUint(uint64(probeID), 10), "probe_name": probeName,
		}, &resolved)
	if devRule != nil && devRule.action == "alert" {
		if devRule.severity != "" {
			severity = devRule.severity
		}
		if devRule.cooldownMin != nil && *devRule.cooldownMin > 0 {
			cooldown = time.Duration(*devRule.cooldownMin) * time.Minute
		}
	}
	if devSuppressed || !resolved.AlertEnabled || !am.canAlertWithCooldown(key, now, cooldown) {
		am.mu.Unlock()
		if devRule != nil {
			am.RecordEventRuleHit(devRule.id)
		}
		return
	}
	am.recordCooldownLocked(key, now, cooldown)
	nc := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()
	if devRule != nil {
		am.RecordEventRuleHit(devRule.id)
	}

	alert := models.Alert{
		Timestamp:  now,
		AlertType:  "PROBE_DATA_TRUNCATED",
		Severity:   severity,
		Message:    fmt.Sprintf("Probe %s sent batch of %d items, kept %d (truncated %d) — possible misconfiguration", probeName, totalItems, retainedItems, totalItems-retainedItems),
		MetricName: "probe_data_truncation",
		ProbeID:    &probeID,
	}

	am.saveAlert(&alert)
	if err := am.notify(&alert, nc); err != nil {
		log.Printf("Failed to send probe truncation alert: %v", err)
	}
}

// CheckEscalations scans unacknowledged alerts and re-sends notifications
// for those that have exceeded their escalation interval.
func (am *AlertManager) CheckEscalations() {
	if am.db == nil {
		return
	}

	am.mu.Lock()
	if !am.policyCache.loaded {
		am.mu.Unlock()
		return
	}

	// Collect policies with escalation enabled — legacy (minutes/repeat) or
	// F19 step chains (a step definition implies escalation regardless of the
	// legacy toggle).
	escalationPolicies := make(map[uint]*models.AlertPolicy)
	policySteps := make(map[uint][]EscalationStep)
	for i := range am.policyCache.policies {
		p := &am.policyCache.policies[i]
		if steps, err := ParseEscalationSteps(p.EscalationSteps); err == nil && len(steps) > 0 {
			escalationPolicies[p.ID] = p
			policySteps[p.ID] = steps
			continue
		}
		if p.EscalationEnabled && p.EscalationMinutes > 0 {
			escalationPolicies[p.ID] = p
		}
	}
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	am.mu.Unlock()

	if len(escalationPolicies) == 0 {
		return
	}

	// Find unacknowledged, non-suppressed alerts
	cutoff := time.Now().Add(-24 * time.Hour) // only look at last 24h
	alerts, err := am.db.GetUnacknowledgedAlerts(cutoff)
	if err != nil {
		log.Printf("CheckEscalations: failed to get alerts: %v", err)
		return
	}

	// Collect escalated alert IDs for batch update
	type escalated struct {
		id       uint
		newCount int
	}
	var escalatedIDs []escalated

	for _, alert := range alerts {
		if alert.PolicyID == nil {
			continue
		}
		// F12/LC-11: an alert attached to a still-open incident had its
		// individual notification muted at fire time — the incident is the
		// story. Don't resurrect it as per-alert escalations while the
		// incident stays open.
		if alert.IncidentID != nil && am.incidentFor(alert.DeviceID) == *alert.IncidentID {
			continue
		}
		// Event-profile toggle gate (v0.11.122): escalation re-notifies were
		// the one ungated notify path — an operator toggling a type Off kept
		// receiving escalations for its already-open alerts. The toggle is
		// the single per-type kill switch; honor it here too.
		if !am.EventTypeToggledOn(alert.DeviceID, alert.SiteID, alert.AlertType) {
			continue
		}
		policy, ok := escalationPolicies[*alert.PolicyID]
		if !ok {
			continue
		}
		elapsed := time.Since(alert.Timestamp)

		resolvedShape := ResolvedAlertConfig{
			PolicyID:        alert.PolicyID,
			NotifyEmail:     policy.NotifyEmail,
			NotifySlack:     policy.NotifySlack,
			NotifyDiscord:   policy.NotifyDiscord,
			NotifyWebhook:   policy.NotifyWebhook,
			NotifyPagerDuty: policy.NotifyPagerDuty,
			NotifyOpsgenie:  policy.NotifyOpsgenie,
			NotifyTeams:     policy.NotifyTeams,
			EmailRecipients: policy.EmailRecipients,
			SlackURL:        policy.SlackWebhookURL,
			DiscordURL:      policy.DiscordWebhookURL,
			WebhookURL:      policy.WebhookURL,
		}

		// F19 step chains: EscalationCount = steps completed. Fire every step
		// whose after_minutes has elapsed and hasn't fired yet, each to
		// exactly its own channels/recipients.
		if steps := policySteps[policy.ID]; len(steps) > 0 {
			completed := alert.EscalationCount
			for i := completed; i < len(steps); i++ {
				if elapsed < time.Duration(steps[i].AfterMinutes)*time.Minute {
					break
				}
				nc := stepNotifyConfig(steps[i], resolvedShape, globalNC)
				escalatedAlert := alert
				escalatedAlert.Message = fmt.Sprintf("[ESCALATION step %d/%d] %s", i+1, len(steps), alert.Message)
				if err := am.notify(&escalatedAlert, nc); err != nil {
					log.Printf("CheckEscalations: step %d send failed for alert %d: %v", i+1, alert.ID, err)
					break // retry this step next cycle; don't skip ahead
				}
				completed = i + 1
			}
			if completed > alert.EscalationCount {
				escalatedIDs = append(escalatedIDs, escalated{alert.ID, completed})
			}
			continue
		}

		// Legacy thin model: re-send on a fixed cadence up to Repeat times.
		if alert.EscalationCount >= policy.EscalationRepeat {
			continue
		}
		expectedEscalations := int(elapsed.Minutes()) / policy.EscalationMinutes
		if expectedEscalations <= alert.EscalationCount {
			continue
		}

		nc := BuildNotifyConfigFromResolved(resolvedShape, globalNC)

		escalatedAlert := alert
		escalatedAlert.Message = fmt.Sprintf("[ESCALATION %d/%d] %s", alert.EscalationCount+1, policy.EscalationRepeat, alert.Message)

		if err := am.notify(&escalatedAlert, nc); err != nil {
			log.Printf("CheckEscalations: failed to send escalation for alert %d: %v", alert.ID, err)
			continue
		}

		escalatedIDs = append(escalatedIDs, escalated{alert.ID, alert.EscalationCount + 1})
	}

	// Batch update escalation counts
	for _, e := range escalatedIDs {
		am.db.Gorm().Model(&models.Alert{}).Where("id = ?", e.id).
			Update("escalation_count", e.newCount)
	}
}
