package alerts

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// State-source rule engine (Phase 1 of the alerting-via-Event-Rules program).
// INTERFACE_DOWN / VPN_TUNNEL_DOWN routing goes through enabled source="state"
// rules for scope/suppress + severity/routing; the fire decision + dampening
// (fire once per outage episode; suppress while an open/acked alert exists; ≤1/
// day flap cap; but fire if up ≥ min_up_seconds) is owned HERE, not by the match
// tree. Legacy resolveAlertConfig firing stays until a type's ownership flag is
// set (see EnsureStateRuleSeeds), so there is never a gap or a double-fire.

const stateOwnedTypesSetting = "state_engine_owns" // CSV of owned event_types

// defaultStateMinUpSeconds / defaultStateDailyCap back a rule whose dampen_json
// omits them.
const (
	defaultStateMinUpSeconds = 3600 // 1h "up before down" fast-path
	defaultStateDailyCap     = 1    // ≤1 alert/day while flapping
	stateDailyWindow         = 24 * time.Hour
)

// stateFireDecision is the outcome of the episode/flap dampening.
type stateFireDecision int

const (
	stateSkip           stateFireDecision = iota // same episode (incl. acked) → nothing
	stateFire                                    // new alert-worthy episode → save + notify
	stateSuppressCapped                          // flapping within the daily cap → save Suppressed, no notify
)

// stateCandidate is a down link/tunnel that matched an alert rule; the DB-driven
// fire decision runs OUTSIDE am.mu (dispatchStateCandidates).
type stateCandidate struct {
	deviceID   uint
	key        string
	alertType  models.AlertType
	metricName string
	message    string
	severity   models.Severity
	policyID   *uint
	maint      bool
	nc         notifier.NotifyConfig
	dampen     dampenParams
}

// setStateOwnedLocked replaces the owned-types set (called from RefreshEventRules
// under am.mu).
func (am *AlertManager) setStateOwnedLocked(csv string) {
	owned := map[string]bool{}
	for _, t := range strings.Split(csv, ",") {
		if t = strings.TrimSpace(t); t != "" {
			owned[t] = true
		}
	}
	am.stateOwned = owned
}

// matchStateRuleLocked returns the first (priority-ordered) enabled state rule
// that applies + matches the fields. Caller holds am.mu.
func (am *AlertManager) matchStateRuleLocked(fields map[string]string, deviceID uint, siteID *uint) (action string, rule *compiledRule, matched bool) {
	vendor := "generic"
	if m, ok := am.deviceMeta[deviceID]; ok && m.Vendor != "" {
		vendor = m.Vendor
	}
	for i := range am.eventRules {
		r := &am.eventRules[i]
		if r.source != "state" {
			continue
		}
		if !r.appliesTo("state", vendor, deviceID, siteID) {
			continue
		}
		if !r.match.eval(fields) {
			continue
		}
		return r.action, r, true
	}
	return "", nil, false
}

// buildStateCandidateLocked resolves severity + routing for a matched alert rule
// and returns the candidate (whose fire is decided later, outside the lock). The
// bool is false when alerting is disabled for this device/type — a per-device
// "alerts off" (AlertsEnabled=false) or a per-type policy AlertRule with
// Enabled=false — mirroring the legacy path's AlertEnabled gate so ownership
// doesn't resurrect an alert an operator deliberately turned off. Caller holds
// am.mu.
func (am *AlertManager) buildStateCandidateLocked(rule *compiledRule, deviceID uint, siteID *uint, key string, alertType models.AlertType, metricName, message string, globalNC notifier.NotifyConfig) (stateCandidate, bool) {
	resolved := am.resolveAlertConfig(deviceID, siteID, alertType)
	if !resolved.AlertEnabled {
		return stateCandidate{}, false
	}
	if rule.severity != "" {
		resolved.Severity = rule.severity
	}
	if rule.policyID != nil {
		am.applyRulePolicy(&resolved, *rule.policyID)
	}
	dp := rule.dampen
	if dp.MinUpSeconds <= 0 {
		dp.MinUpSeconds = defaultStateMinUpSeconds
	}
	// DailyCap: 0 means "no cap" (alert on every outage episode) — the UI and the
	// seed rules always set refire_mode, so an explicitly-configured rule honors
	// its 0 verbatim. Only a rule with NO dampen configured at all (empty blob →
	// refire_mode == "" and cap == 0) falls back to the default cap, so a bare
	// state rule still dampens sensibly. Negatives are blocked at validation.
	if dp.RefireMode == "" && dp.DailyCap == 0 {
		dp.DailyCap = defaultStateDailyCap
	}
	return stateCandidate{
		deviceID: deviceID, key: key, alertType: alertType, metricName: metricName,
		message: message, severity: resolved.Severity, policyID: resolved.PolicyID,
		maint: resolved.InMaintenance, nc: BuildNotifyConfigFromResolved(resolved, globalNC),
		dampen: dp,
	}, true
}

// decideStateFire is the DB-driven episode/flap decision. Pure DB reads — runs
// OUTSIDE am.mu. The "how long was it up" signal is `now − last recovery
// (resolved_at)`, which is persistent across a poller restart (no in-memory
// timing to lose). It is check-then-insert (the caller saves the row after this
// returns) and so assumes a SINGLE-GOROUTINE caller per (device, metric) — true
// today: cmd/poller drives Check{Interface,VPN}Status in sequential loops. If a
// second concurrent poller is ever added, this needs a unique open-row index.
func (am *AlertManager) decideStateFire(c stateCandidate, now time.Time) stateFireDecision {
	if am.db == nil {
		return stateFire
	}
	g := am.db.Gorm()
	dayAgo := now.Add(-stateDailyWindow)

	// (1) A LIVE alert already tracks this outage — an OPEN, non-suppressed row
	// (acked OR not) → suppress. This is what makes "don't re-alert an acked down
	// until it recovers and drops again" work: the ack leaves the row open, so we
	// stay silent until sendRecovery resolves it. On a DB error, skip rather than
	// fire — an uncertain read must never storm a re-notification every cycle.
	var openNotified int64
	if err := g.Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NULL AND suppressed = ?", c.deviceID, c.alertType, c.metricName, false).
		Count(&openNotified).Error; err != nil {
		return stateSkip
	}
	if openNotified > 0 {
		return stateSkip
	}

	// Notifications already delivered in the rolling 24h window — the daily cap is
	// "at most DailyCap NOTIFIED (suppressed=false) alerts per 24h".
	var notifiedToday int64
	if err := g.Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND metric_name = ? AND suppressed = ? AND timestamp >= ?", c.deviceID, c.alertType, c.metricName, false, dayAgo).
		Count(&notifiedToday).Error; err != nil {
		return stateSkip
	}
	capReached := c.dampen.DailyCap > 0 && notifiedToday >= int64(c.dampen.DailyCap)

	// (2) A stuck outage whose only open marker is SUPPRESSED (a flap-capped
	// episode, or one muted by maintenance/incident): a link that flapped and then
	// stayed DOWN would otherwise be silent forever after a misleading "back up".
	// Re-escalate once the newest suppressed marker is ≥24h old AND the daily
	// budget has room. The age guard prevents a per-cycle re-fire loop (each fire
	// writes a fresh marker), so this delivers at most one escalation per day.
	// This step precedes the min_up ≥1h fast-path (step 4); that ordering is safe
	// because recovery (sendRecovery) resolves any open suppressed marker, so a
	// genuine up-≥1h-then-down outage has no open suppressed row here and reaches
	// step 4 normally — an open suppressed marker only coexists with a live-down
	// link.
	var newestSuppressed models.Alert
	if err := g.Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NULL AND suppressed = ?", c.deviceID, c.alertType, c.metricName, true).
		Order("timestamp DESC").First(&newestSuppressed).Error; err == nil {
		if capReached {
			return stateSkip
		}
		if now.Sub(newestSuppressed.Timestamp) >= stateDailyWindow {
			return stateFire
		}
		return stateSkip
	}

	// (3) First-ever down for this resource → always fire.
	var anyCnt int64
	if err := g.Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ? AND metric_name = ?", c.deviceID, c.alertType, c.metricName).
		Count(&anyCnt).Error; err != nil {
		return stateSkip
	}
	if anyCnt == 0 {
		return stateFire
	}

	// (4) Up-run duration = time since the most recent recovery. A link that was
	// up for ≥ min_up_seconds before dropping is a genuinely fresh outage, not a
	// flap — fire even inside the daily cap ("unless it was up for a few hours").
	var lr struct{ ResolvedAt *time.Time }
	g.Model(&models.Alert{}).Select("resolved_at").
		Where("device_id = ? AND alert_type = ? AND metric_name = ? AND resolved_at IS NOT NULL", c.deviceID, c.alertType, c.metricName).
		Order("resolved_at DESC").First(&lr)
	if c.dampen.MinUpSeconds > 0 && lr.ResolvedAt != nil &&
		now.Sub(*lr.ResolvedAt) >= time.Duration(c.dampen.MinUpSeconds)*time.Second {
		return stateFire
	}

	// (5) Daily flap cap: fire while the 24h notify budget has room, else save
	// Suppressed (flap evidence, no notify). DailyCap<=0 disables the cap.
	if c.dampen.DailyCap <= 0 || !capReached {
		return stateFire
	}
	return stateSuppressCapped
}

// dispatchStateCandidates applies the episode/flap decision to each candidate and
// saves/notifies. Runs OUTSIDE am.mu (does its own brief locks). A capped fire is
// SAVED Suppressed (keeps flap evidence + outage visibility) but not notified.
func (am *AlertManager) dispatchStateCandidates(cands []stateCandidate, now time.Time) {
	for i := range cands {
		c := cands[i]
		d := am.decideStateFire(c, now)
		if d == stateSkip {
			continue
		}
		// Incident grouping (F12): a down alert during a device outage attaches to
		// the incident and is muted. incidentFor takes am.mu itself, so it must be
		// called WITHOUT the lock held (RWMutex is non-reentrant).
		var incidentID *uint
		if id := am.incidentFor(c.deviceID); id != 0 {
			incidentID = &id
		}

		suppressed := c.maint || d == stateSuppressCapped || incidentID != nil
		msg := c.message
		if d == stateSuppressCapped {
			msg = "[FLAPPING] " + msg
		}
		alert := models.Alert{
			Timestamp: now, DeviceID: c.deviceID, AlertType: c.alertType, Severity: c.severity,
			Message: msg, MetricName: c.metricName, PolicyID: c.policyID, IncidentID: incidentID,
			Suppressed: suppressed,
		}
		am.saveAlert(&alert)
		if d == stateFire && !suppressed {
			am.markActive(c.key, now) // so a later recovery sends the "back up" notification
			if err := am.notify(&alert, c.nc); err != nil {
				logStateNotifyErr(c.alertType, err)
			}
		}
	}
}

// markActive is the lock-taking wrapper around markActiveLocked.
func (am *AlertManager) markActive(key string, now time.Time) {
	am.mu.Lock()
	am.markActiveLocked(key, now)
	am.mu.Unlock()
}

func logStateNotifyErr(t models.AlertType, err error) {
	fmt.Printf("state alert %s notify failed: %v\n", t, err)
}

// ValidateStateDampenJSON checks a state rule's dampen_json for the NOC editor.
// Empty is allowed (defaults apply). Returns a human-readable message on error.
func ValidateStateDampenJSON(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var dp dampenParams
	if err := json.Unmarshal([]byte(s), &dp); err != nil {
		return "Invalid dampen_json: " + err.Error()
	}
	switch dp.RefireMode {
	case "", "episode":
	default:
		return `dampen_json refire_mode must be "episode" (or empty)`
	}
	if dp.MinUpSeconds < 0 {
		return "dampen_json min_up_seconds must be ≥ 0"
	}
	if dp.DailyCap < 0 {
		return "dampen_json daily_cap must be ≥ 0"
	}
	return ""
}

// ValidateMetricDampenJSON checks a metric rule's dampen_json for the NOC editor.
// Empty is allowed (the rule then inherits the resolved threshold). Returns a
// human-readable message on error. Phase 2 validates the shape; the metric
// evaluator that consumes these params lands in Phase 4.
func ValidateMetricDampenJSON(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var dp dampenParams
	if err := json.Unmarshal([]byte(s), &dp); err != nil {
		return "Invalid dampen_json: " + err.Error()
	}
	switch dp.Mode {
	case "", "static", "zscore":
	default:
		return `dampen_json mode must be "static" or "zscore" (or empty)`
	}
	if dp.Threshold < 0 {
		return "dampen_json threshold must be ≥ 0"
	}
	if dp.ClearThreshold < 0 {
		return "dampen_json clear_threshold must be ≥ 0"
	}
	if dp.ZScoreK < 0 {
		return "dampen_json zscore_k must be ≥ 0"
	}
	// A clear threshold at or above the fire threshold inverts the hysteresis band
	// (recover ≥ fire) — the alert would clear immediately. Only meaningful when
	// both are set here. NOTE: when threshold is omitted (= inherit the resolved
	// Settings→Alerts/policy value), the band cannot be checked at save time; the
	// Phase 4 metric evaluator must clamp clear_threshold below the resolved fire
	// threshold at runtime.
	if dp.Threshold > 0 && dp.ClearThreshold > 0 && dp.ClearThreshold >= dp.Threshold {
		return "dampen_json clear_threshold must be below threshold"
	}
	return ""
}
