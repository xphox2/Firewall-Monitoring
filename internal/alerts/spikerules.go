package alerts

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// Traffic-spike rule evaluator (Phase 4b). The seasonal detector stays in the
// poller; only the fire/notify/resolve path moves onto the rule engine here.
// Spike is the ONLY source that never went through resolveAlertConfig, so
// ProcessSpike deliberately preserves today's behavior (global presence-gated
// delivery, no policy AlertEnabled gate, no AlertManager cooldown, base severity
// from the detector) and only LAYERS rules on top: a spike rule can scope,
// suppress, override severity, tune the detector params, or pin a notify policy.
// Non-regressive by construction; the win is per-rule control + a correct
// open/resolve lifecycle (the old poller path never closed the fired row).

// spikeFields is the matchable field set for a traffic-spike event.
func spikeFields(deviceID uint, ifaceName, metric, vendor string) map[string]string {
	return map[string]string{
		"event_type":     SpikeEventTraffic,
		"interface_name": ifaceName,
		"metric":         metric,
		"vendor":         vendor,
		"device_id":      fmt.Sprintf("%d", deviceID),
	}
}

// matchSpikeRuleLocked returns the first (priority-ordered) enabled spike rule
// that applies + matches. Caller holds am.mu (read or write).
func (am *AlertManager) matchSpikeRuleLocked(fields map[string]string, deviceID uint, siteID *uint) (action string, rule *compiledRule, matched bool) {
	for i := range am.eventRules {
		r := &am.eventRules[i]
		if r.source != "spike" {
			continue
		}
		if !r.appliesTo("spike", fields["vendor"], deviceID, siteID) {
			continue
		}
		if !r.match.eval(fields) {
			continue
		}
		return r.action, r, true
	}
	return "", nil, false
}

// spikeEffSiteVendor returns the effective site (caller's, else the device's) and
// the device vendor. Caller holds am.mu.
func (am *AlertManager) spikeEffSiteVendorLocked(deviceID uint, siteID *uint) (effSite *uint, vendor string) {
	effSite, vendor = siteID, "generic"
	if m, ok := am.deviceMeta[deviceID]; ok {
		if m.Vendor != "" {
			vendor = m.Vendor
		}
		if effSite == nil {
			effSite = m.SiteID
		}
	}
	return effSite, vendor
}

// SpikeParamsFor returns the effective detector params (stddev K + sustain window)
// for a device's interface: the live spike SystemSettings by default (so an
// operator-tuned k/min-duration is HONORED), overridden ONLY when a matching
// enabled ALERT spike rule sets them. Called by the poller before Observe.
func (am *AlertManager) SpikeParamsFor(deviceID uint, siteID *uint, ifaceName string) (k float64, minDur time.Duration) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	k = am.config.Alerts.SpikeStdDevThreshold
	if k <= 0 {
		k = 3.0
	}
	minMin := am.config.Alerts.SpikeMinDurationMinutes
	if minMin <= 0 {
		minMin = 15
	}
	effSite, vendor := am.spikeEffSiteVendorLocked(deviceID, siteID)
	fields := spikeFields(deviceID, ifaceName, "traffic_"+ifaceName, vendor)
	if action, rule, matched := am.matchSpikeRuleLocked(fields, deviceID, effSite); matched && action != "suppress" {
		if rule.dampen.StddevK > 0 {
			k = rule.dampen.StddevK
		}
		if rule.dampen.MinDurationMinutes > 0 {
			minMin = rule.dampen.MinDurationMinutes
		}
	}
	return k, time.Duration(minMin) * time.Minute
}

func spikeKey(deviceID uint, ifaceName string) string {
	return fmt.Sprintf("spike_%d_%s", deviceID, ifaceName)
}

// ProcessSpike fires a sustained-traffic-spike alert. severity is the detector's
// warning/critical; value/mean/message are pre-formatted by the poller (which
// owns humanBps). Delivery defaults to the global snapshot (identical to the old
// poller path) and only routes through a policy when a spike rule pins one.
func (am *AlertManager) ProcessSpike(device *models.Device, iface *models.InterfaceStats, severity string, value, mean float64, message string, siteID *uint) {
	metricName := "traffic_" + iface.Name
	key := spikeKey(device.ID, iface.Name)

	am.mu.Lock()
	now := time.Now()
	// resolveAlertConfig is consulted ONLY for maintenance + (rule-pinned) policy
	// lookup — NOT for AlertEnabled gating or channel selection (spike never used
	// the policy path; keep today's behavior).
	resolved := am.resolveAlertConfig(device.ID, siteID, models.AlertTypeTrafficSpike)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	nc := globalNC
	sev := models.Severity(severity)
	var policyID *uint

	effSite, vendor := am.spikeEffSiteVendorLocked(device.ID, siteID)
	action, rule, matched := am.matchSpikeRuleLocked(spikeFields(device.ID, iface.Name, metricName, vendor), device.ID, effSite)
	if matched {
		if action == "suppress" {
			am.mu.Unlock()
			return // spike suppressed by an operator rule
		}
		am.recordHit(rule.id, now)
		if rule.severity != "" {
			sev = rule.severity
		}
		if rule.policyID != nil {
			am.applyRulePolicy(&resolved, *rule.policyID)
			nc = BuildNotifyConfigFromResolved(resolved, globalNC)
			policyID = resolved.PolicyID
		}
	}
	am.markActiveLocked(key, now)
	inMaint := resolved.InMaintenance
	am.mu.Unlock()

	alert := models.Alert{
		Timestamp:    now,
		DeviceID:     device.ID,
		AlertType:    models.AlertTypeTrafficSpike,
		Severity:     sev,
		Message:      message,
		MetricName:   metricName,
		CurrentValue: value,
		Threshold:    mean,
		PolicyID:     policyID,
		Suppressed:   inMaint,
	}
	am.saveAlert(&alert)
	if !alert.Suppressed {
		if err := am.notify(&alert, nc); err != nil {
			log.Printf("Device %s: spike alert notify failed: %v", device.Name, err)
		}
	}
}

// ProcessSpikeResolve closes an open spike alert when the detector reports the
// spike cleared. Closes the open row (restart-safe) + a companion, notifying only
// if the alert was active in THIS process. Delivery mirrors the fire (global by
// default; policy channels only when a spike rule pins one).
func (am *AlertManager) ProcessSpikeResolve(device *models.Device, iface *models.InterfaceStats, message string, siteID *uint) {
	metricName := "traffic_" + iface.Name
	key := spikeKey(device.ID, iface.Name)

	am.mu.Lock()
	wasActive := am.activeAlerts[key]
	if wasActive {
		delete(am.activeAlerts, key)
		delete(am.fireStart, key)
	}
	resolved := am.resolveAlertConfig(device.ID, siteID, models.AlertTypeTrafficSpike)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	nc := globalNC
	effSite, vendor := am.spikeEffSiteVendorLocked(device.ID, siteID)
	if action, rule, matched := am.matchSpikeRuleLocked(spikeFields(device.ID, iface.Name, metricName, vendor), device.ID, effSite); matched && action != "suppress" && rule.policyID != nil {
		am.applyRulePolicy(&resolved, *rule.policyID)
		nc = BuildNotifyConfigFromResolved(resolved, globalNC)
	}
	inMaint := resolved.InMaintenance
	am.mu.Unlock()

	// Close the open fired row(s) regardless of in-process state (restart-safe;
	// also cleans up a pre-4b orphan row from the old emitSpikeAlert path).
	am.resolveOpenAlertRows(device.ID, models.AlertTypeTrafficSpike, metricName, message)

	if !wasActive {
		return // cold resolve (post-restart / redundant) — clear silently
	}
	now := time.Now()
	companion := models.Alert{
		Timestamp:      now,
		DeviceID:       device.ID,
		AlertType:      models.AlertTypeTrafficSpike + "_RESOLVED",
		Severity:       "info",
		Message:        message,
		MetricName:     "recovery",
		Acknowledged:   true,
		AcknowledgedAt: &now,
		ResolvedAt:     &now,
		Suppressed:     inMaint,
	}
	am.saveAlert(&companion)
	if inMaint {
		return
	}
	notifyAlert := companion
	notifyAlert.MetricName = metricName // LC-42: dedup_key/alias reproduce the fire's key
	if err := am.notify(&notifyAlert, nc); err != nil {
		log.Printf("Device %s: spike resolve notify failed: %v", device.Name, err)
	}
}
