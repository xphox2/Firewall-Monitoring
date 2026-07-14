package alerts

import (
	"strconv"
	"time"

	"firewall-mon/internal/models"
)

// flow_security-source rule evaluator: makes consolidated sFlow SECURITY events
// (port_scan/threat_intel/data_exfil/super_spreader/c2_beacon) first-class in the
// Event Rule engine — a matching suppress rule mutes a source (the unified
// replacement for the retired Silence-Source table), an alert rule overrides
// severity/routing. Matched PER DETECTION: a per-source group spans multiple
// devices + detectors, so the caller drops only the detections a suppress rule
// claims (not the whole group).

// FlowSecFields is the matchable field set for one security detection. srcCanon is
// the caller-canonicalized source address (IPv6 zero-compression normalized).
func FlowSecFields(det *models.FlowDetection, srcCanon string, siteID *uint) map[string]string {
	f := map[string]string{
		"event_type": "security_event",
		"detector":   det.Detector,
		"source_ip":  srcCanon,
		"severity":   det.Severity,
		"device_id":  strconv.FormatUint(uint64(det.DeviceID), 10),
	}
	if siteID != nil {
		f["site_id"] = strconv.FormatUint(uint64(*siteID), 10)
	}
	return f
}

// matchFlowSecurityRuleLocked returns the first (priority-ordered) live
// flow_security rule of ANY action that applies + matches, or nil. Caller holds
// am.mu (RLock suffices). The exact source=="flow_security" filter is REQUIRED —
// appliesTo alone admits "any" rules, and a missing-field neq evaluates true, so a
// broad "any" syslog-noise suppress rule would otherwise silently start eating
// security events. Returns any action so priority ordering holds (a high-priority
// alert/customize rule out-ranks a lower suppress rule, like every other source).
func (am *AlertManager) matchFlowSecurityRuleLocked(fields map[string]string, deviceID uint, siteID *uint) *compiledRule {
	vendor := "generic"
	if m, ok := am.deviceMeta[deviceID]; ok && m.Vendor != "" {
		vendor = m.Vendor
	}
	now := time.Now()
	for i := range am.eventRules {
		r := &am.eventRules[i]
		if r.source != "flow_security" {
			continue
		}
		if r.expired(now) {
			continue
		}
		if !r.appliesTo("flow_security", vendor, deviceID, siteID) {
			continue
		}
		if !r.match.eval(fields) {
			continue
		}
		return r
	}
	return nil
}

// MatchFlowSecurityRule is the poller-facing wrapper: it takes the read lock and
// returns the matched rule's action + id (compiledRule is unexported). matched is
// false when nothing applies. The caller records the hit (RecordEventRuleHit) so
// the customize path in ProcessSecurityEvent doesn't double-count.
func (am *AlertManager) MatchFlowSecurityRule(fields map[string]string, deviceID uint, siteID *uint) (action string, ruleID uint, matched bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	if r := am.matchFlowSecurityRuleLocked(fields, deviceID, siteID); r != nil {
		return r.action, r.id, true
	}
	return "", 0, false
}

// RecordEventRuleHit records one match against a rule id (poller-facing; counts
// flush to the DB on the next refresh).
func (am *AlertManager) RecordEventRuleHit(id uint) { am.recordHit(id, time.Now()) }
