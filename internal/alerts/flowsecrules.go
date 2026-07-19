package alerts

import (
	"strconv"
	"time"

	"firewall-mon/internal/models"
)

// flow_security-source rule evaluator: makes EVERY sFlow detection first-class
// in the Event Rule engine — security (port_scan/threat_intel/…), policy
// (cleartext/denied_then_allowed/…) and operational (capacity/backoff/…) alike.
// A matching suppress rule mutes the detection (the unified replacement for the
// retired Silence-Source table), an alert rule overrides severity/routing.
// Matched PER DETECTION: a per-source group spans multiple devices + detectors,
// so the caller drops only the detections a suppress rule claims (not the whole
// group).

// FlowSecFields is the matchable field set for one flow detection. srcCanon is
// the caller-canonicalized SUBJECT address (SrcAddr for src-keyed detectors,
// the victim DstAddr for victim-keyed ones; IPv6 zero-compression normalized).
// event_type is category-mapped — "security_event" is UNCHANGED for security
// detections so pre-existing operator rules keep matching; policy/operational
// detections surface as "policy_event"/"operational_event". dst_ip/dst_port/
// protocol are set only when the detection carries them, so a missing field
// never phantom-matches an eq.
func FlowSecFields(det *models.FlowDetection, srcCanon string, siteID *uint) map[string]string {
	f := map[string]string{
		"event_type": flowEventType(det.Category),
		"detector":   det.Detector,
		"source_ip":  srcCanon,
		"severity":   det.Severity,
		"device_id":  strconv.FormatUint(uint64(det.DeviceID), 10),
	}
	if siteID != nil {
		f["site_id"] = strconv.FormatUint(uint64(*siteID), 10)
	}
	if det.DstAddr != "" {
		f["dst_ip"] = canonIPStr(det.DstAddr)
	}
	if det.DstPort != 0 {
		f["dst_port"] = strconv.FormatUint(uint64(det.DstPort), 10)
	}
	if det.Protocol != 0 {
		f["protocol"] = strconv.FormatUint(uint64(det.Protocol), 10)
	}
	return f
}

// flowEventType maps a detection category to its matcher event_type value.
// "security_event" is a compatibility constant (shipped v0.11.93 — operator
// rules exist against it); other categories map as "<category>_event", so a
// future category is automatically matchable without a code change here.
// "security_digest" is NOT produced here — the digest consult stamps it
// explicitly (flowSecDigestFields) so operator security_event rules can never
// accidentally govern digests.
func flowEventType(category string) string {
	if category == "" {
		return "security_event"
	}
	return category + "_event"
}

// flowSecDigestFields is the matchable field set for a STORM DIGEST rollup
// (ProcessSecurityDigest, v0.11.119). event_type is the dedicated
// "security_digest" value — deliberately distinct from the per-detection
// "security_event" so a suppress written against per-source cards doesn't
// silently start muting digests (and vice versa). detector rides along, so a
// detector-specific rule (e.g. deny_storm at priority 200) also governs that
// detector's digests ahead of the broad digest rule (210) —
// specific-beats-broad, intended.
func flowSecDigestFields(detector string, siteID *uint) map[string]string {
	f := map[string]string{
		"event_type": "security_digest",
		"detector":   detector,
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
	return firstMatch(am.chainRulesLocked(deviceID, siteID), "flow_security", false, vendor, deviceID, siteID, fields, time.Now())
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

// EventTypeToggledOn reports whether an alert type is enabled by the event-
// profile toggle chain (device → site → Default) for a scope. Public wrapper
// over eventToggleLocked for callers OUTSIDE the resolveAlertConfig path —
// notably the poller's flow-security consolidation (v0.11.122): src-keyed
// security detections collapse into SFLOW_SECURITY before resolveAlertConfig
// ever sees them, so a sub-type toggle (e.g. SFLOW_DENY_STORM → Off) was
// silently inert; the poller now consults the DETECTION's own type here and
// drops toggled-off detections before consolidation. Types with no toggle row
// anywhere resolve ON (sparse-implicit-ON semantics).
func (am *AlertManager) EventTypeToggledOn(deviceID uint, siteID *uint, at models.AlertType) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	enabled, _ := am.eventToggleLocked(deviceID, siteID, at)
	return enabled
}
