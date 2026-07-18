package alerts

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"firewall-mon/internal/logfields"
	"firewall-mon/internal/models"
)

// SuggestRuleForAlert derives an Event Rule that would suppress (or, with the
// action flipped to "alert", customize) the class of a given alert — the backend
// for the "Create Event Rule from this alert" buttons. It is a PURE function so
// the alert→matcher mapping is unit-tested in one place instead of re-parsed in
// JS where it would drift from what the engine actually matches on.
//
// Only the five sources with real evaluators can be suppressed by a rule; every
// other alert family (SFLOW_*, DEVICE_OFFLINE, etc.) returns Supported=false with
// a reason + the correct alternative tool. State types additionally require the
// type to be state-engine-owned (else the rule is inert).

// SuggestInput is the read-only context the handler assembles from an alert.
type SuggestInput struct {
	AlertType  models.AlertType
	DeviceID   uint
	SiteID     *uint
	MetricName string // resource key (interface_<n>/vpn_<n>/traffic_<if>) or, for syslog, the firing rule name
	Message    string // alert.Message: "[<rule>] <host>: <raw>"
	DeviceName string
	Vendor     string          // device vendor, for syslog KV extraction
	StateOwned map[string]bool // state_engine_owns snapshot (event_type -> owned)
	// FiringRulePriority is the priority of the syslog/flow rule named
	// MetricName, if one is currently loaded; the suggestion sorts one above it
	// so it wins.
	FiringRulePriority *int
	// ExistingRuleID names the syslog/flow rule that fired (so "customize" can
	// open it directly instead of creating a near-duplicate).
	ExistingRuleID *uint
	// FiringRuleMatchJSON is the firing flow rule's own matcher; a FLOW_RULE_MATCH
	// suppress suggestion reuses it verbatim (one priority above), so the suppress
	// rule claims exactly the events the firing rule would alert on.
	FiringRuleMatchJSON string
	// SourceAddr is the attacker/source IP for an sFlow-security alert; the
	// flow_security suggestion matches on it (source_ip eq).
	SourceAddr string
	// ProbeID scopes a PROBE_DATA_* suggestion to the reporting probe.
	ProbeID *uint
}

// SuggestedRule is the prefill the editor opens with. Fields mirror the
// EventRule create payload the frontend POSTs.
type SuggestedRule struct {
	Source        string `json:"source"`
	Action        string `json:"action"`
	AlertType     string `json:"alert_type,omitempty"`
	DeviceID      *uint  `json:"device_id,omitempty"`
	SiteID        *uint  `json:"site_id,omitempty"`
	VendorScope   string `json:"vendor_scope,omitempty"`
	Priority      int    `json:"priority"`
	MatchJSON     string `json:"match_json"`
	DampenJSON    string `json:"dampen_json,omitempty"`
	Severity      string `json:"severity,omitempty"`
	SuggestedName string `json:"suggested_name"`
	// ExpiresHours prefills the "temporary rule" duration (0 = permanent). The
	// suppress-a-source entry point defaults this to 24h — the old Silence default.
	ExpiresHours int `json:"expires_hours,omitempty"`
}

// SuggestResult is the endpoint payload.
type SuggestResult struct {
	Supported      bool           `json:"supported"`
	Rule           *SuggestedRule `json:"rule,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	Alternative    string         `json:"alternative,omitempty"` // "silence_source" | "maintenance"
	Effect         string         `json:"effect,omitempty"`
	ExistingRuleID *uint          `json:"existing_rule_id,omitempty"`
}

// matchNode is a compiled-rule condition (mirrors CompileTestRule's schema).
type matchNode struct {
	Op         string      `json:"op"`
	Field      string      `json:"field,omitempty"`
	Value      string      `json:"value,omitempty"`
	Conditions []matchNode `json:"conditions,omitempty"`
}

func eqNode(field, value string) matchNode { return matchNode{Op: "eq", Field: field, Value: value} }
func containsNode(field, value string) matchNode {
	return matchNode{Op: "contains", Field: field, Value: value}
}

// andOrSingle returns a single node directly, or an AND of several.
func andOrSingle(nodes []matchNode) matchNode {
	if len(nodes) == 1 {
		return nodes[0]
	}
	return matchNode{Op: "and", Conditions: nodes}
}

func mustJSON(n matchNode) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// baseSyslogFields are the non-KV fields logfields.Fields always sets; a syslog
// discriminator must NOT key on these (they're struct-int/summary garbage when
// reconstructed from an alert, and never a stable identifier).
var baseSyslogFields = map[string]bool{
	"severity": true, "facility": true, "app_name": true, "hostname": true, "message": true,
}

const suggestDefaultPriority = 10 // beats the priority-100 shipped alert seeds

// SuggestRuleForAlert computes the suggestion. deviceScope wraps DeviceID as a
// pointer only when > 0.
func SuggestRuleForAlert(in SuggestInput) SuggestResult {
	// A recovery companion targets its base class (see ruleSourceForAlertType):
	// normalize here so the suggested rule's name/matcher name the type that
	// actually fires.
	if base, ok := strings.CutSuffix(string(in.AlertType), "_RESOLVED"); ok && base != "INCIDENT" {
		in.AlertType = models.AlertType(base)
	}
	src := ruleSourceForAlertType(in.AlertType)
	if src == "" {
		reason, alt := unsupportedReason(in.AlertType)
		return SuggestResult{Supported: false, Reason: reason, Alternative: alt}
	}

	// State suppress is inert unless the type is state-engine-owned.
	if src == "state" {
		ev := stateEventType(in.AlertType)
		if !in.StateOwned[ev] {
			return SuggestResult{Supported: false,
				Reason:      "Interface/VPN alerts are running on the legacy path (not owned by the state-rule engine), so a suppress rule wouldn't take effect. Use a maintenance window instead.",
				Alternative: "maintenance"}
		}
	}

	dev := deviceScope(in.DeviceID)
	siteID := in.SiteID
	name := suggestName(in.AlertType, in.DeviceName)
	priority := suggestDefaultPriority
	var matchJSON, dampen, effect string
	expiresHours := 0

	switch src {
	case "flow_security":
		if in.AlertType == models.AlertTypeSFlowSecurity || in.AlertType == models.AlertTypeSFlowSecurityDigest {
			// A per-source security alert → suppress/customize that exact attacker
			// IP. The storm DIGEST carries no single source; there the operator
			// mutes each offender individually (per-offender "Suppress source" in
			// the UI), so a digest-level blanket rule is deliberately NOT
			// synthesized (it would blind brand-new attackers of that detector).
			srcIP := canonIPStr(in.SourceAddr)
			if srcIP == "" {
				return SuggestResult{Supported: false,
					Reason:      "This is a storm digest with many sources. Suppress individual offenders from the storm's list instead.",
					Alternative: "per_source"}
			}
			matchJSON = mustJSON(eqNode("source_ip", srcIP))
			effect = fmt.Sprintf("Suppress sFlow security events from %s.", srcIP)
			expiresHours = 24 // temporary by default, like the old Silence
			dev = nil         // match the source across devices (attribution is informational)
			siteID = nil      // …and across sites — a source suppress is global, like the old Silence table
			break
		}
		// Per-detection alert (SFLOW_<DETECTOR>: cleartext, denied_then_allowed,
		// ddos_volumetric, capacity, …) → a detector-scoped rule, narrowed to the
		// alert's subject IP when it carries one, device-scoped by default so a
		// mute on one edge doesn't blind the fleet.
		detector := strings.ToLower(strings.TrimPrefix(string(in.AlertType), "SFLOW_"))
		nodes := []matchNode{eqNode("detector", detector)}
		if srcIP := canonIPStr(in.SourceAddr); srcIP != "" {
			nodes = append(nodes, eqNode("source_ip", srcIP))
			effect = fmt.Sprintf("Suppress %s detections for %s on %s.", detector, srcIP, in.DeviceName)
			expiresHours = 24 // subject-scoped mutes default temporary, like the source suppress
		} else {
			effect = fmt.Sprintf("Suppress %s detections on %s.", detector, in.DeviceName)
		}
		matchJSON = mustJSON(andOrSingle(nodes))
	case "flow":
		// FLOW_RULE_MATCH: the alert came from a flow Event Rule; a suppress rule
		// reuses the firing rule's own matcher one priority above it, so it claims
		// exactly the events that rule would alert on. "Customize" opens the firing
		// rule itself via ExistingRuleID (handled by the caller/UI).
		if in.FiringRuleMatchJSON == "" {
			return SuggestResult{Supported: false,
				Reason:      "The flow rule that fired this alert is no longer loaded (renamed or deleted), so there is no matcher to build a suppression from. Create or edit a flow rule manually.",
				Alternative: ""}
		}
		matchJSON = in.FiringRuleMatchJSON
		effect = fmt.Sprintf("Suppress the flow events matched by rule %q (this suppress rule runs first).", in.MetricName)
		if in.FiringRulePriority != nil {
			priority = *in.FiringRulePriority - 1
			if priority < 0 {
				priority = 0
			}
		}
	case "device":
		// Device/probe health families: an event_type-scoped rule, device-scoped
		// by default, narrowed to the family's natural resource when the alert
		// carries one (interface for INTERFACE_ERRORS, probe for PROBE_DATA_*).
		ev := deviceEventType(in.AlertType)
		nodes := []matchNode{eqNode("event_type", ev)}
		if in.DeviceName != "" {
			effect = fmt.Sprintf("Suppress %s alerts on %s.", in.AlertType, in.DeviceName)
		} else {
			effect = fmt.Sprintf("Suppress %s alerts.", in.AlertType)
		}
		switch in.AlertType {
		case models.AlertTypeInterfaceErrors:
			if ifName := strings.TrimPrefix(in.MetricName, "interface_errors_"); ifName != "" && ifName != in.MetricName {
				nodes = append(nodes, eqNode("interface_name", ifName))
				effect = fmt.Sprintf("Suppress interface-error alerts for %s on %s.", ifName, in.DeviceName)
			}
		case models.AlertTypeProbeDataLag, models.AlertTypeProbeDataTruncated:
			if in.ProbeID != nil {
				nodes = append(nodes, eqNode("probe_id", fmt.Sprintf("%d", *in.ProbeID)))
				effect = fmt.Sprintf("Suppress %s alerts for probe #%d.", in.AlertType, *in.ProbeID)
			}
		}
		matchJSON = mustJSON(andOrSingle(nodes))
	case "metric":
		ev := metricEventType(in.AlertType)
		matchJSON = mustJSON(eqNode("event_type", ev))
		dampen = `{"mode":"static"}`
		effect = fmt.Sprintf("Suppress %s on %s.", in.AlertType, in.DeviceName)
	case "state":
		nodes := []matchNode{eqNode("event_type", stateEventType(in.AlertType))}
		if field, val := stateResource(in.AlertType, in.MetricName); field != "" {
			nodes = append(nodes, eqNode(field, val))
			effect = fmt.Sprintf("Suppress %s for %s on %s.", in.AlertType, val, in.DeviceName)
		} else {
			effect = fmt.Sprintf("Suppress %s on %s (all interfaces/tunnels).", in.AlertType, in.DeviceName)
		}
		matchJSON = mustJSON(andOrSingle(nodes))
	case "spike":
		nodes := []matchNode{eqNode("event_type", "traffic_spike")}
		if iface := strings.TrimPrefix(in.MetricName, "traffic_"); iface != "" && iface != in.MetricName {
			nodes = append(nodes, eqNode("interface_name", iface))
			effect = fmt.Sprintf("Suppress traffic-spike alerts for %s on %s.", iface, in.DeviceName)
		} else {
			effect = fmt.Sprintf("Suppress traffic-spike alerts on %s.", in.DeviceName)
		}
		matchJSON = mustJSON(andOrSingle(nodes))
	case "trap":
		matchJSON = mustJSON(eqNode("trap_type", string(in.AlertType)))
		if dev != nil {
			effect = fmt.Sprintf("Suppress %s traps on %s.", in.AlertType, in.DeviceName)
		} else {
			effect = fmt.Sprintf("Suppress %s traps from all sources (the alert has no resolved device to scope to).", in.AlertType)
		}
	case "syslog":
		mj, ef, ok := syslogMatch(in)
		if !ok {
			// No KV discriminator and no message text → a matcher would be
			// {contains message ""} which matches ALL syslog (a fleet-wide mute).
			return SuggestResult{Supported: false,
				Reason:      "This alert has no log content to derive a matcher from. Use a maintenance window to mute it.",
				Alternative: "maintenance"}
		}
		matchJSON, effect = mj, ef
		if in.FiringRulePriority != nil {
			priority = *in.FiringRulePriority - 1
			if priority < 0 {
				priority = 0
			}
		}
	}

	return SuggestResult{
		Supported: true,
		Effect:    effect,
		Rule: &SuggestedRule{
			Source:        src,
			Action:        "suppress",
			AlertType:     string(in.AlertType),
			DeviceID:      dev,
			SiteID:        siteID,
			Priority:      priority,
			MatchJSON:     matchJSON,
			DampenJSON:    dampen,
			SuggestedName: name,
			ExpiresHours:  expiresHours,
		},
		ExistingRuleID: in.ExistingRuleID,
	}
}

// syslogMatch picks the most stable KV discriminator from the alert's raw line,
// falling back through subtype/level to a message-contains on the prefix-stripped
// text. Returns match_json, a human effect string, and ok=false when the alert
// carries no usable content (empty message with no KV) — in which case the caller
// must NOT synthesize a matcher (a {contains message ""} matches everything).
func syslogMatch(in SuggestInput) (string, string, bool) {
	raw := stripSyslogPrefix(in.Message, in.MetricName)
	fields := logfields.Fields(in.Vendor, &models.SyslogMessage{Message: raw})
	// Preference order among KV-extracted (non-base) fields.
	for _, key := range []string{"logid", "subtype", "logdesc", "level"} {
		if v, ok := fields[key]; ok && v != "" && !baseSyslogFields[key] {
			return mustJSON(eqNode(key, v)), fmt.Sprintf("Suppress syslog events where %s=%s.", key, v), true
		}
	}
	// Fallback: a message-contains on a bounded, stable substring of the raw line.
	sub := boundedSubstring(raw, 60)
	if sub == "" {
		return "", "", false
	}
	return mustJSON(containsNode("message", sub)),
		"Suppress syslog events whose message contains this text (refine the snippet to match the class you want).", true
}

// stripSyslogPrefix removes the "[<rule>] <host>: " prefix fireEventAlert adds,
// leaving the raw log line the engine extracts fields from.
func stripSyslogPrefix(msg, ruleName string) string {
	s := msg
	if p := "[" + ruleName + "] "; strings.HasPrefix(s, p) {
		s = s[len(p):]
	}
	if i := strings.Index(s, ": "); i >= 0 && i < 64 {
		s = s[i+2:]
	}
	return strings.TrimSpace(s)
}

// boundedSubstring returns up to n runes (rune-safe so a multi-byte character
// isn't split into a replacement char that would never match).
func boundedSubstring(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n]))
}

// IsSyslogRuleAlertType reports whether an alert type is served by the syslog
// rule engine — a case where alert.MetricName is a rule NAME (so the
// handler must not treat a metric/state resource key as a rule name).
func IsSyslogRuleAlertType(at models.AlertType) bool {
	return ruleSourceForAlertType(at) == "syslog"
}

// IsRuleNameAlertType reports whether alert.MetricName carries the NAME of the
// Event Rule that fired — true for the syslog rule engine AND the flow rule
// engine (their fireEventAlert stamps the rule name into MetricName). The
// handler uses this to look up the firing rule for priority/customize.
func IsRuleNameAlertType(at models.AlertType) bool {
	s := ruleSourceForAlertType(at)
	return s == "syslog" || s == "flow"
}

// ruleSourceForAlertType maps an alert type to the rule source that can suppress
// it, or "" if no evaluator consults rules for it. A *_RESOLVED recovery
// companion maps to its base type's source: rules gate the FIRE, and
// sendRecovery only notifies when the fire was active, so a suppress built
// from a recovery card correctly targets the class that fired. (Exceptions
// with no base type — INCIDENT_RESOLVED — fall through to unsupported.)
func ruleSourceForAlertType(at models.AlertType) string {
	if base, ok := strings.CutSuffix(string(at), "_RESOLVED"); ok && base != "INCIDENT" {
		at = models.AlertType(base)
	}
	switch at {
	case models.AlertTypeCPUHigh, models.AlertTypeMemoryHigh, models.AlertTypeDiskHigh, models.AlertTypeSessionsHigh:
		return "metric"
	case models.AlertTypeInterfaceDown, models.AlertTypeVPNTunnelDown:
		return "state"
	case models.AlertTypeTrafficSpike:
		return "spike"
	case models.AlertTypeLinkDown, models.AlertTypeHAHeartbeatFail, models.AlertTypeHAMemberDown,
		models.AlertTypeHAMemberUp, models.AlertTypeHAStateChange, models.AlertTypeHASwitch:
		return "trap"
	case models.AlertTypeSyslogEmergency, models.AlertTypeSyslogCritical, models.AlertTypeSyslogAlert,
		models.AlertTypeLogRuleMatch:
		return "syslog"
	case models.AlertTypeFlowRuleMatch:
		return "flow"
	case models.AlertTypeDeviceOffline, models.AlertTypeTelemetryStale, models.AlertTypeInterfaceErrors,
		models.AlertTypeConfigChange, models.AlertTypeSSHHostKeyChanged,
		models.AlertTypeProbeDataLag, models.AlertTypeProbeDataTruncated:
		return "device"
	}
	// EVERY SFLOW_* type — the consolidated security card, per-detection
	// policy/operational alerts, and any FUTURE detector (alert types are
	// auto-derived as SFLOW_<UPPER(detector)>) — is served by the flow_security
	// evaluator: the poller suppress pass and ProcessFlowDetection /
	// ProcessSecurityEvent all consult it. Prefix-matched so a new detector is
	// rule-suppressible on day one (guardrail-tested against detect.Registry()).
	if strings.HasPrefix(string(at), "SFLOW_") {
		return "flow_security"
	}
	return ""
}

// canonIPStr normalizes an IP string (IPv6 zero-compression/case) so a rule
// matches the poller's canonicalized source field; empty/unparseable → "".
func canonIPStr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

func unsupportedReason(at models.AlertType) (reason, alternative string) {
	switch at {
	case models.AlertTypeTestAlert:
		return "This is an operator-triggered test notification — there is no event class behind it to build a rule on.", ""
	case "INCIDENT_RESOLVED":
		return "This is the closing summary of an incident, not a rule-matchable event class. Rule the alert types that opened the incident instead.", ""
	}
	return "This alert type isn't matched by the Event Rule engine, so a rule wouldn't take effect. Use a maintenance window to mute it.", "maintenance"
}

func stateEventType(at models.AlertType) string {
	if at == models.AlertTypeVPNTunnelDown {
		return "vpn_tunnel_down"
	}
	return "interface_down"
}

// stateResource extracts the resource condition (interface_name/tunnel_name) from
// the alert's MetricName (interface_<name> / vpn_<name>). Empty field = no scope.
func stateResource(at models.AlertType, metricName string) (field, value string) {
	if at == models.AlertTypeVPNTunnelDown {
		if v := strings.TrimPrefix(metricName, "vpn_"); v != "" && v != metricName {
			return "tunnel_name", v
		}
		return "", ""
	}
	if v := strings.TrimPrefix(metricName, "interface_"); v != "" && v != metricName {
		return "interface_name", v
	}
	return "", ""
}

func deviceScope(id uint) *uint {
	if id == 0 {
		return nil
	}
	return &id
}

func suggestName(at models.AlertType, deviceName string) string {
	if deviceName != "" {
		return fmt.Sprintf("Suppress %s on %s", at, deviceName)
	}
	return fmt.Sprintf("Suppress %s", at)
}
