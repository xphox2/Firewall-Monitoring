package alerts

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/logfields"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// rules.go — the unified, vendor-aware event-rule engine (migration v35). It
// evaluates operator-defined EventRules against extracted event fields so the
// NOC can alert on "this message but not that one" at the same severity, or
// suppress known noise. Syslog is wired here (Phase 1); flow is a later overlay.
//
// Performance (review H2/M6/Q2): a single field extraction per message; a
// fast-path return when no rules are loaded; per-match hit counting is in-memory
// and flushed in batches (never a per-match UPDATE). Regexes are RE2 (linear),
// so operator-supplied patterns can't ReDoS.

// matchExpr is a compiled condition node: an and/or group (kids) or a leaf
// predicate (op over field/value). Regexes are precompiled at load.
type matchExpr struct {
	op    string // and|or|eq|neq|contains|not_contains|regex|gt|lt|in|exists
	field string
	value string
	vlow  string
	set   map[string]bool // for "in"
	num   float64
	numOK bool
	re    *regexp.Regexp
	kids  []matchExpr
}

// rawMatch is the JSON wire shape of a condition node.
type rawMatch struct {
	Op         string     `json:"op"`
	Field      string     `json:"field,omitempty"`
	Value      string     `json:"value,omitempty"`
	Values     []string   `json:"values,omitempty"`
	Conditions []rawMatch `json:"conditions,omitempty"`
}

func compileMatch(r rawMatch) matchExpr {
	m := matchExpr{op: strings.ToLower(strings.TrimSpace(r.Op)), field: strings.ToLower(r.Field), value: r.Value}
	m.vlow = strings.ToLower(r.Value)
	switch m.op {
	case "and", "or":
		for _, c := range r.Conditions {
			m.kids = append(m.kids, compileMatch(c))
		}
	case "in":
		m.set = make(map[string]bool, len(r.Values))
		for _, v := range r.Values {
			m.set[strings.ToLower(v)] = true
		}
	case "regex":
		if re, err := regexp.Compile(r.Value); err == nil {
			m.re = re
		} else {
			log.Printf("event-rule: bad regex %q: %v (condition will never match)", r.Value, err)
		}
	case "gt", "lt":
		if f, err := strconv.ParseFloat(r.Value, 64); err == nil {
			m.num, m.numOK = f, true
		}
	}
	return m
}

// eval reports whether the compiled expression matches the extracted fields.
func (m *matchExpr) eval(fields map[string]string) bool {
	switch m.op {
	case "and":
		for i := range m.kids {
			if !m.kids[i].eval(fields) {
				return false
			}
		}
		return true
	case "or":
		for i := range m.kids {
			if m.kids[i].eval(fields) {
				return true
			}
		}
		return false
	}
	fv, present := fields[m.field]
	switch m.op {
	case "exists":
		return present
	case "eq":
		return strings.EqualFold(fv, m.value)
	case "neq":
		return !strings.EqualFold(fv, m.value)
	case "contains":
		return strings.Contains(strings.ToLower(fv), m.vlow)
	case "not_contains":
		return !strings.Contains(strings.ToLower(fv), m.vlow)
	case "regex":
		return m.re != nil && m.re.MatchString(fv)
	case "in":
		return m.set[strings.ToLower(fv)]
	case "gt", "lt":
		f, err := strconv.ParseFloat(strings.TrimSpace(fv), 64)
		if err != nil || !m.numOK {
			return false
		}
		if m.op == "gt" {
			return f > m.num
		}
		return f < m.num
	}
	return false
}

// compiledRule is an EventRule ready for evaluation.
type compiledRule struct {
	id          uint
	name        string
	priority    int
	source      string
	vendor      string
	deviceID    *uint
	siteID      *uint
	action      string
	alertType   models.AlertType
	severity    models.Severity
	groupBy     string
	cooldownMin *int
	policyID    *uint
	match       matchExpr
	// dampen holds the parsed per-source dampening params (state source today).
	dampen dampenParams
}

// dampenParams is the parsed DampenJSON. Fields are per-source; state uses
// RefireMode/MinUpSeconds/DailyCap, metric uses Mode/Threshold/ClearThreshold/
// ZScoreK, spike uses StddevK/MinDurationMinutes. Zero values fall back to sane
// defaults at use time. (Phases 2-3 parse the metric/spike fields for validation
// + round-trip; the evaluators that read them land in Phase 4.)
type dampenParams struct {
	// state source
	RefireMode   string `json:"refire_mode,omitempty"`
	MinUpSeconds int    `json:"min_up_seconds,omitempty"`
	DailyCap     int    `json:"daily_cap,omitempty"`
	// metric source
	Mode           string  `json:"mode,omitempty"`            // "static" | "zscore"
	Threshold      float64 `json:"threshold,omitempty"`       // 0 = inherit resolved threshold
	ClearThreshold float64 `json:"clear_threshold,omitempty"` // 0 = default hysteresis
	ZScoreK        float64 `json:"zscore_k,omitempty"`        // 0 = default 3.0
	// spike source
	StddevK            float64 `json:"stddev_k,omitempty"`             // σ multiplier (0 = default 3)
	MinDurationMinutes int     `json:"min_duration_minutes,omitempty"` // sustain window (0 = default 15)
}

// appliesTo reports whether the rule is in scope for an event's source/vendor/
// device/site.
func (r *compiledRule) appliesTo(source, vendor string, deviceID uint, siteID *uint) bool {
	if r.source != "any" && r.source != source {
		return false
	}
	if r.vendor != "" && !strings.EqualFold(r.vendor, vendor) {
		return false
	}
	if r.deviceID != nil && *r.deviceID != deviceID {
		return false
	}
	if r.siteID != nil {
		if siteID == nil || *r.siteID != *siteID {
			return false
		}
	}
	return true
}

func compileRules(rules []models.EventRule) []compiledRule {
	out := make([]compiledRule, 0, len(rules))
	for i := range rules {
		src := rules[i]
		var rm rawMatch
		if strings.TrimSpace(src.MatchJSON) != "" {
			if err := json.Unmarshal([]byte(src.MatchJSON), &rm); err != nil {
				log.Printf("event-rule %d %q: bad match_json, skipping: %v", src.ID, src.Name, err)
				continue
			}
		}
		at := src.AlertType
		if at == "" {
			at = models.AlertTypeLogRuleMatch
			if src.Source == "flow" {
				at = models.AlertTypeFlowRuleMatch
			}
		}
		action := src.Action
		if action == "" {
			action = "alert"
		}
		source := src.Source
		if source == "" {
			source = "syslog"
		}
		var dp dampenParams
		if strings.TrimSpace(src.DampenJSON) != "" {
			if err := json.Unmarshal([]byte(src.DampenJSON), &dp); err != nil {
				log.Printf("event-rule %d %q: bad dampen_json, ignoring: %v", src.ID, src.Name, err)
			}
		}
		out = append(out, compiledRule{
			id: src.ID, name: src.Name, priority: src.Priority, source: source,
			vendor: src.VendorScope, deviceID: src.DeviceID, siteID: src.SiteID,
			action: action, alertType: at, severity: src.Severity, groupBy: src.GroupBy,
			cooldownMin: src.CooldownMinutes, policyID: src.PolicyID, match: compileMatch(rm),
			dampen: dp,
		})
	}
	return out
}

// TestRule is a compiled, DB-free matcher for the NOC rule-tester endpoint:
// compile a candidate match_json once, then check it against recent messages to
// preview what it would match before saving.
type TestRule struct{ expr matchExpr }

// CompileTestRule parses and compiles a candidate match_json.
func CompileTestRule(matchJSON string) (*TestRule, error) {
	var rm rawMatch
	if strings.TrimSpace(matchJSON) != "" {
		if err := json.Unmarshal([]byte(matchJSON), &rm); err != nil {
			return nil, err
		}
	}
	return &TestRule{expr: compileMatch(rm)}, nil
}

// MatchSyslog reports whether the compiled rule matches a syslog message under
// the given vendor (extracting the same fields the live engine would).
func (t *TestRule) MatchSyslog(vendor string, msg *models.SyslogMessage) bool {
	return t.expr.eval(logfields.Fields(vendor, msg))
}

// ruleHit accumulates in-memory hit counts between DB flushes.
type ruleHit struct {
	count int64
	last  time.Time
}

// RefreshEventRules reloads + recompiles enabled rules and the device→vendor/site
// map, and flushes accumulated hit counts. Called on the same cadence as
// RefreshPolicyCache.
func (am *AlertManager) RefreshEventRules(db *database.Database) {
	if db == nil {
		return
	}
	am.flushEventRuleHits(db)

	rules, err := db.GetEnabledEventRules()
	if err != nil {
		log.Printf("RefreshEventRules: load rules: %v", err)
		return
	}
	meta, err := db.LoadDeviceRuleMeta()
	if err != nil {
		log.Printf("RefreshEventRules: load device meta: %v", err)
		return
	}
	compiled := compileRules(rules)
	ownedCSV, _ := db.GetSettingValue(stateOwnedTypesSetting)
	am.mu.Lock()
	am.eventRules = compiled
	am.deviceMeta = meta
	am.setStateOwnedLocked(ownedCSV)
	am.mu.Unlock()
}

func (am *AlertManager) recordHit(id uint, now time.Time) {
	am.hitMu.Lock()
	if am.ruleHits == nil {
		am.ruleHits = make(map[uint]*ruleHit)
	}
	h := am.ruleHits[id]
	if h == nil {
		h = &ruleHit{}
		am.ruleHits[id] = h
	}
	h.count++
	h.last = now
	am.hitMu.Unlock()
}

func (am *AlertManager) flushEventRuleHits(db *database.Database) {
	am.hitMu.Lock()
	if len(am.ruleHits) == 0 {
		am.hitMu.Unlock()
		return
	}
	hits := make([]database.EventRuleHit, 0, len(am.ruleHits))
	for id, h := range am.ruleHits {
		hits = append(hits, database.EventRuleHit{RuleID: id, Count: h.count, LastAt: h.last})
	}
	am.ruleHits = make(map[uint]*ruleHit)
	am.hitMu.Unlock()

	if err := db.FlushEventRuleHits(hits); err != nil {
		log.Printf("flushEventRuleHits: %v", err)
	}
}

// EvaluateSyslog runs the rule engine for one syslog message. It is the single
// mechanism for syslog alerting (the legacy sev0-2 behavior ships as seed
// rules). Returns after the first matching rule: a suppress drops the event, an
// alert fires it.
func (am *AlertManager) EvaluateSyslog(msg *models.SyslogMessage, siteID *uint) error {
	am.mu.RLock()
	rules := am.eventRules
	meta, hasMeta := am.deviceMeta[msg.DeviceID]
	am.mu.RUnlock()
	if len(rules) == 0 {
		return nil // fast path: nothing to evaluate
	}

	vendor := "generic"
	effSite := siteID
	if msg.DeviceID != 0 && hasMeta {
		if meta.Vendor != "" {
			vendor = meta.Vendor
		}
		if effSite == nil {
			effSite = meta.SiteID
		}
	}

	fields := logfields.Fields(vendor, msg) // single extraction, shared across rules
	now := time.Now()
	for i := range rules {
		r := &rules[i]
		if !r.appliesTo("syslog", vendor, msg.DeviceID, effSite) {
			continue
		}
		if !r.match.eval(fields) {
			continue
		}
		am.recordHit(r.id, now)
		if r.action == "suppress" {
			return nil // mute: short-circuit lower-priority rules
		}
		return am.fireEventAlert(r, msg, fields, effSite)
	}
	return nil
}

// fireEventAlert raises an alert for a matched alert-action rule, reusing the
// full pipeline (policy resolution, cooldown w/ DB backstop, maintenance
// suppression, notification). The rule's severity overrides the resolved
// default (H3 precedence).
func (am *AlertManager) fireEventAlert(r *compiledRule, msg *models.SyslogMessage, fields map[string]string, siteID *uint) error {
	groupVal := ""
	if r.groupBy != "" {
		groupVal = fields[r.groupBy]
	}
	key := fmt.Sprintf("rule_%d_%s", r.id, groupVal)

	am.mu.Lock()
	now := time.Now()
	resolved := am.resolveAlertConfig(msg.DeviceID, siteID, r.alertType)
	if r.policyID != nil {
		// Route notifications through the RULE's policy — channels + escalation,
		// not just the ID — so the first notification honors it (not the device's).
		am.applyRulePolicy(&resolved, *r.policyID)
	}
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	cdMin := resolved.CooldownMinutes
	if r.cooldownMin != nil && *r.cooldownMin > 0 {
		cdMin = *r.cooldownMin
	}
	cooldown := time.Duration(cdMin) * time.Minute
	sev := resolved.Severity
	if r.severity != "" {
		sev = r.severity // rule override wins
	}
	canSend := resolved.AlertEnabled && am.canAlertWithCooldown(key, now, cooldown)
	if canSend {
		am.recordCooldownLocked(key, now, cooldown)
	}
	am.mu.Unlock()

	if !canSend {
		return nil
	}

	alert := models.Alert{
		Timestamp:  msg.Timestamp,
		DeviceID:   msg.DeviceID,
		AlertType:  r.alertType,
		Severity:   sev,
		Message:    fmt.Sprintf("[%s] %s: %s", r.name, msg.Hostname, msg.Message),
		MetricName: r.name,
		PolicyID:   resolved.PolicyID,
		Suppressed: resolved.InMaintenance,
	}
	am.saveAlert(&alert)
	if !alert.Suppressed {
		nc := BuildNotifyConfigFromResolved(resolved, globalNC)
		if err := am.notify(&alert, nc); err != nil {
			return fmt.Errorf("event-rule %q notify: %w", r.name, err)
		}
	}
	return nil
}
