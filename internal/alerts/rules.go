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
	id       uint
	name     string
	priority int
	source   string
	vendor   string
	deviceID *uint
	siteID   *uint
	// profileID is the owning Event Rule Profile (v48). 0 is the pinned
	// Default sentinel — buildRuleEngine folds it into the Default partition.
	profileID   uint
	action      string
	alertType   models.AlertType
	severity    models.Severity
	groupBy     string
	cooldownMin *int
	policyID    *uint
	match       matchExpr
	// dampen holds the parsed per-source dampening params (state source today).
	dampen dampenParams
	// expiresAt makes a rule temporary; checked at match time via expired().
	expiresAt *time.Time
}

// expired reports whether a temporary rule's window has passed. Checked at MATCH
// time (not just cache refresh) so an expired rule stops suppressing immediately.
func (r *compiledRule) expired(now time.Time) bool {
	return r.expiresAt != nil && now.After(*r.expiresAt)
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
	// MinThroughputMbps is a POINTER: nil = inherit the global floor, an
	// explicit 0 = disable the floor for this rule's scope (meaningful,
	// unlike StddevK's 0), >0 = override. A value-typed float64 with
	// omitempty could never serialize the explicit 0.
	MinThroughputMbps *float64 `json:"min_throughput_mbps,omitempty"`
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
			profileID: src.ProfileID,
			action:    action, alertType: at, severity: src.Severity, groupBy: src.GroupBy,
			cooldownMin: src.CooldownMinutes, policyID: src.PolicyID, match: compileMatch(rm),
			dampen: dp, expiresAt: src.ExpiresAt,
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

// ruleEngine is the compiled rule set PARTITIONED by owning profile (v48).
// Within a partition, rules keep the DB's priority-asc,id-asc order; ACROSS
// partitions the per-event chain walk (device profile → site profile →
// Default) decides precedence — layer beats priority. Installed by whole-map
// swap, never mutated in place, so a snapshot of its slices stays valid after
// the lock is released.
type ruleEngine struct {
	byProfile        map[uint][]compiledRule
	defaultProfileID uint
	total            int
}

// buildRuleEngine buckets compiled rules by profile. profileID 0 (the pinned
// Default sentinel — rows written by a pre-v48 binary mid-rolling-restart, or
// a test DB without profiles) folds into the Default partition, so a rule can
// never silently detach from the chain.
func buildRuleEngine(compiled []compiledRule, defaultProfileID uint) ruleEngine {
	eng := ruleEngine{
		byProfile:        make(map[uint][]compiledRule),
		defaultProfileID: defaultProfileID,
		total:            len(compiled),
	}
	for i := range compiled {
		pid := compiled[i].profileID
		if pid == 0 {
			pid = defaultProfileID
		}
		eng.byProfile[pid] = append(eng.byProfile[pid], compiled[i])
	}
	return eng
}

// chainRules is one event's snapshot of the profile chain's partitions in
// evaluation order (device profile → site profile → Default, deduped).
// Snapshotting under am.mu and evaluating after release is safe: partitions
// are immutable once installed.
type chainRules struct {
	slices [3][]compiledRule
	n      int
	total  int
}

// chainRulesLocked computes an event's profile chain from the policy cache
// and snapshots the matching partitions. deviceID 0 skips the device layer;
// nil siteID skips the site layer (callers pass their effective site — the
// deviceMeta fallback every evaluator already applies). Dangling
// EventProfileIDs fall through, mirroring resolvedPolicyIDLocked. The Default
// partition ALWAYS anchors the chain. Caller holds am.mu (R or W).
func (am *AlertManager) chainRulesLocked(deviceID uint, siteID *uint) chainRules {
	var ch chainRules
	eng := &am.eventRules
	if eng.total == 0 {
		return ch
	}
	pc := &am.policyCache
	var ids [3]uint
	n := 0
	add := func(pid uint, mustExist bool) {
		if mustExist && (pid == 0 || pc.eventProfiles[pid] == nil) {
			return
		}
		for i := 0; i < n; i++ {
			if ids[i] == pid {
				return
			}
		}
		ids[n] = pid
		n++
	}
	if deviceID != 0 && pc.loaded {
		if cfg := pc.deviceConfigs[deviceID]; cfg != nil && cfg.EventProfileID != nil {
			add(*cfg.EventProfileID, true)
		}
	}
	if siteID != nil && pc.loaded {
		if cfg := pc.siteConfigs[*siteID]; cfg != nil && cfg.EventProfileID != nil {
			add(*cfg.EventProfileID, true)
		}
	}
	add(eng.defaultProfileID, false)
	for i := 0; i < n; i++ {
		ch.slices[i] = eng.byProfile[ids[i]]
		ch.total += len(ch.slices[i])
	}
	ch.n = n
	return ch
}

// firstMatch is the shared chain scan every evaluator funnels through: layer
// beats priority (the walk drains a whole partition before the next); within
// a partition rules run in priority-then-id order; the FIRST live, in-scope,
// matching rule of ANY action wins and stops the walk (a high-priority alert
// rule out-ranks a lower suppress in the same layer, exactly as before).
//
// admitAny=true is the syslog evaluator's contract — source="any" rules
// legitimately fire there. Every other source passes false: their exact-
// source guard is load-bearing (appliesTo alone admits "any", and a missing-
// field neq evaluates true, so a broad "any" syslog-noise suppress rule would
// otherwise silently eat security and telemetry events).
func firstMatch(ch chainRules, source string, admitAny bool, vendor string, deviceID uint, siteID *uint, fields map[string]string, now time.Time) *compiledRule {
	for li := 0; li < ch.n; li++ {
		sl := ch.slices[li]
		for i := range sl {
			r := &sl[i]
			if r.source != source && !(admitAny && r.source == "any") {
				continue
			}
			if r.expired(now) {
				continue
			}
			if !r.appliesTo(source, vendor, deviceID, siteID) {
				continue
			}
			if !r.match.eval(fields) {
				continue
			}
			return r
		}
	}
	return nil
}

// eventRuleState is everything the engine refresh installs, built OUTSIDE the
// lock so RefreshPolicyCache can swap the policy cache and the engine in ONE
// critical section (the old swap-then-refresh sequence took the lock twice,
// leaving a torn window where new assignments met old partitions).
type eventRuleState struct {
	engine          ruleEngine
	meta            map[uint]database.DeviceRuleMeta
	ownedCSV        string
	anyMetricZScore bool
}

// loadEventRuleState does the engine's DB reads + compilation (no lock held).
// ok=false means a read failed and the caller must keep the last-good state.
func (am *AlertManager) loadEventRuleState(db *database.Database) (*eventRuleState, bool) {
	am.flushEventRuleHits(db)
	// Delete expired temporary rules promptly (every refresh, not just the nightly
	// cleanup) so a lapsed "suppress for 24h" rule can't linger in the editor and
	// resurrect-as-permanent on edit, or 400 the enable toggle. Non-fatal.
	if err := db.PruneExpiredEventRules(); err != nil {
		log.Printf("RefreshEventRules: prune expired rules: %v", err)
	}

	rules, err := db.GetEnabledEventRules()
	if err != nil {
		log.Printf("RefreshEventRules: load rules: %v", err)
		return nil, false
	}
	meta, err := db.LoadDeviceRuleMeta()
	if err != nil {
		log.Printf("RefreshEventRules: load device meta: %v", err)
		return nil, false
	}
	// Default profile ID for partitioning (0 when absent — tests / pre-seed
	// boot — which keeps every rule in the byProfile[0] Default bucket).
	defaultProfileID := uint(0)
	if p, err := db.GetDefaultEventRuleProfile(); err == nil {
		defaultProfileID = p.ID
	}
	compiled := compileRules(rules)
	ownedCSV, _ := db.GetSettingValue(stateOwnedTypesSetting)
	// Does any enabled metric rule opt into zscore? Extends the baseline gate.
	// Computed over the FLAT compiled slice, before partitioning, so rules in
	// every profile are seen.
	anyMetricZScore := false
	for i := range compiled {
		if compiled[i].source == "metric" && compiled[i].dampen.Mode == "zscore" {
			anyMetricZScore = true
			break
		}
	}
	return &eventRuleState{
		engine:          buildRuleEngine(compiled, defaultProfileID),
		meta:            meta,
		ownedCSV:        ownedCSV,
		anyMetricZScore: anyMetricZScore,
	}, true
}

// installEventRuleStateLocked swaps the engine state in. Caller holds am.mu.
func (am *AlertManager) installEventRuleStateLocked(st *eventRuleState) {
	am.eventRules = st.engine
	am.deviceMeta = st.meta
	am.setStateOwnedLocked(st.ownedCSV)
	am.anyMetricZScoreRule = st.anyMetricZScore
}

// RefreshEventRules reloads + recompiles enabled rules and the device→vendor/site
// map, and flushes accumulated hit counts. Standalone entry point (tests, and
// any caller that only touched rules); RefreshPolicyCache instead installs the
// same state inside its own single swap.
func (am *AlertManager) RefreshEventRules(db *database.Database) {
	if db == nil {
		return
	}
	st, ok := am.loadEventRuleState(db)
	if !ok {
		return
	}
	am.mu.Lock()
	am.installEventRuleStateLocked(st)
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
// alert fires it. Hot-path discipline preserved: the chain snapshot is taken
// under one RLock and evaluated unlocked (partitions are immutable).
func (am *AlertManager) EvaluateSyslog(msg *models.SyslogMessage, siteID *uint) error {
	am.mu.RLock()
	meta, hasMeta := am.deviceMeta[msg.DeviceID]
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
	ch := am.chainRulesLocked(msg.DeviceID, effSite)
	am.mu.RUnlock()
	if ch.total == 0 {
		return nil // fast path: nothing on this chain to evaluate
	}

	fields := logfields.Fields(vendor, msg) // single extraction, shared across rules
	now := time.Now()
	r := firstMatch(ch, "syslog", true, vendor, msg.DeviceID, effSite, fields, now)
	if r == nil {
		return nil
	}
	am.recordHit(r.id, now)
	if r.action == "suppress" {
		return nil // mute: short-circuit lower-priority rules
	}
	return am.fireEventAlert(r, msg, fields, effSite)
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
