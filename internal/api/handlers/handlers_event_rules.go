package handlers

import (
	"net/http"
	"strings"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// handlers_event_rules.go — CRUD + live tester for the unified event-rule engine
// (migration v35). All routes are admin-only (see adminOnlyRoutes in
// cmd/api/main.go): a suppress rule can silence security alerting, and the
// tester reads raw syslog content.

var (
	validRuleSources = map[string]bool{"syslog": true, "flow": true, "flow_security": true, "any": true, "state": true, "metric": true, "spike": true, "trap": true, "device": true}
	validRuleActions = map[string]bool{"alert": true, "suppress": true}
)

// validateEventRule enforces the invariants the engine assumes.
func validateEventRule(r *models.EventRule) string {
	if strings.TrimSpace(r.Name) == "" {
		return "Rule name is required"
	}
	if len(r.Name) > 200 || len(r.Description) > 1000 {
		return "Name (max 200) or description (max 1000) too long"
	}
	if r.Source == "" {
		r.Source = "syslog"
	}
	if !validRuleSources[r.Source] {
		return "Source must be syslog, flow, flow_security, state, metric, spike, trap, device, or any"
	}
	// On CREATE, a temporary rule's expiry must be in the future (a past ExpiresAt
	// would make the rule dead-on-arrival). On UPDATE we allow a past expiry: a rule
	// whose window already lapsed is still editable/toggle-able (and the refresh
	// prune will remove it) — rejecting it would 400 the Enabled toggle. r.ID is 0
	// only on create.
	if r.ID == 0 && r.ExpiresAt != nil && !r.ExpiresAt.After(time.Now()) {
		return "Expiry must be in the future"
	}
	if r.Action == "" {
		r.Action = "alert"
	}
	if !validRuleActions[r.Action] {
		return "Action must be alert or suppress"
	}
	// match_json must compile (empty = match-all, allowed but unusual).
	if strings.TrimSpace(r.MatchJSON) != "" {
		if _, err := alerts.CompileTestRule(r.MatchJSON); err != nil {
			return "Invalid match_json: " + err.Error()
		}
	}
	// dampen_json is a per-source blob; today only state rules use it (episode/
	// flap dampening). Validate its shape + bounds so a bad blob can't silently
	// disable dampening at runtime.
	if r.Source == "state" {
		if msg := alerts.ValidateStateDampenJSON(r.DampenJSON); msg != "" {
			return msg
		}
	}
	// metric rules (CPU/mem/disk/session thresholds) — validate the threshold blob
	// shape. The evaluator that acts on it ships in a later phase; today these
	// rules are inert (the legacy Settings→Alerts path drives metric alerting).
	if r.Source == "metric" {
		if msg := alerts.ValidateMetricDampenJSON(r.DampenJSON); msg != "" {
			return msg
		}
	}
	// spike rules (traffic-spike detector params). Inert until Phase 4 (the
	// detector still fires directly in the poller). trap rules carry no dampen_json
	// — they scope/route via the base rule fields, so no per-source blob to check.
	if r.Source == "spike" {
		if msg := alerts.ValidateSpikeDampenJSON(r.DampenJSON); msg != "" {
			return msg
		}
	}
	return ""
}

func (h *Handler) ListEventRules(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	rules, err := db.ListEventRules()
	if err != nil {
		httputil.InternalError(c, "Failed to list event rules", err)
		return
	}
	// ?profile_id= filters to one profile's layer (v48). The 0-sentinel folds
	// into the Default profile, so filtering by the Default ID also returns
	// unstamped rows. In-memory filter — the rule table is tiny by design.
	if pidRaw, ok := httputil.ParseUintQuery(c, "profile_id"); ok {
		defaultID := uint(0)
		if def, err := db.GetDefaultEventRuleProfile(); err == nil {
			defaultID = def.ID
		}
		if pidRaw == 0 {
			pidRaw = defaultID // 0-as-Default convention (SuggestedRule docs it)
		}
		filtered := make([]models.EventRule, 0, len(rules))
		for _, r := range rules {
			pid := r.ProfileID
			if pid == 0 {
				pid = defaultID
			}
			if pid == pidRaw {
				filtered = append(filtered, r)
			}
		}
		rules = filtered
	}
	c.JSON(http.StatusOK, response.Success(rules))
}

// GetEventRuleTemplate returns the shipped default-rule definition for an
// alert type as a builder-shaped prefill — the "seed was deleted → recreate a
// fresh copy" path for the UPCOMING toggle-matrix per-type Rule button
// (v0.11.120; this endpoint ships first). NOTE for that consumer: the prefill
// carries the template's real enabled/action — openFromPrefill must NOT apply
// its force-enable/force-suppress defaults, or the disabled-by-design
// templates would go live on recreate.
// GET /admin/api/event-rules/template?alert_type=X
func (h *Handler) GetEventRuleTemplate(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	at := models.AlertType(c.Query("alert_type"))
	if at == "" {
		c.JSON(http.StatusBadRequest, response.Error("alert_type is required"))
		return
	}
	tpl, ok := db.DefaultRuleTemplate(at)
	if !ok {
		reason := "No shipped default rule exists for this alert type"
		if at == models.AlertTypeSFlowAgentDrops {
			reason = "SFLOW_AGENT_DROPS has no emitter yet — nothing produces this alert, so there is no rule to customize"
		}
		c.JSON(http.StatusNotFound, response.Error(reason))
		return
	}
	defaultProfileID := uint(0)
	if def, err := db.GetDefaultEventRuleProfile(); err == nil {
		defaultProfileID = def.ID
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"name":        tpl.Name,
		"description": tpl.Description,
		"source":      tpl.Source,
		"action":      tpl.Action,
		"alert_type":  string(tpl.AlertType),
		"priority":    tpl.Priority,
		"match_json":  tpl.MatchJSON,
		"dampen_json": tpl.DampenJSON,
		"enabled":     tpl.Enabled,
		"profile_id":  defaultProfileID,
	}))
}

// resolveRuleProfileID validates an incoming rule's profile assignment:
// absent/0 → the Default profile; non-zero must exist.
func resolveRuleProfileID(db database.Store, r *models.EventRule) string {
	if r.ProfileID == 0 {
		if def, err := db.GetDefaultEventRuleProfile(); err == nil {
			r.ProfileID = def.ID
		}
		return "" // no Default profile yet (pre-seed boot) — 0-sentinel still maps to Default
	}
	if _, err := db.GetEventRuleProfile(r.ProfileID); err != nil {
		return "Profile not found"
	}
	return ""
}

func (h *Handler) CreateEventRule(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var r models.EventRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	r.ID = 0
	r.SeedVersion = 0 // operator-created rules are never seeds
	if msg := validateEventRule(&r); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	if msg := resolveRuleProfileID(db, &r); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	if err := db.CreateEventRule(&r); err != nil {
		httputil.InternalError(c, "Failed to create event rule", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(r))
}

func (h *Handler) UpdateEventRule(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var r models.EventRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	r.ID = id
	if msg := validateEventRule(&r); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	// A payload WITHOUT profile_id (binds as 0) must PRESERVE the rule's
	// current layer — folding 0 to Default here would silently re-home a
	// non-default rule on every edit from a client that doesn't send the
	// field. Moving a rule to Default is expressed with Default's REAL id.
	if r.ProfileID == 0 {
		if existing, err := db.GetEventRule(id); err == nil {
			r.ProfileID = existing.ProfileID
		}
	}
	if msg := resolveRuleProfileID(db, &r); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	if err := db.UpdateEventRule(&r); err != nil {
		httputil.InternalError(c, "Failed to update event rule", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(r))
}

func (h *Handler) DeleteEventRule(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if err := db.DeleteEventRule(id); err != nil {
		httputil.InternalError(c, "Failed to delete event rule", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"deleted": id}))
}

// TestEventRule previews what a candidate rule would match against recent syslog
// (admin-only, bounded). Returns the match count, rows scanned, and up to 20
// sample matched messages so an operator can validate a rule before saving.
func (h *Handler) TestEventRule(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req struct {
		MatchJSON   string `json:"match_json"`
		VendorScope string `json:"vendor_scope"`
		Limit       int    `json:"limit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	rule, err := alerts.CompileTestRule(req.MatchJSON)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid match_json: "+err.Error()))
		return
	}
	vendor := req.VendorScope
	if vendor == "" {
		vendor = "fortigate" // the only extracting vendor today
	}
	msgs, err := db.RecentSyslogForTest(req.Limit)
	if err != nil {
		httputil.InternalError(c, "Failed to load recent syslog", err)
		return
	}
	matched := 0
	samples := make([]string, 0, 20)
	for i := range msgs {
		if rule.MatchSyslog(vendor, &msgs[i]) {
			matched++
			if len(samples) < 20 {
				samples = append(samples, msgs[i].Message)
			}
		}
	}
	rate := 0.0
	if len(msgs) > 0 {
		rate = float64(matched) / float64(len(msgs))
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"scanned": len(msgs),
		"matched": matched,
		"rate":    rate,
		"samples": samples,
		"vendor":  vendor,
		"note":    "Scans up to the last 24h / 5000 messages; sev6-7 notice traffic is aggregated-and-deleted, so old bulk traffic isn't testable.",
	}))
}
