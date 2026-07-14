package alerts

import (
	"time"

	"firewall-mon/internal/models"
)

// Trap-source rule evaluator (Phase 4a). ProcessTrap is already
// resolveAlertConfig-aware (policy AlertRules); when a trap_type is owned
// (state_engine_owns) this adds a matching source="trap" Event Rule consult on
// top for scope/suppress + per-rule severity/cooldown/routing. Non-regressive:
// owned + no matching rule → the legacy path runs unchanged; not owned → legacy.

// trapFields is the matchable field set for a trap. Vendor is the resolved device
// vendor (empty → "generic"). trap_type is the raw trap identity (e.g.
// HA_MEMBER_DOWN, LINK_DOWN), matching how ProcessTrap keys ownership.
func trapFields(trap *models.TrapEvent, vendor string) map[string]string {
	return map[string]string{
		"trap_type": trap.TrapType,
		"vendor":    vendor,
		"source_ip": trap.SourceIP,
	}
}

// matchTrapRuleLocked returns the first (priority-ordered) enabled trap rule that
// applies + matches. Caller holds am.mu.
func (am *AlertManager) matchTrapRuleLocked(fields map[string]string, deviceID uint, siteID *uint) (action string, rule *compiledRule, matched bool) {
	vendor := "generic"
	if m, ok := am.deviceMeta[deviceID]; ok && m.Vendor != "" {
		vendor = m.Vendor
	}
	for i := range am.eventRules {
		r := &am.eventRules[i]
		if r.source != "trap" {
			continue
		}
		if r.expired(time.Now()) {
			continue
		}
		if !r.appliesTo("trap", vendor, deviceID, siteID) {
			continue
		}
		if !r.match.eval(fields) {
			continue
		}
		return r.action, r, true
	}
	return "", nil, false
}
