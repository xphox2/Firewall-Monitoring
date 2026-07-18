package alerts

import (
	"time"

	"firewall-mon/internal/models"
)

// effective_event.go — the read-only "what actually applies here" resolution
// for Event Rule Profiles (v48). Everything is computed by the SAME locked
// helpers the firing path uses (eventToggleLocked / chainRulesLocked), never a
// reimplementation, so the UI can never disagree with what fires.

// EffectiveEventLayer is one link of the resolved profile chain.
type EffectiveEventLayer struct {
	Layer       string `json:"layer"` // "device" | "site" | "default"
	ProfileID   uint   `json:"profile_id"`
	ProfileName string `json:"profile_name"`
}

// EffectiveEventToggle is one alert type's resolved on/off state.
type EffectiveEventToggle struct {
	AlertType models.AlertType `json:"alert_type"`
	Family    string           `json:"family"`
	Enabled   bool             `json:"enabled"`
	// DecidedBy names the chain layer whose explicit row decided
	// ("device"|"site"|"default") or "implicit" for the all-Inherit ON.
	DecidedBy string `json:"decided_by"`
}

// EffectiveEventRule is one rule that applies to the scope, in evaluation
// order (device layer first; priority order within a layer).
type EffectiveEventRule struct {
	Layer     string     `json:"layer"`
	RuleID    uint       `json:"rule_id"`
	Name      string     `json:"name"`
	Priority  int        `json:"priority"`
	Source    string     `json:"source"`
	Action    string     `json:"action"`
	AlertType string     `json:"alert_type,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// EffectiveEventConfig resolves the profile chain, every alert type's toggle
// state, and the applicable rules for a device (or bare site) scope.
// deviceID=0 + siteID resolves the site view (no device layer); deviceID with
// nil siteID fills the site from deviceMeta exactly like the firing path.
func (am *AlertManager) EffectiveEventConfig(deviceID uint, siteID *uint) (chain []EffectiveEventLayer, toggles []EffectiveEventToggle, rules []EffectiveEventRule) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	pc := &am.policyCache
	effSite := siteID
	if effSite == nil && deviceID != 0 {
		if m, ok := am.deviceMeta[deviceID]; ok {
			effSite = m.SiteID
		}
	}

	profileName := func(id uint) string {
		if p := pc.eventProfiles[id]; p != nil {
			return p.Name
		}
		return ""
	}
	addLayer := func(layer string, pid uint) {
		for _, l := range chain {
			if l.ProfileID == pid {
				return // deduped (e.g. device explicitly assigned the Default profile)
			}
		}
		chain = append(chain, EffectiveEventLayer{Layer: layer, ProfileID: pid, ProfileName: profileName(pid)})
	}
	if deviceID != 0 && pc.loaded {
		if cfg := pc.deviceConfigs[deviceID]; cfg != nil && cfg.EventProfileID != nil && pc.eventProfiles[*cfg.EventProfileID] != nil {
			addLayer("device", *cfg.EventProfileID)
		}
	}
	if effSite != nil && pc.loaded {
		if cfg := pc.siteConfigs[*effSite]; cfg != nil && cfg.EventProfileID != nil && pc.eventProfiles[*cfg.EventProfileID] != nil {
			addLayer("site", *cfg.EventProfileID)
		}
	}
	if pc.defaultEventProfileID != 0 {
		addLayer("default", pc.defaultEventProfileID)
	}

	// Per-type states via the REAL kill-switch resolver.
	registry := models.AllAlertTypes()
	toggles = make([]EffectiveEventToggle, 0, len(registry))
	for _, info := range registry {
		on, layer := am.eventToggleLocked(deviceID, siteID, info.Type)
		decidedBy := layer
		if decidedBy == "" {
			decidedBy = "implicit"
		}
		toggles = append(toggles, EffectiveEventToggle{
			AlertType: info.Type, Family: info.Family, Enabled: on, DecidedBy: decidedBy,
		})
	}

	// Applicable rules via the REAL chain walk's partitions, in evaluation
	// order. chainRulesLocked takes the caller's effective site (it does no
	// deviceMeta fallback itself), so pass effSite.
	ch := am.chainRulesLocked(deviceID, effSite)
	layerLabel := func(idx int) string {
		// chainRulesLocked orders device → site → default with dedup; map the
		// slice index back onto the chain layers computed above (same order,
		// same dedup rules).
		if idx < len(chain) {
			return chain[idx].Layer
		}
		return "default"
	}
	for li := 0; li < ch.n; li++ {
		sl := ch.slices[li]
		for i := range sl {
			r := &sl[i]
			rules = append(rules, EffectiveEventRule{
				Layer: layerLabel(li), RuleID: r.id, Name: r.name, Priority: r.priority,
				Source: r.source, Action: r.action, AlertType: string(r.alertType), ExpiresAt: r.expiresAt,
			})
		}
	}
	return chain, toggles, rules
}
