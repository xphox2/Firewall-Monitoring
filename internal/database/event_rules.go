package database

import (
	"log"
	"strconv"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Seed generations. Each seed rule carries the version it was INTRODUCED in
// (seedVerSyslog/State/Metric/TrapSpike), NOT the current top version — the resurrection
// guard in EnsureDefaultRules only seeds rules whose SeedVersion is newer than
// the last-applied marker, so an operator-deleted older seed is never recreated
// on a version bump (M5). eventRuleSeedVersion is the highest generation and is
// the value written to the marker.
const (
	seedVerSyslog    = 1 // legacy syslog sev0-2 + FortiGate examples
	seedVerState     = 2 // interface/VPN down (Phase 1)
	seedVerMetric    = 3 // CPU/mem/disk/session thresholds (Phase 2, inert)
	seedVerTrapSpike = 4 // traffic spike + HA/LINK trap templates (Phase 3, inert)

	eventRuleSeedVersion = seedVerTrapSpike
)

// EnsureDefaultRules seeds the default event rules exactly once (guarded by a
// SystemSetting marker). The legacy "alert on syslog severity 0-2" behavior
// ships here as three rules emitting the ORIGINAL SYSLOG_* alert types, so
// existing per-type policy config keeps applying; plus a FortiGate VPN-error
// alert and a (disabled) forward-traffic suppress example.
func (d *Database) EnsureDefaultRules() {
	prevMarker := 0
	if v, ok := d.GetSettingValue("event_rules_seed_version"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			if n >= eventRuleSeedVersion {
				return
			}
			prevMarker = n
		}
	}
	// Seeds live in the Default profile layer (v48). If the profile is somehow
	// absent, ProfileID stays 0 — the pinned sentinel the engine maps to
	// Default — so a seed can never silently detach from the chain.
	var defaultProfileID uint
	if p, err := d.GetDefaultEventRuleProfile(); err == nil {
		defaultProfileID = p.ID
	}
	seedFailed := false
	for _, r := range defaultEventRules() {
		// Only seed rules NEWER than the last-applied marker. Re-inserting an older
		// generation's rules on a version bump would resurrect seeds the operator
		// deliberately deleted (DeleteEventRule is a hard delete) — the M5 no-
		// resurrection guarantee. A brand-new install (prevMarker 0) gets them all.
		if r.SeedVersion <= prevMarker {
			continue
		}
		r.ProfileID = defaultProfileID
		var count int64
		d.db.Model(&models.EventRule{}).Where("name = ?", r.Name).Count(&count)
		if count > 0 {
			continue
		}
		if err := d.db.Create(&r).Error; err != nil {
			log.Printf("EnsureDefaultRules: seed %q: %v", r.Name, err)
			seedFailed = true
		}
	}
	// Do NOT advance the marker if any insert failed: the per-generation guard is
	// permanent (SeedVersion <= marker never re-seeds), so advancing past a failed
	// generation would drop that seed forever. Leaving the marker lets the next
	// startup retry (name-dedup skips the ones that did land). Skip the ownership
	// flag too — it must only flip once its state rules exist.
	if seedFailed {
		return
	}
	if err := d.UpsertSetting(&models.SystemSetting{
		Key: "event_rules_seed_version", Value: strconv.Itoa(eventRuleSeedVersion),
		Type: "int", Category: "alerts", Label: "Event rule seed version",
	}); err != nil {
		log.Printf("EnsureDefaultRules: set marker: %v", err)
	}
	// Hand interface/VPN down alerting to the state-rule engine (Phase 1). Set the
	// ownership flag ONLY when it is absent (first ever seed) — never overwrite an
	// existing value on a later generation bump, or an operator who edited it (e.g.
	// reverted a type to the legacy path) would have their choice silently reset on
	// upgrade. Set AFTER the rules exist so a type is never "owned" with no rule.
	// NOTE for a future phase that adds metric/other types here: it must UNION into
	// this value AND gate each type on an enabled matching rule actually existing
	// (a deleted preview template must not leave an owned type silently un-alerting).
	if _, ok := d.GetSettingValue("state_engine_owns"); !ok {
		if err := d.UpsertSetting(&models.SystemSetting{
			Key: "state_engine_owns", Value: "interface_down,vpn_tunnel_down",
			Type: "string", Category: "alerts", Label: "Alert types owned by the state-rule engine",
		}); err != nil {
			log.Printf("EnsureDefaultRules: set state-engine ownership: %v", err)
		}
	}
}

// defaultEventRules is the shipped seed set across all generations; each rule
// carries its introduction version (seedVer*). EnsureDefaultRules seeds only the
// generations newer than the last-applied marker.
func defaultEventRules() []models.EventRule {
	sev := func(s string) models.Severity { return models.Severity(s) }
	return []models.EventRule{
		// Legacy sev0-2 behavior, emitting the original SYSLOG_* types (rule
		// severity left blank so the type's historical default applies).
		{Name: "Syslog Emergency (severity 0)", Description: "Legacy: alert on syslog Emergency messages.",
			Enabled: true, Priority: 100, Source: "syslog", Action: "alert",
			AlertType: models.AlertTypeSyslogEmergency, SeedVersion: seedVerSyslog,
			MatchJSON: `{"op":"eq","field":"severity","value":"0"}`},
		{Name: "Syslog Alert (severity 1)", Description: "Legacy: alert on syslog Alert messages.",
			Enabled: true, Priority: 100, Source: "syslog", Action: "alert",
			AlertType: models.AlertTypeSyslogAlert, SeedVersion: seedVerSyslog,
			MatchJSON: `{"op":"eq","field":"severity","value":"1"}`},
		{Name: "Syslog Critical (severity 2)", Description: "Legacy: alert on syslog Critical messages.",
			Enabled: true, Priority: 100, Source: "syslog", Action: "alert",
			AlertType: models.AlertTypeSyslogCritical, SeedVersion: seedVerSyslog,
			MatchJSON: `{"op":"eq","field":"severity","value":"2"}`},
		// FortiGate VPN/IPsec errors — the actionable signal buried under the
		// forward-traffic flood. Matches regardless of syslog severity.
		{Name: "FortiGate VPN/IPsec errors", Description: "Alert on FortiGate VPN subtype error-level logs (IPsec phase/ESP failures).",
			Enabled: true, Priority: 50, Source: "syslog", VendorScope: "fortigate",
			Action: "alert", Severity: sev("critical"), SeedVersion: seedVerSyslog,
			MatchJSON: `{"op":"and","conditions":[{"op":"eq","field":"subtype","value":"vpn"},{"op":"eq","field":"level","value":"error"}]}`},
		// Example suppression — shipped DISABLED so it can't silently mute a
		// future broad operator alert rule (M5).
		{Name: "Suppress FortiGate forward-traffic warnings", Description: "Example: mute the high-volume forward-traffic warning logs. Disabled by default.",
			Enabled: false, Priority: 10, Source: "syslog", VendorScope: "fortigate",
			Action: "suppress", SeedVersion: seedVerSyslog,
			MatchJSON: `{"op":"and","conditions":[{"op":"eq","field":"subtype","value":"forward"},{"op":"eq","field":"level","value":"warning"}]}`},
		// State-source built-ins (seed_version 2): interface and VPN down alerting,
		// now owned by the state-rule engine (see EnsureDefaultRules ownership flag).
		// Severity is left blank so the per-type default/policy still applies. The
		// dampening blob encodes the flap policy: fire once per outage episode,
		// stay silent while down (incl. acked), at most one alert/day while
		// flapping, but fire immediately when the link was up ≥1h before dropping.
		{Name: "Interface down", Description: "Alert when a monitored interface that has been up goes down. Fire-once-per-outage with flap dampening.",
			Enabled: true, Priority: 100, Source: "state", Action: "alert",
			AlertType: models.AlertTypeInterfaceDown, SeedVersion: seedVerState,
			MatchJSON:  `{"op":"eq","field":"event_type","value":"interface_down"}`,
			DampenJSON: `{"refire_mode":"episode","min_up_seconds":3600,"daily_cap":1}`},
		{Name: "VPN tunnel down", Description: "Alert when a monitored VPN tunnel that has been up goes down. Fire-once-per-outage with flap dampening.",
			Enabled: true, Priority: 100, Source: "state", Action: "alert",
			AlertType: models.AlertTypeVPNTunnelDown, SeedVersion: seedVerState,
			MatchJSON:  `{"op":"eq","field":"event_type","value":"vpn_tunnel_down"}`,
			DampenJSON: `{"refire_mode":"episode","min_up_seconds":3600,"daily_cap":1}`},
		// Metric-source built-ins (seed_version 3). ACTIVE as of Phase 4a:
		// CheckSystemStatus always consults matching metric rules (no ownership
		// flag), falling back to the legacy path on no match. dampen_json carries
		// mode only (no threshold) so they INHERIT the operator's existing
		// Settings→Alerts / policy / device thresholds — non-regressive. Leave the
		// threshold blank in the rule to keep inheriting; set it to override.
		// Severity blank ⇒ per-type default. To turn a type OFF, use a suppress
		// rule (deleting the template falls back to the legacy path, which still
		// alerts).
		{Name: "CPU high", Description: "Threshold alert when device CPU usage is high. Inherits the Settings → Alerts / policy threshold unless you set one here.",
			Enabled: true, Priority: 100, Source: "metric", Action: "alert",
			AlertType: models.AlertTypeCPUHigh, SeedVersion: seedVerMetric,
			MatchJSON:  `{"op":"eq","field":"event_type","value":"cpu_high"}`,
			DampenJSON: `{"mode":"static"}`},
		{Name: "Memory high", Description: "Threshold alert when device memory usage is high. Inherits the Settings → Alerts / policy threshold unless you set one here.",
			Enabled: true, Priority: 100, Source: "metric", Action: "alert",
			AlertType: models.AlertTypeMemoryHigh, SeedVersion: seedVerMetric,
			MatchJSON:  `{"op":"eq","field":"event_type","value":"memory_high"}`,
			DampenJSON: `{"mode":"static"}`},
		{Name: "Disk high", Description: "Threshold alert when device disk usage is high. Inherits the Settings → Alerts / policy threshold unless you set one here.",
			Enabled: true, Priority: 100, Source: "metric", Action: "alert",
			AlertType: models.AlertTypeDiskHigh, SeedVersion: seedVerMetric,
			MatchJSON:  `{"op":"eq","field":"event_type","value":"disk_high"}`,
			DampenJSON: `{"mode":"static"}`},
		{Name: "Session count high", Description: "Threshold alert when device session count is high. Inherits the Settings → Alerts / policy threshold unless you set one here.",
			Enabled: true, Priority: 100, Source: "metric", Action: "alert",
			AlertType: models.AlertTypeSessionsHigh, SeedVersion: seedVerMetric,
			MatchJSON:  `{"op":"eq","field":"event_type","value":"sessions_high"}`,
			DampenJSON: `{"mode":"static"}`},
		// Spike-source built-in (seed_version 4). ACTIVE as of Phase 4b: the poller
		// routes the seasonal traffic-spike detector's fire/resolve through
		// ProcessSpike/ProcessSpikeResolve, always consulting this rule (scope/
		// suppress/severity/policy). dampen_json is EMPTY so the detector params
		// INHERIT the live Settings→Alerts spike sensitivity/sustain — set stddev_k/
		// min_duration_minutes in the rule to override for its scope. Non-regressive.
		{Name: "Traffic spike", Description: "Alert on a sustained traffic spike vs the interface's seasonal baseline. Inherits the Settings → Alerts spike sensitivity unless you set values here.",
			Enabled: true, Priority: 100, Source: "spike", Action: "alert",
			AlertType: models.AlertTypeTrafficSpike, SeedVersion: seedVerTrapSpike,
			MatchJSON:  `{"op":"eq","field":"event_type","value":"traffic_spike"}`,
			DampenJSON: `{}`},
		// Trap-source built-ins (seed_version 4). ACTIVE as of Phase 4a: ProcessTrap
		// always consults matching trap rules (any trap type, no ownership flag) for
		// scope/suppress + per-rule severity/routing on top of the existing policy
		// path, falling back to the legacy path on no match. Severity blank ⇒
		// per-type default applies. No dampen_json — traps route via the base rule
		// fields. Match on trap_type. To mute a trap type, use a suppress rule
		// (deleting the template falls back to the legacy policy path).
		{Name: "HA member down", Description: "HA cluster member down (SNMP trap).",
			Enabled: true, Priority: 100, Source: "trap", Action: "alert",
			AlertType: models.AlertTypeHAMemberDown, SeedVersion: seedVerTrapSpike,
			MatchJSON: `{"op":"eq","field":"trap_type","value":"HA_MEMBER_DOWN"}`},
		{Name: "HA heartbeat failure", Description: "HA cluster heartbeat lost (SNMP trap).",
			Enabled: true, Priority: 100, Source: "trap", Action: "alert",
			AlertType: models.AlertTypeHAHeartbeatFail, SeedVersion: seedVerTrapSpike,
			MatchJSON: `{"op":"eq","field":"trap_type","value":"HA_HEARTBEAT_FAIL"}`},
		{Name: "HA failover", Description: "HA cluster failover/switch (SNMP trap).",
			Enabled: true, Priority: 100, Source: "trap", Action: "alert",
			AlertType: models.AlertTypeHASwitch, SeedVersion: seedVerTrapSpike,
			MatchJSON: `{"op":"eq","field":"trap_type","value":"HA_SWITCH"}`},
		{Name: "Link down (trap)", Description: "Interface link down reported by SNMP trap.",
			Enabled: true, Priority: 100, Source: "trap", Action: "alert",
			AlertType: models.AlertTypeLinkDown, SeedVersion: seedVerTrapSpike,
			MatchJSON: `{"op":"eq","field":"trap_type","value":"LINK_DOWN"}`},
	}
}

// event_rules.go — persistence for the unified, vendor-aware alert/suppress rule
// engine (migration v35). CRUD for the NOC rule builder plus the engine-facing
// loaders (enabled rules + device vendor/site metadata) and a batched hit-count
// flush (per-match counting happens in-memory; see internal/alerts/rules.go).

// ListEventRules returns all rules ordered for the NOC list (priority, then id).
func (d *Database) ListEventRules() ([]models.EventRule, error) {
	var rules []models.EventRule
	err := d.db.Order("priority asc, id asc").Find(&rules).Error
	return rules, err
}

// GetEnabledEventRules returns only enabled rules, in evaluation order.
func (d *Database) GetEnabledEventRules() ([]models.EventRule, error) {
	var rules []models.EventRule
	err := d.db.Where("enabled = ?", true).Order("priority asc, id asc").Find(&rules).Error
	return rules, err
}

// GetEventRule loads one rule by id.
func (d *Database) GetEventRule(id uint) (*models.EventRule, error) {
	var r models.EventRule
	if err := d.db.First(&r, id).Error; err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateEventRule inserts a new rule.
func (d *Database) CreateEventRule(r *models.EventRule) error {
	return d.db.Create(r).Error
}

// UpdateEventRule persists edits to an existing rule. Uses a map-free struct
// save on the id so zero-values (e.g. Enabled=false, Priority=0) are written.
// dampen_json MUST be in the Select list — it holds the state flap params and
// the metric threshold params, so omitting it silently drops every threshold /
// dampening edit made through the editor.
func (d *Database) UpdateEventRule(r *models.EventRule) error {
	return d.db.Model(&models.EventRule{ID: r.ID}).Select(
		"name", "description", "enabled", "priority", "source", "vendor_scope",
		"device_id", "site_id", "match_json", "action", "alert_type", "severity",
		"group_by", "cooldown_minutes", "policy_id", "dampen_json", "expires_at", "updated_at",
	).Updates(r).Error
}

// PruneExpiredEventRules deletes temporary rules whose expiry has passed (v0.11.93,
// the unified replacement for the old flow-source-suppression prune). Expiry is
// already enforced at match time; this is housekeeping so the table doesn't
// accumulate dead temp rules. A permanent rule (expires_at IS NULL) is never
// touched.
func (d *Database) PruneExpiredEventRules() error {
	return d.db.Where("expires_at IS NOT NULL AND expires_at <= ?", time.Now()).
		Delete(&models.EventRule{}).Error
}

// DeleteEventRule removes a rule by id.
func (d *Database) DeleteEventRule(id uint) error {
	return d.db.Delete(&models.EventRule{}, id).Error
}

// RecentSyslogForTest returns the most recent syslog messages for the rule
// tester, bounded in count and time so the admin-only endpoint can't scan the
// whole 42M-row table. limit is clamped to [1, 5000]; only the last 24h.
func (d *Database) RecentSyslogForTest(limit int) ([]models.SyslogMessage, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	var msgs []models.SyslogMessage
	err := d.db.Where("timestamp >= ?", time.Now().Add(-24*time.Hour)).
		Order("id desc").Limit(limit).Find(&msgs).Error
	return msgs, err
}

// DeviceRuleMeta is the per-device attribution the engine needs to pick a vendor
// extractor and evaluate site-scoped rules without a per-message DB read.
type DeviceRuleMeta struct {
	Vendor string
	SiteID *uint
}

// LoadDeviceRuleMeta returns deviceID → {vendor, siteID} for all devices. Called
// on the same cadence as the policy cache refresh.
func (d *Database) LoadDeviceRuleMeta() (map[uint]DeviceRuleMeta, error) {
	var rows []struct {
		ID     uint
		Vendor string
		SiteID *uint
	}
	if err := d.db.Model(&models.Device{}).Select("id", "vendor", "site_id").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[uint]DeviceRuleMeta, len(rows))
	for _, r := range rows {
		out[r.ID] = DeviceRuleMeta{Vendor: r.Vendor, SiteID: r.SiteID}
	}
	return out, nil
}

// EventRuleHit is a batched hit-count delta flushed from the in-memory counters.
type EventRuleHit struct {
	RuleID uint
	Count  int64
	LastAt time.Time
}

// FlushEventRuleHits applies accumulated per-rule hit counts in one short
// transaction (H2: never a per-match UPDATE on the hot path).
func (d *Database) FlushEventRuleHits(hits []EventRuleHit) error {
	if len(hits) == 0 {
		return nil
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		for _, h := range hits {
			if err := tx.Model(&models.EventRule{}).Where("id = ?", h.RuleID).
				Updates(map[string]any{
					"hit_count":   gorm.Expr("hit_count + ?", h.Count),
					"last_hit_at": h.LastAt,
				}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
