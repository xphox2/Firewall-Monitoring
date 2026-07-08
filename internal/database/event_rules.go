package database

import (
	"log"
	"strconv"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// eventRuleSeedVersion marks the shipped seed set. Bump it (and add to
// defaultEventRules) to introduce a new generation of defaults; the one-time
// marker guarantees an operator-deleted seed is never resurrected (M5).
const eventRuleSeedVersion = 1

// EnsureDefaultRules seeds the default event rules exactly once (guarded by a
// SystemSetting marker). The legacy "alert on syslog severity 0-2" behavior
// ships here as three rules emitting the ORIGINAL SYSLOG_* alert types, so
// existing per-type policy config keeps applying; plus a FortiGate VPN-error
// alert and a (disabled) forward-traffic suppress example.
func (d *Database) EnsureDefaultRules() {
	if v, ok := d.GetSettingValue("event_rules_seed_version"); ok {
		if n, _ := strconv.Atoi(v); n >= eventRuleSeedVersion {
			return
		}
	}
	for _, r := range defaultEventRules() {
		var count int64
		d.db.Model(&models.EventRule{}).Where("name = ?", r.Name).Count(&count)
		if count > 0 {
			continue
		}
		if err := d.db.Create(&r).Error; err != nil {
			log.Printf("EnsureDefaultRules: seed %q: %v", r.Name, err)
		}
	}
	if err := d.UpsertSetting(&models.SystemSetting{
		Key: "event_rules_seed_version", Value: strconv.Itoa(eventRuleSeedVersion),
		Type: "int", Category: "alerts", Label: "Event rule seed version",
	}); err != nil {
		log.Printf("EnsureDefaultRules: set marker: %v", err)
	}
}

// defaultEventRules is the shipped seed set (seed_version 1).
func defaultEventRules() []models.EventRule {
	sev := func(s string) models.Severity { return models.Severity(s) }
	return []models.EventRule{
		// Legacy sev0-2 behavior, emitting the original SYSLOG_* types (rule
		// severity left blank so the type's historical default applies).
		{Name: "Syslog Emergency (severity 0)", Description: "Legacy: alert on syslog Emergency messages.",
			Enabled: true, Priority: 100, Source: "syslog", Action: "alert",
			AlertType: models.AlertTypeSyslogEmergency, SeedVersion: eventRuleSeedVersion,
			MatchJSON: `{"op":"eq","field":"severity","value":"0"}`},
		{Name: "Syslog Alert (severity 1)", Description: "Legacy: alert on syslog Alert messages.",
			Enabled: true, Priority: 100, Source: "syslog", Action: "alert",
			AlertType: models.AlertTypeSyslogAlert, SeedVersion: eventRuleSeedVersion,
			MatchJSON: `{"op":"eq","field":"severity","value":"1"}`},
		{Name: "Syslog Critical (severity 2)", Description: "Legacy: alert on syslog Critical messages.",
			Enabled: true, Priority: 100, Source: "syslog", Action: "alert",
			AlertType: models.AlertTypeSyslogCritical, SeedVersion: eventRuleSeedVersion,
			MatchJSON: `{"op":"eq","field":"severity","value":"2"}`},
		// FortiGate VPN/IPsec errors — the actionable signal buried under the
		// forward-traffic flood. Matches regardless of syslog severity.
		{Name: "FortiGate VPN/IPsec errors", Description: "Alert on FortiGate VPN subtype error-level logs (IPsec phase/ESP failures).",
			Enabled: true, Priority: 50, Source: "syslog", VendorScope: "fortigate",
			Action: "alert", Severity: sev("critical"), SeedVersion: eventRuleSeedVersion,
			MatchJSON: `{"op":"and","conditions":[{"op":"eq","field":"subtype","value":"vpn"},{"op":"eq","field":"level","value":"error"}]}`},
		// Example suppression — shipped DISABLED so it can't silently mute a
		// future broad operator alert rule (M5).
		{Name: "Suppress FortiGate forward-traffic warnings", Description: "Example: mute the high-volume forward-traffic warning logs. Disabled by default.",
			Enabled: false, Priority: 10, Source: "syslog", VendorScope: "fortigate",
			Action: "suppress", SeedVersion: eventRuleSeedVersion,
			MatchJSON: `{"op":"and","conditions":[{"op":"eq","field":"subtype","value":"forward"},{"op":"eq","field":"level","value":"warning"}]}`},
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
func (d *Database) UpdateEventRule(r *models.EventRule) error {
	return d.db.Model(&models.EventRule{ID: r.ID}).Select(
		"name", "description", "enabled", "priority", "source", "vendor_scope",
		"device_id", "site_id", "match_json", "action", "alert_type", "severity",
		"group_by", "cooldown_minutes", "policy_id", "updated_at",
	).Updates(r).Error
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
