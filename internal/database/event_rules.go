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
	seedVerSyslog       = 1 // legacy syslog sev0-2 + FortiGate examples
	seedVerState        = 2 // interface/VPN down (Phase 1)
	seedVerMetric       = 3 // CPU/mem/disk/session thresholds (Phase 2, inert)
	seedVerTrapSpike    = 4 // traffic spike + HA/LINK trap templates (Phase 3, inert)
	seedVerFullCoverage = 5 // one editable default rule per remaining alert type
	seedVerServerHealth = 6 // the fwmon server's own volumes (SERVER_DISK_HIGH)

	eventRuleSeedVersion = seedVerServerHealth
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
		// GORM zero-value trap, twice over: Enabled:false is OMITTED on Create
		// because the column carries default:true, AND Create writes the column
		// default back into the struct — so the intent must be captured BEFORE
		// the insert and pinned with an explicit single-column Update after.
		// Without this the disabled-by-design seeds (HA member up opt-in, the
		// two custom-rule templates) land enabled and start alerting.
		//
		// The insert and the pin run in ONE transaction: if the pin fails (or
		// the process dies between them), the insert rolls back too — a
		// half-landed row would otherwise pass the name-dedup check on the
		// retry boot and stay wrongly ENABLED forever (for a disabled suppress
		// seed that's silent alert loss, the worst class).
		wantDisabled := !r.Enabled
		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(&r).Error; err != nil {
				return err
			}
			if wantDisabled {
				return tx.Model(&models.EventRule{}).Where("id = ?", r.ID).
					Update("enabled", false).Error
			}
			return nil
		}); err != nil {
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

		// ── Generation 5: full coverage ─────────────────────────────────────
		// One editable default rule per remaining alert type, so EVERY type
		// has a customization surface (severity/cooldown/routing/scope/
		// suppress), not just the profile toggle. All gen-5 rules ship with
		// blank overrides (severity ""/cooldown nil/policy nil/dampen "") —
		// verified behavior-neutral per evaluator: the overlays guard every
		// field and no non-syslog emitter reads GroupBy or the rule dedup key.
		// Priority 200 (broad flow rules 210) so any operator rule at the
		// editor default (100) or suggester default (10) always wins firstMatch.
		// The only type with NO rule is SFLOW_AGENT_DROPS — it has no emitter
		// anywhere yet; add its seed when one lands.

		// device source — matches devicerules.go deviceEventType values.
		{Name: "Default: Device offline", Description: "Fires when a device stops responding to the collector. Customize severity/cooldown/routing here, add site/device scope, or switch to Suppress to mute.",
			Enabled: true, Priority: 200, Source: "device", Action: "alert",
			AlertType: models.AlertTypeDeviceOffline, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"device_offline"}`},
		{Name: "Default: Telemetry stale", Description: "Device reachable but polled SNMP/SSH telemetry stopped arriving. Blank severity/cooldown inherit the type defaults (warning / 30m).",
			Enabled: true, Priority: 200, Source: "device", Action: "alert",
			AlertType: models.AlertTypeTelemetryStale, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"telemetry_stale"}`},
		// Gen 6. Carries an explicit cooldown because the type default is
		// SHADOWED: applyPolicyChannels overwrites CooldownMinutes from the
		// policy, and the Default policy seeds 5 minutes — so without a
		// rule-level value (which wins over policy-level) a full disk would
		// re-page every 5 minutes instead of every 30.
		{Name: "Default: Server disk high", Description: "The Firewall-Mon server's OWN disk volume is above the configured percentage, or below the free-space floor. Distinct from DISK_HIGH, which only covers monitored devices. Blank severity inherits the type default (critical).",
			Enabled: true, Priority: 200, Source: "device", Action: "alert",
			AlertType: models.AlertTypeServerDiskHigh, SeedVersion: seedVerServerHealth,
			CooldownMinutes: func() *int { v := 30; return &v }(),
			MatchJSON:       `{"op":"eq","field":"event_type","value":"server_disk_high"}`},
		{Name: "Default: Interface errors", Description: "Interface error/discard delta alert. Add an interface_name condition to mute or re-grade one noisy port.",
			Enabled: true, Priority: 200, Source: "device", Action: "alert",
			AlertType: models.AlertTypeInterfaceErrors, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"interface_errors"}`},
		{Name: "Default: Config change", Description: "Device configuration changed. Extra matchable fields: method, changed_by, impact.",
			Enabled: true, Priority: 200, Source: "device", Action: "alert",
			AlertType: models.AlertTypeConfigChange, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"config_change"}`},
		{Name: "Default: SSH host key changed", Description: "SSH host key changed (possible MITM or reinstall). Matchable field: fingerprint. Defaults to critical.",
			Enabled: true, Priority: 200, Source: "device", Action: "alert",
			AlertType: models.AlertTypeSSHHostKeyChanged, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"ssh_host_key_changed"}`},
		{Name: "Default: Probe data lag", Description: "Collector data arriving late for a probe. Governed by the Default/site layers only (no device attribution). Add a probe_id condition to scope one probe.",
			Enabled: true, Priority: 200, Source: "device", Action: "alert",
			AlertType: models.AlertTypeProbeDataLag, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"probe_data_lag"}`},
		{Name: "Default: Probe data truncated", Description: "Collector payload truncated. Governed by the Default layer ONLY — moving this rule to a site/device profile disables it. Matchable: probe_id, probe_name.",
			Enabled: true, Priority: 200, Source: "device", Action: "alert",
			AlertType: models.AlertTypeProbeDataTruncated, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"probe_data_truncated"}`},

		// trap source. HA_STATE_CHANGE parses as warning — an enabled blank
		// rule is neutral. HA_MEMBER_UP parses as INFO: ProcessTrap's LC-14
		// gate drops info/notice traps UNLESS a rule matches, so this seed
		// MUST ship disabled — enabling it is the documented opt-in.
		{Name: "Default: HA state change", Description: "HA state transition trap (warning). Customize severity/cooldown/routing here.",
			Enabled: true, Priority: 200, Source: "trap", Action: "alert",
			AlertType: models.AlertTypeHAStateChange, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"trap_type","value":"HA_STATE_CHANGE"}`},
		{Name: "Default: HA member up", Description: "HA member rejoined (informational trap — muted by default). ENABLE this rule to opt the info-severity trap into alerting.",
			Enabled: false, Priority: 200, Source: "trap", Action: "alert",
			AlertType: models.AlertTypeHAMemberUp, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"trap_type","value":"HA_MEMBER_UP"}`},

		// flow_security, detector-specific — match the detect registry Name()
		// strings. Broad hit counters on these are per-detection (noisy by
		// design); the rules are customize handles, not counters.
		{Name: "Default: Cleartext protocol", Description: "Cleartext protocol where encryption is expected. Add source_ip/dst_port conditions to narrow; switch to Suppress to mute.",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowCleartext, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"cleartext"}`},
		{Name: "Default: Unexpected egress", Description: "Egress to an unexpected destination network. Add source_ip/dst conditions to narrow; switch to Suppress to mute.",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowUnexpectedEgress, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"unexpected_egress"}`},
		{Name: "Default: DDoS volumetric", Description: "Victim-keyed volumetric DDoS. source_ip carries the VICTIM address. Defaults to critical.",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowDDoSVolumetric, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"ddos_volumetric"}`},
		{Name: "Default: DDoS prefix", Description: "Victim-prefix-keyed DDoS. source_ip carries the victim prefix. Defaults to critical.",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowDDoSPrefix, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"ddos_prefix"}`},
		{Name: "Default: Deny storm (per source)", Description: "Deny-storm detections consolidate into the SFLOW_SECURITY card; this rule governs the underlying detections AND deny-storm digests (Suppress mutes both; severity applies when deny_storm wins the card).",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowDenyStorm, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"deny_storm"}`},
		{Name: "Default: Deny storm victim", Description: "Victim-keyed deny storm (many sources denied hitting one target). source_ip carries the victim.",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowDenyStormVictim, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"deny_storm_victim"}`},
		{Name: "Default: Denied then allowed", Description: "A source that was denied later got an allow through a different policy. Matchable: source_ip, policy fields.",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowDeniedThenAllowed, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"denied_then_allowed"}`},
		{Name: "Default: sFlow sampling backoff", Description: "Agent raised its sampling rate under load (telemetry fidelity drop).",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowSamplingBackoff, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"sampling_backoff"}`},
		{Name: "Default: Flow capacity", Description: "Interface running near capacity per flow telemetry.",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowCapacity, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"capacity"}`},
		{Name: "Default: Sampling rate change", Description: "sFlow sampling rate changed on an agent (guards the pre-multiplied-bytes contract).",
			Enabled: true, Priority: 200, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowSamplingRateChange, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"detector","value":"sampling_rate_change"}`},

		// flow_security, broad — priority 210 so every detector-specific rule
		// above (200) wins first. security_digest is stamped explicitly by the
		// digest consult (never raw FlowSecFields) so security_event rules
		// can't accidentally govern digests.
		{Name: "Default: Security event (per-source card)", Description: "Per-source consolidated security card (port scan, threat intel, exfil, spreader, beacon, deny storm). Detector-specific rules above take precedence.",
			Enabled: true, Priority: 210, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowSecurity, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"security_event"}`},
		{Name: "Default: Security storm digest", Description: "Cross-source storm rollup (one digest per site+detector per cycle). Suppress here mutes digests without touching per-source cards.",
			Enabled: true, Priority: 210, Source: "flow_security", Action: "alert",
			AlertType: models.AlertTypeSFlowSecurityDigest, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"event_type","value":"security_digest"}`},

		// Custom-rule output templates — DISABLED. These types are emitted BY
		// operator-authored rules, so a live seed would be circular; each
		// template is a safe starting point (placeholder match that hits
		// nothing until edited).
		{Name: "Default: Custom log rule (template)", Description: "Template: enable and edit the match to build your own syslog rule; severity/cooldown set here apply to its LOG_RULE_MATCH alerts. The placeholder pattern matches nothing until you change it.",
			Enabled: false, Priority: 200, Source: "syslog", Action: "alert",
			AlertType: models.AlertTypeLogRuleMatch, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"contains","field":"message","value":"EDIT-THIS-PATTERN"}`},
		{Name: "Default: Custom flow rule (template)", Description: "Template for a future flow-match rule. NOTE: the flow source has no live evaluator yet (forward-plumbing since v0.11.111) — enabling this does nothing until it lands.",
			Enabled: false, Priority: 200, Source: "flow", Action: "alert",
			AlertType: models.AlertTypeFlowRuleMatch, SeedVersion: seedVerFullCoverage,
			MatchJSON: `{"op":"eq","field":"dst_port","value":"NEVER-MATCHES"}`},
	}
}

// DefaultRuleTemplate returns the shipped seed definition for an alert type
// (any generation) — the UI's "seed was deleted → prefill a fresh copy" path.
// Single source of truth: the template is the same struct the seeder inserts.
func (d *Database) DefaultRuleTemplate(at models.AlertType) (*models.EventRule, bool) {
	for _, r := range defaultEventRules() {
		if r.AlertType == at {
			rule := r
			return &rule, true
		}
	}
	return nil, false
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

// CreateEventRule inserts a new rule. Same GORM trap as the seeder
// (v0.11.119): Enabled:false is OMITTED from the INSERT (column default:true)
// and the default is written back into the struct — even Select("*") doesn't
// force it — so an operator creating a rule DISABLED (or recreating a
// disabled template) would silently get an ENABLED rule. Capture intent
// first, pin with an explicit update in the same transaction.
func (d *Database) CreateEventRule(r *models.EventRule) error {
	wantDisabled := !r.Enabled
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(r).Error; err != nil {
			return err
		}
		if wantDisabled {
			if err := tx.Model(&models.EventRule{}).Where("id = ?", r.ID).
				Update("enabled", false).Error; err != nil {
				return err
			}
			r.Enabled = false // undo GORM's default write-back for the caller
		}
		return nil
	})
}

// UpdateEventRule persists edits to an existing rule. Uses a map-free struct
// save on the id so zero-values (e.g. Enabled=false, Priority=0) are written.
// dampen_json MUST be in the Select list — it holds the state flap params and
// the metric threshold params, so omitting it silently drops every threshold /
// dampening edit made through the editor.
func (d *Database) UpdateEventRule(r *models.EventRule) error {
	// profile_id is in the Select list (v48): the handler resolves absent/0 to
	// the Default profile before calling, so an update can move a rule between
	// layers but can never zero it out.
	return d.db.Model(&models.EventRule{ID: r.ID}).Select(
		"name", "description", "enabled", "priority", "source", "vendor_scope",
		"device_id", "site_id", "profile_id", "match_json", "action", "alert_type", "severity",
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
