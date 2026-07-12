package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

// Phase 5a: the effective-config endpoint must report the value that actually
// FIRES, with correct per-field provenance, so the device/site modals can show
// "inherits X from <layer>" vs "overridden here" vs "set by rule". These tests
// pin resolvedPolicyIDLocked (the shared policy selection) and EffectiveAlertConfig
// (the config-chain + metric-rule reconciliation) against the resolver itself.

// buildPolicyCache assembles a loaded PolicyCache from the given policies (the
// one flagged IsDefault becomes defaultPolicy), device configs, and site configs.
func buildPolicyCache(policies []*models.AlertPolicy, devCfgs map[uint]*models.DeviceAlertConfig, siteCfgs map[uint]*models.SiteAlertConfig) PolicyCache {
	c := PolicyCache{
		policyByID:    map[uint]*models.AlertPolicy{},
		deviceConfigs: devCfgs,
		siteConfigs:   siteCfgs,
		loaded:        true,
	}
	if c.deviceConfigs == nil {
		c.deviceConfigs = map[uint]*models.DeviceAlertConfig{}
	}
	if c.siteConfigs == nil {
		c.siteConfigs = map[uint]*models.SiteAlertConfig{}
	}
	for _, p := range policies {
		c.policies = append(c.policies, *p)
		c.policyByID[p.ID] = p
		if p.IsDefault {
			c.defaultPolicy = p
		}
	}
	return c
}

func uptr(v uint) *uint { return &v }

func TestResolvedPolicyIDLocked_5a(t *testing.T) {
	t.Parallel()
	am, _ := newTestManager(t)
	def := &models.AlertPolicy{ID: 1, Name: "default", IsDefault: true}
	devPol := &models.AlertPolicy{ID: 2, Name: "device"}
	sitePol := &models.AlertPolicy{ID: 3, Name: "site"}
	am.policyCache = buildPolicyCache(
		[]*models.AlertPolicy{def, devPol, sitePol},
		map[uint]*models.DeviceAlertConfig{
			10: {DeviceID: 10, AlertsEnabled: true, PolicyID: uptr(2)},  // device-assigned
			11: {DeviceID: 11, AlertsEnabled: true, PolicyID: uptr(99)}, // dangling
		},
		map[uint]*models.SiteAlertConfig{
			5: {SiteID: 5, PolicyID: uptr(3)}, // site-assigned
		},
	)

	site5 := uptr(5)
	cases := []struct {
		name     string
		deviceID uint
		siteID   *uint
		want     *uint
	}{
		{"device-assigned wins", 10, site5, uptr(2)},
		{"site-assigned when no device policy", 12, site5, uptr(3)},
		{"default fallback", 12, nil, uptr(1)},
		{"dangling device policy falls through to site", 11, site5, uptr(3)},
		{"deviceID=0 falls to default", 0, nil, uptr(1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := am.resolvedPolicyIDLocked(tc.deviceID, tc.siteID)
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Fatalf("resolvedPolicyIDLocked(%d, %v) = %v, want %v", tc.deviceID, tc.siteID, deref(got), deref(tc.want))
			}
		})
	}

	// No default policy in the cache → nil.
	am.policyCache = buildPolicyCache([]*models.AlertPolicy{devPol}, nil, nil)
	if got := am.resolvedPolicyIDLocked(0, nil); got != nil {
		t.Fatalf("no default policy should yield nil, got %v", *got)
	}
}

func deref(p *uint) any {
	if p == nil {
		return "nil"
	}
	return *p
}

// cpuRulePolicy is a default policy carrying one CPU_HIGH AlertRule threshold.
func cpuRulePolicy(threshold float64) *models.AlertPolicy {
	return &models.AlertPolicy{
		ID: 1, Name: "default", IsDefault: true,
		Rules: []models.AlertRule{{PolicyID: 1, AlertType: models.AlertTypeCPUHigh, Enabled: true, Threshold: threshold}},
	}
}

func TestEffectiveAlertConfig_Provenance_5a(t *testing.T) {
	t.Parallel()

	t.Run("policy-rule threshold", func(t *testing.T) {
		am, _ := newTestManager(t)
		am.policyCache = buildPolicyCache([]*models.AlertPolicy{cpuRulePolicy(90)}, nil, nil)
		res, prov := am.EffectiveAlertConfig(7, nil, models.AlertTypeCPUHigh, "cpu_usage")
		if res.Threshold != 90 || prov.Threshold != "policy" {
			t.Fatalf("got threshold=%v prov=%q, want 90 policy", res.Threshold, prov.Threshold)
		}
	})

	t.Run("site override", func(t *testing.T) {
		am, _ := newTestManager(t)
		am.policyCache = buildPolicyCache(
			[]*models.AlertPolicy{cpuRulePolicy(90)}, nil,
			map[uint]*models.SiteAlertConfig{5: {SiteID: 5, CPUThreshold: 70}},
		)
		res, prov := am.EffectiveAlertConfig(0, uptr(5), models.AlertTypeCPUHigh, "cpu_usage")
		if res.Threshold != 70 || prov.Threshold != "site" {
			t.Fatalf("got threshold=%v prov=%q, want 70 site", res.Threshold, prov.Threshold)
		}
	})

	t.Run("device over site precedence", func(t *testing.T) {
		am, _ := newTestManager(t)
		am.policyCache = buildPolicyCache(
			[]*models.AlertPolicy{cpuRulePolicy(90)},
			map[uint]*models.DeviceAlertConfig{7: {DeviceID: 7, AlertsEnabled: true, CPUThreshold: 85}},
			map[uint]*models.SiteAlertConfig{5: {SiteID: 5, CPUThreshold: 70}},
		)
		res, prov := am.EffectiveAlertConfig(7, uptr(5), models.AlertTypeCPUHigh, "cpu_usage")
		if res.Threshold != 85 || prov.Threshold != "device" {
			t.Fatalf("got threshold=%v prov=%q, want 85 device", res.Threshold, prov.Threshold)
		}
	})

	t.Run("equal-value override still labeled device not inherited", func(t *testing.T) {
		am, _ := newTestManager(t)
		am.policyCache = buildPolicyCache(
			[]*models.AlertPolicy{cpuRulePolicy(90)},
			map[uint]*models.DeviceAlertConfig{7: {DeviceID: 7, AlertsEnabled: true, CPUThreshold: 90}}, // == policy
			nil,
		)
		res, prov := am.EffectiveAlertConfig(7, nil, models.AlertTypeCPUHigh, "cpu_usage")
		if res.Threshold != 90 || prov.Threshold != "device" {
			t.Fatalf("equal-value override: got threshold=%v prov=%q, want 90 device", res.Threshold, prov.Threshold)
		}
	})

	t.Run("global fallback when no override", func(t *testing.T) {
		am, _ := newTestManager(t)
		am.config.Alerts.CPUThreshold = 80
		// Default policy with a CPU rule that sets NO threshold (inherit).
		p := &models.AlertPolicy{ID: 1, Name: "default", IsDefault: true,
			Rules: []models.AlertRule{{PolicyID: 1, AlertType: models.AlertTypeCPUHigh, Enabled: true}}}
		am.policyCache = buildPolicyCache([]*models.AlertPolicy{p}, nil, nil)
		res, prov := am.EffectiveAlertConfig(7, nil, models.AlertTypeCPUHigh, "cpu_usage")
		if res.Threshold != 80 || prov.Threshold != "global" {
			t.Fatalf("got threshold=%v prov=%q, want 80 global", res.Threshold, prov.Threshold)
		}
	})

	t.Run("alerts disabled on device", func(t *testing.T) {
		am, _ := newTestManager(t)
		am.policyCache = buildPolicyCache(
			[]*models.AlertPolicy{cpuRulePolicy(90)},
			map[uint]*models.DeviceAlertConfig{7: {DeviceID: 7, AlertsEnabled: false}},
			nil,
		)
		res, prov := am.EffectiveAlertConfig(7, nil, models.AlertTypeCPUHigh, "cpu_usage")
		if res.AlertEnabled || !prov.AlertsDisabled {
			t.Fatalf("got AlertEnabled=%v AlertsDisabled=%v, want false true", res.AlertEnabled, prov.AlertsDisabled)
		}
	})
}

func TestEffectiveAlertConfig_MetricRuleReconciliation_5a(t *testing.T) {
	t.Parallel()

	t.Run("metric rule threshold wins over chain", func(t *testing.T) {
		am, db := newTestManager(t)
		setHysteresisPolicy(am, 90, 0) // policy CPU threshold 90
		addCPUMetricRule(t, am, db, "alert", "", `{"threshold":50}`)
		res, prov := am.EffectiveAlertConfig(7, nil, models.AlertTypeCPUHigh, "cpu_usage")
		if res.Threshold != 50 || prov.Threshold != "rule" {
			t.Fatalf("got threshold=%v prov=%q, want 50 rule", res.Threshold, prov.Threshold)
		}
		if prov.RuleID == 0 || prov.RuleName == "" {
			t.Fatalf("expected rule id/name in provenance, got id=%d name=%q", prov.RuleID, prov.RuleName)
		}
	})

	t.Run("suppress rule flags suppressed_by_rule", func(t *testing.T) {
		am, db := newTestManager(t)
		setHysteresisPolicy(am, 90, 0)
		addCPUMetricRule(t, am, db, "suppress", "", "")
		res, prov := am.EffectiveAlertConfig(7, nil, models.AlertTypeCPUHigh, "cpu_usage")
		if !prov.SuppressedByRule || prov.RuleID == 0 {
			t.Fatalf("expected suppressed_by_rule with rule id, got suppressed=%v id=%d", prov.SuppressedByRule, prov.RuleID)
		}
		// Threshold still reflects the chain (suppress mutes fire, doesn't change math).
		if res.Threshold != 90 {
			t.Fatalf("suppress should leave chain threshold, got %v", res.Threshold)
		}
	})

	t.Run("no metric rule leaves chain provenance", func(t *testing.T) {
		am, db := newTestManager(t)
		setHysteresisPolicy(am, 90, 0)
		am.RefreshEventRules(db) // no rules
		_, prov := am.EffectiveAlertConfig(7, nil, models.AlertTypeCPUHigh, "cpu_usage")
		if prov.Threshold != "policy" || prov.SuppressedByRule {
			t.Fatalf("no rule: got prov threshold=%q suppressed=%v, want policy false", prov.Threshold, prov.SuppressedByRule)
		}
	})
}
