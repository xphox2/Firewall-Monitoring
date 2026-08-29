package alerts

import (
	"testing"

	"firewall-mon/internal/models"
)

// intPtr is a small helper for the nullable StormSources overrides.
func intPtr(n int) *int { return &n }

// TestSeededDefaultCadenceIs360: on a seeded-default install the effective
// resolved cooldown for the two noisy security types is 360 (the seeded rule
// wins over the policy-level CooldownMinutes:5 shadow). Guards A1.
func TestSeededDefaultCadenceIs360(t *testing.T) {
	am, db := newTestManager(t)
	db.EnsureDefaultPolicy() // seeds SFLOW_SECURITY + _DIGEST 360-min rules
	am.RefreshPolicyCache(db)

	for _, at := range []models.AlertType{models.AlertTypeSFlowSecurity, models.AlertTypeSFlowSecurityDigest} {
		got := am.resolveAlertConfig(0, nil, at).CooldownMinutes
		if got != 360 {
			t.Errorf("resolved cooldown for %s = %d, want 360", at, got)
		}
	}
}

// TestStormThreshold_NilVsZero: the storm threshold resolves with `!= nil`
// semantics — nil inherits, a non-nil 0 disables, N overrides. This is the
// inversion vs CooldownMinutes' `>0` guard; guards C2/(v).
func TestStormThreshold_NilVsZero(t *testing.T) {
	am, _ := newTestManager(t)
	am.SetStormSourcesDefault(25)

	// No overrides → global default.
	policy := &models.AlertPolicy{ID: 1, Name: "p", IsDefault: true,
		Rules: []models.AlertRule{{PolicyID: 1, AlertType: models.AlertTypeSFlowSecurityDigest, Enabled: true}}}
	installPolicyCache(am, policy, nil)
	if got := am.StormThreshold(nil); got != 25 {
		t.Errorf("nil override → %d, want global default 25", got)
	}

	// Rule override N=5 → 5.
	policy.Rules[0].StormSources = intPtr(5)
	installPolicyCache(am, policy, nil)
	if got := am.StormThreshold(nil); got != 5 {
		t.Errorf("rule override 5 → %d, want 5", got)
	}

	// Rule override 0 → disabled (0), NOT inherit.
	policy.Rules[0].StormSources = intPtr(0)
	installPolicyCache(am, policy, nil)
	if got := am.StormThreshold(nil); got != 0 {
		t.Errorf("rule override 0 → %d, want 0 (disabled), not inherit", got)
	}
}

// TestStormThreshold_SiteOverride: a per-site StormSources override beats the
// rule/global value for that site.
func TestStormThreshold_SiteOverride(t *testing.T) {
	am, _ := newTestManager(t)
	am.SetStormSourcesDefault(25)
	var siteID uint = 3
	policy := &models.AlertPolicy{ID: 1, Name: "p", IsDefault: true}
	installPolicyCache(am, policy, nil)
	// Attach a site config with a lower threshold.
	am.policyCache.siteConfigs[siteID] = &models.SiteAlertConfig{SiteID: siteID, StormSources: intPtr(3)}
	if got := am.StormThreshold(&siteID); got != 3 {
		t.Errorf("site override → %d, want 3", got)
	}
	// A different site with no override → global default.
	var other uint = 9
	if got := am.StormThreshold(&other); got != 25 {
		t.Errorf("un-overridden site → %d, want 25", got)
	}
}

// TestStormThreshold_ToggledOffFallsBackToPerSource is the AUDIT-243 follow-up
// pin: StormThreshold is a routing consumer with no fire-side AlertEnabled
// guard. After AUDIT-243 the resolver flows PAST the event-profile toggle, so a
// digest rule's StormSources override (5) is now applied even when the digest
// type is toggled OFF — which would drop the rollup threshold into range for a
// live storm that ProcessSecurityDigest then silently swallows (it drops on
// !AlertEnabled). StormThreshold must return 0 for a toggled-off digest so the
// storm falls back to the per-source path, while an ENABLED digest still honors
// the override.
func TestStormThreshold_ToggledOffFallsBackToPerSource(t *testing.T) {
	newCache := func() *models.AlertPolicy {
		return &models.AlertPolicy{ID: 1, Name: "p", IsDefault: true,
			Rules: []models.AlertRule{{PolicyID: 1, AlertType: models.AlertTypeSFlowSecurityDigest,
				Enabled: true, StormSources: intPtr(5)}}}
	}

	// Digest toggled ON → the rule override applies (5).
	am, _ := newTestManager(t)
	am.SetStormSourcesDefault(25)
	installPolicyCache(am, newCache(), nil)
	installDefaultProfileToggles(am, map[models.AlertType]bool{models.AlertTypeSFlowSecurityDigest: true})
	if got := am.StormThreshold(nil); got != 5 {
		t.Fatalf("digest enabled → StormThreshold %d, want 5 (rule override honored)", got)
	}

	// Digest toggled OFF → StormThreshold must be 0 (per-source fallback), NOT
	// the 5 the resolver now flows through to.
	am2, _ := newTestManager(t)
	am2.SetStormSourcesDefault(25)
	installPolicyCache(am2, newCache(), nil)
	installDefaultProfileToggles(am2, map[models.AlertType]bool{models.AlertTypeSFlowSecurityDigest: false})
	if got := am2.StormThreshold(nil); got != 0 {
		t.Fatalf("digest toggled off → StormThreshold %d, want 0 so a storm falls back "+
			"to the per-source SFLOW_SECURITY path instead of a swallowed digest", got)
	}
}

// TestProcessSecurityDigest_OneAlertForManySources: N distinct sources collapse
// into ONE digest whose CurrentValue is the distinct-source count and severity is
// the max in the group. Guards C4/(k)/(q).
func TestProcessSecurityDigest_OneAlertForManySources(t *testing.T) {
	am, db := newTestManager(t)
	am.SetStormSourcesDefault(5)

	var group []*models.FlowDetection
	for i := 0; i < 30; i++ {
		sev := "warning"
		if i == 0 {
			sev = "critical" // one critical → digest severity must be critical
		}
		d := saveDet(t, db, secDet("198.51.100."+itoaTest(i), "port_scan", sev))
		group = append(group, d)
	}
	id, err := am.ProcessSecurityDigest(nil, "port_scan", group)
	if err != nil || id == 0 {
		t.Fatalf("ProcessSecurityDigest id=%d err=%v", id, err)
	}
	if n := countAlerts(t, am); n != 1 {
		t.Fatalf("want 1 digest alert, got %d", n)
	}
	a := getAlert(t, db, id)
	if a.AlertType != models.AlertTypeSFlowSecurityDigest {
		t.Errorf("alert_type = %s, want DIGEST", a.AlertType)
	}
	if a.Severity != "critical" {
		t.Errorf("digest severity = %s, want critical (max in group)", a.Severity)
	}
	if int(a.CurrentValue) != 30 {
		t.Errorf("CurrentValue = %v, want 30 (distinct sources)", a.CurrentValue)
	}
	if a.SourceAddr != "" {
		t.Errorf("digest SourceAddr = %q, want empty", a.SourceAddr)
	}
}

// TestProcessSecurityDigest_PersistsSiteID: a site-scoped digest persists its
// SiteID so the alerts UI can name the site (DeviceID is 0 for the rollup, so the
// device→site path can't resolve it). Guards v0.11.57.
func TestProcessSecurityDigest_PersistsSiteID(t *testing.T) {
	am, db := newTestManager(t)
	am.SetStormSourcesDefault(5)

	var siteID uint = 7
	var group []*models.FlowDetection
	for i := 0; i < 10; i++ {
		group = append(group, saveDet(t, db, secDet("192.0.2."+itoaTest(i), "port_scan", "warning")))
	}
	id, err := am.ProcessSecurityDigest(&siteID, "port_scan", group)
	if err != nil || id == 0 {
		t.Fatalf("ProcessSecurityDigest id=%d err=%v", id, err)
	}
	a := getAlert(t, db, id)
	if a.DeviceID != 0 {
		t.Errorf("digest DeviceID = %d, want 0 (site-scoped rollup)", a.DeviceID)
	}
	if a.SiteID == nil || *a.SiteID != siteID {
		t.Errorf("digest SiteID = %v, want %d", a.SiteID, siteID)
	}
}

// TestProcessSecurityDigest_FoldsAcrossCycles: a second cycle for the same
// (site, detector) reuses the open digest (same id) and grows the count, without
// creating a new alert. Guards (p).
func TestProcessSecurityDigest_FoldsAcrossCycles(t *testing.T) {
	am, db := newTestManager(t)
	am.SetStormSourcesDefault(5)

	var g1 []*models.FlowDetection
	for i := 0; i < 10; i++ {
		g1 = append(g1, saveDet(t, db, secDet("203.0.113."+itoaTest(i), "threat_intel", "warning")))
	}
	id1, _ := am.ProcessSecurityDigest(nil, "threat_intel", g1)
	if id1 == 0 {
		t.Fatal("cycle 1 should open a digest")
	}

	var g2 []*models.FlowDetection
	for i := 10; i < 25; i++ {
		g2 = append(g2, saveDet(t, db, secDet("203.0.113."+itoaTest(i), "threat_intel", "warning")))
	}
	id2, _ := am.ProcessSecurityDigest(nil, "threat_intel", g2)
	if id2 != id1 {
		t.Fatalf("cycle 2 digest id=%d, want same as cycle 1 (%d)", id2, id1)
	}
	if n := countAlerts(t, am); n != 1 {
		t.Fatalf("folding must not create a new alert; got %d", n)
	}
	a := getAlert(t, db, id1)
	if int(a.CurrentValue) != 15 {
		t.Errorf("folded CurrentValue = %v, want 15 (second cycle's distinct count)", a.CurrentValue)
	}
}

// itoaTest keeps the digest tests independent of any package helper.
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
