package capability

import (
	"reflect"
	"testing"
)

func TestLookup_FallsBackToGeneric(t *testing.T) {
	t.Parallel()
	if Lookup("nope").Vendor != "generic" || Lookup("fortigate").Vendor != "fortigate" {
		t.Fatal("Lookup fallback")
	}
	if !reflect.DeepEqual(Vendors(), []string{"fortigate", "generic", "meraki", "opnsense", "pfsense", "unifi"}) {
		t.Errorf("Vendors() = %v", Vendors())
	}
	p := Lookup("meraki")
	if p.Can(NatSrcIP) {
		t.Error("meraki cannot supply NAT (not in syslog or NetFlow); an unlisted field must be SourceNone")
	}
	if p.Spec(AdminUser).Source != SourceAPI {
		t.Error("meraki admin audit is API-only")
	}
}

// TestFeature pins the static per-vendor verdicts the UI and detectors will
// read: a feature is unsupported when any required field cannot be supplied,
// degraded when every field exists but one is config-dependent or partial,
// supported otherwise — and the fields that caused it come back.
func TestFeature(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		feature, vendor string
		want            FeatureState
		why             []Field
	}{
		{"deny_analytics", "fortigate", Supported, nil},
		{"deny_analytics", "opnsense", Degraded, []Field{Action}},
		{"deny_analytics", "unifi", Degraded, []Field{Action}},
		{"policy_bytes", "fortigate", Degraded, []Field{RuleKey, BytesOut, BytesIn}},
		{"policy_bytes", "meraki", Degraded, []Field{RuleKey}}, // bytes are NetFlow/full, rule_key syslog/config_dependent
		{"nat_forensics", "pfsense", Unsupported, []Field{NatSrcIP}},
		{"nat_forensics", "meraki", Unsupported, []Field{NatSrcIP}},
		{"admin_login_audit", "meraki", Unsupported, []Field{AdminSrcIP}}, // admin_user is API-sourced (exists), admin_src_ip has no source at all
		{"admin_login_audit", "fortigate", Supported, nil},
		{"wan_health", "unifi", Degraded, []Field{WANName, MetricValue}}, // SIEM integration must be on; 113 has no loss figure
		{"utm_trends", "unifi", Degraded, []Field{SigID, SigName, Severity}},
		{"config_audit", "unifi", Degraded, []Field{ConfigPath, AdminUser}},
		{"no_such_feature", "fortigate", Supported, nil},
	} {
		state, why := Feature(tc.feature, tc.vendor)
		if state != tc.want || !reflect.DeepEqual(why, tc.why) {
			t.Errorf("Feature(%s, %s) = %s %v, want %s %v", tc.feature, tc.vendor, state, why, tc.want, tc.why)
		}
	}
}
