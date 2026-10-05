package alerts

import (
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestFields_SeedRulesStillMatch: the shipped syslog seed rules are written
// against FortiOS native keys (subtype / level). The 0.11.293 logfields.Fields
// adds the canonical event.* view BESIDE those keys; this pins that the
// natives are still there by compiling the real seeds from the database
// package and matching them against the lines they were written for.
func TestFields_SeedRulesStillMatch(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	db.EnsureDefaultRules()
	rules, err := db.ListEventRules()
	if err != nil {
		t.Fatal(err)
	}
	vpnErr := &models.SyslogMessage{Severity: 3, Message: `type="event" subtype="vpn" level="error" vd="root" logdesc="IPsec phase 1 error" action="negotiate" remip=203.0.113.51 vpntunnel="to-branch-03"`}
	fwdWarn := &models.SyslogMessage{Severity: 4, Message: `type="traffic" subtype="forward" level="warning" vd="root" srcip=192.0.2.10 dstip=203.0.113.20 action="accept" policyid=12`}
	matched := map[string]bool{}
	for _, r := range rules {
		if r.Source != "syslog" {
			continue
		}
		tr, err := CompileTestRule(r.MatchJSON)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		switch r.Name {
		case "FortiGate VPN/IPsec errors":
			matched[r.Name] = tr.MatchSyslog("fortigate", vpnErr)
			if tr.MatchSyslog("fortigate", fwdWarn) {
				t.Errorf("%s matched the forward-traffic warning", r.Name)
			}
		case "Suppress FortiGate forward-traffic warnings":
			matched[r.Name] = tr.MatchSyslog("fortigate", fwdWarn)
			if tr.MatchSyslog("fortigate", vpnErr) {
				t.Errorf("%s matched the VPN error", r.Name)
			}
		}
	}
	for _, name := range []string{"FortiGate VPN/IPsec errors", "Suppress FortiGate forward-traffic warnings"} {
		if !matched[name] {
			t.Errorf("seed %q no longer matches its own line through logfields.Fields", name)
		}
	}
	// And the canonical view lets one rule cover every vendor: event.action.
	deny, _ := CompileTestRule(`{"op":"eq","field":"event.action","value":"deny"}`)
	fg := &models.SyslogMessage{Message: `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny"`}
	pf := &models.SyslogMessage{AppName: "filterlog", Message: `5,,,1000000103,igb0,match,block,in,4,0x0,,64,1,0,none,6,tcp,60,203.0.113.9,198.51.100.10,54321,443`}
	if !deny.MatchSyslog("fortigate", fg) || !deny.MatchSyslog("opnsense", pf) {
		t.Errorf("event.action eq deny: fortigate=%v opnsense=%v", deny.MatchSyslog("fortigate", fg), deny.MatchSyslog("opnsense", pf))
	}
}
