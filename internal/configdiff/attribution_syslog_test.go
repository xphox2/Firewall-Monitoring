package configdiff

import "testing"

// TestHasSyslogAudit_OnlyFortiGate pins the capability set: FortiGate is the
// one vendor whose syslog carries a config-change audit event the server can
// parse. Every other registered vendor — and an unknown one — must report
// false, which is what keeps ReceiveConfigRevision from running the FortiOS
// key=value parser over a Palo Alto or OPNsense device's syslog.
func TestHasSyslogAudit_OnlyFortiGate(t *testing.T) {
	if !HasSyslogAudit("fortigate") {
		t.Fatal("HasSyslogAudit(fortigate) = false, want true")
	}
	if !HasSyslogAudit("FortiGate") {
		t.Error("HasSyslogAudit is case-sensitive; Lookup lower-cases and so must the gate")
	}
	for _, v := range []string{"paloalto", "cisco_asa", "sonicwall", "firewalla", "pfsense", "opnsense", "generic", "unifi", "meraki", "", "acme"} {
		if HasSyslogAudit(v) {
			t.Errorf("HasSyslogAudit(%q) = true, want false — only FortiGate emits a parsable config-change audit event", v)
		}
	}
}

// TestParseSyslogAudit_Dispatch: the vendor-dispatched parser yields the
// FortiOS attribution for a fortigate device and nothing for a vendor without
// the capability, even when the line itself would parse as a FortiOS event.
func TestParseSyslogAudit_Dispatch(t *testing.T) {
	const line = `logid="0100044546" type="event" subtype="system" user="alice" ui="GUI(192.0.2.7)" action="Edit" cfgpath="firewall.policy" cfgobj="2"`

	att, ok := ParseSyslogAudit("fortigate", line)
	if !ok {
		t.Fatal("ParseSyslogAudit(fortigate) = !ok for a config-change audit line")
	}
	if att.User != "alice" || att.Source != "192.0.2.7" || att.Method != "GUI" {
		t.Errorf("fortigate attribution = %+v, want user alice from 192.0.2.7 via GUI", att)
	}
	if _, ok := ParseSyslogAudit("fortigate", `logid="0000000013" type="traffic" action="deny" user="alice"`); ok {
		t.Error("a non-audit FortiOS line parsed as a config change")
	}
	if att, ok := ParseSyslogAudit("paloalto", line); ok {
		t.Errorf("ParseSyslogAudit(paloalto) = %+v, ok — a vendor without SyslogAuditParser must never attribute", att)
	}
}
