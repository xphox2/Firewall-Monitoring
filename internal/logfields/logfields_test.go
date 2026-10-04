package logfields

import (
	"testing"

	"firewall-mon/internal/models"
)

func TestFortiGateExtract(t *testing.T) {
	tests := []struct {
		name   string
		msg    models.SyslogMessage
		vendor string
		want   map[string]string // subset that must match
		absent []string          // keys that must NOT be present
	}{
		{
			name: "forward traffic warning (the noise)",
			msg: models.SyslogMessage{
				Severity: 4, Facility: 23, Hostname: "FGT-HUB",
				Message: `type="traffic" subtype="forward" level="warning" vd="root" srcintf="internal" srcintfrole="lan" action="accept"`,
			},
			vendor: "fortigate",
			want: map[string]string{
				"subtype": "forward", "level": "warning", "srcintf": "internal",
				"action": "accept", "severity": "4", "facility": "23",
				// canonical view beside the natives (0.11.293)
				"event.class": "network", "event.action": "allow", "event.src_if": "internal", "event.src_role": "lan", "event.ruleset": "root",
			},
		},
		{
			name: "vpn ipsec error (the signal)",
			msg: models.SyslogMessage{
				Severity: 3, Hostname: "FGT-HUB",
				Message: `type="event" subtype="vpn" level="error" logdesc="IPsec phase 1 error" action="negotiate"`,
			},
			vendor: "fortigate",
			want: map[string]string{
				"subtype": "vpn", "level": "error", "logdesc": "IPsec phase 1 error", "action": "negotiate",
				"event.class": "vpn_session", "event.action": "deny",
			},
		},
		{
			name: "C2: logid/type split OUTSIDE Message must still extract",
			msg: models.SyslogMessage{
				Severity:       5,
				AppName:        `logid=0100044546`, // collector put this token in app_name
				StructuredData: `type="event"`,     // and this in structured_data
				Message:        `subtype="system" msg="Configuration changed" cfgpath="firewall.policy" user="alice"`,
			},
			vendor: "fortigate",
			want: map[string]string{
				"logid": "0100044546", "type": "event", "subtype": "system",
				"msg": "Configuration changed", "event.class": "config_change", "event.admin_user": "alice",
			},
		},
		{
			name:   "unmapped FortiOS type still exposes its natives, no event view",
			msg:    models.SyslogMessage{Severity: 5, Message: `type="event" subtype="router" level="notice" msg="BGP neighbor Up"`},
			vendor: "fortigate",
			want:   map[string]string{"subtype": "router", "level": "notice"},
			absent: []string{"event.class"},
		},
		{
			name:   "generic vendor: a self-describing k=v line exposes its tokens and the canonical view",
			msg:    models.SyslogMessage{Severity: 4, Message: `src=192.0.2.10 dst=203.0.113.20 action=drop`},
			vendor: "cisco_asa", // not registered -> generic mapper
			want:   map[string]string{"severity": "4", "src": "192.0.2.10", "event.action": "deny", "event.dst_ip": "203.0.113.20"},
		},
		{
			name:   "generic vendor: free text gets base fields only",
			msg:    models.SyslogMessage{Severity: 4, Message: `Interface eth0 link is up`},
			vendor: "cisco_asa",
			want:   map[string]string{"severity": "4", "message": `Interface eth0 link is up`},
			absent: []string{"event.class", "src"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Fields(tc.vendor, &tc.msg)
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("field %q = %q, want %q (all=%v)", k, got[k], v, got)
				}
			}
			for _, k := range tc.absent {
				if _, ok := got[k]; ok {
					t.Errorf("field %q should be absent, got %q", k, got[k])
				}
			}
		})
	}
}

// TestFields_EventViewBesideNatives (plan §7.1): the canonical keys live under
// `event.` and never clobber a native key. A FortiOS deny keeps action="deny"
// AND gains event.action=deny; a filterlog block keeps action="block" AND
// gains event.action=deny — the same rule matches both through event.action.
func TestFields_EventViewBesideNatives(t *testing.T) {
	fg := Fields("fortigate", &models.SyslogMessage{Message: `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny" policyid=20`})
	pf := Fields("opnsense", &models.SyslogMessage{AppName: "filterlog", Message: `5,,,1000000103,igb0,match,block,in,4,0x0,,64,1,0,none,6,tcp,60,203.0.113.9,198.51.100.10,54321,443`})
	if fg["action"] != "deny" || fg["event.action"] != "deny" {
		t.Errorf("fortigate: action=%q event.action=%q", fg["action"], fg["event.action"])
	}
	if pf["action"] != "block" || pf["event.action"] != "deny" {
		t.Errorf("opnsense: action=%q event.action=%q", pf["action"], pf["event.action"])
	}
	for _, f := range []map[string]string{fg, pf} {
		if f["event.src_ip"] != "203.0.113.9" || f["event.dst_ip"] != "198.51.100.10" || f["event.proto"] != "6" || f["event.class"] != "network" {
			t.Errorf("canonical tuple missing: %v", f)
		}
	}
	if fg["event.rule_key"] != "i:20" || pf["event.rule_key"] != "u:1000000103" {
		t.Errorf("rule keys: fg=%q pf=%q", fg["event.rule_key"], pf["event.rule_key"])
	}
}

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		`srcip=10.0.0.5 srcport=443`:   `srcip=#.#.#.# srcport=#`,
		`IPsec phase 2 error id 12345`: `IPsec phase # error id #`,
		"multiple   spaces\tand\ttabs": "multiple spaces and tabs",
	}
	for in, want := range tests {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
