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
				Message: `subtype="forward" level="warning" vd="root" srcintf="internal" srcintfrole="lan" action="accept"`,
			},
			vendor: "fortigate",
			want: map[string]string{
				"subtype": "forward", "level": "warning", "srcintf": "internal",
				"action": "accept", "severity": "4", "facility": "23",
			},
		},
		{
			name: "vpn ipsec error (the signal)",
			msg: models.SyslogMessage{
				Severity: 3, Hostname: "FGT-HUB",
				Message: `subtype="vpn" level="error" logdesc="IPsec phase 1 error" action="negotiate"`,
			},
			vendor: "fortigate",
			want: map[string]string{
				"subtype": "vpn", "level": "error", "logdesc": "IPsec phase 1 error", "action": "negotiate",
			},
		},
		{
			name: "C2: logid/type split OUTSIDE Message must still extract",
			msg: models.SyslogMessage{
				Severity:       5,
				AppName:        `logid=0100044546`, // collector put this token in app_name
				StructuredData: `type="event"`,     // and this in structured_data
				Message:        `subtype="system" msg="Configuration changed"`,
			},
			vendor: "fortigate",
			want: map[string]string{
				"logid": "0100044546", "type": "event", "subtype": "system",
				"msg": "Configuration changed",
			},
		},
		{
			name:   "generic vendor gets base fields only",
			msg:    models.SyslogMessage{Severity: 4, Message: `subtype="forward" level="warning"`},
			vendor: "cisco_asa", // not registered -> generic fallback
			want:   map[string]string{"severity": "4", "message": `subtype="forward" level="warning"`},
			absent: []string{"subtype", "level"},
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
					t.Errorf("field %q should be absent for generic vendor, got %q", k, got[k])
				}
			}
		})
	}
}

func TestRegistry(t *testing.T) {
	if !Has("fortigate") {
		t.Error("fortigate must be registered")
	}
	if !Has("opnsense") || !Has("pfsense") {
		t.Error("opnsense/pfsense stubs must be registered")
	}
	if Has("cisco_asa") {
		t.Error("cisco_asa is not profiled; Has must be false")
	}
	if Lookup("nope").Vendor() != "generic" {
		t.Errorf("unknown vendor must fall back to generic, got %q", Lookup("nope").Vendor())
	}
	if Lookup("FortiGate").Vendor() != "fortigate" {
		t.Error("Lookup must be case-insensitive")
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
