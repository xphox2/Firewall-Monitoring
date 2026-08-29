package logfields

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestOPNsenseFilterlogExtract (AUDIT-280): the OPNsense filterlog extractor
// parses the pf CSV into matchable structured fields, and pfSense shares the
// exact same parser.
func TestOPNsenseFilterlogExtract(t *testing.T) {
	// Real-shape OPNsense IPv4 TCP block: the CSV common prefix
	// (rule,sub,anchor,tracker,iface,reason,action,dir,ipver) then IPv4 header
	// (…,protonum=6,proto=tcp,length,src,dst) then tcp ports.
	ipv4 := models.SyslogMessage{
		Severity: 4, Facility: 4, Hostname: "opnsense.lab",
		AppName: "filterlog",
		Message: `filterlog[42]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,203.0.113.9,198.51.100.10,54321,443,0,S,1234567890,,65535,,mss;nop`,
	}
	got := Fields("opnsense", &ipv4)
	wantV4 := map[string]string{
		"action": "block", "interface": "igb0", "reason": "match", "dir": "in",
		"ipversion": "4", "proto": "6", "protoname": "tcp",
		"srcip": "203.0.113.9", "dstip": "198.51.100.10",
		"srcport": "54321", "dstport": "443",
	}
	for k, v := range wantV4 {
		if got[k] != v {
			t.Errorf("ipv4 field %q = %q, want %q (all=%v)", k, got[k], v, got)
		}
	}

	// IPv6 UDP pass: proto text precedes protonum, src/dst shift to 15/16.
	ipv6 := models.SyslogMessage{
		Severity: 5, AppName: "filterlog",
		Message: `filterlog[42]: 12,,,900,igb1,match,pass,out,6,0x00,0x00000,64,udp,17,80,2001:db8::1,2001:db8::2,5353,5353`,
	}
	g6 := Fields("opnsense", &ipv6)
	wantV6 := map[string]string{
		"action": "pass", "ipversion": "6", "protoname": "udp", "proto": "17",
		"srcip": "2001:db8::1", "dstip": "2001:db8::2", "srcport": "5353", "dstport": "5353",
	}
	for k, v := range wantV6 {
		if g6[k] != v {
			t.Errorf("ipv6 field %q = %q, want %q (all=%v)", k, g6[k], v, g6)
		}
	}

	// pfSense shares the parser — same line, same structured fields.
	pf := Fields("pfsense", &ipv4)
	for _, k := range []string{"action", "srcip", "dstip", "dstport", "proto"} {
		if pf[k] != got[k] {
			t.Errorf("pfsense field %q = %q, want same as opnsense %q", k, pf[k], got[k])
		}
	}

	// A line with no filterlog CSV yields only base fields (no structured leak).
	plain := models.SyslogMessage{Severity: 6, Message: "some non-filterlog notice"}
	if pg := Fields("opnsense", &plain); pg["action"] != "" || pg["srcip"] != "" {
		t.Errorf("non-filterlog line must not produce structured fields, got %v", pg)
	}
}
