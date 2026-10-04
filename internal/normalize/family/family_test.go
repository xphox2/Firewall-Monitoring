package family

import (
	"reflect"
	"testing"
)

// The netfilter and Meraki tokenizers ship ahead of their mappers (S-2b, the
// UniFi / Meraki vendor PR), so their shape is pinned here directly. Samples
// follow the vendor documentation; untested on real hardware.

func TestParseNetfilter(t *testing.T) {
	t.Parallel()
	line := `kernel: [WAN_LOCAL-D-2000] DESCR="Drop All Other Traffic" IN=eth4 OUT= MAC=00:00:5e:00:53:01:00:00:5e:00:53:02:08:00 SRC=203.0.113.9 DST=198.51.100.1 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=TCP SPT=51514 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0`
	if !HasNetfilter(line) {
		t.Fatal("gate rejected a netfilter line")
	}
	nf, ok := ParseNetfilter(line)
	if !ok || nf.Ruleset != "WAN_LOCAL" || nf.Verdict != "D" || nf.Index != "2000" {
		t.Fatalf("prefix: %+v ok=%v", nf, ok)
	}
	for k, v := range map[string]string{"descr": "Drop All Other Traffic", "in": "eth4", "out": "", "src": "203.0.113.9", "dst": "198.51.100.1", "proto": "TCP", "spt": "51514", "dpt": "22"} {
		if nf.Fields[k] != v {
			t.Errorf("field %s = %q, want %q", k, nf.Fields[k], v)
		}
	}
	// Zone-pair chains (Network 9.0+), RET verdict, no index, and a dash in
	// the ruleset name.
	for _, tc := range []struct{ prefix, ruleset, verdict, index string }{
		{"[LAN_LOCAL-RET-2147483647]", "LAN_LOCAL", "RET", "2147483647"},
		{"[Internal-to-External-A-5]", "Internal-to-External", "A", "5"},
		{"[GUEST_IN-D]", "GUEST_IN", "D", ""},
	} {
		nf, ok := ParseNetfilter(tc.prefix + " IN=br0 OUT=eth4 SRC=192.0.2.10 DST=203.0.113.20 PROTO=UDP SPT=5353 DPT=53")
		if !ok || nf.Ruleset != tc.ruleset || nf.Verdict != tc.verdict || nf.Index != tc.index {
			t.Errorf("%s: %+v ok=%v", tc.prefix, nf, ok)
		}
	}
	for _, not := range []string{`[12345] some bracketed thing IN=eth0`, `[UFW BLOCK] IN=eth0 SRC=192.0.2.1`, `no prefix SRC=192.0.2.1`, `[WAN_IN-X-1] IN=eth0`} {
		if HasNetfilter(not) {
			t.Errorf("gate accepted %q", not)
		}
	}
}

func TestParseMeraki(t *testing.T) {
	t.Parallel()
	// Category supplied by the collector (app_name), body only.
	m, ok := ParseMeraki("flows", `src=192.0.2.10 dst=203.0.113.20 mac=00:00:5E:00:53:0A protocol=udp sport=55719 dport=53 pattern: allow all`)
	if !ok || m.Category != "flows" || m.Fields["src"] != "192.0.2.10" || m.Fields["dport"] != "53" || m.TailKind != "pattern" || m.Tail != "allow all" || m.Subtype != "" {
		t.Fatalf("flows: %+v ok=%v", m, ok)
	}
	// No category hint: a re-joined v5 line carries host + category inline;
	// bare words before the pairs are the subtype; single-quoted values keep
	// their spaces; the tail is the message.
	m, ok = ParseMeraki("", `fw-example-05 security_event ids_alerted signature=1:2100498:7 priority=2 timestamp=1759579200.123456 direction=egress protocol=tcp/ip src=192.0.2.10:51514 dst=203.0.113.20:80 message: GPL ATTACK_RESPONSE id check returned root`)
	if !ok || m.Category != "security_event" || m.Subtype != "ids_alerted" || m.Fields["signature"] != "1:2100498:7" || m.Fields["protocol"] != "tcp/ip" || m.TailKind != "message" || m.Tail != "GPL ATTACK_RESPONSE id check returned root" {
		t.Fatalf("security_event: %+v ok=%v", m, ok)
	}
	m, ok = ParseMeraki("events", `type=vpn_connectivity_change vpn_type='site-to-site' peer_contact='203.0.113.5:51856' peer_ident='branch two' connectivity='false'`)
	if !ok || m.Fields["type"] != "vpn_connectivity_change" || m.Fields["peer_ident"] != "branch two" || m.Fields["connectivity"] != "false" {
		t.Fatalf("events: %+v ok=%v", m, ok)
	}
	// Free text: everything is subtype.
	m, ok = ParseMeraki("events", `failover to wan1`)
	if !ok || m.Subtype != "failover to wan1" || len(m.Fields) != 0 {
		t.Fatalf("free text: %+v ok=%v", m, ok)
	}
	if _, ok := ParseMeraki("", `src=192.0.2.10 dst=203.0.113.20 pattern: allow all`); ok {
		t.Error("no category anywhere must not parse")
	}
	if IsMerakiCategory("urls") != true || IsMerakiCategory("filterlog") {
		t.Error("category set")
	}
}

func TestParseCEF(t *testing.T) {
	t.Parallel()
	c, ok := ParseCEF(`Oct  4 12:00:00 fw-example-06 CEF:0|Ubiquiti|UniFi Network|9.3.45|201|Threat Detected and Blocked|7|UNIFIcategory=Security msg=Blocked\=yes src=203.0.113.9 spt=44000 dst=192.0.2.10 dpt=22 proto=TCP act=Blocked UNIFIpolicyName=IPS Default Policy UNIFIflowId=null`)
	if !ok || c.Vendor != "Ubiquiti" || c.Product != "UniFi Network" || c.SignatureID != "201" || c.Name != "Threat Detected and Blocked" || c.Severity != "7" {
		t.Fatalf("header: %+v ok=%v", c, ok)
	}
	for k, v := range map[string]string{"unificategory": "Security", "msg": "Blocked=yes", "src": "203.0.113.9", "act": "Blocked", "unifipolicyname": "IPS Default Policy", "unififlowid": "null"} {
		if c.Ext[k] != v {
			t.Errorf("ext %s = %q, want %q", k, c.Ext[k], v)
		}
	}
	// Escaped pipes in the header, no extension at all, and a non-record.
	c, ok = ParseCEF(`CEF:0|Example|Pipe\|Product|1|7|Name with \| pipe|3|`)
	if !ok || c.Product != "Pipe|Product" || c.Name != "Name with | pipe" || len(c.Ext) != 0 {
		t.Fatalf("escaped header: %+v ok=%v", c, ok)
	}
	if _, ok := ParseCEF(`CEF:0|too|few|fields`); ok {
		t.Error("short header accepted")
	}
	if HasCEF(`this line mentions x-CEF:0 glued to a word, then far away ` + string(make([]byte, cefSniffLen)) + ` CEF:0|a|b|c|d|e|f|`) {
		t.Error("marker beyond the sniff window accepted")
	}
}

func TestParseKV_Filterlog_Text(t *testing.T) {
	t.Parallel()
	kv := ParseKV(`host app date=2026-10-04 msg="quoted value" empty= TAG=X bare`)
	if !reflect.DeepEqual(kv, map[string]string{"date": "2026-10-04", "msg": "quoted value", "empty": "", "tag": "X"}) {
		t.Errorf("ParseKV = %v", kv)
	}
	if HasKV("no pairs here") || !HasKV("a=b") || HasKV(" =b") {
		t.Error("HasKV gate")
	}
	fl, ok := ParseFilterlog(`filterlog[42]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,203.0.113.9,198.51.100.10,54321,443,0,S`)
	if !ok || fl.Tracker != "1000000103" || fl.Action != "block" || fl.Proto != "6" || fl.Src != "203.0.113.9" || fl.DstPort != "443" {
		t.Fatalf("filterlog: %+v ok=%v", fl, ok)
	}
	// ICMP: the two columns after dst are type / id; the tokenizer keeps them
	// (the native srcport / dstport keys always carried them) and the mapper
	// decides they are not ports.
	icmp, ok := ParseFilterlog(`5,,,1000000103,igb0,match,block,in,4,0x0,,64,1,0,none,1,icmp,84,203.0.113.9,198.51.100.10,request,1234,5678`)
	if !ok || icmp.Proto != "1" || icmp.SrcPort != "request" || icmp.DstPort != "1234" {
		t.Fatalf("icmp filterlog: %+v ok=%v", icmp, ok)
	}
	if FindFilterlog("no commas here at all") != "" || FindFilterlog("a,b,c,d,e,f,g") != "" {
		t.Error("pre-gate")
	}
	tx, ok := ParseText(`dnsmasq[123]: query[AAAA] www.example.com from 192.0.2.10`)
	if !ok || tx.Kind != "dnsmasq_query" || tx.Fields["qtype"] != "AAAA" || tx.Fields["qname"] != "www.example.com" || tx.Fields["src"] != "192.0.2.10" {
		t.Fatalf("text: %+v ok=%v", tx, ok)
	}
	tx, ok = ParseText(`dnsmasq-dhcp[123]: DHCPACK(br0) 192.0.2.10 00:00:5e:00:53:0a alice-laptop`)
	if !ok || tx.Kind != "dnsmasq_dhcpack" || tx.Fields["mac"] != "00:00:5e:00:53:0a" || tx.Fields["host"] != "alice-laptop" || tx.Fields["iface"] != "br0" {
		t.Fatalf("dhcp: %+v ok=%v", tx, ok)
	}
	if HasText("nothing from the catalogue") {
		t.Error("text gate")
	}
}
