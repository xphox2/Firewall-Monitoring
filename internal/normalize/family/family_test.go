package family

import (
	"reflect"
	"testing"
)

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
