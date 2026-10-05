package normalize

import (
	"bufio"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// Fixtures live in testdata/<vendor>/cases.jsonl: one JSON object per line,
// {"name": "...", "msg": <models.SyslogMessage as the collector ships it>}.
// Each has a golden in cases.golden.json (outcome, reason, native tokens and
// the event.* view). `go test ./internal/normalize -update` rewrites the
// goldens; review the diff — it IS the test. unparsed.txt lists, by name, the
// cases that are expected NOT to map (one per line, `#` comments allowed), so
// a mapper regression that silently stops mapping a case fails
// TestFixtures_NoSilentDrops even before the golden diff is read.
//
// Every fixture is synthetic (RFC 5737 / 3849 addresses, IANA documentation
// MACs, fw-example-NN hosts, example.com) — TestFixtures_Hygiene enforces it.
var update = flag.Bool("update", false, "rewrite the golden files")

type fixture struct {
	Name string               `json:"name"`
	Msg  models.SyslogMessage `json:"msg"`
}

type golden struct {
	Name    string            `json:"name"`
	Outcome string            `json:"outcome"`
	Reason  string            `json:"reason,omitempty"`
	Native  map[string]string `json:"native,omitempty"`
	Event   map[string]string `json:"event,omitempty"`
}

func fixtureVendors(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob("testdata/*/cases.jsonl")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no fixtures under testdata/: %v", err)
	}
	var vendors []string
	for _, d := range dirs {
		vendors = append(vendors, filepath.Base(filepath.Dir(d)))
	}
	sort.Strings(vendors)
	return vendors
}

func loadFixtures(t *testing.T, vendor string) []fixture {
	t.Helper()
	fh, err := os.Open(filepath.Join("testdata", vendor, "cases.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var out []fixture
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	seen := map[string]bool{}
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var f fixture
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("%s/cases.jsonl:%d: %v", vendor, n, err)
		}
		if f.Name == "" || seen[f.Name] {
			t.Fatalf("%s/cases.jsonl:%d: missing or duplicate name %q", vendor, n, f.Name)
		}
		seen[f.Name] = true
		out = append(out, f)
	}
	return out
}

func run(vendor string, f fixture) golden {
	ev, out := Normalize(vendor, &f.Msg)
	g := golden{Name: f.Name, Outcome: out.Kind.String(), Reason: out.Reason, Native: ev.Native}
	if out.Kind == OutcomeOK {
		g.Event = map[string]string{}
		ev.Fields(g.Event)
	}
	return g
}

func TestNormalize_Golden(t *testing.T) {
	t.Parallel()
	for _, vendor := range fixtureVendors(t) {
		vendor := vendor
		t.Run(vendor, func(t *testing.T) {
			var got []golden
			for _, f := range loadFixtures(t, vendor) {
				got = append(got, run(vendor, f))
			}
			path := filepath.Join("testdata", vendor, "cases.golden.json")
			if *update {
				b, _ := json.MarshalIndent(got, "", "  ")
				if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			var want []golden
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			byName := map[string]golden{}
			for _, w := range want {
				byName[w.Name] = w
			}
			for _, g := range got {
				w, ok := byName[g.Name]
				if !ok {
					t.Errorf("%s: no golden (run with -update)", g.Name)
					continue
				}
				if g.Outcome != w.Outcome || g.Reason != w.Reason {
					t.Errorf("%s: outcome %s %q, golden %s %q", g.Name, g.Outcome, g.Reason, w.Outcome, w.Reason)
				}
				diffMaps(t, g.Name+" event", g.Event, w.Event)
				diffMaps(t, g.Name+" native", g.Native, w.Native)
			}
			if len(got) != len(want) {
				t.Errorf("%d cases, %d goldens (run with -update)", len(got), len(want))
			}
		})
	}
}

func diffMaps(t *testing.T, label string, got, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if gv, ok := got[k]; !ok {
			t.Errorf("%s: %s missing (golden %q)", label, k, v)
		} else if gv != v {
			t.Errorf("%s: %s = %q, golden %q", label, k, gv, v)
		}
	}
	for k, v := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: %s = %q not in golden", label, k, v)
		}
	}
}

// TestFixtures_NoSilentDrops: every fixture maps, or is listed in the
// vendor's unparsed.txt as a known gap.
func TestFixtures_NoSilentDrops(t *testing.T) {
	t.Parallel()
	for _, vendor := range fixtureVendors(t) {
		known := map[string]bool{}
		if raw, err := os.ReadFile(filepath.Join("testdata", vendor, "unparsed.txt")); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if name, _, _ := strings.Cut(line, "#"); strings.TrimSpace(name) != "" {
					known[strings.TrimSpace(name)] = true
				}
			}
		}
		for _, f := range loadFixtures(t, vendor) {
			g := run(vendor, f)
			switch {
			case g.Outcome == "ok" && known[f.Name]:
				t.Errorf("%s/%s maps now — remove it from unparsed.txt", vendor, f.Name)
			case g.Outcome != "ok" && !known[f.Name]:
				t.Errorf("%s/%s: %s %q but not listed in unparsed.txt", vendor, f.Name, g.Outcome, g.Reason)
			}
			if g.Outcome == "ok" && g.Event["event.class"] == "unknown" {
				t.Errorf("%s/%s mapped without a class", vendor, f.Name)
			}
		}
	}
}

var (
	ipv4Lit = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Lit = regexp.MustCompile(`\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b`)
	macLit  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)
	hostLit = regexp.MustCompile(`\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\b`)
	// publicTLDs are the suffixes a real host name in a fixture would carry.
	publicTLDs = map[string]bool{"com": true, "net": true, "org": true, "io": true, "co": true, "uk": true, "de": true, "nl": true,
		"ca": true, "us": true, "edu": true, "gov": true, "mil": true, "info": true, "biz": true, "dev": true, "app": true, "cloud": true,
		"lan": true, "local": true, "home": true, "internal": true, "arpa": true, "eu": true, "fr": true, "au": true, "ch": true, "tk": true}
	okNets = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("fe80::/10"),
	}
)

// TestFixtures_Hygiene: the repos are public — fixtures carry documentation
// addresses only (the repo-wide guard in test/guardrails covers the tree; this
// one names the exact fixture line).
func TestFixtures_Hygiene(t *testing.T) {
	t.Parallel()
	for _, vendor := range fixtureVendors(t) {
		raw, err := os.ReadFile(filepath.Join("testdata", vendor, "cases.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(raw), "\n") {
			// A netfilter MAC= field (dst + src + ethertype, 14 colon-separated
			// bytes) parses as an IPv6 literal; strip MAC-shaped runs first.
			noMAC := macLit.ReplaceAllString(line, "")
			for _, lit := range append(ipv4Lit.FindAllString(line, -1), ipv6Lit.FindAllString(noMAC, -1)...) {
				a, err := netip.ParseAddr(lit)
				if err != nil {
					continue // a version string or a MAC-shaped token
				}
				ok := false
				for _, p := range okNets {
					ok = ok || p.Contains(a)
				}
				if !ok {
					t.Errorf("%s/cases.jsonl:%d: %s is outside the documentation ranges", vendor, n+1, lit)
				}
			}
			for _, m := range macLit.FindAllString(line, -1) {
				if !strings.HasPrefix(strings.ToLower(m), "00:00:5e:00:53:") {
					t.Errorf("%s/cases.jsonl:%d: MAC %s is not in the IANA documentation range 00:00:5e:00:53:xx", vendor, n+1, m)
				}
			}
			for _, h := range hostLit.FindAllString(strings.ToLower(line), -1) {
				// Only names under a public TLD count (FortiOS app names like
				// HTTPS.BROWSER and config paths like firewall.policy are not
				// host names); everything under example.com/.net/.org is fine.
				tld := h[strings.LastIndexByte(h, '.')+1:]
				if !publicTLDs[tld] || h == "example."+tld || strings.HasSuffix(h, ".example."+tld) {
					continue
				}
				t.Errorf("%s/cases.jsonl:%d: host name %q is outside example.com / fw-example-NN", vendor, n+1, h)
			}
		}
	}
}

// TestEnumsJSMirror: cmd/api/static/js/enums.js carries the same names and
// values as enums.go.
func TestEnumsJSMirror(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../cmd/api/static/js/enums.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(raw)
	pair := regexp.MustCompile(`([a-z_]+):\s*(\d+)`)
	for table, want := range EnumTables() {
		start := strings.Index(js, table+": {")
		if start < 0 {
			t.Errorf("enums.js: table %s missing", table)
			continue
		}
		body := js[start+len(table)+3:]
		body = body[:strings.Index(body, "}")]
		got := map[string]int64{}
		for _, m := range pair.FindAllStringSubmatch(body, -1) {
			var v int64
			for _, c := range m[2] {
				v = v*10 + int64(c-'0')
			}
			got[m[1]] = v
		}
		for name, v := range want {
			if gv, ok := got[name]; !ok || gv != v {
				t.Errorf("enums.js %s.%s = %d/%v, Go says %d", table, name, gv, ok, v)
			}
		}
		for name := range got {
			if _, ok := want[name]; !ok {
				t.Errorf("enums.js %s.%s has no Go counterpart", table, name)
			}
		}
	}
}

func TestRuleKey(t *testing.T) {
	t.Parallel()
	id := int64(12)
	idx := int32(2000)
	for _, tc := range []struct {
		uid, name, ruleset string
		id                 *int64
		idx                *int32
		want               string
	}{
		{uid: "4b5c6d7e-0000-0000-0000-00000000000c", id: &id, ruleset: "root", want: "u:4b5c6d7e-0000-0000-0000-00000000000c"},
		{id: &id, ruleset: "root", name: "LAN-to-WAN", want: "i:root/12"},
		{id: &id, want: "i:12"},
		{name: "Allow  All", ruleset: "", want: "n:allow all"},
		{name: "x", ruleset: "vpn_firewall", want: "n:vpn_firewall/x"},
		{name: "IPS Default Policy", ruleset: "ids/ips", want: "n:ids_ips/ips default policy"}, // '/' in the ruleset would be ambiguous
		{idx: &idx, ruleset: "a/b/c", want: "x:a_b_c/2000"},
		{idx: &idx, ruleset: "WAN_LOCAL", want: "x:WAN_LOCAL/2000"},
		{want: ""},
	} {
		if got := RuleKey(tc.uid, tc.id, tc.name, tc.ruleset, tc.idx); got != tc.want {
			t.Errorf("RuleKey(%+v) = %q, want %q", tc, got, tc.want)
		}
	}
}

func TestCountry(t *testing.T) {
	t.Parallel()
	for name, cc := range map[string]string{"Netherlands": "NL", "united states": "US", "Russian Federation": "RU", "Russia": "RU",
		"Korea, Republic of": "KR", "Reserved": "", "Asia/Pacific Region": "", "": ""} {
		if got := CountryCode(name); got != cc {
			t.Errorf("CountryCode(%q) = %q, want %q", name, got, cc)
		}
	}
	if CountryName("RU") != "Russian Federation" || CountryName("CZ") != "Czech Republic" || CountryName("") != "" {
		t.Errorf("CountryName prefers the FortiOS spelling: RU=%q CZ=%q", CountryName("RU"), CountryName("CZ"))
	}
}

// TestNormalize_FortiGateCEF_HintOrNot (review S-2a #1): a FortiGate switched
// to CEF output normalizes the same whether the collector's `format: cef`
// hint is present (live ingest) or not (a row re-read from the database for
// the backfill or the rule tester). The CEF family comes first in the
// FortiGate order because the key=value gate would otherwise claim the
// record's extension and map nothing.
func TestNormalize_FortiGateCEF_HintOrNot(t *testing.T) {
	t.Parallel()
	line := `CEF:0|Fortinet|Fortigate|v7.4.3|0000000013|traffic:forward close|3|deviceExternalId=FGT60FTK00000000 FTNTFGTlogid=0000000013 cat=traffic:forward act=deny src=192.0.2.10 spt=51514 dst=203.0.113.20 dpt=443 proto=6`
	hinted, hOut := Normalize("fortigate", &models.SyslogMessage{Message: line, Format: "cef"})
	stored, sOut := Normalize("fortigate", &models.SyslogMessage{Message: line})
	for _, c := range []struct {
		name string
		ev   Event
		out  Outcome
	}{{"hinted", hinted, hOut}, {"stored", stored, sOut}} {
		if c.out.Kind != OutcomeOK || c.out.Family != FamilyCEF || c.ev.Action != ActionDeny || c.ev.SrcIP.String() != "192.0.2.10" || c.ev.Native["cef_id"] != "0000000013" {
			t.Errorf("%s: %s %q family=%v action=%v src=%v cef_id=%q", c.name, c.out.Kind, c.out.Reason, c.out.Family, c.ev.Action, c.ev.SrcIP, c.ev.Native["cef_id"])
		}
	}
	hm, sm := map[string]string{}, map[string]string{}
	hinted.Fields(hm)
	stored.Fields(sm)
	diffMaps(t, "hinted vs stored", hm, sm)
}

// TestNormalize_FortiGateKV_MentioningCEF: with CEF tried first for
// FortiGate, a FortiOS key=value line whose quoted msg contains a CEF record
// must still be a FortiOS line — the CEF gate rejects a non-leading marker
// preceded by any '='.
func TestNormalize_FortiGateKV_MentioningCEF(t *testing.T) {
	t.Parallel()
	line := `date=2026-10-04 msg="saw CEF:0|a|b|c|d|e|f|x=1 in payload" time=12:00:00 devname="fw-example-01" logid="0100044547" type="event" subtype="system" level="information" vd="root" logdesc="Object attribute configured" user="alice" ui="GUI(192.0.2.10)" action="Edit" cfgpath="log.syslogd.setting" cfgobj="format" cfgattr="format[default->cef]"`
	ev, out := Normalize("fortigate", &models.SyslogMessage{Message: line})
	if out.Kind != OutcomeOK || out.Family != FamilyFortiOSKV || ev.Class != ClassConfigChange || ev.Native["subtype"] != "system" {
		t.Fatalf("got %s %q family=%v class=%v subtype=%q", out.Kind, out.Reason, out.Family, ev.Class, ev.Native["subtype"])
	}
	if _, cef := ev.Native["cef_id"]; cef {
		t.Errorf("CEF natives leaked into a FortiOS line: %v", ev.Native)
	}
	// A real record after a plain syslog header (no '=' before the marker) is still CEF.
	if _, out := Normalize("fortigate", &models.SyslogMessage{Message: `fw-example-01 CEF:0|Fortinet|Fortigate|v7|0000000013|forward|3|src=192.0.2.1 dst=203.0.113.1 act=deny`}); out.Family != FamilyCEF {
		t.Errorf("header-prefixed record: family=%v %s %q", out.Family, out.Kind, out.Reason)
	}
}

// TestFortiGateTypeInference: logid typing applies to the 10-digit FortiOS
// form only; anything else falls to the subtype vocabulary, and the UTM
// prefix table names every UTM log type so an unmapped one is reported as
// utm/<subtype>.
func TestFortiGateTypeInference(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		line   string
		class  Class
		kind   OutcomeKind
		reason string
	}{
		{`logid=13 subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny"`, ClassNetwork, OutcomeOK, ""},
		{`logid=13 srcip=203.0.113.9 action="deny"`, 0, OutcomeUnparsed, "fortigate: not a FortiOS log (no type/logid)"},
		{`logid=2000000001 subtype="virtual-patch" srcip=203.0.113.9 action="blocked"`, 0, OutcomeUnparsed, "fortigate: utm/virtual-patch not mapped"},
		{`logid=0800000001 subtype="voip" srcip=203.0.113.9`, 0, OutcomeUnparsed, "fortigate: utm/voip not mapped"},
		{`logid=0100032001 user="alice" logdesc="Admin login successful" srcip=192.0.2.10 ui="GUI(192.0.2.10)" subtype="system"`, ClassAuth, OutcomeOK, ""},
	} {
		ev, out := Normalize("fortigate", &models.SyslogMessage{Message: tc.line})
		if out.Kind != tc.kind || out.Reason != tc.reason || (tc.kind == OutcomeOK && ev.Class != tc.class) {
			t.Errorf("%.50s: %s %q class=%v, want %s %q class=%v", tc.line, out.Kind, out.Reason, ev.Class, tc.kind, tc.reason, tc.class)
		}
	}
}

// TestEvent_SlabOverflowKeepsValues: more pointer columns than the slab holds
// fall back to individual boxes; every value must survive copying the Event.
func TestEvent_SlabOverflowKeepsValues(t *testing.T) {
	t.Parallel()
	line := `type="traffic" subtype="forward" policyid=1 sentbyte=2 rcvdbyte=3 sentpkt=4 rcvdpkt=5 duration=6 srcip=192.0.2.1 dstip=192.0.2.2 transip=192.0.2.3 tranip=192.0.2.4 trandisp="snat+dnat" srcport=1 dstport=2 transport=3 tranport=4 proto=6 apprisk="high" action="accept"`
	ev, out := Normalize("fortigate", &models.SyslogMessage{Message: line})
	if out.Kind != OutcomeOK {
		t.Fatal(out)
	}
	cp := ev
	if *cp.RuleID != 1 || *cp.BytesOut != 2 || *cp.BytesIn != 3 || *cp.PktsOut != 4 || *cp.PktsIn != 5 || *cp.DurationMS != 6000 ||
		*cp.NatSrcPort != 3 || *cp.NatDstPort != 4 || cp.NatDstIP.String() != "192.0.2.4" || *cp.AppRisk != 4 || *cp.SrcPort != 1 {
		t.Errorf("values wrong after copy: %+v", cp)
	}
	var e Event
	var ptrs []*int64
	for i := int64(0); i < 20; i++ {
		ptrs = append(ptrs, e.p64(i))
	}
	for i, p := range ptrs {
		if *p != int64(i) {
			t.Errorf("slot %d = %d", i, *p)
		}
	}
}

// TestNormalize_UnknownVendorIsGeneric: a vendor without a mapper takes the
// generic one (CEF / filterlog / k=v), never nil.
func TestNormalize_UnknownVendorIsGeneric(t *testing.T) {
	t.Parallel()
	if Lookup("nope").Vendor() != "generic" || Has("nope") || !Has("FortiGate") {
		t.Fatal("registry fallback / case folding broken")
	}
	ev, out := Normalize("sonicwall", &models.SyslogMessage{Message: `id=firewall sn=0000000000 time="2026-10-04 12:00:00" fw=203.0.113.1 pri=6 c=262144 m=98 msg="Connection Opened" n=1 src=192.0.2.10:51514:X0 dst=203.0.113.20:443:X1 proto=tcp/https`})
	if out.Kind != OutcomeOK || ev.Class != ClassNetwork || ev.SrcIP.String() != "192.0.2.10" || ev.DstPort == nil || *ev.DstPort != 443 {
		t.Fatalf("generic kv: %s %q class=%v src=%v dst_port=%v", out.Kind, out.Reason, ev.Class, ev.SrcIP, ev.DstPort)
	}
}
