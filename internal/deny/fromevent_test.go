package deny

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
)

// TestDenyParity: for every FortiGate / pf fixture in internal/normalize's
// testdata, the vendor-neutral FromEvent(Normalize(msg)) yields exactly the
// DeniedEvent ProjectVendor projects today (or, for both, nothing). This is
// the contract S-4 relies on when it switches ingest to the normalized path.
// The block-policy pattern is exercised too (IP_BLOCK* matches the
// `traffic_start_block_policy` fixture's policy name).
func TestDenyParity(t *testing.T) {
	t.Parallel()
	cfg := PatternConfig{Pattern: "IP_BLOCK*"}
	projected := 0
	for _, vendor := range []string{"fortigate", "opnsense", "pfsense"} {
		fh, err := os.Open(filepath.Join("..", "normalize", "testdata", vendor, "cases.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			var f struct {
				Name string               `json:"name"`
				Msg  models.SyslogMessage `json:"msg"`
			}
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				t.Fatal(err)
			}
			f.Msg.DeviceID, f.Msg.ProbeID = 7, 3
			if ok := assertParity(t, vendor+"/"+f.Name, vendor, &f.Msg, cfg); ok {
				projected++
			}
		}
		fh.Close()
	}
	if projected < 7 {
		t.Fatalf("only %d fixtures projected a deny — the parity check needs the deny fixtures", projected)
	}
}

// assertParity compares the two projections for one message and reports
// whether a row was projected.
func assertParity(t *testing.T, name, vendor string, msg *models.SyslogMessage, cfg PatternConfig) bool {
	t.Helper()
	want, wantOK := ProjectVendor(vendor, msg, nil, cfg)
	ev, out := normalize.Normalize(vendor, msg)
	got, gotOK := FromEvent(&ev, nil, cfg)
	if wantOK != gotOK {
		t.Errorf("%s: ProjectVendor ok=%v, FromEvent ok=%v (normalize %s %q; %+v)", name, wantOK, gotOK, out.Kind, out.Reason, got)
		return false
	}
	if wantOK && !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n ProjectVendor %+v\n FromEvent     %+v", name, want, got)
	}
	return wantOK
}

// TestDenyParity_NegativeControls (review S-2a #5): lines around the edges of
// the literal action="deny" gate — a UTM verdict word in a traffic line, a
// deny with no type= (inferred from logid, then from subtype), the block
// policy on a local-in start, a long country name, a scope-local source,
// alternate country spellings, and pf lines with "block" in free text — must
// project identically or not at all on both paths.
func TestDenyParity_NegativeControls(t *testing.T) {
	t.Parallel()
	cfg := PatternConfig{Pattern: "IP_BLOCK*"}
	for _, tc := range []struct{ vendor, line string }{
		{"fortigate", `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="blocked" policyid=20`},
		{"fortigate", `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny" policyid=20 srcintfrole="wan" service="HTTPS" policyname="x"`},
		{"fortigate", `logid=0000000013 subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny" policyid=20`},
		{"fortigate", `subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny" policyid=20`},
		{"fortigate", `subtype="local" srcip=203.0.113.9 dstip=198.51.100.10 proto=17 action="deny" policyid=0 service="DNS"`},
		{"fortigate", `type="traffic" subtype="local" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="start" policyid=20 policyname="IP_BLOCK_1"`},
		{"fortigate", `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="start" policyid=20 policyname="ALLOW-WEB"`},
		{"fortigate", `type="traffic" subtype="forward" srcip=fe80::1 dstip=198.51.100.10 proto=6 action="deny"`},
		{"fortigate", `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=224.0.0.251 proto=17 action="deny"`},
		{"fortigate", `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny" srccountry="` + strings.Repeat("Ü", 40) + `"`},
		{"fortigate", `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny" policyid=20 srccountry="Czechia" dstcountry="Russia"`},
		{"fortigate", `type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny" srccountry="Korea, Republic of" dstcountry="South Korea"`},
		{"fortigate", `type="traffic" subtype="forward" srcip=not-an-ip dstip=198.51.100.10 proto=6 action="deny"`},
		{"fortigate", `type="traffic" subtype="forward" srcip=203.0.113.9 proto=6 action="deny"`},
		{"fortigate", `Interface wan1 link down action="deny"`},
		{"opnsense", `9,,,1000000009,igb1,match,reject,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.9,198.51.100.10,1,2`},
		{"opnsense", `5,,,1000000103,igb0,match,block,in,4,0x0,,64,1,0,none,1,icmp,84,203.0.113.9,198.51.100.10,request,1234,5678`},
		{"pfsense", `9,,,1000000009,igb1,match,block,in,4,0x0,,64,1,0,DF,17,udp,60,203.0.113.9,198.51.100.10,1,2`},
		{"pfsense", `sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2 block`},
		{"pfsense", `7,,,2000000001,igb1,match,rdr,in,4,0x0,,64,1,0,none,6,tcp,60,192.0.2.10,203.0.113.20,51514,443`},
	} {
		assertParity(t, tc.vendor+" "+tc.line[:min(40, len(tc.line))], tc.vendor, &models.SyslogMessage{Message: tc.line, DeviceID: 1}, cfg)
	}
}

// TestFromEvent_IntendedDifferences documents where FromEvent deliberately
// departs from ProjectVendor (CHANGELOG 0.11.293), so a future change to
// either side is a conscious one:
//   - a UTM finding or an event-log line carrying the literal action="deny"
//     is not denied traffic (FortiOS UTM verdicts are blocked / dropped /
//     reset; event logs use deny for authentication outcomes). ProjectVendor
//     gates on the literal string and would store them;
//   - FortiOS always writes proto numerically; a word is mapped to its
//     number (ProjectVendor stores 0);
//   - a policy id beyond uint32 is NULL / 0 (ProjectVendor truncates it).
func TestFromEvent_IntendedDifferences(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		line        string
		wantProject bool // ProjectVendor
		wantEvent   bool // FromEvent
		policyID    uint32
		proto       uint8
	}{
		{`type="utm" subtype="app-ctrl" srcip=203.0.113.9 dstip=198.51.100.10 proto=6 action="deny" policyid=20`, true, false, 0, 0},
		{`type="event" subtype="user" srcip=203.0.113.9 dstip=198.51.100.10 action="deny"`, true, false, 0, 0},
		{`type="utm" subtype="webfilter" srcip=192.0.2.11 dstip=203.0.113.40 dstport=443 proto=6 hostname="games.example.com" action="blocked" catdesc="Games"`, false, false, 0, 0},
		{`type="traffic" subtype="forward" srcip=203.0.113.9 dstip=198.51.100.10 proto=tcp action="deny" policyid=99999999999`, true, true, 0, 6},
	} {
		msg := &models.SyslogMessage{Message: tc.line}
		_, pOK := ProjectVendor("fortigate", msg, nil, PatternConfig{})
		ev, _ := normalize.Normalize("fortigate", msg)
		got, eOK := FromEvent(&ev, nil, PatternConfig{})
		if pOK != tc.wantProject || eOK != tc.wantEvent {
			t.Errorf("%.60s: ProjectVendor ok=%v (want %v), FromEvent ok=%v (want %v)", tc.line, pOK, tc.wantProject, eOK, tc.wantEvent)
		}
		if eOK && (got.PolicyID != tc.policyID || got.Protocol != tc.proto) {
			t.Errorf("%.60s: FromEvent policy_id=%d proto=%d, want %d/%d", tc.line, got.PolicyID, got.Protocol, tc.policyID, tc.proto)
		}
	}
}
