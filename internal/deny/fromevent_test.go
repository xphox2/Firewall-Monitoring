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
			want, wantOK := ProjectVendor(vendor, &f.Msg, nil, cfg)
			ev, _ := normalize.Normalize(vendor, &f.Msg)
			got, gotOK := FromEvent(&ev, nil, cfg)
			if wantOK != gotOK {
				t.Errorf("%s/%s: ProjectVendor ok=%v, FromEvent ok=%v (%+v)", vendor, f.Name, wantOK, gotOK, got)
				continue
			}
			if wantOK {
				projected++
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s/%s:\n ProjectVendor %+v\n FromEvent     %+v", vendor, f.Name, want, got)
				}
			}
		}
		fh.Close()
	}
	if projected < 5 {
		t.Fatalf("only %d fixtures projected a deny — the parity check needs the deny fixtures", projected)
	}
}

// TestFromEvent_UTMBlockIsNotADeny: a web-filter block is a UTM finding in
// deny_storm terms, not denied traffic — ProjectVendor never projected it
// (it gates on the literal action="deny") and FromEvent must not either.
func TestFromEvent_UTMBlockIsNotADeny(t *testing.T) {
	t.Parallel()
	msg := &models.SyslogMessage{Message: `type="utm" subtype="webfilter" srcip=192.0.2.11 dstip=203.0.113.40 dstport=443 proto=6 hostname="games.example.com" action="blocked" catdesc="Games"`}
	ev, out := normalize.Normalize("fortigate", msg)
	if out.Kind != normalize.OutcomeOK || ev.Action != normalize.ActionDeny {
		t.Fatalf("fixture should normalize to a deny-action HTTP event: %v %v", out, ev.Action)
	}
	if _, ok := FromEvent(&ev, nil, PatternConfig{}); ok {
		t.Error("web-filter block projected as a denied event")
	}
}
