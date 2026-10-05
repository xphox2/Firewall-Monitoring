package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
	"firewall-mon/internal/notifier"
)

// Synthetic fixtures (the internal/normalize goldens): RFC 5737 addresses,
// fw-example-NN hosts, alice. One row per vendor shape the S-4 ingest must
// route: FortiGate traffic close (allow, poluuid rule), local-in deny
// (policy 0), admin login (auth → sec_events), config change (config_change →
// sec_events); pfSense filterlog block; UniFi netfilter drop and CEF 201 IPS
// finding; Meraki flows deny; a generic CEF deny.
const (
	fgClose       = `date=2026-10-04 time=12:00:01 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1759579201000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.10 srcport=51514 srcintf="port2" srcintfrole="lan" dstip=203.0.113.20 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Netherlands" sessionid=2101301 proto=6 action="close" policyid=12 policytype="policy" poluuid="4b5c6d7e-0000-0000-0000-00000000000c" policyname="LAN-to-WAN" service="HTTPS" trandisp="snat" transip=203.0.113.2 transport=51514 appid=40568 app="HTTPS.BROWSER" appcat="Web.Client" apprisk="medium" applist="default" duration=61 sentbyte=5231 rcvdbyte=12033 sentpkt=22 rcvdpkt=19 srchwvendor="Example" devtype="Computer" osname="Linux" srcmac="00:00:5e:00:53:0a" srcname="alice-laptop" user="alice" group="staff"`
	fgLocalDeny   = `date=2026-10-04 time=12:00:03 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1759579203000000000 tz="+0000" logid="0001000014" type="traffic" subtype="local" level="notice" vd="root" srcip=203.0.113.77 srcport=52000 srcintf="wan1" srcintfrole="wan" dstip=203.0.113.1 dstport=22 dstintf="unknown0" dstintfrole="undefined" srccountry="United States" dstcountry="Reserved" sessionid=2101303 proto=6 action="deny" policyid=0 policytype="local-in-policy" service="SSH" app="SSH" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0`
	fgAdminLogin  = `date=2026-10-04 time=12:03:00 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1759579380000000000 tz="+0000" logid="0100032001" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" sn="1759579380" user="alice" ui="https(192.0.2.10)" method="https" srcip=192.0.2.10 dstip=192.0.2.1 action="login" status="success" reason="none" profile="super_admin" msg="Administrator alice logged in successfully from https(192.0.2.10)"`
	fgConfigEdit  = `date=2026-10-04 time=12:03:02 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1759579382000000000 tz="+0000" logid="0100044547" type="event" subtype="system" level="information" vd="root" logdesc="Object attribute configured" user="alice" ui="GUI(192.0.2.10)" action="Edit" cfgtid=100 cfgpath="firewall.policy" cfgobj="12" cfgattr="status[enable->disable]" msg="Edit firewall.policy 12"`
	pfBlock       = `5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,203.0.113.9,198.51.100.10,54321,443,0,S,1234567890,,65535,,mss;nop`
	ufNetfilter   = `[WAN_LOCAL-D-2147483647] DESCR="[WAN_LOCAL]Drop All Other Traf" IN=eth4 OUT= MAC=00:00:5e:00:53:01:00:00:5e:00:53:02:08:00 SRC=203.0.113.9 DST=198.51.100.1 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=TCP SPT=51514 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0`
	ufCEF201      = `CEF:0|Ubiquiti|UniFi Network|9.3.45|201|Threat Detected and Blocked|7|UNIFIcategory=Security UNIFIsubCategory=IPS UNIFIhost=fw-example-07 UNIFIutcTime=2026-10-04T12:00:00.000Z proto=TCP spt=44000 dpt=22 src=203.0.113.9 dst=192.0.2.10 act=Blocked app=SSH UNIFIrisk=High UNIFIpolicyName=IPS Default Policy UNIFIpolicyType=IPS UNIFIdirection=inbound UNIFIsrcZone=External UNIFIdstZone=Internal UNIFItotalBytes=1540 UNIFItotalPackets=12 UNIFIbytesSent=1024 UNIFIbytesReceived=516 UNIFIipsSignature=ET SCAN Potential SSH Scan UNIFIipsSignatureId=2001219 msg=Threat Detected and Blocked`
	mkFlowsDeny   = `src=203.0.113.9 dst=198.51.100.5 protocol=tcp sport=44000 dport=3389 pattern: 1 all`
	genCEFDeny    = `CEF:0|Example|Edge Firewall|2.1|1001|Connection denied|6|src=203.0.113.9 spt=44000 dst=198.51.100.10 dpt=3389 proto=TCP act=deny app=RDP cs1=Block-RDP deviceInboundInterface=eth0 msg=denied by policy`
	fgV5SplitBody = `subtype="forward" level="warning" vd="root" srcip=203.0.113.9 srcport=44000 srcintf="wan1" srcintfrole="wan" dstip=198.51.100.150 dstport=3389 dstintf="port3" dstintfrole="dmz" srccountry="Mauritania" dstcountry="Reserved" sessionid=2101302 proto=6 action="deny" policyid=20 policytype="policy" service="RDP" policyname="IP_BLOCK-2" crscore=30 craction=131072 crlevel="high"`
)

// normalizeFixture is the handler-level test fleet: one device per vendor,
// all owned by the probe.
type normalizeFixture struct {
	h     *Handler
	db    *database.Database
	probe *models.Probe
	dev   map[string]*models.Device // vendor → device
}

func newNormalizeFixture(t *testing.T, schemaVersion int, cfg *config.Config) *normalizeFixture {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	if cfg == nil {
		cfg = &config.Config{}
	}
	h := NewHandler(cfg, nil, db)
	probe, fg := setupProbeAndDevice(t, db)
	if err := db.Gorm().Model(&models.Probe{}).Where("id = ?", probe.ID).Update("schema_version", schemaVersion).Error; err != nil {
		t.Fatalf("set probe schema version: %v", err)
	}
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", fg.ID).Update("vendor", "fortigate").Error; err != nil {
		t.Fatalf("set fortigate vendor: %v", err)
	}
	f := &normalizeFixture{h: h, db: db, probe: probe, dev: map[string]*models.Device{"fortigate": fg}}
	for i, vendor := range []string{"pfsense", "unifi", "meraki", "generic"} {
		d := &models.Device{Name: "fw-example-0" + string(rune('3'+i)), IPAddress: "192.0.2." + string(rune('3'+i)), Vendor: vendor, ProbeID: &probe.ID}
		if err := db.Gorm().Create(d).Error; err != nil {
			t.Fatalf("create %s device: %v", vendor, err)
		}
		f.dev[vendor] = d
	}
	return f
}

func (f *normalizeFixture) msg(vendor, appName, format, message string) map[string]interface{} {
	return map[string]interface{}{
		"device_id": f.dev[vendor].ID,
		"timestamp": time.Now().UTC(),
		"severity":  5,
		"facility":  20,
		"hostname":  f.dev[vendor].Name,
		"app_name":  appName,
		"format":    format,
		"message":   message,
	}
}

// mixedBatch is the nine-row, five-vendor batch.
func (f *normalizeFixture) mixedBatch() []map[string]interface{} {
	return []map[string]interface{}{
		f.msg("fortigate", "traffic", "fortios_kv", fgClose),
		f.msg("fortigate", "traffic", "fortios_kv", fgLocalDeny),
		f.msg("fortigate", "event", "fortios_kv", fgAdminLogin),
		f.msg("fortigate", "event", "fortios_kv", fgConfigEdit),
		f.msg("pfsense", "filterlog", "rfc3164", pfBlock),
		f.msg("unifi", "kernel", "rfc3164", ufNetfilter),
		f.msg("unifi", "", "cef", ufCEF201),
		f.msg("meraki", "flows", "meraki", mkFlowsDeny),
		f.msg("generic", "", "cef", genCEFDeny),
	}
}

func (f *normalizeFixture) post(t *testing.T, batch []map[string]interface{}) {
	t.Helper()
	w := doTestRequest(t, f.h.ReceiveSyslogMessages, "POST", "/syslog", f.probe.ID, f.probe.RegistrationKey, batch)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); int(saved) != len(batch) {
		t.Fatalf("saved = %v, want %d", saved, len(batch))
	}
}

func countRows(t *testing.T, db *database.Database, model interface{}, where string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	q := db.Gorm().Model(model)
	if where != "" {
		q = q.Where(where, args...)
	}
	if err := q.Count(&n).Error; err != nil {
		t.Fatalf("count %T: %v", model, err)
	}
	return n
}

// TestReceiveSyslog_NormalizesMixedVendorBatch is the S-4 wiring test: one
// posted batch lands typed rows in net_events / sec_events, catalog rows in
// fw_rules, observed-field counters (after a flush) in device_field_observed,
// deny rows in denied_events, and every raw syslog row — with raw_id linking
// each typed row to its raw row. Run at schema v6 (framing contract) and v5
// (the v5 run also carries a pre-1.3.48 positional-split FortiGate row that
// only the re-framing fallback can normalize). Fails on the pre-S-4 ingest
// with zero rows in every normalized table.
func TestReceiveSyslog_NormalizesMixedVendorBatch(t *testing.T) {
	for _, tc := range []struct {
		name          string
		schemaVersion int
	}{{"v6", 6}, {"v5", 5}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNormalizeFixture(t, tc.schemaVersion, nil)
			batch := f.mixedBatch()
			if tc.schemaVersion < 6 {
				// A pre-1.3.48 collector's positional RFC 5424 split: the first
				// FortiOS pairs sit in the header columns and there is no format
				// hint. Reframe re-joins them; the line is a deny on policy 20.
				batch = append(batch, map[string]interface{}{
					"device_id":       f.dev["fortigate"].ID,
					"timestamp":       time.Now().UTC(),
					"severity":        4,
					"facility":        20,
					"hostname":        `devid="FGT60FTK00000000"`,
					"app_name":        "eventtime=1759579202000000000",
					"process_id":      `tz="+0000"`,
					"message_id":      `logid="0000000013"`,
					"structured_data": `type="traffic"`,
					"message":         fgV5SplitBody,
				})
			}
			f.post(t, batch)

			if n := countRows(t, f.db, &models.SyslogMessage{}, ""); int(n) != len(batch) {
				t.Fatalf("syslog_messages = %d, want %d (raw rows are saved first, always)", n, len(batch))
			}
			// Network class: FG close + FG deny + PF block + UF netfilter + MK
			// flows + generic CEF (+ the v5 split deny).
			wantNet := int64(6)
			if tc.schemaVersion < 6 {
				wantNet++
			}
			if n := countRows(t, f.db, &models.NetEvent{}, ""); n != wantNet {
				t.Errorf("net_events = %d, want %d", n, wantNet)
			}
			if n := countRows(t, f.db, &models.NetEvent{}, "raw_id IS NULL"); n != 0 {
				t.Errorf("%d net_events row(s) without raw_id: every ingested row must link to its syslog_messages row", n)
			}
			// Every raw_id must be a real syslog_messages id.
			if n := countRows(t, f.db, &models.NetEvent{}, "raw_id NOT IN (SELECT id FROM syslog_messages)"); n != 0 {
				t.Errorf("%d net_events row(s) whose raw_id is not a syslog_messages id", n)
			}
			// Other classes: FG admin login (auth), FG config change
			// (config_change), UF CEF 201 (finding).
			if n := countRows(t, f.db, &models.SecEvent{}, ""); n != 3 {
				t.Errorf("sec_events = %d, want 3", n)
			}
			if n := countRows(t, f.db, &models.SecEvent{}, "class = ?", int16(normalize.ClassConfigChange)); n != 1 {
				t.Errorf("sec_events config_change = %d, want 1", n)
			}
			if n := countRows(t, f.db, &models.SecEvent{}, "class = ? AND device_id = ?", int16(normalize.ClassFinding), f.dev["unifi"].ID); n != 1 {
				t.Errorf("sec_events finding for the UniFi device = %d, want 1", n)
			}
			// Deny projection through deny.FromEvent: every network-class deny
			// with routable endpoints — FG local deny, PF block, UF drop, MK
			// deny, generic CEF deny (+ v5 split deny); the FG close is not.
			wantDenied := int64(5)
			if tc.schemaVersion < 6 {
				wantDenied++
			}
			if n := countRows(t, f.db, &models.DeniedEvent{}, ""); n != wantDenied {
				t.Errorf("denied_events = %d, want %d", n, wantDenied)
			}
			if n := countRows(t, f.db, &models.DeniedEvent{}, "device_id = ? AND src_addr = ?", f.dev["fortigate"].ID, "203.0.113.77"); n != 1 {
				t.Errorf("FortiGate local-in deny not projected (rows = %d)", n)
			}
			// Rule catalog: one row per (device, rule_key) named by the batch.
			for _, want := range []struct {
				vendor, ruleKey string
			}{
				{"fortigate", "u:4b5c6d7e-0000-0000-0000-00000000000c"},
				{"fortigate", "i:root/0"},
				{"pfsense", "u:1000000103"},
				{"unifi", "x:WAN_LOCAL/2147483647"},
				{"meraki", "n:all"},
				{"generic", "n:block-rdp"},
			} {
				if n := countRows(t, f.db, &models.FwRule{}, "device_id = ? AND rule_key = ?", f.dev[want.vendor].ID, want.ruleKey); n != 1 {
					t.Errorf("fw_rules (%s, %q) = %d, want 1", want.vendor, want.ruleKey, n)
				}
			}
			var fgRule models.FwRule
			if err := f.db.Gorm().Where("device_id = ? AND rule_key = ?", f.dev["fortigate"].ID, "u:4b5c6d7e-0000-0000-0000-00000000000c").First(&fgRule).Error; err == nil {
				if fgRule.RuleName == nil || *fgRule.RuleName != "LAN-to-WAN" {
					t.Errorf("fw_rules FortiGate rule_name = %v, want LAN-to-WAN", fgRule.RuleName)
				}
				if fgRule.Source != models.FwRuleSourceLog {
					t.Errorf("fw_rules source = %d, want log (%d)", fgRule.Source, models.FwRuleSourceLog)
				}
			} else {
				t.Errorf("load FortiGate fw_rules row: %v", err)
			}
			// Observed fields reach the table on flush, per (device, class).
			if n := countRows(t, f.db, &models.DeviceFieldObserved{}, ""); n != 0 {
				t.Errorf("device_field_observed = %d before the flush, want 0 (counters are buffered in memory)", n)
			}
			f.h.FlushFieldObserved()
			var fgSrc models.DeviceFieldObserved
			if err := f.db.Gorm().Where("device_id = ? AND class = ? AND field = ?", f.dev["fortigate"].ID, int16(normalize.ClassNetwork), "src_ip").First(&fgSrc).Error; err != nil {
				t.Errorf("device_field_observed (fortigate, network, src_ip): %v", err)
			} else if want := int64(wantNet - 4); fgSrc.Count != want {
				// FG network rows: close + local deny (+ v5 split).
				t.Errorf("observed src_ip count = %d, want %d", fgSrc.Count, want)
			}
			if n := countRows(t, f.db, &models.DeviceFieldObserved{}, "device_id = ? AND field = ?", f.dev["fortigate"].ID, "bytes_in"); n != 1 {
				t.Errorf("observed (fortigate, bytes_in) rows = %d, want 1 (FortiGate traffic carries rcvdbyte)", n)
			}
			if n := countRows(t, f.db, &models.DeviceFieldObserved{}, "device_id = ? AND field = ?", f.dev["meraki"].ID, "bytes_in"); n != 0 {
				t.Errorf("observed (meraki, bytes_in) rows = %d, want 0 (Meraki syslog carries no bytes)", n)
			}
			if n := countRows(t, f.db, &models.DeviceFieldObserved{}, "device_id = ? AND class = ? AND field = ?", f.dev["fortigate"].ID, int16(normalize.ClassConfigChange), "config_path"); n != 1 {
				t.Errorf("observed (fortigate, config_change, config_path) rows = %d, want 1", n)
			}
			// A second flush with nothing new writes nothing (and does not
			// double the counts).
			f.h.FlushFieldObserved()
			if err := f.db.Gorm().Where("id = ?", fgSrc.ID).First(&fgSrc).Error; err == nil && fgSrc.Count != wantNet-4 {
				t.Errorf("observed src_ip count after an empty flush = %d, want %d", fgSrc.Count, wantNet-4)
			}
			// The S-5 watermark is recorded once.
			if v, ok := f.db.GetSettingValue(normalizeIngestStartedSetting); !ok {
				t.Errorf("%s not recorded after the first normalized batch", normalizeIngestStartedSetting)
			} else if _, err := time.Parse(time.RFC3339, v); err != nil {
				t.Errorf("%s = %q is not RFC 3339: %v", normalizeIngestStartedSetting, v, err)
			}
		})
	}
}

// TestReceiveSyslog_IngestStartedSettingNeverOverwritten pins the watermark
// contract the S-5 backfill relies on: a second process (or a restart with a
// cold in-process flag) must not move normalize_ingest_started_at forward.
func TestReceiveSyslog_IngestStartedSettingNeverOverwritten(t *testing.T) {
	f := newNormalizeFixture(t, 6, nil)
	f.post(t, f.mixedBatch())
	first, ok := f.db.GetSettingValue(normalizeIngestStartedSetting)
	if !ok {
		t.Fatalf("%s not recorded", normalizeIngestStartedSetting)
	}
	// Simulate a restart: forget that the row exists, then ingest again.
	f.h.normalizeStarted.Store(false)
	time.Sleep(1100 * time.Millisecond) // RFC 3339 has second resolution
	f.post(t, f.mixedBatch())
	if again, _ := f.db.GetSettingValue(normalizeIngestStartedSetting); again != first {
		t.Errorf("%s moved from %q to %q; it must stay at the first normalized batch", normalizeIngestStartedSetting, first, again)
	}
}

// TestReceiveSyslog_NormalizeDisabled_LegacyPath pins the rollback-by-config
// contract: with NORMALIZE_ENABLED=false the raw rows and the legacy deny
// projection (FortiGate + filterlog only) are written exactly as before and
// nothing reaches the normalized tables.
func TestReceiveSyslog_NormalizeDisabled_LegacyPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Normalize.Disabled = true
	f := newNormalizeFixture(t, 6, cfg)
	batch := f.mixedBatch()
	f.post(t, batch)
	if n := countRows(t, f.db, &models.SyslogMessage{}, ""); int(n) != len(batch) {
		t.Fatalf("syslog_messages = %d, want %d", n, len(batch))
	}
	for _, m := range []interface{}{&models.NetEvent{}, &models.SecEvent{}, &models.FwRule{}} {
		if n := countRows(t, f.db, m, ""); n != 0 {
			t.Errorf("%T rows = %d with normalization disabled, want 0", m, n)
		}
	}
	f.h.FlushFieldObserved()
	if n := countRows(t, f.db, &models.DeviceFieldObserved{}, ""); n != 0 {
		t.Errorf("device_field_observed rows = %d with normalization disabled, want 0", n)
	}
	// Legacy deny.ProjectVendor: the FortiGate local deny and the pf block,
	// not the UniFi / Meraki / generic denies.
	if n := countRows(t, f.db, &models.DeniedEvent{}, ""); n != 2 {
		t.Errorf("denied_events (legacy path) = %d, want 2", n)
	}
	if _, ok := f.db.GetSettingValue(normalizeIngestStartedSetting); ok {
		t.Errorf("%s must not be recorded while normalization is disabled", normalizeIngestStartedSetting)
	}
}

// countingMapper is a normalize.Mapper stub that counts Map calls, so a test
// can prove how many times a message was parsed.
type countingMapper struct{ calls *atomic.Int64 }

func (countingMapper) Vendor() string               { return "counting-test" }
func (countingMapper) Families() []normalize.Family { return []normalize.Family{normalize.FamilyKV} }
func (m countingMapper) Map(tok normalize.Tokens, _ *models.SyslogMessage, ev *normalize.Event) normalize.Outcome {
	m.calls.Add(1)
	ev.Class = normalize.ClassNetwork
	ev.Activity = normalize.ActivityTraffic
	ev.Action = normalize.ActionDeny
	ev.SrcIP = net.ParseIP(tok.KV["src"])
	ev.DstIP = net.ParseIP(tok.KV["dst"])
	ev.RuleKey = "n:" + tok.KV["rule"]
	return normalize.Outcome{Kind: normalize.OutcomeOK}
}

// TestIngest_OneParsePerMessage: with a rule loaded (so the rule engine
// evaluates every message), the deny projection active and the normalized
// tables written, each message is parsed exactly once. The pre-S-4 ingest
// also parsed once here (its deny projection does not know this vendor), so
// the parse-count half of this test guards the tempting variant — the rule
// engine re-parsing a message the storage path already normalized — while
// the row assertions fail on the pre-S-4 code (no rows).
func TestIngest_OneParsePerMessage(t *testing.T) {
	var calls atomic.Int64
	normalize.Register(countingMapper{calls: &calls})

	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	h := NewHandler(cfg, nil, db)
	am := alerts.NewAlertManager(cfg, notifier.NewNotifier(cfg), db)
	h.SetAlertManager(am)
	probe, dev := setupProbeAndDevice(t, db)
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", dev.ID).Update("vendor", "counting-test").Error; err != nil {
		t.Fatal(err)
	}
	r := models.EventRule{Name: "any", Enabled: true, Source: "syslog", Action: "suppress",
		MatchJSON: `{"op":"exists","field":"message"}`}
	if err := db.CreateEventRule(&r); err != nil {
		t.Fatal(err)
	}
	am.RefreshEventRules(db)

	const n = 7
	batch := make([]map[string]interface{}, 0, n)
	for i := 0; i < n; i++ {
		batch = append(batch, map[string]interface{}{
			"device_id": dev.ID, "timestamp": time.Now().UTC(), "severity": 5, "facility": 20,
			"hostname": "fw-example-01", "format": "rfc3164",
			"message": "src=203.0.113.9 dst=198.51.100.10 rule=r1 verdict=deny",
		})
	}
	w := doTestRequest(t, h.ReceiveSyslogMessages, "POST", "/syslog", probe.ID, probe.RegistrationKey, batch)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if got := calls.Load(); got != n {
		t.Errorf("mapper calls = %d for %d messages, want exactly %d (one parse per message)", got, n, n)
	}
	if rows := countRows(t, db, &models.NetEvent{}, ""); rows != n {
		t.Errorf("net_events = %d, want %d", rows, n)
	}
	if rows := countRows(t, db, &models.DeniedEvent{}, ""); rows != n {
		t.Errorf("denied_events = %d, want %d (deny.FromEvent over the same events)", rows, n)
	}
	if rows := countRows(t, db, &models.FwRule{}, "device_id = ? AND rule_key = ?", dev.ID, "n:r1"); rows != 1 {
		t.Errorf("fw_rules (dev, n:r1) = %d, want 1 (deduped per batch)", rows)
	}
}

// TestRecentKeys_TTLAndBound: a key is recent only after mark and only inside
// the window, a repeat inside the window does not extend it, and the set
// never exceeds max keys.
func TestRecentKeys_TTLAndBound(t *testing.T) {
	l := recentKeys[fwRuleKey]{ttl: fwRuleSeenTTL, max: fwRuleSeenMax}
	now := time.Unix(1_759_579_200, 0)
	k := fwRuleKey{dev: 1, rk: "u:a"}
	if l.recent(k, now) {
		t.Fatal("an unmarked key must not be recent")
	}
	l.mark(k, now)
	if !l.recent(k, now.Add(fwRuleSeenTTL-time.Second)) {
		t.Error("a marked key inside the window must be recent")
	}
	if l.recent(k, now.Add(fwRuleSeenTTL+time.Second)) {
		t.Error("a marked key past the window must not be recent (recent() must not extend it)")
	}
	for i := 0; i < fwRuleSeenMax+100; i++ {
		l.mark(fwRuleKey{dev: 2, rk: string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))}, now)
	}
	if got := l.size(); got > fwRuleSeenMax {
		t.Errorf("window holds %d keys, cap is %d", got, fwRuleSeenMax)
	}
}

// failingStore wraps the real test store and fails selected writes a given
// number of times, to prove the retry contracts of the ingest.
type failingStore struct {
	database.Store
	failInsertSetting int
	failUpsertRules   int
	dropFirstID       bool
	insertCalls       int
}

func (f *failingStore) WithContextStore(context.Context) database.Store { return f }

func (f *failingStore) InsertSettingIfAbsent(s *models.SystemSetting) (bool, error) {
	f.insertCalls++
	if f.failInsertSetting > 0 {
		f.failInsertSetting--
		return false, errors.New("injected: settings unavailable")
	}
	return f.Store.InsertSettingIfAbsent(s)
}

func (f *failingStore) UpsertFwRules(rules []models.FwRule) error {
	if f.failUpsertRules > 0 {
		f.failUpsertRules--
		return errors.New("injected: fw_rules unavailable")
	}
	return f.Store.UpsertFwRules(rules)
}

// SaveSyslogMessages saves normally, then forgets the first row's id — what
// the per-row fallback leaves behind for a row it could not salvage.
func (f *failingStore) SaveSyslogMessages(msgs []models.SyslogMessage) error {
	err := f.Store.SaveSyslogMessages(msgs)
	if f.dropFirstID && len(msgs) > 0 {
		msgs[0].ID = 0
	}
	return err
}

// TestIngest_WatermarkInsertOnly: a failed insert leaves the in-process flag
// clear so the next batch retries; once recorded, later inserts are no-ops
// and the stored value never changes — even when the flag is cleared (a
// restart) and the setting read path is not consulted at all.
func TestIngest_WatermarkInsertOnly(t *testing.T) {
	f := newNormalizeFixture(t, 6, nil)
	fs := &failingStore{Store: f.h.db, failInsertSetting: 1}
	f.h.db = fs
	f.post(t, f.mixedBatch())
	if f.h.normalizeStarted.Load() {
		t.Fatal("flag set although the insert failed")
	}
	if _, ok := f.db.GetSettingValue(normalizeIngestStartedSetting); ok {
		t.Fatal("setting recorded although the insert failed")
	}
	f.post(t, f.mixedBatch())
	first, ok := f.db.GetSettingValue(normalizeIngestStartedSetting)
	if !ok || !f.h.normalizeStarted.Load() {
		t.Fatalf("setting not recorded on the retry (ok=%v flag=%v)", ok, f.h.normalizeStarted.Load())
	}
	// Restart: flag cold, insert attempted again, value must not move.
	f.h.normalizeStarted.Store(false)
	time.Sleep(1100 * time.Millisecond) // RFC 3339 second resolution
	calls := fs.insertCalls
	f.post(t, f.mixedBatch())
	if fs.insertCalls != calls+1 {
		t.Errorf("insert attempts = %d, want %d (one retry after the cold flag)", fs.insertCalls, calls+1)
	}
	if again, _ := f.db.GetSettingValue(normalizeIngestStartedSetting); again != first {
		t.Errorf("%s moved from %q to %q; ON CONFLICT DO NOTHING must keep the first", normalizeIngestStartedSetting, first, again)
	}
	if !f.h.normalizeStarted.Load() {
		t.Error("flag not set after the no-op insert found the row")
	}
	// Direct check of the store contract.
	inserted, err := f.db.InsertSettingIfAbsent(&models.SystemSetting{Key: normalizeIngestStartedSetting, Value: "later"})
	if err != nil || inserted {
		t.Errorf("InsertSettingIfAbsent on an existing key = (%v, %v), want (false, nil)", inserted, err)
	}
}

// TestIngest_FwRulesMarkedAfterSuccess: a failed fw_rules upsert leaves the
// keys unmarked, so the next batch retries them; after a success the same
// keys are not upserted again inside the window.
func TestIngest_FwRulesMarkedAfterSuccess(t *testing.T) {
	f := newNormalizeFixture(t, 6, nil)
	fs := &failingStore{Store: f.h.db, failUpsertRules: 1}
	f.h.db = fs
	f.post(t, f.mixedBatch())
	if n := countRows(t, f.db, &models.FwRule{}, ""); n != 0 {
		t.Fatalf("fw_rules = %d after the injected failure, want 0", n)
	}
	if f.h.fwRuleSeen.size() != 0 {
		t.Fatalf("%d keys marked seen although the upsert failed", f.h.fwRuleSeen.size())
	}
	f.post(t, f.mixedBatch())
	// Seven rules: the six network-class ones plus the UniFi CEF 201 policy.
	if n := countRows(t, f.db, &models.FwRule{}, ""); n != 7 {
		t.Errorf("fw_rules = %d after the retry, want 7", n)
	}
	if f.h.fwRuleSeen.size() != 7 {
		t.Errorf("keys marked seen = %d, want 7", f.h.fwRuleSeen.size())
	}
}

// TestIngest_UnsavedRawRowStoredNowhere: a row whose raw save left no id
// (per-row fallback dropped it) produces no net_events / denied_events /
// fw_rules / observed rows — a typed row without raw_id would be
// unreconcilable for the backfill.
func TestIngest_UnsavedRawRowStoredNowhere(t *testing.T) {
	f := newNormalizeFixture(t, 6, nil)
	f.h.db = &failingStore{Store: f.h.db, dropFirstID: true}
	batch := []map[string]interface{}{
		f.msg("fortigate", "traffic", "fortios_kv", fgLocalDeny), // id dropped
		f.msg("fortigate", "traffic", "fortios_kv", fgClose),
	}
	f.post(t, batch)
	if n := countRows(t, f.db, &models.NetEvent{}, ""); n != 1 {
		t.Errorf("net_events = %d, want 1 (the unsaved row must not be stored)", n)
	}
	if n := countRows(t, f.db, &models.DeniedEvent{}, ""); n != 0 {
		t.Errorf("denied_events = %d, want 0 (the deny was the unsaved row)", n)
	}
	if n := countRows(t, f.db, &models.FwRule{}, "rule_key = ?", "i:root/0"); n != 0 {
		t.Errorf("fw_rules for the unsaved row = %d, want 0", n)
	}
	f.h.FlushFieldObserved()
	var obs models.DeviceFieldObserved
	if err := f.db.Gorm().Where("device_id = ? AND field = ?", f.dev["fortigate"].ID, "src_ip").First(&obs).Error; err != nil || obs.Count != 1 {
		t.Errorf("observed src_ip count = %d (%v), want 1", obs.Count, err)
	}
}

// TestIngest_NetfilterDenyCollapsed: five identical UniFi netfilter drops
// within two seconds (one blocked TCP connect's SYN retries) project ONE
// denied_events row while every packet keeps its net_events row; a different
// tuple and the same tuple after the window each project again. pf filterlog
// (also per packet) is not collapsed — parity with the previous projection.
func TestIngest_NetfilterDenyCollapsed(t *testing.T) {
	f := newNormalizeFixture(t, 6, nil)
	// In the past so clampIngestTimestamp leaves the spacing alone (a future
	// timestamp is clamped to the server's now).
	t0 := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	at := func(m map[string]interface{}, ts time.Time) map[string]interface{} { m["timestamp"] = ts; return m }
	other := strings.Replace(ufNetfilter, "SPT=51514", "SPT=51515", 1)
	batch := []map[string]interface{}{
		at(f.msg("unifi", "kernel", "rfc3164", ufNetfilter), t0),
		at(f.msg("unifi", "kernel", "rfc3164", ufNetfilter), t0.Add(300*time.Millisecond)),
		at(f.msg("unifi", "kernel", "rfc3164", ufNetfilter), t0.Add(900*time.Millisecond)),
		at(f.msg("unifi", "kernel", "rfc3164", ufNetfilter), t0.Add(1500*time.Millisecond)),
		at(f.msg("unifi", "kernel", "rfc3164", ufNetfilter), t0.Add(1900*time.Millisecond)),
		at(f.msg("unifi", "kernel", "rfc3164", other), t0.Add(time.Second)),                 // different source port
		at(f.msg("unifi", "kernel", "rfc3164", ufNetfilter), t0.Add(2500*time.Millisecond)), // past the window
		at(f.msg("pfsense", "filterlog", "rfc3164", pfBlock), t0),
		at(f.msg("pfsense", "filterlog", "rfc3164", pfBlock), t0.Add(500*time.Millisecond)),
	}
	f.post(t, batch)
	if n := countRows(t, f.db, &models.NetEvent{}, ""); int(n) != len(batch) {
		t.Errorf("net_events = %d, want %d (storage keeps every packet)", n, len(batch))
	}
	if n := countRows(t, f.db, &models.DeniedEvent{}, "device_id = ?", f.dev["unifi"].ID); n != 3 {
		t.Errorf("UniFi denied_events = %d, want 3 (first of the burst, the other tuple, the one past the window)", n)
	}
	if n := countRows(t, f.db, &models.DeniedEvent{}, "device_id = ?", f.dev["pfsense"].ID); n != 2 {
		t.Errorf("pf denied_events = %d, want 2 (filterlog is not collapsed)", n)
	}
	var row models.DeniedEvent
	if err := f.db.Gorm().Where("device_id = ?", f.dev["unifi"].ID).First(&row).Error; err == nil && row.SrcIntfRole != models.IntfRoleWAN {
		t.Errorf("UniFi WAN_LOCAL deny src_intf_role = %d, want wan (%d) so deny_storm counts it", row.SrcIntfRole, models.IntfRoleWAN)
	}
}

// TestRunObservedFlusher_FlushesOnCancelThenFinal: the loop flushes what it
// holds when its context is cancelled and returns; what a draining request
// records after that reaches the table through the caller's final flush.
func TestRunObservedFlusher_FlushesOnCancelThenFinal(t *testing.T) {
	f := newNormalizeFixture(t, 6, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.h.RunObservedFlusher(ctx) }()
	f.post(t, f.mixedBatch())
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunObservedFlusher did not return after cancel")
	}
	if n := countRows(t, f.db, &models.DeviceFieldObserved{}, ""); n == 0 {
		t.Fatal("no observed rows flushed on cancel")
	}
	// A request that drained after the loop exited.
	f.post(t, f.mixedBatch())
	var before, after models.DeviceFieldObserved
	q := f.db.Gorm().Where("device_id = ? AND class = ? AND field = ?", f.dev["fortigate"].ID, int16(normalize.ClassNetwork), "src_ip")
	q.First(&before)
	f.h.FlushFieldObserved() // what main does after server.Shutdown
	q.First(&after)
	if after.Count != before.Count*2 {
		t.Errorf("observed src_ip count after the final flush = %d, want %d (post-cancel records must reach the table)", after.Count, before.Count*2)
	}
}

// TestObservedBuffer_CapAndDrain: the buffer counts per (device, class),
// refuses new pairs past observedMaxKeys, and drain empties it.
func TestObservedBuffer_CapAndDrain(t *testing.T) {
	var b observedBuffer
	now := time.Now()
	ev := normalize.Event{Action: normalize.ActionDeny, SrcIP: net.ParseIP("203.0.113.9")}
	p := ev.Present()
	for i := 0; i < observedMaxKeys+50; i++ {
		b.record(uint(i+1), normalize.ClassNetwork, p, now)
	}
	b.record(1, normalize.ClassNetwork, p, now) // existing pair keeps counting
	b.mu.Lock()
	pairs := len(b.m)
	b.mu.Unlock()
	if pairs != observedMaxKeys {
		t.Errorf("buffer holds %d pairs, want exactly the cap %d", pairs, observedMaxKeys)
	}
	rows := b.drain()
	byField := map[string]int64{}
	for _, r := range rows {
		if r.DeviceID == 1 {
			byField[r.Field] = r.Count
		}
	}
	if byField["action"] != 2 || byField["src_ip"] != 2 {
		t.Errorf("device 1 counts = %v, want action=2 src_ip=2", byField)
	}
	if byField["dst_ip"] != 0 {
		t.Errorf("dst_ip counted %d although the event had none", byField["dst_ip"])
	}
	if again := b.drain(); len(again) != 0 {
		t.Errorf("second drain returned %d rows, want 0", len(again))
	}
}
