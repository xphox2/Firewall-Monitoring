package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"

	"github.com/gin-gonic/gin"
)

// fortiGateBenchLines are the two dominant FortiOS traffic shapes (a forward
// close with the full identity / app / byte set, and a local-in deny) a
// `logtraffic all` stream is made of. Synthetic (RFC 5737, fw-example-01).
var fortiGateBenchLines = []string{
	`date=2026-10-04 time=12:00:01 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1759579201000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.10 srcport=51514 srcintf="port2" srcintfrole="lan" dstip=203.0.113.20 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Netherlands" sessionid=2101301 proto=6 action="close" policyid=12 policytype="policy" poluuid="4b5c6d7e-0000-0000-0000-00000000000c" policyname="LAN-to-WAN" service="HTTPS" trandisp="snat" transip=203.0.113.2 transport=51514 appid=40568 app="HTTPS.BROWSER" appcat="Web.Client" apprisk="medium" applist="default" duration=61 sentbyte=5231 rcvdbyte=12033 sentpkt=22 rcvdpkt=19 srchwvendor="Example" devtype="Computer" osname="Linux" srcmac="00:00:5e:00:53:0a" srcname="alice-laptop" user="alice" group="staff"`,
	`date=2026-10-04 time=12:00:03 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1759579203000000000 tz="+0000" logid="0001000014" type="traffic" subtype="local" level="notice" vd="root" srcip=203.0.113.77 srcport=52000 srcintf="wan1" srcintfrole="wan" dstip=203.0.113.1 dstport=22 dstintf="unknown0" dstintfrole="undefined" srccountry="United States" dstcountry="Reserved" sessionid=2101303 proto=6 action="deny" policyid=0 policytype="local-in-policy" service="SSH" app="SSH" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0`,
}

// benchSyslogBatch is one 1000-row FortiGate syslog batch body as a 1.3.48+
// collector ships it (format hint on every row).
func benchSyslogBatch(deviceID uint, n int) []byte {
	now := time.Now().UTC()
	msgs := make([]map[string]interface{}, n)
	for i := range msgs {
		msgs[i] = map[string]interface{}{
			"device_id": deviceID,
			"timestamp": now.Add(time.Duration(i) * time.Millisecond),
			"severity":  5,
			"facility":  20,
			"hostname":  "fw-example-01",
			"app_name":  "traffic",
			"format":    "fortios_kv",
			"message":   fortiGateBenchLines[i%len(fortiGateBenchLines)],
		}
	}
	body, err := json.Marshal(msgs)
	if err != nil {
		panic(err)
	}
	return body
}

// benchHandler builds a handler over the SQLite test backend with a FortiGate
// device, a probe at the given schema version and (withRule) one enabled
// syslog rule so the rule engine evaluates every message instead of taking
// its empty-chain fast path.
func benchHandler(b *testing.B, schemaVersion int, withRule bool) (*Handler, *models.Probe, *models.Device) {
	b.Helper()
	db := database.NewDatabaseForTesting(b)
	cfg := &config.Config{}
	h := NewHandler(cfg, nil, db)
	am := alerts.NewAlertManager(cfg, notifier.NewNotifier(cfg), db)
	h.SetAlertManager(am)

	site := &models.Site{Name: "bench-site"}
	if err := db.Gorm().Create(site).Error; err != nil {
		b.Fatalf("create site: %v", err)
	}
	const key = "bench-key-abc123"
	probe := &models.Probe{Name: "bench-probe", SiteID: site.ID, RegistrationKey: database.HashProbeKey(key),
		ApprovalStatus: "approved", Status: "online", SchemaVersion: schemaVersion}
	if err := db.Gorm().Create(probe).Error; err != nil {
		b.Fatalf("create probe: %v", err)
	}
	probe.RegistrationKey = key
	dev := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate", ProbeID: &probe.ID}
	if err := db.Gorm().Create(dev).Error; err != nil {
		b.Fatalf("create device: %v", err)
	}
	if withRule {
		r := models.EventRule{Name: "bench", Enabled: true, Source: "syslog", Action: "suppress",
			MatchJSON: `{"op":"eq","field":"subtype","value":"vpn"}`}
		if err := db.CreateEventRule(&r); err != nil {
			b.Fatalf("create rule: %v", err)
		}
		am.RefreshEventRules(db)
	}
	return h, probe, dev
}

// benchNoDBStore keeps the handler's reads on the real test database but
// turns the batch WRITES into no-ops (the raw save still assigns IDs as GORM
// would), so the `nodb` variants measure the handler's own CPU — decode,
// normalization, rule engine, deny projection, row mapping — rather than the
// SQLite driver's bind loop, which dominates the full variants and is not
// the production write path (PostgreSQL COPY).
type benchNoDBStore struct{ database.Store }

func (s benchNoDBStore) WithContextStore(context.Context) database.Store { return s }
func (s benchNoDBStore) SaveSyslogMessages(msgs []models.SyslogMessage) error {
	for i := range msgs {
		msgs[i].ID = uint(i + 1)
	}
	return nil
}
func (benchNoDBStore) SaveDeniedEvents([]models.DeniedEvent) error { return nil }
func (benchNoDBStore) SaveNetEvents([]models.NetEvent) error       { return nil }
func (benchNoDBStore) SaveSecEvents([]models.SecEvent) error       { return nil }
func (benchNoDBStore) UpsertFwRules([]models.FwRule) error         { return nil }

// BenchmarkReceiveSyslogBatch drives one 1000-row FortiGate batch through
// ReceiveSyslogMessages per iteration: probe auth, JSON decode, the raw
// syslog save, the rule engine (one rule loaded) and whatever the ingest
// derives from the batch. The full variants run on the SQLite backend, whose
// driver's parameter binding bounds the absolute numbers; the `nodb`
// variants stub the writes and isolate the handler's CPU. The before/after
// comparison for the S-4 wiring (one parse per message feeding the rule
// engine, the deny projection and the normalized tables) is what the
// benchmark exists for.
func BenchmarkReceiveSyslogBatch(b *testing.B) {
	for _, tc := range []struct {
		name          string
		schemaVersion int
		withRule      bool
		noDB          bool
	}{
		{"v6_rule", 6, true, false},
		{"v5_rule", 5, true, false},
		{"v6_norule", 6, false, false},
		{"v6_rule_nodb", 6, true, true},
		{"v5_rule_nodb", 5, true, true},
		{"v6_norule_nodb", 6, false, true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			h, probe, dev := benchHandler(b, tc.schemaVersion, tc.withRule)
			if tc.noDB {
				h.db = benchNoDBStore{Store: h.db}
			}
			body := benchSyslogBatch(dev.ID, 1000)
			router := gin.New()
			router.POST("/probes/:id/syslog", h.ReceiveSyslogMessages)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/probes/%d/syslog", probe.ID), bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+probe.RegistrationKey)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					b.Fatalf("status = %d: %s", w.Code, w.Body.String())
				}
			}
		})
	}
}
