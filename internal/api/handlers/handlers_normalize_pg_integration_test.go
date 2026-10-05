//go:build integration

package handlers

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
)

// TestNormalizeIngest_Postgres drives the S-4 ingest end to end on real
// PostgreSQL: handler → raw save → one parse per message → pgx COPY into the
// day-partitioned net_events (the production write path the SQLite lane
// cannot exercise), GORM insert into sec_events, the fw_rules upsert and the
// device_field_observed flush, then the capability API reading the observed
// half back. Skips unless TEST_PG_DSN is set.
func TestNormalizeIngest_Postgres(t *testing.T) {
	db := database.NewIntegrationDB(t)
	if err := db.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	h := NewHandler(&config.Config{}, nil, db)
	probe, fg := setupProbeAndDevice(t, db)
	if err := db.Gorm().Model(&models.Probe{}).Where("id = ?", probe.ID).Update("schema_version", 6).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", fg.ID).Update("vendor", "fortigate").Error; err != nil {
		t.Fatal(err)
	}
	pf := &models.Device{Name: "fw-example-03", IPAddress: "192.0.2.3", Vendor: "pfsense", ProbeID: &probe.ID}
	if err := db.Gorm().Create(pf).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mk := func(dev *models.Device, app, format, message string) map[string]interface{} {
		return map[string]interface{}{
			"device_id": dev.ID, "timestamp": now, "severity": 5, "facility": 20,
			"hostname": dev.Name, "app_name": app, "format": format, "message": message,
		}
	}
	// 996 FortiGate traffic rows (the COPY batch shape) + four other classes:
	// exactly the handler's 1000-row batch cap.
	batch := make([]map[string]interface{}, 0, 1000)
	for i := 0; i < 996; i++ {
		line := fgClose
		if i%2 == 1 {
			line = fgLocalDeny
		}
		batch = append(batch, mk(fg, "traffic", "fortios_kv", line))
	}
	batch = append(batch,
		mk(fg, "event", "fortios_kv", fgAdminLogin),
		mk(fg, "event", "fortios_kv", fgConfigEdit),
		mk(pf, "filterlog", "rfc3164", pfBlock),
		mk(pf, "sshd", "rfc3164", "Failed password for bob from 203.0.113.9 port 2222 ssh2"),
	)
	w := doTestRequest(t, h.ReceiveSyslogMessages, "POST", "/syslog", probe.ID, probe.RegistrationKey, batch)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}

	var n int64
	db.Gorm().Model(&models.SyslogMessage{}).Count(&n)
	if int(n) != len(batch) {
		t.Fatalf("syslog_messages = %d, want %d", n, len(batch))
	}
	db.Gorm().Model(&models.NetEvent{}).Count(&n)
	if n != 997 {
		t.Errorf("net_events = %d, want 997 (996 FortiGate traffic + 1 pf block)", n)
	}
	// Routed into today's DAY leaf, not the default child.
	leaf := fmt.Sprintf("net_events_%s", now.Format("20060102"))
	var inLeaf int64
	if err := db.Gorm().Raw(fmt.Sprintf("SELECT COUNT(*) FROM %s", leaf)).Scan(&inLeaf).Error; err != nil {
		t.Fatalf("count %s: %v", leaf, err)
	}
	if inLeaf != 997 {
		t.Errorf("%s holds %d rows, want 997", leaf, inLeaf)
	}
	var inDefault int64
	db.Gorm().Raw("SELECT COUNT(*) FROM net_events_default").Scan(&inDefault)
	if inDefault != 0 {
		t.Errorf("net_events_default holds %d rows, want 0", inDefault)
	}
	// Typed columns round-trip through COPY: inet, the deny action, raw_id.
	var denies int64
	db.Gorm().Raw("SELECT COUNT(*) FROM net_events WHERE action = ? AND src_ip = '203.0.113.77'::inet AND raw_id IS NOT NULL", int16(normalize.ActionDeny)).Scan(&denies)
	if denies != 498 {
		t.Errorf("FortiGate local-in deny rows by inet + action = %d, want 498", denies)
	}
	var linked int64
	db.Gorm().Raw("SELECT COUNT(*) FROM net_events e JOIN syslog_messages s ON s.id = e.raw_id").Scan(&linked)
	if linked != 997 {
		t.Errorf("net_events rows joined to their raw row = %d, want 997", linked)
	}
	// sec_events: admin login (auth), config change, sshd failure (auth).
	db.Gorm().Model(&models.SecEvent{}).Count(&n)
	if n != 3 {
		t.Errorf("sec_events = %d, want 3", n)
	}
	// fw_rules: the two FortiGate rules once each (LRU dedup across 1000 hits)
	// and the pf rule.
	db.Gorm().Model(&models.FwRule{}).Count(&n)
	if n != 3 {
		t.Errorf("fw_rules = %d, want 3", n)
	}
	db.Gorm().Model(&models.DeniedEvent{}).Count(&n)
	if n != 499 {
		t.Errorf("denied_events = %d, want 499", n)
	}
	// Observed counters land on flush and the capability API reads them.
	h.FlushFieldObserved()
	var obs models.DeviceFieldObserved
	if err := db.Gorm().Where("device_id = ? AND class = ? AND field = ?", fg.ID, int16(normalize.ClassNetwork), "bytes_in").First(&obs).Error; err != nil {
		t.Fatalf("observed (fortigate, network, bytes_in): %v", err)
	}
	if obs.Count != 996 {
		t.Errorf("observed bytes_in count = %d, want 996", obs.Count)
	}
	rows, err := db.GetFieldObserved(fg.ID, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int64{}
	for _, r := range rows {
		seen[r.Field] = r.Count
	}
	if seen["src_ip"] != 997 { // 996 traffic + the admin login's srcip (auth class, summed across classes)
		t.Errorf("GetFieldObserved src_ip = %d, want 997", seen["src_ip"])
	}
	// Repeating the same batch grows net_events but not fw_rules (LRU within
	// TTL) and the watermark stays put.
	first, _ := db.GetSettingValue(normalizeIngestStartedSetting)
	w = doTestRequest(t, h.ReceiveSyslogMessages, "POST", "/syslog", probe.ID, probe.RegistrationKey, batch)
	if w.Code != http.StatusOK {
		t.Fatalf("second batch status = %d: %s", w.Code, w.Body.String())
	}
	db.Gorm().Model(&models.NetEvent{}).Count(&n)
	if n != 1994 {
		t.Errorf("net_events after the second batch = %d, want 1994", n)
	}
	db.Gorm().Model(&models.FwRule{}).Count(&n)
	if n != 3 {
		t.Errorf("fw_rules after the second batch = %d, want 3", n)
	}
	if again, _ := db.GetSettingValue(normalizeIngestStartedSetting); again != first || first == "" {
		t.Errorf("%s = %q then %q; must be recorded once", normalizeIngestStartedSetting, first, again)
	}
}
