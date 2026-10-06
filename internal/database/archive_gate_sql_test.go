package database

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// archiveGateDisabledGolden is every statement the rollup tick and the daily
// retention pass send to syslog_messages, flow_samples and flow_if_counters
// (sorted), captured from the code BEFORE the retention gate existed
// (0.11.303) on the fixture below. With archiving disabled the gate must send
// exactly these — no added predicate, no read of the archive's tables or of
// the override setting — whatever the archive manifest holds. Regenerate only
// from pre-gate code: ARCHIVE_GATE_GOLDEN_PRINT=1 prints the capture.
var archiveGateDisabledGolden = []string{
	"DELETE FROM `flow_if_counters` WHERE id IN (SELECT `id` FROM `flow_if_counters` WHERE timestamp < ? LIMIT 10000)",
	"DELETE FROM `flow_samples` WHERE id IN (SELECT `id` FROM `flow_samples` WHERE timestamp < ? ORDER BY timestamp LIMIT 10000)",
	"DELETE FROM `flow_samples` WHERE timestamp >= ? AND timestamp < ? AND id <= ?",
	"DELETE FROM `syslog_messages` WHERE id IN (SELECT `id` FROM `syslog_messages` WHERE timestamp < ? AND severity IN (?,?) ORDER BY timestamp LIMIT 10000)",
	"DELETE FROM `syslog_messages` WHERE id IN (SELECT `id` FROM `syslog_messages` WHERE timestamp < ? AND severity IN (?,?,?,?,?,?) ORDER BY timestamp LIMIT 10000)",
	"DELETE FROM `syslog_messages` WHERE timestamp >= ? AND timestamp < ? AND severity = ? AND id <= ?",
	"SELECT COALESCE(MAX(id), 0) FROM `flow_samples`",
	"SELECT COALESCE(MAX(id), 0) FROM `syslog_messages`",
	"SELECT COALESCE(MAX(id), 0) FROM `syslog_messages`",
	"SELECT MIN(timestamp) FROM `flow_samples` WHERE timestamp < ? AND id <= ?",
	"SELECT MIN(timestamp) FROM `flow_samples` WHERE timestamp >= ? AND timestamp < ? AND id <= ?",
	"SELECT MIN(timestamp) FROM `syslog_messages` WHERE severity = ? AND timestamp < ? AND id <= ?",
	"SELECT MIN(timestamp) FROM `syslog_messages` WHERE severity = ? AND timestamp < ? AND id <= ?",
	"SELECT MIN(timestamp) FROM `syslog_messages` WHERE severity = ? AND timestamp >= ? AND timestamp < ? AND id <= ?",
	"SELECT `id` FROM `flow_if_counters` WHERE timestamp < ? LIMIT 10000",
	"SELECT `id` FROM `flow_samples` WHERE timestamp < ? ORDER BY timestamp LIMIT 10000",
	"SELECT `id` FROM `syslog_messages` WHERE timestamp < ? AND severity IN (?,?) ORDER BY timestamp LIMIT 10000",
	"SELECT `id` FROM `syslog_messages` WHERE timestamp < ? AND severity IN (?,?,?,?,?,?) ORDER BY timestamp LIMIT 10000",
	"SELECT strftime('%Y-%m-%d %H:%M', (CAST(strftime('%s', timestamp) AS INTEGER) / 300) * 300, 'unixepoch') as bucket, device_id, src_addr, dst_addr, dst_port, protocol, app_category, direction, service_port, class_rev, scope_local, dst_country, dst_asn, flow_source, firewall_event, SUM(bytes) as bytes_sum, SUM(packets) as packets_sum, COUNT(*) as flow_count, AVG(sampling_rate) as sampling_rate_avg FROM `flow_samples` WHERE timestamp >= ? AND timestamp < ? AND id <= ? GROUP BY bucket, device_id, src_addr, dst_addr, dst_port, protocol, app_category, direction, service_port, class_rev, scope_local, dst_country, dst_asn, flow_source, firewall_event",
	"SELECT strftime('%Y-%m-%d %H:00', timestamp) as bucket, device_id, severity, facility, app_name, COUNT(*) as count, MIN(message) as sample_message FROM `syslog_messages` WHERE timestamp >= ? AND timestamp < ? AND severity = ? AND id <= ? GROUP BY bucket, device_id, severity, facility, app_name",
}

// TestArchiveGate_DisabledSQLUnchanged: with archiving disabled (the default)
// the delete paths are byte-identical to the pre-gate code even when the
// archive manifest holds chunks that would hold every row and an override
// row exists. A guard, not a regression test: it passes against the pre-gate
// code by construction (that is where its golden comes from).
func TestArchiveGate_DisabledSQLUnchanged(t *testing.T) {
	d := NewDatabaseForTesting(t)
	// Ten minutes past a UTC hour, so no row pair straddles an aggregation
	// window and the statement count does not depend on the clock.
	old := time.Now().Add(-40 * 24 * time.Hour).Truncate(time.Hour).Add(10 * time.Minute)
	recent := time.Now().Add(-3 * time.Hour).Truncate(time.Hour).Add(10 * time.Minute)
	for i := 1; i <= 6; i++ {
		sev := 3
		if i%2 == 0 {
			sev = 6
		}
		if err := d.db.Create(&models.SyslogMessage{Timestamp: old.Add(time.Duration(i) * time.Second), DeviceID: 1, ProbeID: 1,
			Hostname: "fw-example-01", AppName: "traffic", Message: "srcip=192.0.2.10", Severity: sev}).Error; err != nil {
			t.Fatal(err)
		}
		if err := d.db.Create(&models.FlowSample{Timestamp: recent.Add(time.Duration(i) * time.Second), DeviceID: 1, ProbeID: 1,
			SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7", DstPort: 443, Protocol: 6, Bytes: 1500, Packets: 1, SamplingRate: 1}).Error; err != nil {
			t.Fatal(err)
		}
		if err := d.db.Create(&models.FlowInterfaceCounter{Timestamp: old.Add(time.Duration(i) * time.Second), DeviceID: 1, ProbeID: 1,
			SamplerAddress: "192.0.2.1", IfIndex: uint32(i)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	day := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for _, tb := range []string{export.TableSyslog, export.TableFlows, export.TableCounters} {
		if err := d.db.Create(&models.ArchiveChunk{SourceTable: tb, Seq: 1, IDLo: 0, IDHi: 1, PeriodStart: day, PeriodEnd: day.Add(time.Hour),
			Month: "2026-08", Status: models.ArchiveChunkNeedsAttention}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := d.db.Create(&models.SystemSetting{Key: "archive_gate_override_until_syslog", Value: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}).Error; err != nil {
		t.Fatal(err)
	}

	var stmts []string
	recording := true
	capture := func(tx *gorm.DB) {
		if !recording {
			return
		}
		s := tx.Statement.SQL.String()
		for _, w := range []string{"syslog_messages", "flow_samples", "flow_if_counters", "archive_"} {
			if strings.Contains(s, w) {
				stmts = append(stmts, s)
				return
			}
		}
	}
	cb := d.db.Callback()
	for name, err := range map[string]error{
		"q": cb.Query().After("gorm:query").Register("test:gate_q", capture),
		"r": cb.Row().After("gorm:row").Register("test:gate_r", capture),
		"d": cb.Delete().After("gorm:delete").Register("test:gate_d", capture),
		"x": cb.Raw().After("gorm:raw").Register("test:gate_x", capture),
		"u": cb.Update().After("gorm:update").Register("test:gate_u", capture),
	} {
		if err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	ret := config.RetentionConfig{DefaultDays: 30, SyslogCriticalDays: 30, SyslogInfoDays: 7, FlowDays: 30}
	d.RunFlowRollupCycle()
	if err := d.RunSyslogAggregationCycle(ret); err != nil {
		t.Fatal(err)
	}
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatal(err)
	}
	recording = false // not the test's own counts below
	sort.Strings(stmts)
	if os.Getenv("ARCHIVE_GATE_GOLDEN_PRINT") != "" {
		for _, s := range stmts {
			t.Logf("GOLDEN %q,", s)
		}
	}
	for _, tb := range []string{"syslog_messages", "flow_samples", "flow_if_counters"} {
		var n int64
		d.db.Table(tb).Count(&n)
		if n != 0 {
			t.Errorf("%s: %d rows left; disabled archiving must not hold anything", tb, n)
		}
	}
	if len(stmts) != len(archiveGateDisabledGolden) {
		t.Fatalf("%d statements on the raw tables, want %d:\n%s", len(stmts), len(archiveGateDisabledGolden), strings.Join(stmts, "\n"))
	}
	for i := range stmts {
		if stmts[i] != archiveGateDisabledGolden[i] {
			t.Errorf("statement %d:\n got %s\nwant %s", i, stmts[i], archiveGateDisabledGolden[i])
		}
	}
}
