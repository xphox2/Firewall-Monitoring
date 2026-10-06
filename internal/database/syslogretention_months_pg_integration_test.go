//go:build integration

package database

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
)

// TestSyslogRetentionMonths_PartitionDrop_PG: RETENTION_SYSLOG_MONTHS=1 on the
// fresh-install shape (monthly leaves) with the archive gate on. A leaf is
// dropped only when its whole range is older than the month cutoff AND its
// max(id) is at or below V; the leaf the cutoff falls in is kept and trimmed
// by the row DELETE; severity 6 stays raw for the month. With months off and
// RETENTION_SYSLOG_CRITICAL_DAYS=0 (forever) the same old leaf is never
// dropped — the switch is what moves it.
func TestSyslogRetentionMonths_PartitionDrop_PG(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true}
	daysRet := config.RetentionConfig{DefaultDays: 30, SyslogCriticalDays: 0, SyslogInfoDays: 7, FlowDays: 30}
	monthsRet := daysRet
	monthsRet.SyslogMonths = 1

	now := time.Now().UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	// M-3 and M-2 end before every one-month cutoff; M-1 ends after it.
	m3 := gatePGMonthLeaf(t, d, "syslog_messages", month.AddDate(0, -3, 0))
	m2 := gatePGMonthLeaf(t, d, "syslog_messages", month.AddDate(0, -2, 0))
	m1 := gatePGMonthLeaf(t, d, "syslog_messages", month.AddDate(0, -1, 0))
	gatePGSeedSyslog(t, d, month.AddDate(0, -3, 0), now, 200000)
	for _, leaf := range []string{m3, m2, m1} {
		if gatePGCount(t, d, fmt.Sprintf("SELECT count(*) FROM %s", leaf)) == 0 {
			t.Fatalf("the fixture must put rows in %s", leaf)
		}
	}
	var maxID int64
	d.db.Raw("SELECT max(id) FROM syslog_messages").Scan(&maxID)

	// V = the last row of M-3.
	var v int64
	d.db.Raw(`SELECT max(id) FROM syslog_messages WHERE "timestamp" < ?`, month.AddDate(0, -2, 0)).Scan(&v)
	gatePGVerified(t, d, export.TableSyslog, v)
	above := gatePGCount(t, d, "SELECT count(*) FROM syslog_messages WHERE id > ?", v)

	// Months off, critical kept forever: M-3 is wholly verified and still
	// never dropped.
	if err := d.CleanupOldData(daysRet); err != nil {
		t.Fatal(err)
	}
	if leaves := gatePGLeaves(t, d, "syslog_messages"); !leaves[m3] {
		t.Fatalf("days mode with RETENTION_SYSLOG_CRITICAL_DAYS=0 dropped %s: %v", m3, leaves)
	}

	// Months on: M-3 is dropped, M-2 is expired but held (max(id) > V), M-1
	// holds the cutoff and is kept.
	if err := d.RunSyslogAggregationCycle(monthsRet); err != nil {
		t.Fatal(err)
	}
	if err := d.CleanupOldData(monthsRet); err != nil {
		t.Fatal(err)
	}
	leaves := gatePGLeaves(t, d, "syslog_messages")
	if leaves[m3] || !leaves[m2] || !leaves[m1] {
		t.Fatalf("leaves %v: want %s dropped (older than the month, max(id) <= V), %s held by the gate, %s kept (holds the cutoff)",
			leaves, m3, m2, m1)
	}
	if n := gatePGCount(t, d, "SELECT count(*) FROM syslog_messages WHERE id > ?", v); n != above {
		t.Fatalf("%d rows above V left, want all %d", n, above)
	}

	// The archive catches up: M-2 drops, every row (any severity) older than
	// the month cutoff is gone, and severity 6 inside the month stays raw
	// (the legacy 7-day window would have summarised it).
	gatePGVerified(t, d, export.TableSyslog, maxID)
	if err := d.RunSyslogAggregationCycle(monthsRet); err != nil {
		t.Fatal(err)
	}
	if err := d.CleanupOldData(monthsRet); err != nil {
		t.Fatal(err)
	}
	cutoff := monthsAgo(time.Now(), 1)
	if gatePGLeaves(t, d, "syslog_messages")[m2] {
		t.Fatalf("%s still attached after V passed it", m2)
	}
	if !gatePGLeaves(t, d, "syslog_messages")[m1] {
		t.Fatalf("%s dropped although the month cutoff %s falls inside it", m1, cutoff)
	}
	if n := gatePGCount(t, d, `SELECT count(*) FROM syslog_messages WHERE "timestamp" < ?`, cutoff.Add(-time.Minute)); n != 0 {
		t.Fatalf("%d rows older than the month cutoff %s left", n, cutoff)
	}
	if n := gatePGCount(t, d, `SELECT count(*) FROM syslog_messages WHERE severity = 6 AND "timestamp" BETWEEN ? AND ?`,
		cutoff.Add(time.Hour), now.AddDate(0, 0, -8)); n == 0 {
		t.Fatal("severity 6 inside the month was consumed: months must keep it raw for the month")
	}
}
