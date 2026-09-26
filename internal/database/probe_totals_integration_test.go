//go:build integration

// ProbeTelemetryTotals answers large tables from pg_stats, per partition leaf.
// Only real Postgres has those statistics — on SQLite the function always
// takes the exact path — so this lane is the only proof of the estimate path,
// of reading leaves rather than the partitioned parent, and of the exact
// fallback for a probe that is a most-common value nowhere.
package database

import (
	"math"
	"testing"

	"firewall-mon/internal/models"
)

func TestProbeTotalsIntegration_EstimatesPerLeaf(t *testing.T) {
	d := NewIntegrationDB(t)
	if !pgIsPartitioned(t, d, "syslog_messages") {
		t.Skip("syslog_messages is not partitioned on this schema")
	}
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	site := models.Site{Name: "s"}
	if err := d.db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	var ids []uint
	for _, n := range []string{"big", "old", "tiny"} {
		p := models.Probe{Name: n, SiteID: site.ID, RegistrationKey: n, ApprovalStatus: "approved"}
		if err := d.db.Create(&p).Error; err != nil {
			t.Fatal(err)
		}
		ids = append(ids, p.ID)
	}
	big, old, tiny := ids[0], ids[1], ids[2]

	// big: 1.2M rows this month. old: 150k rows in a far-past month, which
	// lands in the default partition — a second leaf. tiny: 3 rows among the
	// 1.2M, too rare to be a most-common value in any leaf.
	for _, q := range []struct {
		sql  string
		args []interface{}
	}{
		{`INSERT INTO syslog_messages (timestamp, severity, probe_id, message)
		  SELECT now() - (g % 1000) * interval '1 second', 5, ?, 'm' FROM generate_series(1, 1200000) g`, []interface{}{big}},
		{`INSERT INTO syslog_messages (timestamp, severity, probe_id, message)
		  SELECT timestamp '2001-01-15', 5, ?, 'm' FROM generate_series(1, 150000) g`, []interface{}{old}},
		{`INSERT INTO syslog_messages (timestamp, severity, probe_id, message)
		  SELECT now(), 5, ?, 'm' FROM generate_series(1, 3) g`, []interface{}{tiny}},
	} {
		if err := d.db.Exec(q.sql, q.args...).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Analyze the LEAVES only, the way autovacuum does. The parent keeps no
	// statistics, so a reader of the parent's pg_stats would find nothing.
	var leaves []string
	if err := d.db.Raw(`SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'syslog_messages'::regclass`).Scan(&leaves).Error; err != nil {
		t.Fatal(err)
	}
	for _, l := range leaves {
		if err := d.db.Exec(`ANALYZE "` + l + `"`).Error; err != nil {
			t.Fatalf("analyze %s: %v", l, err)
		}
	}

	got, err := d.ProbeTelemetryTotals(ids)
	if err != nil {
		t.Fatal(err)
	}
	near := func(have, want int64) bool { return math.Abs(float64(have-want)) <= 0.05*float64(want) }
	isApprox := func(p ProbeTotals) bool {
		for _, f := range p.Approx {
			if f == "syslog" {
				return true
			}
		}
		return false
	}
	if p := got[big]; !near(p.Syslog, 1200000) || !isApprox(p) {
		t.Errorf("big: syslog=%d approx=%v, want ~1,200,000 estimated", p.Syslog, p.Approx)
	}
	if p := got[old]; !near(p.Syslog, 150000) || !isApprox(p) {
		t.Errorf("old: syslog=%d approx=%v, want ~150,000 estimated from the second leaf", p.Syslog, p.Approx)
	}
	if p := got[tiny]; p.Syslog != 3 || isApprox(p) {
		t.Errorf("tiny: syslog=%d approx=%v, want exactly 3 (a most-common value in no leaf)", p.Syslog, p.Approx)
	}
	// Small tables stay exact.
	if p := got[big]; p.Traps != 0 || len(p.Approx) != 1 {
		t.Errorf("big: traps=%d approx=%v, want 0 and only syslog estimated", p.Traps, p.Approx)
	}
}
