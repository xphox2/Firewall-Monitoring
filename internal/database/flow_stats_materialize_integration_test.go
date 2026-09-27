//go:build integration

// The materialized Flows run relies on one pinned connection carrying its
// session-local scope table through every query. The SQLite unit lane cannot
// prove that — its harness has a single connection, so every query shares it
// regardless. On PostgreSQL the pool has many connections: a query that
// escaped the pin would fail with `relation "flow_scope_…" does not exist`.
package database

import (
	"context"
	"strings"
	"testing"
)

func pgFlowScopeTablesLeft(t *testing.T, d *Database) int64 {
	t.Helper()
	var n int64
	if err := d.db.Raw(`SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname LIKE 'pg_temp%' AND c.relname LIKE 'flow_scope_%'`).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFlowStatsMaterializedIntegration_EqualsDirectOnPostgres(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	seedFlowWeek(t, d)
	port := uint16(443)
	asn := uint32(15169)
	for _, tc := range []struct {
		name string
		f    FlowStatsFilter
	}{
		{"src", FlowStatsFilter{SrcAddr: "10.0.0.1"}},
		{"dst", FlowStatsFilter{DstAddr: "8.8.8.8"}},
		{"src cidr", FlowStatsFilter{SrcAddr: "10.0.0.0/24"}},
		{"port", FlowStatsFilter{DstPort: &port}},
		{"asn", FlowStatsFilter{DstASN: &asn}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flowStatsMaterialize = false
			direct := flowStatsJSON(t, d, 168, tc.f)
			flowStatsMaterialize = true
			mat := flowStatsJSON(t, d, 168, tc.f)
			if direct != mat {
				t.Fatalf("materialized differs from direct on PostgreSQL:\ndirect: %s\nmater.: %s", direct, mat)
			}
			if strings.Contains(mat, `"degraded":true`) {
				t.Fatalf("degraded on PostgreSQL (a query escaped the pinned connection?): %s", mat)
			}
		})
	}
	flowStatsMaterialize = true
	if n := pgFlowScopeTablesLeft(t, d); n != 0 {
		t.Fatalf("%d scope tables left in temp schemas", n)
	}
}

// On PostgreSQL a cancel usually costs the connection (pgx reports it as a bad
// connection), taking the scope table with the session. Either way nothing may
// be left, the panels must be reported partial, and the pool must still work.
func TestFlowStatsMaterializedIntegration_CancelLeavesNothing(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	seedFlowWeek(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := d.WithContext(ctx).GetFlowStatsOpts(168, FlowStatsFilter{SrcAddr: "10.0.0.1"}, FlowStatsOptions{
		Progress: func(p FlowStatsProgress) {
			if p.Label == "Reading day 4 of 7" {
				cancel()
			}
		},
	})
	if err == nil && (res == nil || !res.Degraded) {
		t.Fatal("a cancelled scan must not report a complete result")
	}
	if n := pgFlowScopeTablesLeft(t, d); n != 0 {
		t.Fatalf("%d scope tables left after cancel", n)
	}
	if _, err := d.GetFlowStats(24, FlowStatsFilter{}); err != nil {
		t.Fatalf("pool unusable after a cancelled run: %v", err)
	}
}
