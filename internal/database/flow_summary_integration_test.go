//go:build integration

// The summariser emits SQL the SQLite lane cannot validate: COALESCE inside a
// GROUP BY, an integer-to-text cast, and a multi-part string concatenation used
// as both a SELECT alias and a grouping key. Those go through the Dialect split,
// so the unit tests exercise the SQLite spelling and never the PostgreSQL one —
// which is the only one production runs.
//
// It also covers the two things that can only misbehave on a real engine: a
// NULL dst_country grouping separately from ” and then colliding on the unique
// key (which fails the whole bucket), and the numeric scan of aggregate columns.
package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestFlowSummaryIntegration_ExactAndEngineSafe(t *testing.T) {
	d := NewIntegrationDB(t)
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)

	rows := []models.FlowRollup{
		{Timestamp: base.Add(5 * time.Minute), DeviceID: 1, IntervalType: "5m",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			DstCountry: "US", DstASN: 15169, BytesSum: 1000, PacketsSum: 10, FlowCount: 2},
		{Timestamp: base.Add(10 * time.Minute), DeviceID: 1, IntervalType: "5m",
			SrcAddr: "10.0.0.2", DstAddr: "1.1.1.1", DstPort: 53, Protocol: 17,
			BytesSum: 2000, PacketsSum: 20, FlowCount: 3},
		{Timestamp: base.Add(15 * time.Minute), DeviceID: 1, IntervalType: "5m",
			SrcAddr: "169.254.0.1", DstAddr: "224.0.0.1", DstPort: 0, Protocol: 2,
			ScopeLocal: true, BytesSum: 500, PacketsSum: 5, FlowCount: 1},
	}
	if err := d.db.Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A NULL country alongside an empty one. On PostgreSQL these GROUP separately
	// but both scan into a Go string as "", so without COALESCE the two rows
	// collide on idx_flow_summary_key and the bucket fails to write entirely.
	if err := d.db.Exec(`INSERT INTO flow_rollups
		(timestamp, device_id, interval_type, src_addr, dst_addr, dst_port, protocol,
		 app_category, direction, scope_local, dst_country, dst_asn, flow_source, firewall_event,
		 bytes_sum, packets_sum, flow_count, sampling_rate_avg)
		VALUES (?, 1, '5m', '10.0.0.3', '9.9.9.9', 443, 6, 0, 0, false, NULL, 0, 0, 0, 700, 7, 1, 1)`,
		base.Add(20*time.Minute)).Error; err != nil {
		t.Fatalf("seed NULL-country row: %v", err)
	}

	if !d.RunFlowSummaryCycle() {
		t.Fatal("RunFlowSummaryCycle wrote nothing")
	}

	var want, got struct {
		Bytes   uint64
		Packets uint64
		Flows   int64
	}
	if err := d.db.Model(&models.FlowRollup{}).
		Where("timestamp >= ? AND timestamp < ?", base, base.Add(time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
		Scan(&want).Error; err != nil {
		t.Fatalf("source totals: %v", err)
	}
	if err := d.db.Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1h", base).
		Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
		Scan(&got).Error; err != nil {
		t.Fatalf("summary totals: %v", err)
	}
	if got != want {
		t.Errorf("summary %+v does not match source %+v on PostgreSQL. A NULL dst_country "+
			"grouping apart from '' collides on the unique key and fails the whole bucket.", got, want)
	}

	// The casts and concatenation must have produced usable values, not empty
	// strings or an error swallowed upstream.
	var port, asn, convo models.FlowSummaryTop
	if err := d.db.Where("dimension = ?", flowSummaryDimDstPort).Order("bytes_sum DESC").First(&port).Error; err != nil {
		t.Fatalf("no port rows: %v", err)
	}
	if port.Value != "443" {
		t.Errorf("top port value is %q, want \"443\" — the integer-to-text cast is wrong", port.Value)
	}
	if err := d.db.Where("dimension = ?", flowSummaryDimDstASN).First(&asn).Error; err != nil {
		t.Fatalf("no ASN rows: %v", err)
	}
	if asn.Value != "15169" {
		t.Errorf("top ASN value is %q, want \"15169\"", asn.Value)
	}
	if err := d.db.Where("dimension = ?", flowSummaryDimConversation).Order("bytes_sum DESC").First(&convo).Error; err != nil {
		t.Fatalf("no conversation rows: %v", err)
	}
	if parts := strings.Split(convo.Value, "|"); len(parts) != 4 {
		t.Errorf("conversation key %q does not split into src|dst|port|proto", convo.Value)
	} else if parts[0] != "10.0.0.1" || parts[2] != "443" {
		t.Errorf("conversation key %q does not describe the top conversation", convo.Value)
	}

	// Scope-local traffic must be kept apart, or multicast noise crowds the
	// talker lists.
	var localTops int64
	d.db.Model(&models.FlowSummaryTop{}).Where("scope_local = ?", true).Count(&localTops)
	if localTops == 0 {
		t.Error("no scope-local top-N rows were written")
	}

	// And a second pass must change nothing.
	before := got
	d.RunFlowSummaryCycle()
	if err := d.db.Model(&models.FlowSummary{}).
		Where("interval_type = ? AND timestamp = ?", "1h", base).
		Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
		Scan(&got).Error; err != nil {
		t.Fatalf("summary totals after second pass: %v", err)
	}
	if got != before {
		t.Errorf("a second pass changed the totals from %+v to %+v; the writer is merging, not recomputing", before, got)
	}
}
