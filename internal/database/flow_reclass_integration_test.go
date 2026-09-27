//go:build integration

// Real-PostgreSQL proof of the flow-history reclassification (v0.11.265): the
// array-literal UPDATE, the transaction-level maintenance lock, a partitioned
// flow_samples, and a sparse flow_rollups id space like production's (ids span
// about 2.8x the rows, because promotion consumes them). SQLite cannot
// exercise any of those paths. Runs in the integration lane (TEST_PG_DSN, -p 1).
package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/classify"
)

func TestPostgresFlowReclass_RealisticVolume(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	if !pgIsPartitioned(t, d, "flow_samples") {
		t.Fatal("flow_samples is not partitioned on a fresh schema; the partitioned path cannot be proven")
	}
	oldSleep := reclassSleep
	reclassSleep = func(time.Duration) {}
	t.Cleanup(func() { reclassSleep = oldSleep })

	const rollups, samples = 300000, 60000
	start := time.Now()
	// Rollups with gaps: every third id is used, like production's 2.8x span.
	if err := d.db.Exec(`INSERT INTO flow_rollups (id, timestamp, device_id, interval_type, src_addr, dst_addr, dst_port, protocol,
			bytes_sum, packets_sum, flow_count, sampling_rate_avg, direction, service_port)
		SELECT g * 3, now() - (g * interval '10 seconds'), 1, '1h',
			CASE WHEN g % 2 = 0 THEN '66.179.9.' || (144 + g % 16) ELSE '198.51.100.' || (g % 250) END,
			CASE WHEN g % 2 = 0 THEN '203.0.113.' || (g % 250) ELSE '66.179.9.' || (144 + g % 16) END,
			CASE WHEN g % 5 = 0 THEN 51000 + g % 1000 ELSE 443 END, 6, 100, 1, 1, 1, 4,
			CASE WHEN g % 7 = 0 THEN 8443 ELSE 0 END
		FROM generate_series(1, ?) AS g`, rollups).Error; err != nil {
		t.Fatalf("seed rollups: %v", err)
	}
	if err := d.db.Exec(`SELECT setval('flow_rollups_id_seq', (SELECT MAX(id) FROM flow_rollups))`).Error; err != nil {
		t.Fatalf("setval: %v", err)
	}
	if err := d.db.Exec(`INSERT INTO flow_samples (timestamp, device_id, probe_id, sampler_address, src_addr, dst_addr, src_port, dst_port,
			protocol, bytes, packets, sampling_rate, direction, created_at)
		SELECT now() - (g * interval '50 milliseconds'), 1, 0, '10.9.1.1',
			'66.179.9.' || (144 + g % 16), '203.0.113.' || (g % 250), 443, 40000 + g % 20000, 6, 100, 1, 1, 4, now()
		FROM generate_series(1, ?) AS g`, samples).Error; err != nil {
		t.Fatalf("seed samples: %v", err)
	}
	d.db.Exec("ANALYZE flow_rollups")
	d.db.Exec("ANALYZE flow_samples")
	t.Logf("seeded %d rollups (sparse ids) + %d samples in %s", rollups, samples, time.Since(start).Round(time.Millisecond))

	// The slice UPDATE must be a bounded index range scan on the real indexes.
	var plan []string
	if err := d.db.Raw(`EXPLAIN UPDATE flow_rollups AS r SET direction = v.d, service_port = v.s, class_rev = 1
		FROM unnest('{3,6,9}'::bigint[], '{1,2,3}'::smallint[], '{443,443,0}'::integer[]) AS v(id, d, s)
		WHERE r.id = v.id AND r.id >= 3 AND r.id <= 9 AND r.class_rev < 1`).Scan(&plan).Error; err != nil {
		t.Fatalf("explain: %v", err)
	}
	if joined := strings.Join(plan, "\n"); strings.Contains(joined, "Seq Scan on flow_rollups") {
		t.Errorf("the slice UPDATE plans a sequential scan of flow_rollups:\n%s", joined)
	}

	nets := ownNets
	setFor := func(rev uint16) (*classify.InternalSet, error) { return classify.NewInternalSet(nets, rev), nil }

	// Mid-walk, an API without its network list stamps revision-0 samples and
	// a real promotion rolls them up: old-revision rollups land ABOVE the
	// rollup walk's pass-start MAX, where only the locked verification can
	// find them — it must, and re-walk from just below them.
	promotedOld := int64(0)
	reclassReadHook = func(table string, lo, hi int64) error {
		if promotedOld == 0 && table == reclassTableRollups && lo > 300000 {
			if err := d.db.Exec(`INSERT INTO flow_samples (timestamp, device_id, probe_id, sampler_address, src_addr, dst_addr,
					src_port, dst_port, protocol, bytes, packets, sampling_rate, direction, created_at)
				SELECT now() - interval '70 minutes' + (g * interval '1 second'), 2, 0, '10.9.1.1', '66.179.9.150', '203.0.113.' || (g % 250),
					443, 41000 + g, 6, 100, 1, 1, 4, now()
				FROM generate_series(1, 500) AS g`).Error; err != nil {
				return err
			}
			d.aggregateFlowsToRollup(time.Now().Add(-time.Hour), "5m")
			d.db.Raw(`SELECT COUNT(*) FROM flow_rollups WHERE device_id = 2 AND class_rev = 0`).Scan(&promotedOld)
			if promotedOld == 0 {
				t.Fatal("the promotion produced no old-revision rollups; the case under test did not occur")
			}
		}
		return nil
	}
	t.Cleanup(func() { reclassReadHook = nil })

	runStart := time.Now()
	steps := 0
	for ; steps < 200; steps++ {
		if err := d.RunFlowReclassStep(setFor, time.Minute); err != nil {
			t.Fatalf("step %d: %v", steps, err)
		}
		if d.FlowReclassDoneRev() >= 1 {
			break
		}
	}
	elapsed := time.Since(runStart)
	if d.FlowReclassDoneRev() != 1 {
		t.Fatalf("the run did not complete in %d steps: %+v", steps, d.GetFlowReclassStatus())
	}
	st := d.GetFlowReclassStatus()
	t.Logf("reclassified %d rows in %s over %d steps (%.0f rows/s, including the concurrent promotion)",
		st.Updated, elapsed.Round(time.Millisecond), steps+1, float64(st.Updated)/elapsed.Seconds())

	for _, table := range []string{"flow_samples", "flow_rollups"} {
		var left int64
		d.db.Table(table).Where("class_rev < 1").Count(&left)
		if left != 0 {
			t.Errorf("%s still has %d old-revision rows after the run", table, left)
		}
	}

	// Parity with the ingest classifier on a sample of rows.
	set := classify.NewInternalSet(nets, 1)
	var rows []struct {
		SrcAddr, DstAddr string
		DstPort          uint16
		Protocol         uint8
		Direction        uint8
		ServicePort      uint16
	}
	d.db.Raw(`SELECT src_addr, dst_addr, dst_port, protocol, direction, service_port FROM flow_rollups WHERE id % 997 = 0 LIMIT 500`).Scan(&rows)
	if len(rows) == 0 {
		t.Fatal("no rows sampled for parity")
	}
	for _, r := range rows {
		if want := set.Direction(r.SrcAddr, r.DstAddr); r.Direction != want {
			t.Errorf("%s -> %s: direction %d, the ingest classifier says %d", r.SrcAddr, r.DstAddr, r.Direction, want)
		}
		if r.ServicePort == 0 && classify.ServicePortFromDst(r.Protocol, r.DstPort) != 0 {
			t.Errorf("%s -> %s:%d: service_port 0, inference says %d", r.SrcAddr, r.DstAddr, r.DstPort, classify.ServicePortFromDst(r.Protocol, r.DstPort))
		}
	}
	var kept int64
	d.db.Raw(`SELECT COUNT(*) FROM flow_rollups WHERE service_port = 8443`).Scan(&kept)
	if want := int64(rollups / 7); kept < want {
		t.Errorf("%d rows kept their exact service_port 8443, want at least %d", kept, want)
	}
	if req, ok := d.GetSettingValue(flowSummaryRecomputeRequestKey); !ok || !strings.HasPrefix(req, fmt.Sprintf("%d|", 1)) {
		t.Errorf("summary recompute request = %q", req)
	}
}
