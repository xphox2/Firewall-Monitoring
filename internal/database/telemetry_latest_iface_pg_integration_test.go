//go:build integration

// GetAllLatestInterfaces was rewritten (v0.11.244) from an unbounded
// MAX(timestamp) GROUP BY device_id into a correlated subquery driven from the
// devices table, after the old shape was measured on production as a Parallel
// Seq Scan reading 423,092 buffers about four times a minute — which made
// interface_stats the single largest source of read I/O in the database.
//
// That measurement was taken on PRODUCTION, where interface_stats is NOT
// partitioned: it was populated before the empty-only partition conversion, so
// it went down the manual-runbook path and stayed a plain table. A FRESH INSTALL
// partitions it (migrate.go partitionTables), and the CI Postgres lane is the
// fresh-install shape — so the plan the production benchmark validated is not
// the plan most installs will run.
//
// This test closes that gap. It is the only place the rewrite meets a
// partitioned interface_stats, and it asserts both that the results are right
// and that the plan is still per-device index descents (MergeAppend over child
// index scans) rather than a scan of every child.
package database

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestPGGetAllLatestInterfaces_PartitionedParent(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	if !pgIsPartitioned(t, d, "interface_stats") {
		t.Fatal("interface_stats is not a partitioned parent — this test is not exercising the fresh-install shape")
	}

	for _, name := range []string{"fw-a", "fw-b", "fw-quiet"} {
		dev := models.Device{Name: name}
		if err := d.Gorm().Create(&dev).Error; err != nil {
			t.Fatalf("seed device %s: %v", name, err)
		}
	}

	// Spread the history across partitions: "now" lands in the current monthly
	// child, and the backdated rows land in the DEFAULT child (EnsurePartitions
	// creates current + future months only). A device's newest row must be found
	// whichever child holds it.
	now := time.Now().UTC().Truncate(time.Hour)
	old := now.AddDate(0, -2, 0)

	rows := []models.InterfaceStats{
		// Device 1: superseded snapshot in the default child, newest in the current one.
		{DeviceID: 1, Timestamp: old, Name: "stale1", Index: 1},
		{DeviceID: 1, Timestamp: old, Name: "stale2", Index: 2},
		{DeviceID: 1, Timestamp: now, Name: "cur1", Index: 1},
		{DeviceID: 1, Timestamp: now, Name: "cur2", Index: 2},
		// Device 2: only a current snapshot.
		{DeviceID: 2, Timestamp: now, Name: "b1", Index: 1},
		// Device 3: ONLY an old snapshot, living in the default child. This is the
		// case a `since` bound would silently drop, taking the device out of VPN,
		// overlay and L2 detection.
		{DeviceID: 3, Timestamp: old, Name: "quiet1", Index: 1},
	}
	for i := range rows {
		if err := d.Gorm().Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed stats: %v", err)
		}
	}

	got, err := d.GetAllLatestInterfaces()
	if err != nil {
		t.Fatalf("GetAllLatestInterfaces: %v", err)
	}

	byDev := map[uint][]string{}
	for _, r := range got {
		byDev[r.DeviceID] = append(byDev[r.DeviceID], r.Name)
	}
	if len(byDev[1]) != 2 {
		t.Errorf("device 1 returned %v, want its 2 current-partition interfaces", byDev[1])
	}
	for _, n := range byDev[1] {
		if strings.HasPrefix(n, "stale") {
			t.Errorf("device 1 returned %q from a superseded snapshot in another partition", n)
		}
	}
	if len(byDev[2]) != 1 {
		t.Errorf("device 2 returned %v, want 1", byDev[2])
	}
	if len(byDev[3]) != 1 {
		t.Errorf("device 3 returned %v, want 1 — a device whose only snapshot is old, and in the DEFAULT partition, must still be reported", byDev[3])
	}
}

// TestPGGetAllLatestInterfaces_PartitionedPlanUsesIndexes is the plan assertion.
// Correct results are not enough: the whole point of the rewrite is that cost
// scales with device count rather than table size, and a partitioned parent is
// where that could silently stop being true.
//
// The assertion is deliberately scoped to the SubPlan — the correlated
// MAX(timestamp) — and not to the whole plan. Sequential scans DO legitimately
// appear elsewhere: EnsurePartitions creates six future monthly children plus a
// default, all empty, and scanning a zero-page relation is free (cost=0.00..0.00),
// so the planner picks it and is right to. What must never happen is the
// correlated MAX falling back to a scan, because that is the O(table-size)
// behaviour the rewrite exists to remove.
//
// Volume matters here. At a few hundred rows a seq scan of a seven-page child is
// genuinely cheaper and the planner correctly says so, which would make a
// small-fixture assertion test the fixture rather than the query. The seed below
// is large enough that the index is unambiguously the right plan.
func TestPGGetAllLatestInterfaces_PartitionedPlanUsesIndexes(t *testing.T) {
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}

	dev := models.Device{Name: "fw-a"}
	if err := d.Gorm().Create(&dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Bulk seed in one statement — 20k rows row-by-row through GORM would
	// dominate the test's runtime for no added coverage.
	if err := d.Gorm().Exec(`
		INSERT INTO interface_stats (device_id, timestamp, name, index)
		SELECT ?, date_trunc('hour', now()) - ((g % 5000) * interval '1 minute'),
		       'if' || (g % 24), (g % 24)
		FROM generate_series(1, 20000) g`, dev.ID).Error; err != nil {
		t.Fatalf("bulk seed: %v", err)
	}
	if err := d.Gorm().Exec(`ANALYZE interface_stats`).Error; err != nil {
		t.Fatalf("analyze: %v", err)
	}

	var lines []string
	if err := d.Gorm().Raw(`EXPLAIN
		SELECT i.* FROM devices d
		JOIN interface_stats i
		  ON i.device_id = d.id
		 AND i.timestamp = (SELECT MAX(s.timestamp) FROM interface_stats s WHERE s.device_id = d.id)`).
		Scan(&lines).Error; err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	plan := strings.Join(lines, "\n")

	// The join must resolve the device through the composite index rather than
	// filtering after a scan.
	if !strings.Contains(plan, "device_id = d.id") {
		t.Errorf("the join is not pushing device_id into an index condition.\nPlan:\n%s", plan)
	}

	// The correlated MAX must walk (device_id, timestamp) backwards per child.
	if !strings.Contains(plan, "_device_ts") {
		t.Errorf("the correlated MAX(timestamp) is not using the (device_id, timestamp) index "+
			"on any partition; cost would scale with table size.\nPlan:\n%s", plan)
	}

	// No sequential scan of a POPULATED partition. Empty children are excluded by
	// cost, not by name: EnsurePartitions creates six future months plus a
	// default, all empty, and the planner correctly seq-scans a zero-page
	// relation at cost=0.00..0.00. Anything dearer than that is the pathology.
	seqScan := regexp.MustCompile(`Seq Scan on (interface_stats\S*)\s+\(cost=([0-9.]+)\.\.([0-9.]+)`)
	for _, m := range seqScan.FindAllStringSubmatch(plan, -1) {
		if m[3] != "0.00" {
			t.Errorf("populated partition %s is sequentially scanned (cost=%s..%s). That is the "+
				"O(table-size) behaviour this rewrite removed — on production the old shape read "+
				"423,092 buffers about four times a minute.\nPlan:\n%s", m[1], m[2], m[3], plan)
		}
	}
	t.Logf("partitioned plan:\n%s", plan)
}
