//go:build integration

// Real-PostgreSQL proof of the device purge (v0.11.243): the batched delete
// walks every RANGE partition of a partitioned parent INCLUDING the DEFAULT
// child, leaves every other device's rows alone, survives a partition being
// dropped underneath it (retention, SQLSTATE 42P01), and a cancel between
// batches leaves a resumable retired device. SQLite (purge_test.go) cannot
// exercise any of the partition paths, so this suite is CI's only evidence for
// them. Runs in the integration lane (TEST_PG_DSN, -p 1, see ci.yml).
package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// pgPurgeDB resets the schema, runs the migration chain and creates the
// monthly partitions (current month + 6 ahead, plus the DEFAULT child — the
// migrations alone leave a freshly converted parent without leaves), then
// proves the two tables this suite seeds are partitioned parents.
func pgPurgeDB(t *testing.T) *Database {
	t.Helper()
	d := NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	for _, table := range []string{"denied_events", "interface_stats"} {
		if !pgIsPartitioned(t, d, table) {
			t.Fatalf("%s is NOT a partitioned parent after the migration chain on a fresh PG schema; "+
				"the partition paths of the purge cannot be proven on it", table)
		}
		// The DEFAULT child must carry the plan's (device_id, timestamp) index
		// like every monthly leaf. Before the EnsurePartitions fix it was
		// created bare (pkey only) and every purge batch on it was a full
		// scan + sort.
		idx := fmt.Sprintf("idx_%s_default_device_ts", table)
		var has bool
		if err := d.db.Raw("SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = ? AND indexname = ?)", table+"_default", idx).Scan(&has).Error; err != nil {
			t.Fatalf("probe %s: %v", idx, err)
		}
		if !has {
			t.Fatalf("%s_default has no %s index — EnsurePartitions must apply the leaf index plan to the DEFAULT child", table, idx)
		}
	}
	return d
}

// pgChildren lists the leaf partitions of parent (any order).
func pgChildren(t *testing.T, d *Database, parent string) []string {
	t.Helper()
	var names []string
	if err := d.db.Raw(`SELECT c.relname FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = ? ORDER BY c.relname`, parent).Scan(&names).Error; err != nil {
		t.Fatalf("children of %s: %v", parent, err)
	}
	return names
}

// pgCount runs `SELECT count(*) FROM <rel> WHERE <col> = deviceID` on one
// relation (a parent, a leaf, or a plain table).
func pgCount(t *testing.T, d *Database, rel, col string, deviceID uint) int64 {
	t.Helper()
	var n int64
	if err := d.db.Raw(fmt.Sprintf("SELECT count(*) FROM %s WHERE %s = ?", rel, col), deviceID).Scan(&n).Error; err != nil {
		t.Fatalf("count %s.%s=%d: %v", rel, col, deviceID, err)
	}
	return n
}

// pgCountPerChild returns device rows per leaf of a partitioned parent.
func pgCountPerChild(t *testing.T, d *Database, parent string, deviceID uint) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, ch := range pgChildren(t, d, parent) {
		out[ch] = pgCount(t, d, ch, "device_id", deviceID)
	}
	return out
}

// seedIfaceStats inserts n interface_stats rows for deviceID in ONE statement,
// timestamps stepping back `step` per row from the SQL expression base:
// n*step covers the spread. From now(), rows in the current month land in its
// leaf and older ones in the DEFAULT child (EnsurePartitions creates no past
// months), so a 3-month spread exercises both.
func seedIfaceStats(t *testing.T, d *Database, deviceID uint, n int, step time.Duration, base string) {
	t.Helper()
	start := time.Now()
	if err := d.db.Exec(fmt.Sprintf(`INSERT INTO interface_stats (timestamp, device_id, name, status, "index", in_bytes, out_bytes)
		SELECT %s - (g * ?::interval), ?, 'port' || (g %% 8), 'up', g %% 8, g * 1000, g * 500
		FROM generate_series(1, ?) AS g`, base), step.String(), deviceID, n).Error; err != nil {
		t.Fatalf("seed interface_stats device %d: %v", deviceID, err)
	}
	t.Logf("seeded %d interface_stats rows for device %d in %s", n, deviceID, time.Since(start).Round(time.Millisecond))
}

// seedDeniedEvents inserts perBucket rows for deviceID into three buckets:
// the current month (its leaf), next month (its leaf) and two months back
// (no leaf → DEFAULT child). Returns the rows inserted.
func seedDeniedEvents(t *testing.T, d *Database, deviceID uint, perBucket int) int64 {
	t.Helper()
	for _, offset := range []string{"0 months", "1 month", "-2 months"} {
		if err := d.db.Exec(`INSERT INTO denied_events (timestamp, device_id, src_addr, dst_addr, src_port, dst_port, protocol)
			SELECT date_trunc('month', now()) + ?::interval + (g * interval '1 minute'), ?, '10.0.0.' || (g % 250), '8.8.8.8', 40000 + g, 443, 6
			FROM generate_series(1, ?) AS g`, offset, deviceID, perBucket).Error; err != nil {
			t.Fatalf("seed denied_events device %d bucket %s: %v", deviceID, offset, err)
		}
	}
	return int64(3 * perBucket)
}

// seedSmallRows adds one alerts / vpn_status / device_config_revisions row for
// dev, plus (once, for the pair) the shared A↔B ipsec_tunnels intent and the
// device_connections rows. Returns the number of rows the purge PLAN deletes
// for dev (device_connections is outside the plan: DeleteDevice clears it).
func seedSmallRows(t *testing.T, d *Database, dev *models.Device, tag string) int64 {
	t.Helper()
	now := time.Now()
	for _, row := range []interface{}{
		&models.Alert{DeviceID: dev.ID, Message: tag + " alert", Timestamp: now, AlertType: "DEVICE_OFFLINE", Severity: "critical"},
		&models.VPNStatus{DeviceID: dev.ID, Timestamp: now, TunnelName: tag + "-vpn", Status: "up"},
		&models.DeviceConfigRevision{DeviceID: dev.ID, Timestamp: now, Checksum: tag + "-sum", ConfigText: "config system global\nend"},
	} {
		if err := d.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T for %s: %v", row, tag, err)
		}
	}
	return 3
}

// explainNodes flattens an EXPLAIN (FORMAT JSON) plan into "<Node Type>" and
// index names, walking every nested Plans array.
type explainNode struct {
	Type     string `json:"Node Type"`
	Index    string `json:"Index Name"`
	Relation string `json:"Relation Name"`
	Plans    []explainNode
}

// flattenPlan walks the tree; a node without its own "Relation Name" (a
// Bitmap Index Scan under a Bitmap Heap Scan) inherits its ancestor's.
func flattenPlan(n explainNode, inherited string, out *[]explainNode) {
	if n.Relation == "" {
		n.Relation = inherited
	}
	*out = append(*out, n)
	for _, c := range n.Plans {
		flattenPlan(c, n.Relation, out)
	}
}

func explainSubquery(t *testing.T, d *Database, rel string, deviceID uint) []explainNode {
	t.Helper()
	var raw string
	row := d.db.Raw(fmt.Sprintf("EXPLAIN (FORMAT JSON) SELECT id FROM %s WHERE device_id = ? ORDER BY timestamp LIMIT 2000", rel), deviceID).Row()
	if err := row.Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN on %s: %v", rel, err)
	}
	var top []struct {
		Plan explainNode `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(raw), &top); err != nil || len(top) != 1 {
		t.Fatalf("EXPLAIN JSON on %s: %v (%s)", rel, err, raw)
	}
	var flat []explainNode
	flattenPlan(top[0].Plan, "", &flat)
	return flat
}

// Index names EnsurePartitions gives the model's (device_id, timestamp) index
// idx_iface_device_ts on a leaf (idx_<leaf>_device_ts, partitionIndexSuffix)
// and the (timestamp) index (idx_<leaf>_timestamp). A plain (unpartitioned)
// table carries the model's own names.
var (
	deviceTSIndex  = regexp.MustCompile(`^(idx_iface_device_ts|idx_interface_stats_[0-9a-z_]+_device_ts)$`)
	timestampIndex = regexp.MustCompile(`^(idx_interface_stats_timestamp|idx_interface_stats_[0-9a-z_]+_timestamp)$`)
)

// assertIndexedScan runs the purge's batch subquery through EXPLAIN on rel
// (a parent or a leaf) and fails unless every populated leaf the plan reads
// is read by an index scan — never a Seq Scan — on an index strict permits:
//   - strict: only the (device_id, timestamp) index (a device that is a
//     minority of the table, the usual purge);
//   - lenient: (device_id, timestamp) OR (timestamp) — for a device holding
//     ~all of a leaf the planner may legitimately walk the timestamp index in
//     order and filter device_id, which is the same bounded index walk.
//
// Leaves with no rows for the device are ignored: PostgreSQL plans an EMPTY
// relation as a zero-cost scan of whatever it likes. Returns leaf → index for
// the log.
func assertIndexedScan(t *testing.T, d *Database, rel string, deviceID uint, populated map[string]int64, strict bool) map[string]string {
	t.Helper()
	seen := map[string]string{}
	for _, n := range explainSubquery(t, d, rel, deviceID) {
		if populated[n.Relation] == 0 {
			continue
		}
		switch n.Type {
		case "Seq Scan":
			t.Errorf("EXPLAIN %s (device %d): Seq Scan on %s (%d rows of the device) — the purge subquery must walk an index", rel, deviceID, n.Relation, populated[n.Relation])
		case "Index Scan", "Index Only Scan", "Bitmap Index Scan":
			seen[n.Relation] = n.Type + " " + n.Index
			switch {
			case deviceTSIndex.MatchString(n.Index):
			case !strict && timestampIndex.MatchString(n.Index):
			default:
				t.Errorf("EXPLAIN %s (device %d): %s on %s uses %q, want the (device_id, timestamp) index%s", rel, deviceID, n.Type, n.Relation, n.Index,
					map[bool]string{true: "", false: " (or the timestamp index)"}[strict])
			}
		}
	}
	// Completeness: a parent plan must read every populated leaf through an
	// index; a leaf plan must read that leaf.
	if _, isLeaf := populated[rel]; isLeaf {
		if seen[rel] == "" {
			t.Errorf("EXPLAIN %s (device %d): no index scan node on the leaf", rel, deviceID)
		}
		return seen
	}
	for leaf, rows := range populated {
		if rows > 0 && seen[leaf] == "" {
			t.Errorf("EXPLAIN %s (device %d): leaf %s (%d rows) is not read through an index", rel, deviceID, leaf, rows)
		}
	}
	return seen
}

// batchCounter wires purgeBatchHook to count batches per relation.
type batchCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (b *batchCounter) hook(table string, _ int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.counts[table]++
	return nil
}

func (b *batchCounter) total(prefix string) (n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for rel, c := range b.counts {
		if strings.HasPrefix(rel, prefix) {
			n += c
		}
	}
	return n
}

func planEntry(t *testing.T, table string) *purgeTable {
	t.Helper()
	for i := range devicePurgeTables {
		if devicePurgeTables[i].table == table {
			return &devicePurgeTables[i]
		}
	}
	t.Fatalf("%s is not in devicePurgeTables", table)
	return nil
}

func newDevice(t *testing.T, d *Database, name, ip string) *models.Device {
	t.Helper()
	dev := &models.Device{Name: name, IPAddress: ip}
	if err := d.db.Create(dev).Error; err != nil {
		t.Fatalf("create device %s: %v", name, err)
	}
	return dev
}

func deviceRetired(t *testing.T, d *Database, id uint) bool {
	t.Helper()
	dev, err := d.GetDevice(id)
	if err != nil {
		t.Fatalf("GetDevice(%d): %v", id, err)
	}
	return dev.RetiredAt != nil
}

// TestPGPurge_RemovesDeviceAcrossPartitions: 200,000 interface_stats rows over
// three months (current-month leaf + DEFAULT child), denied_events in two
// monthly leaves AND the DEFAULT child, one row each in alerts / vpn_status /
// device_config_revisions, the shared A↔B ipsec_tunnels intent and an A→B
// device_connections row — the purge removes every A row from every relation,
// leaves B's rows (and B's B→C connection) untouched, deletes the device row,
// and the job's counters land exactly on the seeded total.
//
// The A↔B tunnel intent is a SHARED row: purging A removes it for B too. That
// is by design (the estimate lists it with the peer's name and the handler
// refuses while it is deploying); this test asserts the removal.
func TestPGPurge_RemovesDeviceAcrossPartitions(t *testing.T) {
	d := pgPurgeDB(t)
	a := seedRetiredDevice(t, d, "fw-a-purged")
	b := newDevice(t, d, "fw-b-survivor", "10.0.0.2")
	c := newDevice(t, d, "fw-c-peer", "10.0.0.3")

	const ifaceA, ifaceB = 200000, 5000
	// 200,000 rows × 38 s ≈ 88 days; 5,000 rows × 25 min ≈ 87 days.
	seedIfaceStats(t, d, a.ID, ifaceA, 38*time.Second, "now()")
	seedIfaceStats(t, d, b.ID, ifaceB, 25*time.Minute, "now()")
	deniedA := seedDeniedEvents(t, d, a.ID, 300)
	deniedB := seedDeniedEvents(t, d, b.ID, 50)
	plannedA := int64(ifaceA) + deniedA + seedSmallRows(t, d, a, "a")
	seedSmallRows(t, d, b, "b")
	// Shared tunnel intent (status not deploying) and the connection rows.
	// RetireDevice already cleared A's connections, so A→B is seeded AFTER the
	// retire to prove DeleteDevice (the purge's last step) clears it.
	if err := d.db.Create(&models.IPSecTunnel{Name: "a-to-b", ADeviceID: a.ID, BDeviceID: b.ID, Status: "draft"}).Error; err != nil {
		t.Fatalf("seed ipsec tunnel: %v", err)
	}
	plannedA++ // the tunnel is deleted through a_device_id
	for _, conn := range []*models.DeviceConnection{
		{Name: "a-b", SourceDeviceID: a.ID, DestDeviceID: b.ID},
		{Name: "b-c", SourceDeviceID: b.ID, DestDeviceID: c.ID},
	} {
		if err := d.db.Create(conn).Error; err != nil {
			t.Fatalf("seed connection %s: %v", conn.Name, err)
		}
	}
	// Fresh planner statistics: a partitioned parent is never auto-analyzed
	// and the leaves were just bulk-loaded.
	for _, table := range []string{"interface_stats", "denied_events"} {
		if err := d.db.Exec("ANALYZE " + table).Error; err != nil {
			t.Fatalf("ANALYZE %s: %v", table, err)
		}
	}

	// Seed shape: A and B in ≥2 monthly leaves AND the DEFAULT child.
	deniedBeforeA := pgCountPerChild(t, d, "denied_events", a.ID)
	deniedBeforeB := pgCountPerChild(t, d, "denied_events", b.ID)
	for name, per := range map[string]map[string]int64{"A": deniedBeforeA, "B": deniedBeforeB} {
		monthly, inDefault := 0, per["denied_events_default"]
		for ch, n := range per {
			if ch != "denied_events_default" && n > 0 {
				monthly++
			}
		}
		if monthly < 2 || inDefault == 0 {
			t.Fatalf("denied_events seed for %s: %d monthly leaves with rows, default=%d, want ≥2 and >0: %v", name, monthly, inDefault, per)
		}
	}
	var deniedBSum int64
	for _, n := range deniedBeforeB {
		deniedBSum += n
	}
	if deniedBSum != deniedB {
		t.Fatalf("denied_events B per-child sum = %d, want the %d seeded (a row landed outside the children?)", deniedBSum, deniedB)
	}
	ifaceBefore := pgCountPerChild(t, d, "interface_stats", a.ID)
	if ifaceBefore["interface_stats_default"] == 0 || pgCount(t, d, "interface_stats", "device_id", a.ID) != ifaceA {
		t.Fatalf("interface_stats seed for A: %v (want %d total with rows in the DEFAULT child)", ifaceBefore, ifaceA)
	}
	t.Logf("interface_stats A per child: %v", ifaceBefore)
	t.Logf("denied_events A per child: %v; B per child: %v", deniedBeforeA, deniedBeforeB)

	// The batch subquery must be index-backed on every populated leaf: on the
	// parent and on each leaf the purge actually deletes from (the batch SQL
	// names the leaf). A holds ~97% of the rows, so the planner may walk the
	// timestamp index and filter; B (2.4%) must use the (device_id, timestamp)
	// index — the shape of almost every real purge.
	ifaceBeforeB := pgCountPerChild(t, d, "interface_stats", b.ID)
	t.Logf("EXPLAIN interface_stats (parent) device A: %v", assertIndexedScan(t, d, "interface_stats", a.ID, ifaceBefore, false))
	t.Logf("EXPLAIN interface_stats (parent) device B: %v", assertIndexedScan(t, d, "interface_stats", b.ID, ifaceBeforeB, true))
	for ch, n := range ifaceBefore {
		if n > 0 {
			t.Logf("EXPLAIN %s (leaf) device A: %v", ch, assertIndexedScan(t, d, ch, a.ID, ifaceBefore, false))
		}
	}
	for ch, n := range ifaceBeforeB {
		if n > 0 {
			t.Logf("EXPLAIN %s (leaf) device B: %v", ch, assertIndexedScan(t, d, ch, b.ID, ifaceBeforeB, true))
		}
	}

	counter := &batchCounter{counts: map[string]int{}}
	purgeBatchHook = counter.hook
	defer func() { purgeBatchHook = nil }()

	job := queueAndClaim(t, d, a)
	start := time.Now()
	if err := d.RunDevicePurge(context.Background(), job.ID); err != nil {
		t.Fatalf("RunDevicePurge: %v", err)
	}
	wall := time.Since(start)
	ifaceBatches := counter.total("interface_stats")
	t.Logf("purge wall time %s; %d rows deleted → %.0f rows/s; interface_stats batches=%d (%d rows per batch, %s inter-batch sleep), denied_events batches=%d, all relations=%d",
		wall.Round(time.Millisecond), plannedA, float64(plannedA)/wall.Seconds(), ifaceBatches,
		planEntry(t, "interface_stats").batch, purgeInterBatchSleep, counter.total("denied_events"), counter.total(""))
	if ifaceBatches < ifaceA/planEntry(t, "interface_stats").batch {
		t.Errorf("interface_stats batches = %d, want at least %d for %d rows", ifaceBatches, ifaceA/planEntry(t, "interface_stats").batch, ifaceA)
	}

	// Every A row gone from every relation, every child, and the DEFAULT child.
	for ch, n := range pgCountPerChild(t, d, "denied_events", a.ID) {
		if n != 0 {
			t.Errorf("denied_events child %s still holds %d rows of A", ch, n)
		}
	}
	for ch, n := range pgCountPerChild(t, d, "interface_stats", a.ID) {
		if n != 0 {
			t.Errorf("interface_stats child %s still holds %d rows of A", ch, n)
		}
	}
	for _, rel := range []string{"interface_stats", "denied_events", "alerts", "vpn_status", "device_config_revisions"} {
		if n := pgCount(t, d, rel, "device_id", a.ID); n != 0 {
			t.Errorf("%s still holds %d rows of A", rel, n)
		}
	}
	if n := pgCount(t, d, "ipsec_tunnels", "a_device_id", a.ID) + pgCount(t, d, "ipsec_tunnels", "b_device_id", a.ID); n != 0 {
		t.Errorf("ipsec_tunnels still references A: %d", n)
	}
	if n := pgCount(t, d, "device_connections", "source_device_id", a.ID) + pgCount(t, d, "device_connections", "dest_device_id", a.ID); n != 0 {
		t.Errorf("device_connections still references A: %d", n)
	}
	if deviceExists(t, d, a.ID) {
		t.Error("device A row still present")
	}

	// B intact — except the shared A↔B tunnel, removed by design.
	if got := pgCountPerChild(t, d, "denied_events", b.ID); fmt.Sprint(got) != fmt.Sprint(deniedBeforeB) {
		t.Errorf("denied_events B per child changed: before %v after %v", deniedBeforeB, got)
	}
	if n := pgCount(t, d, "interface_stats", "device_id", b.ID); n != ifaceB {
		t.Errorf("interface_stats B = %d, want %d", n, ifaceB)
	}
	for _, rel := range []string{"alerts", "vpn_status", "device_config_revisions"} {
		if n := pgCount(t, d, rel, "device_id", b.ID); n != 1 {
			t.Errorf("%s B = %d, want 1", rel, n)
		}
	}
	if n := pgCount(t, d, "ipsec_tunnels", "a_device_id", b.ID) + pgCount(t, d, "ipsec_tunnels", "b_device_id", b.ID); n != 0 {
		t.Errorf("B's shared tunnel with A survived (%d rows); the intent is one row and is removed with A by design", n)
	}
	if n := pgCount(t, d, "device_connections", "source_device_id", b.ID); n != 1 {
		t.Errorf("B→C connection = %d rows, want 1 (the purge must only clear A's)", n)
	}
	if !deviceExists(t, d, b.ID) || !deviceExists(t, d, c.ID) {
		t.Error("survivor device row deleted")
	}

	got, err := d.GetDevicePurgeJob(job.ID)
	if err != nil {
		t.Fatalf("reload job: %v", err)
	}
	if got.Status != DevicePurgeStatusDone || got.FinishedAt == nil {
		t.Errorf("job = %+v, want done", got)
	}
	if got.TablesDone != got.TablesTotal || got.TablesTotal != len(devicePurgeTables)+1 || got.CurrentTable != purgeFinalStep {
		t.Errorf("progress = %d/%d current=%q", got.TablesDone, got.TablesTotal, got.CurrentTable)
	}
	if got.RowsDeleted != plannedA {
		t.Errorf("rows_deleted = %d, want the seeded A total %d", got.RowsDeleted, plannedA)
	}
}

// TestPGPurge_CancelMidwayThenResume: with a 500-row batch on interface_stats,
// a cancel requested from another goroutine right after the first batch's
// progress callback is observed at the next between-batch check — the job ends
// `cancelled` after exactly two batches, the device is still retired with the
// remaining rows, and a new job resumes and completes.
func TestPGPurge_CancelMidwayThenResume(t *testing.T) {
	d := pgPurgeDB(t)
	a := seedRetiredDevice(t, d, "fw-cancel-pg")
	const rows, batch = 5000, 500
	// All 5,000 rows inside NEXT month's leaf (it always exists: current+6),
	// so the first non-empty relation holds > 2 batches whatever the date —
	// counting back from now() would straddle a month edge in the first ~80
	// minutes of a month and split the rows across two relations.
	seedIfaceStats(t, d, a.ID, rows, time.Second, "date_trunc('month', now()) + interval '2 months'")
	small := seedSmallRows(t, d, a, "cancel")

	entry := planEntry(t, "interface_stats")
	origBatch := entry.batch
	entry.batch = batch
	defer func() { entry.batch = origBatch }()

	job := queueAndClaim(t, d, a)
	firstBatchDone := make(chan struct{})
	cancelApplied := make(chan struct{})
	var once sync.Once
	go func() {
		<-firstBatchDone
		status, applied, err := d.CancelDevicePurgeJob(job.ID)
		if err != nil || !applied || status != DevicePurgeStatusCancelling {
			t.Errorf("cancel running job: status=%q applied=%v err=%v", status, applied, err)
		}
		close(cancelApplied)
	}()
	purgeBatchHook = func(table string, batchNo int) error {
		// batchNo 2 on a leaf = the first batch on it completed and its
		// progress callback ran. Block until the other goroutine has flipped
		// the row to `cancelling`, so batch 2's own progress check sees it.
		if strings.HasPrefix(table, "interface_stats") && batchNo == 2 {
			once.Do(func() { close(firstBatchDone) })
			select {
			case <-cancelApplied:
			case <-time.After(10 * time.Second):
				t.Error("cancel goroutine did not apply within 10 s")
			}
		}
		return nil
	}
	defer func() { purgeBatchHook = nil }()

	if err := d.RunDevicePurge(context.Background(), job.ID); err != nil {
		t.Fatalf("RunDevicePurge: %v (a cancel is not an error)", err)
	}
	got, _ := d.GetDevicePurgeJob(job.ID)
	if got.Status != DevicePurgeStatusCancelled || got.FinishedAt == nil {
		t.Fatalf("job = %+v, want cancelled", got)
	}
	remaining := pgCount(t, d, "interface_stats", "device_id", a.ID)
	if got.RowsDeleted != 2*batch || remaining != rows-2*batch {
		t.Errorf("after cancel: rows_deleted=%d remaining=%d, want %d and %d (two batches of %d)", got.RowsDeleted, remaining, 2*batch, rows-2*batch, batch)
	}
	if !deviceExists(t, d, a.ID) {
		t.Fatal("device row deleted by a cancelled purge")
	}
	if !deviceRetired(t, d, a.ID) {
		t.Error("device un-retired by a cancelled purge")
	}
	if n := pgCount(t, d, "alerts", "device_id", a.ID); n != 1 {
		t.Errorf("alerts (a later plan table) touched by a cancelled run: %d rows, want 1", n)
	}

	// Resume: a new job finishes from what remains.
	purgeBatchHook = nil
	if active, _ := d.GetActiveDevicePurgeJob(a.ID); active != nil {
		t.Fatalf("cancelled job still counts as active: %+v", active)
	}
	job2 := queueAndClaim(t, d, a)
	if err := d.RunDevicePurge(context.Background(), job2.ID); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	got2, _ := d.GetDevicePurgeJob(job2.ID)
	if got2.Status != DevicePurgeStatusDone || got2.TablesDone != got2.TablesTotal {
		t.Errorf("re-run job = %+v, want done", got2)
	}
	if got2.RowsDeleted != remaining+small {
		t.Errorf("re-run rows_deleted = %d, want %d (the remaining stats + %d small rows)", got2.RowsDeleted, remaining+small, small)
	}
	if n := pgCount(t, d, "interface_stats", "device_id", a.ID); n != 0 || deviceExists(t, d, a.ID) {
		t.Errorf("after re-run: %d rows remain, deviceExists=%v", n, deviceExists(t, d, a.ID))
	}
}

// TestPGPurge_PartitionDroppedMidRun: after the first batch on a denied_events
// leaf, another connection DROPs that leaf (what retention does to an aged-out
// month). The next batch fails with SQLSTATE 42P01; purgeTableRows must
// re-enumerate the children and finish the remaining leaves — the job ends
// `done` and no A row survives anywhere.
func TestPGPurge_PartitionDroppedMidRun(t *testing.T) {
	d := pgPurgeDB(t)
	a := seedRetiredDevice(t, d, "fw-drop-pg")
	b := newDevice(t, d, "fw-drop-survivor", "10.0.0.2")
	// 3 buckets × 400 = 1,200 A rows: the current-month leaf holds 400, so a
	// 100-row batch reaches batch 2 there. Which leaf comes first is decided
	// by purgeRelations (oldest range first, DEFAULT last): the current
	// month. Its name is captured from the hook, not assumed.
	seedDeniedEvents(t, d, a.ID, 400)
	seedDeniedEvents(t, d, b.ID, 40)
	deniedBeforeB := pgCountPerChild(t, d, "denied_events", b.ID)

	entry := planEntry(t, "denied_events")
	origBatch := entry.batch
	entry.batch = 100
	defer func() { entry.batch = origBatch }()

	// A second, independent connection pool for the DROP — the retention
	// cron or an operator session, not the purge's own handle.
	other, err := Connect(integrationCfgFromDSN(t, strings.TrimSpace(os.Getenv("TEST_PG_DSN"))))
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	defer other.Close()

	var logBuf bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prevOut)

	var dropped string
	var once sync.Once
	purgeBatchHook = func(table string, batchNo int) error {
		if strings.HasPrefix(table, "denied_events_") && table != "denied_events_default" && batchNo == 2 {
			once.Do(func() {
				dropped = table
				if err := other.Gorm().Exec("DROP TABLE " + table).Error; err != nil {
					t.Errorf("drop %s from the other connection: %v", table, err)
				}
			})
		}
		return nil
	}
	defer func() { purgeBatchHook = nil }()

	job := queueAndClaim(t, d, a)
	runErr := d.RunDevicePurge(context.Background(), job.ID)
	log.SetOutput(prevOut)
	if runErr != nil {
		t.Fatalf("RunDevicePurge: %v\nlog:\n%s", runErr, logBuf.String())
	}
	if dropped == "" {
		t.Fatal("the hook never saw a second batch on a monthly denied_events leaf; the drop path was not exercised")
	}
	if !strings.Contains(logBuf.String(), "partition "+dropped+" of denied_events vanished mid-run") {
		t.Errorf("42P01 re-enumeration did not fire for %s; log:\n%s", dropped, logBuf.String())
	}
	var exists bool
	if err := d.db.Raw("SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = ?)", dropped).Scan(&exists).Error; err != nil || exists {
		t.Errorf("%s should be gone (err=%v exists=%v)", dropped, err, exists)
	}

	got, _ := d.GetDevicePurgeJob(job.ID)
	if got.Status != DevicePurgeStatusDone || got.TablesDone != got.TablesTotal {
		t.Fatalf("job = %+v, want done; log:\n%s", got, logBuf.String())
	}
	if n := pgCount(t, d, "denied_events", "device_id", a.ID); n != 0 {
		t.Errorf("denied_events still holds %d rows of A after the re-enumeration", n)
	}
	for ch, n := range pgCountPerChild(t, d, "denied_events", a.ID) {
		if n != 0 {
			t.Errorf("denied_events child %s still holds %d rows of A", ch, n)
		}
	}
	if deviceExists(t, d, a.ID) {
		t.Error("device row still present")
	}
	// B: intact in every leaf that still exists (the dropped leaf took B's
	// rows with it — that is the DROP, not the purge).
	for ch, n := range pgCountPerChild(t, d, "denied_events", b.ID) {
		if n != deniedBeforeB[ch] {
			t.Errorf("denied_events B in %s = %d, want %d", ch, n, deniedBeforeB[ch])
		}
	}
	t.Logf("dropped %s after its first batch; job rows_deleted=%d (excludes the %d A rows the DROP took)", dropped, got.RowsDeleted, 400-100)
}
