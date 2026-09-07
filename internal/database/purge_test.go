package database

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"gorm.io/gorm/schema"
)

// seedDeviceRows inserts one row keyed to deviceID into EVERY device-keyed
// table of the test harness (reflection over testModels), including
// device_connections (both directions) and the two-column ipsec_tunnels (one
// row with the device on each end). String columns get unique values so the
// NOT NULL / unique-index tables (device_tunnels.name, probe_commands.
// command_id, ipsec_tunnels.name, ping_stats (device,target), ...) accept
// them; *uint device columns are set to &deviceID. Returns the number of rows
// the purge plan is expected to delete (everything except device_connections
// and the job table, which are outside devicePurgeTables).
func seedDeviceRows(t *testing.T, d *Database, deviceID uint, tag string) (planned int64) {
	t.Helper()
	var cache sync.Map
	seq := 0
	uniq := func(table, col string) string {
		seq++
		return fmt.Sprintf("%s-%s-%s-%d", tag, table, col, seq)
	}
	for _, m := range testModels {
		s, err := schema.Parse(m, &cache, schema.NamingStrategy{})
		if err != nil {
			t.Fatalf("schema.Parse(%T): %v", m, err)
		}
		if s.Table == "device_purge_jobs" {
			continue
		}
		var keyCols []string
		for _, f := range s.Fields {
			if deviceKeyColumns[f.DBName] {
				keyCols = append(keyCols, f.DBName)
			}
		}
		if len(keyCols) == 0 {
			continue
		}
		// One row per device-keyed column, with THAT column set to the device
		// (the other key column, if any, points at nobody: 0).
		for _, keyCol := range keyCols {
			v := reflect.New(reflect.TypeOf(m).Elem()).Elem()
			for _, f := range s.Fields {
				if f.DBName == "" {
					continue
				}
				fv := v.FieldByName(f.Name)
				if !fv.IsValid() || !fv.CanSet() {
					continue
				}
				switch {
				case f.DBName == keyCol:
					switch fv.Kind() {
					case reflect.Uint, reflect.Uint32, reflect.Uint64:
						fv.SetUint(uint64(deviceID))
					case reflect.Ptr:
						p := reflect.New(fv.Type().Elem())
						p.Elem().SetUint(uint64(deviceID))
						fv.Set(p)
					default:
						t.Fatalf("%s.%s: unexpected kind %s for a device key", s.Table, f.DBName, fv.Kind())
					}
				case deviceKeyColumns[f.DBName]:
					// the other end of a two-column table: leave 0/nil
				case fv.Kind() == reflect.String:
					fv.SetString(uniq(s.Table, f.DBName))
				case fv.Type() == reflect.TypeOf(time.Time{}):
					fv.Set(reflect.ValueOf(time.Now().Add(-time.Hour)))
				}
			}
			if err := d.db.Table(s.Table).Create(v.Addr().Interface()).Error; err != nil {
				t.Fatalf("seed %s (%s=%d): %v", s.Table, keyCol, deviceID, err)
			}
			if s.Table != "device_connections" {
				planned++
			}
		}
	}
	return planned
}

// countDeviceRows sums, over every device-keyed table (incl. device_connections),
// the rows keyed to deviceID on any of its key columns.
func countDeviceRows(t *testing.T, d *Database, deviceID uint) (total int64, perTable map[string]int64) {
	t.Helper()
	perTable = map[string]int64{}
	for table, cols := range deviceKeyedTables(t, testModels) {
		if table == "device_purge_jobs" {
			continue
		}
		for _, col := range cols {
			var n int64
			if err := d.db.Raw(fmt.Sprintf("SELECT count(*) FROM %s WHERE %s = ?", table, col), deviceID).Scan(&n).Error; err != nil {
				t.Fatalf("count %s.%s: %v", table, col, err)
			}
			perTable[table] += n
			total += n
		}
	}
	return total, perTable
}

func seedRetiredDevice(t *testing.T, d *Database, name string) *models.Device {
	t.Helper()
	dev := &models.Device{Name: name, IPAddress: "10.0.0.1"}
	if err := d.db.Create(dev).Error; err != nil {
		t.Fatalf("create device %s: %v", name, err)
	}
	if err := d.RetireDevice(dev.ID); err != nil {
		t.Fatalf("retire %s: %v", name, err)
	}
	return dev
}

func queueAndClaim(t *testing.T, d *Database, dev *models.Device) *models.DevicePurgeJob {
	t.Helper()
	job := &models.DevicePurgeJob{DeviceID: dev.ID, DeviceUUID: dev.UUID, DeviceName: dev.Name, RequestedBy: "admin1"}
	if err := d.CreateDevicePurgeJob(job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	won, err := d.ClaimDevicePurgeJob(job.ID)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	return job
}

func deviceExists(t *testing.T, d *Database, id uint) bool {
	t.Helper()
	var n int64
	if err := d.db.Model(&models.Device{}).Where("id = ?", id).Count(&n).Error; err != nil {
		t.Fatalf("count devices: %v", err)
	}
	return n > 0
}

// TestRunDevicePurge_RemovesExactlyTheDevice: one row in every device-keyed
// table for the doomed device and for a survivor, plus device_id=0 rows in the
// tables that legitimately carry them; the purge removes exactly the doomed
// device's rows (both ends of the two-column tables), deletes its device row,
// and the job's progress fields land at the end state.
func TestRunDevicePurge_RemovesExactlyTheDevice(t *testing.T) {
	d := NewDatabaseForTesting(t)
	doomed := seedRetiredDevice(t, d, "fw-doomed")
	survivor := &models.Device{Name: "fw-survivor", IPAddress: "10.0.0.2"}
	if err := d.db.Create(survivor).Error; err != nil {
		t.Fatalf("create survivor: %v", err)
	}
	planned := seedDeviceRows(t, d, doomed.ID, "doomed")
	seedDeviceRows(t, d, survivor.ID, "survivor")
	survivorBefore, _ := countDeviceRows(t, d, survivor.ID)

	// device_id = 0 rows: agent/cross-device detections, probe-level commands,
	// a probe-scoped alert. The purge must never match 0.
	for _, row := range []interface{}{
		&models.FlowDetection{DeviceID: 0, Detector: "x", DedupKey: "zero-1", DetectedAt: time.Now()},
		&models.ProbeCommand{DeviceID: 0, ProbeID: 1, CommandID: "zero-cmd", Type: "noop"},
		&models.Alert{DeviceID: 0, Message: "probe offline", Timestamp: time.Now()},
	} {
		if err := d.db.Create(row).Error; err != nil {
			t.Fatalf("seed device_id=0 row %T: %v", row, err)
		}
	}
	// Count ONLY the single-column tables' device_id=0 rows: the two-column
	// tables seeded above carry 0 on their "other end", and those rows are
	// legitimately deleted through the doomed device's column.
	countZero := func() (n int64) {
		for _, table := range []string{"flow_detections", "probe_commands", "alerts"} {
			var c int64
			if err := d.db.Raw(fmt.Sprintf("SELECT count(*) FROM %s WHERE device_id = 0", table)).Scan(&c).Error; err != nil {
				t.Fatalf("count %s device_id=0: %v", table, err)
			}
			n += c
		}
		return n
	}
	zeroBefore := countZero()
	if zeroBefore != 3 {
		t.Fatalf("device_id=0 seed: %d rows, want 3", zeroBefore)
	}

	doomedBefore, per := countDeviceRows(t, d, doomed.ID)
	if doomedBefore == 0 || per["ipsec_tunnels"] != 2 || per["device_connections"] != 2 {
		t.Fatalf("seed shape: total=%d ipsec=%d conns=%d", doomedBefore, per["ipsec_tunnels"], per["device_connections"])
	}

	job := queueAndClaim(t, d, doomed)
	if err := d.RunDevicePurge(context.Background(), job.ID); err != nil {
		t.Fatalf("RunDevicePurge: %v", err)
	}

	after, perAfter := countDeviceRows(t, d, doomed.ID)
	if after != 0 {
		t.Errorf("rows still keyed to the purged device: %d %v", after, perAfter)
	}
	if deviceExists(t, d, doomed.ID) {
		t.Error("device row still present after a successful purge")
	}
	if got, _ := countDeviceRows(t, d, survivor.ID); got != survivorBefore {
		t.Errorf("survivor rows = %d, want %d (purge touched another device)", got, survivorBefore)
	}
	if !deviceExists(t, d, survivor.ID) {
		t.Error("survivor device row deleted")
	}
	if got := countZero(); got != zeroBefore {
		t.Errorf("device_id=0 rows = %d, want %d (purge must never match 0)", got, zeroBefore)
	}

	got, err := d.GetDevicePurgeJob(job.ID)
	if err != nil {
		t.Fatalf("reload job: %v", err)
	}
	if got.Status != DevicePurgeStatusDone || got.FinishedAt == nil || got.StartedAt == nil {
		t.Errorf("job = %+v, want done with started/finished set", got)
	}
	if got.RowsDeleted != planned {
		t.Errorf("rows_deleted = %d, want %d (one row per planned table/column)", got.RowsDeleted, planned)
	}
	if got.TablesTotal != len(devicePurgeTables)+1 || got.TablesDone != got.TablesTotal || got.CurrentTable != purgeFinalStep {
		t.Errorf("progress = %d/%d current=%q, want %d/%d current=%q", got.TablesDone, got.TablesTotal, got.CurrentTable,
			len(devicePurgeTables)+1, len(devicePurgeTables)+1, purgeFinalStep)
	}
	if got.DeviceUUID != doomed.UUID || got.DeviceName != "fw-doomed" {
		t.Errorf("job keeps device identity: uuid=%q name=%q", got.DeviceUUID, got.DeviceName)
	}
}

// TestRunDevicePurge_FailedBatchLeavesDeviceRetired: a batch error (test hook
// on the LAST plan table) ends the job as failed with the message, and the
// device row — deleted only after every table — is still there, still retired.
func TestRunDevicePurge_FailedBatchLeavesDeviceRetired(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-fail")
	seedDeviceRows(t, d, dev.ID, "fail")
	last := devicePurgeTables[len(devicePurgeTables)-1].table

	purgeBatchHook = func(table string, batchNo int) error {
		if table == last {
			return errors.New("simulated batch failure")
		}
		return nil
	}
	defer func() { purgeBatchHook = nil }()

	job := queueAndClaim(t, d, dev)
	err := d.RunDevicePurge(context.Background(), job.ID)
	if err == nil || !strings.Contains(err.Error(), "simulated batch failure") {
		t.Fatalf("RunDevicePurge err = %v, want the simulated failure", err)
	}
	got, _ := d.GetDevicePurgeJob(job.ID)
	if got.Status != DevicePurgeStatusFailed || !strings.Contains(got.Error, "simulated batch failure") || got.FinishedAt == nil {
		t.Errorf("job = %+v, want failed with the error recorded", got)
	}
	if got.CurrentTable != last {
		t.Errorf("current_table = %q, want %q (where it failed)", got.CurrentTable, last)
	}
	if !deviceExists(t, d, dev.ID) {
		t.Fatal("device row deleted although a table failed — the row must be deleted LAST")
	}
	reloaded, _ := d.GetDevice(dev.ID)
	if reloaded.RetiredAt == nil {
		t.Error("device un-retired by a failed purge")
	}
	// Earlier tables were emptied, the failing one was not.
	_, per := countDeviceRows(t, d, dev.ID)
	if per[devicePurgeTables[0].table] != 0 || per[last] != 1 {
		t.Errorf("per-table after failure: first=%d last=%d, want 0 and 1", per[devicePurgeTables[0].table], per[last])
	}
	// A retry is a NEW job (the failed one is terminal) and completes.
	purgeBatchHook = nil
	if active, _ := d.GetActiveDevicePurgeJob(dev.ID); active != nil {
		t.Fatalf("failed job still counts as active: %+v", active)
	}
	job2 := queueAndClaim(t, d, dev)
	if err := d.RunDevicePurge(context.Background(), job2.ID); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if deviceExists(t, d, dev.ID) {
		t.Error("device still present after the re-run")
	}
}

// TestRunDevicePurge_CancelBetweenBatches: with a tiny batch size the cancel
// endpoint's `cancelling` flip is observed between batches — the job ends
// `cancelled`, the device stays retired with partial data, and a later purge
// resumes and completes.
func TestRunDevicePurge_CancelBetweenBatches(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-cancel")
	for i := 0; i < 10; i++ {
		if err := d.db.Create(&models.SyslogMessage{DeviceID: dev.ID, Message: fmt.Sprintf("m%d", i), Timestamp: time.Now()}).Error; err != nil {
			t.Fatalf("seed syslog: %v", err)
		}
	}
	origBatch := devicePurgeTables[0].batch
	devicePurgeTables[0].batch = 2 // syslog_messages: 5 batches of 2
	defer func() { devicePurgeTables[0].batch = origBatch }()

	job := queueAndClaim(t, d, dev)
	purgeBatchHook = func(table string, batchNo int) error {
		if table == "syslog_messages" && batchNo == 2 {
			status, applied, err := d.CancelDevicePurgeJob(job.ID)
			if err != nil || !applied || status != DevicePurgeStatusCancelling {
				t.Errorf("cancel running job: status=%q applied=%v err=%v", status, applied, err)
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
	var remaining int64
	d.db.Model(&models.SyslogMessage{}).Where("device_id = ?", dev.ID).Count(&remaining)
	if remaining != 6 || got.RowsDeleted != 4 {
		t.Errorf("after cancel: remaining=%d rows_deleted=%d, want 6 and 4 (two batches of two)", remaining, got.RowsDeleted)
	}
	if !deviceExists(t, d, dev.ID) {
		t.Fatal("device row deleted by a cancelled purge")
	}

	// Re-run resumes from whatever is left.
	purgeBatchHook = nil
	job2 := queueAndClaim(t, d, dev)
	if err := d.RunDevicePurge(context.Background(), job2.ID); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	got2, _ := d.GetDevicePurgeJob(job2.ID)
	d.db.Model(&models.SyslogMessage{}).Where("device_id = ?", dev.ID).Count(&remaining)
	if got2.Status != DevicePurgeStatusDone || remaining != 0 || deviceExists(t, d, dev.ID) {
		t.Errorf("re-run: status=%q remaining=%d deviceExists=%v", got2.Status, remaining, deviceExists(t, d, dev.ID))
	}
	if got2.RowsDeleted != 6 {
		t.Errorf("re-run rows_deleted = %d, want the 6 that remained", got2.RowsDeleted)
	}
}

// TestRunDevicePurge_ShutdownReturnsJobToPending: a cancelled parent context
// (graceful shutdown) does not fail the job — it goes back to pending so the
// next primary resumes it.
func TestRunDevicePurge_ShutdownReturnsJobToPending(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-shutdown")
	seedDeviceRows(t, d, dev.ID, "shutdown")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	purgeBatchHook = func(table string, batchNo int) error {
		if table == devicePurgeTables[3].table {
			cancel() // "shutdown" arrives while the 4th table is being processed
		}
		return nil
	}
	defer func() { purgeBatchHook = nil }()

	job := queueAndClaim(t, d, dev)
	err := d.RunDevicePurge(ctx, job.ID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDevicePurge err = %v, want context.Canceled", err)
	}
	got, _ := d.GetDevicePurgeJob(job.ID)
	if got.Status != DevicePurgeStatusPending || got.FinishedAt != nil {
		t.Fatalf("job = %+v, want pending (resumable) after shutdown", got)
	}
	if !deviceExists(t, d, dev.ID) {
		t.Fatal("device row deleted by an interrupted purge")
	}
	// The next primary claims and finishes it.
	won, err := d.ClaimDevicePurgeJob(job.ID)
	if err != nil || !won {
		t.Fatalf("re-claim after shutdown: won=%v err=%v", won, err)
	}
	if err := d.RunDevicePurge(context.Background(), job.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got, _ := d.GetDevicePurgeJob(job.ID); got.Status != DevicePurgeStatusDone {
		t.Errorf("resumed job status = %q, want done", got.Status)
	}
}

// TestRequeueStaleDevicePurgeJobs: a running job with an old heartbeat is
// requeued; a fresh one is not; a stale cancelling one is finished cancelled.
func TestRequeueStaleDevicePurgeJobs(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-stale")
	mk := func(status string, age time.Duration) uint {
		job := &models.DevicePurgeJob{DeviceID: dev.ID, DeviceName: dev.Name}
		if err := d.CreateDevicePurgeJob(job); err != nil {
			t.Fatalf("create: %v", err)
		}
		// UpdateColumns bypasses GORM's auto-updated_at so the heartbeat age
		// is exactly what the test sets.
		if err := d.db.Model(&models.DevicePurgeJob{}).Where("id = ?", job.ID).
			UpdateColumns(map[string]interface{}{"status": status, "updated_at": time.Now().Add(-age)}).Error; err != nil {
			t.Fatalf("age job: %v", err)
		}
		return job.ID
	}
	stale := mk(DevicePurgeStatusRunning, 3*time.Minute)
	fresh := mk(DevicePurgeStatusRunning, 10*time.Second)
	staleCancelling := mk(DevicePurgeStatusCancelling, 3*time.Minute)
	done := mk(DevicePurgeStatusDone, 24*time.Hour)

	n, err := d.RequeueStaleDevicePurgeJobs(purgeStaleAfter)
	if err != nil || n != 1 {
		t.Fatalf("requeue: n=%d err=%v, want 1", n, err)
	}
	want := map[uint]string{
		stale: DevicePurgeStatusPending, fresh: DevicePurgeStatusRunning,
		staleCancelling: DevicePurgeStatusCancelled, done: DevicePurgeStatusDone,
	}
	for id, status := range want {
		got, _ := d.GetDevicePurgeJob(id)
		if got.Status != status {
			t.Errorf("job %d status = %q, want %q", id, got.Status, status)
		}
	}
	// The requeued job is claimable and finishes.
	won, err := d.ClaimDevicePurgeJob(stale)
	if err != nil || !won {
		t.Fatalf("claim requeued: won=%v err=%v", won, err)
	}
	if err := d.RunDevicePurge(context.Background(), stale); err != nil {
		t.Fatalf("run requeued: %v", err)
	}
	if got, _ := d.GetDevicePurgeJob(stale); got.Status != DevicePurgeStatusDone {
		t.Errorf("requeued job status = %q, want done", got.Status)
	}
}

// TestClaimDevicePurgeJob_CASRejectsSecondClaimant: the pending→running claim
// is a compare-and-set, so exactly one claimant wins; ClaimNext walks the
// queue in id order and returns nil on an empty queue.
func TestClaimDevicePurgeJob_CASRejectsSecondClaimant(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-cas")
	if j, err := d.ClaimNextDevicePurgeJob(); err != nil || j != nil {
		t.Fatalf("empty queue: job=%v err=%v", j, err)
	}
	job := &models.DevicePurgeJob{DeviceID: dev.ID}
	if err := d.CreateDevicePurgeJob(job); err != nil {
		t.Fatal(err)
	}
	first, err := d.ClaimDevicePurgeJob(job.ID)
	if err != nil || !first {
		t.Fatalf("first claim: won=%v err=%v", first, err)
	}
	second, err := d.ClaimDevicePurgeJob(job.ID)
	if err != nil || second {
		t.Fatalf("second claim: won=%v err=%v, want false", second, err)
	}
	if j, _ := d.ClaimNextDevicePurgeJob(); j != nil {
		t.Errorf("ClaimNext found a claimable job after the CAS: %+v", j)
	}
	got, _ := d.GetDevicePurgeJob(job.ID)
	if got.Status != DevicePurgeStatusRunning || got.StartedAt == nil {
		t.Errorf("claimed job = %+v", got)
	}
}

// TestCancelDevicePurgeJob_Transitions: pending → cancelled, running →
// cancelling, terminal → not applied.
func TestCancelDevicePurgeJob_Transitions(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-xfer")
	job := &models.DevicePurgeJob{DeviceID: dev.ID}
	if err := d.CreateDevicePurgeJob(job); err != nil {
		t.Fatal(err)
	}
	if st, ok, err := d.CancelDevicePurgeJob(job.ID); err != nil || !ok || st != DevicePurgeStatusCancelled {
		t.Fatalf("cancel pending: st=%q ok=%v err=%v", st, ok, err)
	}
	if got, _ := d.GetDevicePurgeJob(job.ID); got.FinishedAt == nil {
		t.Error("cancelled pending job has no finished_at")
	}
	if st, ok, _ := d.CancelDevicePurgeJob(job.ID); ok || st != "" {
		t.Errorf("cancel of a cancelled job applied: st=%q", st)
	}
	job2 := queueAndClaim(t, d, dev)
	if st, ok, err := d.CancelDevicePurgeJob(job2.ID); err != nil || !ok || st != DevicePurgeStatusCancelling {
		t.Fatalf("cancel running: st=%q ok=%v err=%v", st, ok, err)
	}
	if active, _ := d.GetActiveDevicePurgeJob(dev.ID); active == nil || active.ID != job2.ID {
		t.Errorf("cancelling job must still count as active: %+v", active)
	}
	list, err := d.ListDevicePurgeJobs(20)
	if err != nil || len(list) != 2 || list[0].ID != job2.ID || list[1].ID != job.ID {
		t.Errorf("ListDevicePurgeJobs = %+v err=%v, want active first then terminal", list, err)
	}
}

// TestEstimateDevicePurge_CappedCounts: per-table counts stop at the cap and
// report capped=true; tunnels list the peer device's name.
func TestEstimateDevicePurge_CappedCounts(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-est")
	peer := &models.Device{Name: "fw-peer", IPAddress: "10.0.0.9"}
	if err := d.db.Create(peer).Error; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := d.db.Create(&models.SyslogMessage{DeviceID: dev.ID, Message: "m", Timestamp: time.Now()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := d.db.Create(&models.InterfaceStats{DeviceID: dev.ID, Name: "port1", Timestamp: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	for _, tun := range []*models.IPSecTunnel{
		{Name: "hq-to-branch", ADeviceID: peer.ID, BDeviceID: dev.ID, Status: "up"},
		{Name: "branch-to-hq", ADeviceID: dev.ID, BDeviceID: peer.ID, Status: "draft"},
		{Name: "elsewhere", ADeviceID: peer.ID, BDeviceID: 0, Status: "draft"},
	} {
		if err := d.db.Create(tun).Error; err != nil {
			t.Fatal(err)
		}
	}
	orig := purgeEstimateCap
	purgeEstimateCap = 3
	defer func() { purgeEstimateCap = orig }()

	est, err := d.EstimateDevicePurge(dev.ID)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	byTable := map[string]DevicePurgeEstimateTable{}
	for _, row := range est.Tables {
		byTable[row.Table] = row
	}
	if len(est.Tables) != len(devicePurgeTables) {
		t.Errorf("estimate lists %d tables, want %d", len(est.Tables), len(devicePurgeTables))
	}
	if r := byTable["syslog_messages"]; !r.Capped || r.Rows != 2 {
		t.Errorf("syslog_messages = %+v, want capped with rows=cap-1", r)
	}
	if r := byTable["interface_stats"]; r.Capped || r.Rows != 1 {
		t.Errorf("interface_stats = %+v, want exact 1", r)
	}
	if r := byTable["ipsec_tunnels"]; r.Capped || r.Rows != 2 {
		t.Errorf("ipsec_tunnels = %+v, want 2 (one per end)", r)
	}
	if est.Total != 2+1+2 {
		t.Errorf("total = %d, want 5", est.Total)
	}
	if len(est.Tunnels) != 2 {
		t.Fatalf("tunnels = %+v, want the two referencing the device", est.Tunnels)
	}
	for _, tn := range est.Tunnels {
		if tn.PeerDevice != "fw-peer" || tn.ID == 0 || tn.Name == "" {
			t.Errorf("tunnel %+v, want peer fw-peer", tn)
		}
	}
}

// TestDevicePurgeWorker_Tick: one tick claims and runs the oldest pending job
// to completion; a second tick on an empty queue is a no-op.
func TestDevicePurgeWorker_Tick(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-tick")
	seedDeviceRows(t, d, dev.ID, "tick")
	job := &models.DevicePurgeJob{DeviceID: dev.ID, DeviceName: dev.Name}
	if err := d.CreateDevicePurgeJob(job); err != nil {
		t.Fatal(err)
	}
	w := NewDevicePurgeWorker(d)
	w.Tick(context.Background())
	got, _ := d.GetDevicePurgeJob(job.ID)
	if got.Status != DevicePurgeStatusDone || deviceExists(t, d, dev.ID) {
		t.Fatalf("after tick: status=%q deviceExists=%v", got.Status, deviceExists(t, d, dev.ID))
	}
	w.Tick(context.Background()) // empty queue: nothing to do, no panic
	if list, _ := d.ListDevicePurgeJobs(20); len(list) != 1 {
		t.Errorf("jobs after idle tick = %d, want 1", len(list))
	}
}

// TestCleanupOldData_PrunesTerminalPurgeJobs: terminal jobs older than 30 days
// are removed by retention; live and recent ones are kept.
func TestCleanupOldData_PrunesTerminalPurgeJobs(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := seedRetiredDevice(t, d, "fw-ret")
	mk := func(status string, age time.Duration) uint {
		job := &models.DevicePurgeJob{DeviceID: dev.ID}
		if err := d.CreateDevicePurgeJob(job); err != nil {
			t.Fatal(err)
		}
		if err := d.db.Model(&models.DevicePurgeJob{}).Where("id = ?", job.ID).
			UpdateColumns(map[string]interface{}{"status": status, "updated_at": time.Now().Add(-age)}).Error; err != nil {
			t.Fatal(err)
		}
		return job.ID
	}
	oldDone := mk(DevicePurgeStatusDone, 40*24*time.Hour)
	oldFailed := mk(DevicePurgeStatusFailed, 40*24*time.Hour)
	oldPending := mk(DevicePurgeStatusPending, 40*24*time.Hour)
	recentDone := mk(DevicePurgeStatusDone, 24*time.Hour)

	if err := d.CleanupOldData(config.RetentionConfig{}); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}
	for id, wantGone := range map[uint]bool{oldDone: true, oldFailed: true, oldPending: false, recentDone: false} {
		_, err := d.GetDevicePurgeJob(id)
		gone := err != nil
		if gone != wantGone {
			t.Errorf("job %d gone=%v, want %v", id, gone, wantGone)
		}
	}
}
