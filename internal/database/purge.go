package database

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync/atomic"
	"time"

	"firewall-mon/internal/models"
)

// Permanent device purge (v0.11.243).
//
// Retire keeps every row. The purge is the explicit "remove the data too"
// path: an admin-only, re-authenticated, name-confirmed job that the API's
// primary instance runs in the background — batched so a device with tens of
// millions of syslog rows never takes a long lock, resumable (every predicate
// is idempotent, so a cancelled or failed job re-runs from whatever remains),
// and cancellable between batches. The device row is deleted LAST, through the
// existing DeleteDevice, so a job that stops early leaves a retired device with
// partial data — never a dangling device_id.

// purgeTable is one entry of the purge plan. Every field is a compile-time
// literal from this file: the SQL in batchedDeleteWhere / EstimateDevicePurge
// is built from these strings, so nothing here may ever come from a caller.
type purgeTable struct {
	table string
	// columns are the device-keyed columns; the loop runs once per column with
	// the predicate `<col> = ?` (never IS NULL, never 0 — rows with device_id
	// 0 are agent/cross-device rows that belong to no device).
	columns []string
	// orderBy is the subquery's ORDER BY: the timestamp column for every table
	// with a (device_id, <ts>) index (walks the index instead of a seq scan),
	// `id` for the rest.
	orderBy string
	// batch overrides cleanupDeleteBatchSize for the widest tables (0 = default).
	batch int
}

// devicePurgeTables is the purge plan in deletion order: largest tables first
// (so a cancelled job has reclaimed the most), the device's own config and
// alert rows last, then DeleteDevice (which also clears device_connections).
// TestDevicePurgeTables_CoverEveryDeviceKeyedModel reflects over every model
// in baselineModels/testModels and fails if a device-keyed table is missing.
var devicePurgeTables = []purgeTable{
	{table: "syslog_messages", columns: []string{"device_id"}, orderBy: "timestamp", batch: 2000},
	{table: "interface_stats", columns: []string{"device_id"}, orderBy: "timestamp", batch: 2000},
	{table: "hardware_sensors", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "processor_stats", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "vpn_status", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "ping_results", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "system_status", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "flow_samples", columns: []string{"device_id"}, orderBy: "timestamp", batch: 2000},
	{table: "trap_events", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "denied_events", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "syslog_summaries", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "flow_if_counters", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "flow_rollups", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "interface_errors", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "process_stats", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "ha_status", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "security_stats", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "sdwan_health", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "license_info", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "disk_usage", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "load_average", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "uptime_records", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "interface_addresses", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "topology_entries", columns: []string{"device_id"}, orderBy: "id"},
	{table: "topology_neighbors", columns: []string{"device_id"}, orderBy: "id"},
	{table: "ping_stats", columns: []string{"device_id"}, orderBy: "id"},
	{table: "flow_detections", columns: []string{"device_id"}, orderBy: "id"},
	{table: "probe_commands", columns: []string{"device_id"}, orderBy: "id"},
	{table: "device_tunnels", columns: []string{"device_id"}, orderBy: "id"},
	{table: "device_alert_configs", columns: []string{"device_id"}, orderBy: "id"},
	{table: "event_rules", columns: []string{"device_id"}, orderBy: "id"},
	{table: "maintenance_windows", columns: []string{"device_id"}, orderBy: "id"},
	// Shared row: a tunnel intent references two devices. Deleting it removes
	// the intent for the peer as well — the handler refuses the purge while any
	// tunnel on the device is deploying/verifying/rolling_back, and the
	// estimate lists the tunnels with their peer so the operator sees it.
	{table: "ipsec_tunnels", columns: []string{"a_device_id", "b_device_id"}, orderBy: "id"},
	{table: "device_config_revisions", columns: []string{"device_id"}, orderBy: "id"},
	{table: "alerts", columns: []string{"device_id"}, orderBy: "timestamp"},
	{table: "incidents", columns: []string{"device_id"}, orderBy: "id"},
}

// purgeFinalStep is the CurrentTable value of the last step (DeleteDevice).
const purgeFinalStep = "devices"

// purgeStaleAfter is the heartbeat window after which a `running` job is
// considered orphaned and requeued (RequeueStaleDevicePurgeJobs).
const purgeStaleAfter = 2 * time.Minute

// purgeHeartbeatInterval is how often a run touches its job's updated_at
// independently of batch progress. A single batch is bounded by the 120 s
// statement_timeout and a lock-wait retry sequence can exceed purgeStaleAfter
// without deleting a row, so progress alone would let a LIVE job be requeued.
var purgeHeartbeatInterval = 30 * time.Second

// errPurgeCancelled is the context cause a run uses when it observes the
// `cancelling` status between batches.
var errPurgeCancelled = errors.New("purge cancelled")

// purgeRelations returns the relations to run the batched delete against for
// one plan table: on a Postgres RANGE-partitioned parent, every child from
// pg_inherits INCLUDING the DEFAULT partition (unlike dropPartitionsOlderThan,
// which must skip it), oldest first; otherwise (SQLite, or a plain table as on
// a not-yet-partitioned prod) the table itself. Deleting per child by name
// keeps each batch's plan on one heap and lets a child dropped by retention
// mid-run (SQLSTATE 42P01) be handled by re-enumerating.
func (d *Database) purgeRelations(table string) ([]string, error) {
	if !d.dialect.IsPostgres() {
		return []string{table}, nil
	}
	var isPartitioned bool
	if err := d.db.Raw(`SELECT EXISTS (
		SELECT 1 FROM pg_partitioned_table pt
		JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = ?)`, table).Scan(&isPartitioned).Error; err != nil {
		return nil, err
	}
	if !isPartitioned {
		return []string{table}, nil
	}
	type childPart struct {
		Name  string
		Bound string
	}
	var children []childPart
	if err := d.db.Raw(`
		SELECT c.relname AS name, pg_get_expr(c.relpartbound, c.oid) AS bound
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class parent ON parent.oid = i.inhparent
		WHERE parent.relname = ?`, table).Scan(&children).Error; err != nil {
		return nil, err
	}
	type ordered struct {
		name  string
		upper time.Time
		ok    bool
	}
	list := make([]ordered, 0, len(children))
	for _, ch := range children {
		upper, ok := parsePartitionUpperBound(ch.Bound)
		list = append(list, ordered{name: ch.Name, upper: upper, ok: ok})
	}
	// Oldest range first; the DEFAULT child (no parseable bound) last.
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].ok != list[j].ok {
			return list[i].ok
		}
		if !list[i].ok {
			return list[i].name < list[j].name
		}
		return list[i].upper.Before(list[j].upper)
	})
	out := make([]string, 0, len(list))
	for _, o := range list {
		out = append(out, o.name)
	}
	if len(out) == 0 {
		return []string{table}, nil // partitioned parent with no children: nothing to delete, but harmless
	}
	return out, nil
}

// purgeTableRows runs the batched delete for one plan entry: once per
// device-keyed column, over every relation purgeRelations returns. A relation
// that vanishes mid-run (retention dropped the partition; 42P01) triggers a
// re-enumeration and the loop continues with the children not yet done.
func (d *Database) purgeTableRows(ctx context.Context, pt purgeTable, deviceID uint, progress func(rows int64)) error {
	for _, col := range pt.columns {
		rels, err := d.purgeRelations(pt.table)
		if err != nil {
			return fmt.Errorf("enumerate %s: %w", pt.table, err)
		}
		done := map[string]bool{}
		for i := 0; i < len(rels); i++ {
			rel := rels[i]
			if done[rel] {
				continue
			}
			err := d.batchedDeleteWhere(ctx, rel, col+" = ?", pt.orderBy, pt.batch, []interface{}{deviceID}, progress)
			if err == nil {
				done[rel] = true
				continue
			}
			if sqlState(err) == "42P01" && rel != pt.table {
				log.Printf("device-purge: partition %s of %s vanished mid-run (dropped by retention); re-enumerating", rel, pt.table)
				done[rel] = true
				fresh, ferr := d.purgeRelations(pt.table)
				if ferr != nil {
					return fmt.Errorf("re-enumerate %s: %w", pt.table, ferr)
				}
				rels, i = fresh, -1
				continue
			}
			return err
		}
	}
	return nil
}

// RunDevicePurge executes one CLAIMED job (status `running`) to completion,
// cancellation, failure, or shutdown:
//
//   - per plan table: CurrentTable is set, every batch adds to RowsDeleted
//     (that UPDATE is also the heartbeat), TablesDone advances;
//   - between batches the job's status is re-read: `cancelling` stops the run
//     and finishes it as `cancelled` — the device stays retired with whatever
//     rows remain, and a later purge resumes from there;
//   - any other error finishes the job as `failed` with the message;
//   - ctx cancelled (graceful shutdown) flips the row back to `pending` with a
//     fresh 5 s context so the next primary resumes it immediately;
//   - success runs DeleteDevice last (device row + device_connections, open
//     incidents resolved — there are none left by then) and marks `done`.
//
// The returned error is the run's disposition for logging; the job row is the
// source of truth.
func (d *Database) RunDevicePurge(ctx context.Context, jobID uint) error {
	job, err := d.GetDevicePurgeJob(jobID)
	if err != nil {
		return fmt.Errorf("purge job %d: load: %w", jobID, err)
	}
	if job.Status != DevicePurgeStatusRunning {
		return fmt.Errorf("purge job %d: status %q, want running (claim it first)", jobID, job.Status)
	}
	deviceID := job.DeviceID
	total := len(devicePurgeTables) + 1
	if err := d.updatePurgeJob(ctx, jobID, map[string]interface{}{
		"tables_total": total, "tables_done": 0, "current_table": "", "error": "",
	}); err != nil {
		return d.finishPurgeJob(jobID, DevicePurgeStatusFailed, err)
	}
	log.Printf("device-purge: job %d starting for device %d (%s, uuid %s), %d tables", jobID, deviceID, job.DeviceName, job.DeviceUUID, total-1)

	runCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)

	// Heartbeat ticker: keeps updated_at fresh through long batches and
	// lock-wait retries so RequeueStaleDevicePurgeJobs never steals a live job.
	hbDone := make(chan struct{})
	go func() {
		t := time.NewTicker(purgeHeartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-hbDone:
				return
			case <-t.C:
				if runCtx.Err() != nil {
					return
				}
				if err := d.touchPurgeJob(runCtx, jobID); err != nil && runCtx.Err() == nil {
					log.Printf("device-purge: job %d heartbeat: %v", jobID, err)
				}
			}
		}
	}()
	defer close(hbDone)

	// checkCancel re-reads the status; `cancelling` stops the run via the
	// context so the in-flight loop exits at its next ctx check.
	checkCancel := func() {
		var status string
		if err := d.db.WithContext(runCtx).Model(&models.DevicePurgeJob{}).Select("status").Where("id = ?", jobID).Scan(&status).Error; err != nil {
			return // transient read error: keep going, the next batch re-checks
		}
		if status == DevicePurgeStatusCancelling {
			stop(errPurgeCancelled)
		}
	}

	var rowsSoFar int64 = job.RowsDeleted
	for i, pt := range devicePurgeTables {
		if err := runCtx.Err(); err != nil {
			return d.settlePurgeInterrupt(runCtx, jobID)
		}
		checkCancel()
		if err := d.updatePurgeJob(runCtx, jobID, map[string]interface{}{"current_table": pt.table, "tables_done": i}); err != nil {
			if runCtx.Err() != nil {
				return d.settlePurgeInterrupt(runCtx, jobID)
			}
			return d.finishPurgeJob(jobID, DevicePurgeStatusFailed, err)
		}
		var tableRows int64
		progress := func(rows int64) {
			tableRows += rows
			rowsSoFar += rows
			if err := d.updatePurgeJob(runCtx, jobID, map[string]interface{}{"rows_deleted": rowsSoFar}); err != nil && runCtx.Err() == nil {
				log.Printf("device-purge: job %d progress write: %v", jobID, err)
			}
			checkCancel()
		}
		if err := d.purgeTableRows(runCtx, pt, deviceID, progress); err != nil {
			if runCtx.Err() != nil {
				return d.settlePurgeInterrupt(runCtx, jobID)
			}
			log.Printf("device-purge: job %d device %d: %s failed after %d rows: %v", jobID, deviceID, pt.table, tableRows, err)
			return d.finishPurgeJob(jobID, DevicePurgeStatusFailed, err)
		}
		log.Printf("device-purge: job %d device %d: %s done, %d rows (%d total, %d/%d tables)", jobID, deviceID, pt.table, tableRows, rowsSoFar, i+1, total)
	}

	if err := runCtx.Err(); err != nil {
		return d.settlePurgeInterrupt(runCtx, jobID)
	}
	checkCancel()
	if runCtx.Err() != nil {
		return d.settlePurgeInterrupt(runCtx, jobID)
	}
	if err := d.updatePurgeJob(runCtx, jobID, map[string]interface{}{"current_table": purgeFinalStep, "tables_done": total - 1}); err != nil {
		return d.finishPurgeJob(jobID, DevicePurgeStatusFailed, err)
	}
	// Device row LAST, through the existing DeleteDevice (device_connections,
	// open-incident resolution, the row). Idempotent on a re-run whose device
	// row is already gone: the DELETE simply affects zero rows.
	if err := d.DeleteDevice(deviceID); err != nil {
		return d.finishPurgeJob(jobID, DevicePurgeStatusFailed, fmt.Errorf("delete device row: %w", err))
	}
	if err := d.updatePurgeJob(context.Background(), jobID, map[string]interface{}{"tables_done": total}); err != nil {
		log.Printf("device-purge: job %d: final progress write: %v", jobID, err)
	}
	log.Printf("device-purge: job %d done: device %d (%s) removed, %d rows deleted", jobID, deviceID, job.DeviceName, rowsSoFar)
	return d.finishPurgeJob(jobID, DevicePurgeStatusDone, nil)
}

// settlePurgeInterrupt records how an interrupted run ends: a cancel request
// → `cancelled`; a parent-context cancel (shutdown) → back to `pending`, on a
// fresh short context because the run's own context is already dead.
func (d *Database) settlePurgeInterrupt(runCtx context.Context, jobID uint) error {
	if errors.Is(context.Cause(runCtx), errPurgeCancelled) {
		log.Printf("device-purge: job %d cancelled by request; partial data remains, device stays retired", jobID)
		return d.finishPurgeJob(jobID, DevicePurgeStatusCancelled, nil)
	}
	fresh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now()
	res := d.db.WithContext(fresh).Model(&models.DevicePurgeJob{}).
		Where("id = ? AND status IN (?)", jobID, []string{DevicePurgeStatusRunning, DevicePurgeStatusCancelling}).
		Updates(map[string]interface{}{"status": DevicePurgeStatusPending, "updated_at": now, "error": "interrupted by shutdown; will resume"})
	if res.Error != nil {
		log.Printf("device-purge: job %d could not be returned to pending on shutdown (%v); the stale-heartbeat requeue will recover it", jobID, res.Error)
		return res.Error
	}
	log.Printf("device-purge: job %d returned to pending on shutdown; the next primary resumes it", jobID)
	return context.Canceled
}

// finishPurgeJob writes a terminal status (done/failed/cancelled) on the
// background context — a run's context may already be cancelled by then.
func (d *Database) finishPurgeJob(jobID uint, status string, cause error) error {
	now := time.Now()
	cols := map[string]interface{}{"status": status, "finished_at": now, "updated_at": now}
	if cause != nil {
		cols["error"] = cause.Error()
	}
	if err := d.db.Model(&models.DevicePurgeJob{}).Where("id = ?", jobID).Updates(cols).Error; err != nil {
		log.Printf("device-purge: job %d: could not record %s: %v", jobID, status, err)
		if cause != nil {
			return cause
		}
		return err
	}
	return cause
}

// updatePurgeJob applies cols to the job row and stamps updated_at (the
// worker heartbeat). The status column is never written here.
func (d *Database) updatePurgeJob(ctx context.Context, jobID uint, cols map[string]interface{}) error {
	cols["updated_at"] = time.Now()
	return d.db.WithContext(ctx).Model(&models.DevicePurgeJob{}).Where("id = ?", jobID).Updates(cols).Error
}

// touchPurgeJob is the heartbeat-only write: it refreshes updated_at while the
// job is still live (running or cancelling) and touches nothing else.
func (d *Database) touchPurgeJob(ctx context.Context, jobID uint) error {
	return d.db.WithContext(ctx).Model(&models.DevicePurgeJob{}).
		Where("id = ? AND status IN (?)", jobID, []string{DevicePurgeStatusRunning, DevicePurgeStatusCancelling}).
		Update("updated_at", time.Now()).Error
}

// DevicePurgeWorker is the API primary's purge loop driver. cmd/api ticks it
// every 5 s while it holds the singleton; one Tick requeues stale jobs, claims
// the oldest pending job and runs it to its end — jobs run strictly one at a
// time. Cross-process safety is layered: the in-process atomic single-flight,
// the CAS claim on the job row, and the advisory lock held for the run.
type DevicePurgeWorker struct {
	db      *Database
	running atomic.Bool
}

// NewDevicePurgeWorker binds the worker to the background (durable) Database.
func NewDevicePurgeWorker(db *Database) *DevicePurgeWorker {
	return &DevicePurgeWorker{db: db}
}

// Tick runs at most one job. It returns immediately when a run is already in
// flight in this process, when another process holds the purge advisory lock,
// or when the queue is empty. Errors are logged, never returned: the next tick
// simply tries again.
func (w *DevicePurgeWorker) Tick(ctx context.Context) {
	if !w.running.CompareAndSwap(false, true) {
		return
	}
	defer w.running.Store(false)
	if ctx.Err() != nil {
		return
	}
	// Idle fast path: no live row at all means nothing to requeue or claim, so
	// don't pin a connection for the advisory lock every 5 s on a quiet system.
	var live int64
	if err := w.db.db.Model(&models.DevicePurgeJob{}).Where("status IN (?)", devicePurgeActiveStatuses).Count(&live).Error; err != nil {
		log.Printf("device-purge: queue probe failed: %v", err)
		return
	}
	if live == 0 {
		return
	}
	release, acquired, err := w.db.AcquireDevicePurgeLock()
	if err != nil {
		log.Printf("device-purge: advisory lock probe failed: %v", err)
		return
	}
	if !acquired {
		return // another API process is running a purge
	}
	defer release()

	if n, err := w.db.RequeueStaleDevicePurgeJobs(purgeStaleAfter); err != nil {
		log.Printf("device-purge: stale-job requeue failed: %v", err)
	} else if n > 0 {
		log.Printf("device-purge: requeued %d job(s) whose worker heartbeat was lost", n)
	}
	job, err := w.db.ClaimNextDevicePurgeJob()
	if err != nil {
		log.Printf("device-purge: claim failed: %v", err)
		return
	}
	if job == nil {
		return
	}
	if err := w.db.RunDevicePurge(ctx, job.ID); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("device-purge: job %d ended: %v", job.ID, err)
	}
}
