package database

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Device purge job lifecycle (v0.11.243). See models.DevicePurgeJob.
const (
	DevicePurgeStatusPending    = "pending"
	DevicePurgeStatusRunning    = "running"
	DevicePurgeStatusCancelling = "cancelling"
	DevicePurgeStatusDone       = "done"
	DevicePurgeStatusFailed     = "failed"
	DevicePurgeStatusCancelled  = "cancelled"
)

// devicePurgeActiveStatuses are the non-terminal states: at most one job per
// device may be in one of them, and only these are shown as "in progress".
var devicePurgeActiveStatuses = []string{DevicePurgeStatusPending, DevicePurgeStatusRunning, DevicePurgeStatusCancelling}

// CreateDevicePurgeJob enqueues a purge for a device. Callers (the handler)
// have already verified the device is retired and that no active job exists;
// the row starts `pending` regardless of what the caller set.
func (d *Database) CreateDevicePurgeJob(job *models.DevicePurgeJob) error {
	if job.DeviceID == 0 {
		return errors.New("CreateDevicePurgeJob: device_id required")
	}
	job.ID = 0
	job.Status = DevicePurgeStatusPending
	job.CurrentTable = ""
	job.RowsDeleted = 0
	job.TablesDone = 0
	job.TablesTotal = len(devicePurgeTables) + 1
	job.Error = ""
	job.StartedAt = nil
	job.FinishedAt = nil
	return d.db.Create(job).Error
}

// GetDevicePurgeJob returns one job by id (gorm.ErrRecordNotFound if absent).
func (d *Database) GetDevicePurgeJob(id uint) (*models.DevicePurgeJob, error) {
	var job models.DevicePurgeJob
	if err := d.db.First(&job, id).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

// GetLatestDevicePurgeJob returns the newest job for a device, in any state
// (gorm.ErrRecordNotFound if the device was never queued).
func (d *Database) GetLatestDevicePurgeJob(deviceID uint) (*models.DevicePurgeJob, error) {
	var job models.DevicePurgeJob
	if err := d.db.Where("device_id = ?", deviceID).Order("id DESC").First(&job).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

// GetActiveDevicePurgeJob returns the device's pending/running/cancelling job,
// or (nil, nil) when there is none — the handler's "already queued" check.
func (d *Database) GetActiveDevicePurgeJob(deviceID uint) (*models.DevicePurgeJob, error) {
	var job models.DevicePurgeJob
	err := d.db.Where("device_id = ? AND status IN (?)", deviceID, devicePurgeActiveStatuses).
		Order("id DESC").First(&job).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// ListDevicePurgeJobs returns every non-terminal job (oldest first — the
// worker's queue order) followed by the newest recentTerminal terminal ones.
func (d *Database) ListDevicePurgeJobs(recentTerminal int) ([]models.DevicePurgeJob, error) {
	var active []models.DevicePurgeJob
	if err := d.db.Where("status IN (?)", devicePurgeActiveStatuses).Order("id ASC").Find(&active).Error; err != nil {
		return nil, err
	}
	var terminal []models.DevicePurgeJob
	if recentTerminal > 0 {
		if err := d.db.Where("status NOT IN (?)", devicePurgeActiveStatuses).
			Order("id DESC").Limit(recentTerminal).Find(&terminal).Error; err != nil {
			return nil, err
		}
	}
	return append(active, terminal...), nil
}

// CancelDevicePurgeJob requests a cancel. Both transitions are compare-and-set
// so a concurrent worker claim can't be lost: a `pending` job becomes
// `cancelled` outright; a `running` job becomes `cancelling`, which the worker
// observes between batches and finishes as `cancelled`. Returns the status the
// job now has, or "" (applied=false) when the job is not in a cancellable state
// — the caller turns that into a 409.
func (d *Database) CancelDevicePurgeJob(id uint) (status string, applied bool, err error) {
	now := time.Now()
	res := d.db.Model(&models.DevicePurgeJob{}).
		Where("id = ? AND status = ?", id, DevicePurgeStatusPending).
		Updates(map[string]interface{}{
			"status": DevicePurgeStatusCancelled, "finished_at": now, "updated_at": now,
		})
	if res.Error != nil {
		return "", false, res.Error
	}
	if res.RowsAffected == 1 {
		return DevicePurgeStatusCancelled, true, nil
	}
	res = d.db.Model(&models.DevicePurgeJob{}).
		Where("id = ? AND status = ?", id, DevicePurgeStatusRunning).
		Updates(map[string]interface{}{"status": DevicePurgeStatusCancelling, "updated_at": now})
	if res.Error != nil {
		return "", false, res.Error
	}
	if res.RowsAffected == 1 {
		return DevicePurgeStatusCancelling, true, nil
	}
	return "", false, nil
}

// ClaimDevicePurgeJob is the worker's compare-and-set claim: pending → running
// in one UPDATE guarded by the current status, so two API processes that both
// believe they are primary (the singleton probe errs toward primary) can never
// both run one job — exactly one UPDATE sees RowsAffected == 1.
func (d *Database) ClaimDevicePurgeJob(id uint) (bool, error) {
	now := time.Now()
	res := d.db.Model(&models.DevicePurgeJob{}).
		Where("id = ? AND status = ?", id, DevicePurgeStatusPending).
		Updates(map[string]interface{}{
			"status": DevicePurgeStatusRunning, "started_at": now, "updated_at": now,
			"error": "", "finished_at": nil,
		})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// ClaimNextDevicePurgeJob claims the oldest pending job (queue order), retrying
// past any row another claimant wins. (nil, nil) when the queue is empty.
func (d *Database) ClaimNextDevicePurgeJob() (*models.DevicePurgeJob, error) {
	for {
		var job models.DevicePurgeJob
		err := d.db.Where("status = ?", DevicePurgeStatusPending).Order("id ASC").First(&job).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		won, err := d.ClaimDevicePurgeJob(job.ID)
		if err != nil {
			return nil, err
		}
		if !won {
			continue // lost the CAS to another process; try the next row
		}
		return d.GetDevicePurgeJob(job.ID)
	}
}

// RequeueStaleDevicePurgeJobs puts a `running` job whose heartbeat
// (updated_at, touched on every batch and by the run's heartbeat ticker) is
// older than staleAfter back to `pending`, so a job orphaned by a crashed
// process is picked up by the next tick. A live job never qualifies. A stale
// `cancelling` job (cancel requested, then the worker died) is finished as
// `cancelled`: the cancel already means "stop; partial state is acceptable".
// Returns the number of rows requeued.
func (d *Database) RequeueStaleDevicePurgeJobs(staleAfter time.Duration) (int64, error) {
	now := time.Now()
	cutoff := now.Add(-staleAfter)
	res := d.db.Model(&models.DevicePurgeJob{}).
		Where("status = ? AND updated_at < ?", DevicePurgeStatusRunning, cutoff).
		Updates(map[string]interface{}{
			"status":     DevicePurgeStatusPending,
			"updated_at": now,
			"error":      "requeued: worker heartbeat lost",
		})
	if res.Error != nil {
		return 0, res.Error
	}
	requeued := res.RowsAffected
	res = d.db.Model(&models.DevicePurgeJob{}).
		Where("status = ? AND updated_at < ?", DevicePurgeStatusCancelling, cutoff).
		Updates(map[string]interface{}{
			"status": DevicePurgeStatusCancelled, "finished_at": now, "updated_at": now,
			"error": "cancelled: worker heartbeat lost while cancelling",
		})
	if res.Error != nil {
		return requeued, res.Error
	}
	return requeued, nil
}

// purgeEstimateCap is the per-table LIMIT of the estimate's count subquery. An
// uncapped count(*) on prod's syslog_messages (134M rows) would exceed the
// 30 s statement timeout, and even a capped probe walks the index for every
// row it counts across 36 tables on the request path; capping at 100,001 lets
// the dialog say "100,000+" and keeps the whole estimate well inside the
// request's statement timeout.
var purgeEstimateCap int64 = 100001

// DevicePurgeEstimateTable is one row of the purge estimate.
type DevicePurgeEstimateTable struct {
	Table string `json:"table"`
	Rows  int64  `json:"rows"`
	// Capped is true when the table holds MORE than Rows (the count hit the
	// cap) — render as "100,000+".
	Capped bool `json:"capped"`
	// Error is set (Rows 0, Capped false) when this table's count failed —
	// a missing relation, a statement timeout — and the rest of the estimate
	// still counted. The purge itself is unaffected; the dialog says the
	// estimate is incomplete.
	Error string `json:"error,omitempty"`
}

// DevicePurgeEstimateTunnel is an IPSec tunnel intent the purge will remove,
// with the name of the device on the other end (the tunnel is a shared row —
// removing it removes the intent for both ends).
type DevicePurgeEstimateTunnel struct {
	ID         uint   `json:"id"`
	Name       string `json:"name"`
	PeerDevice string `json:"peer_device"`
}

// DevicePurgeEstimate is the response of the estimate endpoint.
type DevicePurgeEstimate struct {
	Tables  []DevicePurgeEstimateTable  `json:"tables"`
	Total   int64                       `json:"total"`
	Tunnels []DevicePurgeEstimateTunnel `json:"tunnels"`
}

// EstimateDevicePurge counts, per table in the purge plan, the rows keyed to
// the device — capped (see purgeEstimateCap) so the largest tables stay inside
// the statement timeout — and lists the IPSec tunnel intents that reference it.
// A table whose count fails is reported with Error set and rows 0 and the
// estimate continues: the dialog is advisory, and one slow or missing table
// must not hide the other 35 counts or block the purge itself.
func (d *Database) EstimateDevicePurge(deviceID uint) (*DevicePurgeEstimate, error) {
	est := &DevicePurgeEstimate{
		Tables:  make([]DevicePurgeEstimateTable, 0, len(devicePurgeTables)),
		Tunnels: []DevicePurgeEstimateTunnel{},
	}
	for _, pt := range devicePurgeTables {
		row := DevicePurgeEstimateTable{Table: pt.table}
		for _, col := range pt.columns {
			var n int64
			// table/col are compile-time literals from devicePurgeTables.
			q := fmt.Sprintf("SELECT count(*) FROM (SELECT 1 FROM %s WHERE %s = ? LIMIT %d) s", pt.table, col, purgeEstimateCap)
			if err := d.db.Raw(q, deviceID).Scan(&n).Error; err != nil {
				log.Printf("device-purge: estimate for device %d: %s could not be counted: %v", deviceID, pt.table, err)
				row = DevicePurgeEstimateTable{Table: pt.table, Error: shortError(err, 120)}
				break
			}
			if n >= purgeEstimateCap {
				row.Capped = true
				n = purgeEstimateCap - 1
			}
			row.Rows += n
		}
		est.Tables = append(est.Tables, row)
		est.Total += row.Rows
	}
	tunnels, err := d.ListIPSecTunnelsForDevice(deviceID)
	if err != nil {
		return nil, err
	}
	peerIDs := make([]uint, 0, len(tunnels))
	for _, t := range tunnels {
		peer := t.BDeviceID
		if peer == deviceID {
			peer = t.ADeviceID
		}
		if peer != 0 && peer != deviceID {
			peerIDs = append(peerIDs, peer)
		}
	}
	names := map[uint]string{}
	if len(peerIDs) > 0 {
		var peers []struct {
			ID   uint
			Name string
		}
		if err := d.db.Model(&models.Device{}).Select("id, name").Where("id IN (?)", peerIDs).Scan(&peers).Error; err != nil {
			return nil, fmt.Errorf("estimate: resolve peers: %w", err)
		}
		for _, p := range peers {
			names[p.ID] = p.Name
		}
	}
	for _, t := range tunnels {
		peer := t.BDeviceID
		if peer == deviceID {
			peer = t.ADeviceID
		}
		est.Tunnels = append(est.Tunnels, DevicePurgeEstimateTunnel{ID: t.ID, Name: t.Name, PeerDevice: names[peer]})
	}
	return est, nil
}

// ListIPSecTunnelsForDevice returns every tunnel intent that has the device on
// either end (oldest first). PSK is cleared like ListIPSecTunnels.
func (d *Database) ListIPSecTunnelsForDevice(deviceID uint) ([]models.IPSecTunnel, error) {
	var ms []models.IPSecTunnel
	err := d.db.Where("a_device_id = ? OR b_device_id = ?", deviceID, deviceID).Order("id ASC").Find(&ms).Error
	for i := range ms {
		ms[i].PSK = ""
	}
	return ms, err
}

// shortError renders err for a JSON field: the first line, cut at max runes.
func shortError(err error, max int) string {
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if r := []rune(msg); len(r) > max {
		msg = string(r[:max]) + "…"
	}
	return msg
}
