package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// purgeCtx builds an authenticated admin gin.Context for the purge routes.
func purgeCtx(method string, deviceID uint, username string, userID uint, body string) (*gin.Context, *httptest.ResponseRecorder) {
	c, rec := jsonReq(method, "/admin/api/devices/x/purge", body)
	c.Params = idParam(deviceID)
	c.Set("username", username)
	c.Set("user_id", userID)
	c.Set("role", auth.RoleAdmin)
	return c, rec
}

func purgeTestSetup(t *testing.T) (*Handler, *database.Database, *models.Admin, *models.Device) {
	t.Helper()
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	dev := &models.Device{Name: "fw-old", IPAddress: "10.0.0.1"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := db.RetireDevice(dev.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	return h, db, u, dev
}

func decodeJob(t *testing.T, rec *httptest.ResponseRecorder) models.DevicePurgeJob {
	t.Helper()
	var resp struct {
		Data models.DevicePurgeJob `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode job: %v (%s)", err, rec.Body.String())
	}
	return resp.Data
}

func auditCount(db *database.Database, action string) int64 {
	var n int64
	db.Gorm().Model(&models.AuditLog{}).Where("action = ?", action).Count(&n)
	return n
}

// TestPurgeDevice_Preconditions walks the POST's checks in their order: not
// retired (409), wrong confirm name (400), wrong password (403), then the
// happy path (202 + audit row), then a second request while the job is
// active (409 with job_id).
func TestPurgeDevice_Preconditions(t *testing.T) {
	h, db, u, dev := purgeTestSetup(t)
	const good = `{"confirm_name":"fw-old","password":"s3cret-pw"}`

	// Not retired.
	live := &models.Device{Name: "fw-live", IPAddress: "10.0.0.2"}
	if err := db.Gorm().Create(live).Error; err != nil {
		t.Fatal(err)
	}
	c, rec := purgeCtx(http.MethodPost, live.ID, "admin1", u.ID, `{"confirm_name":"fw-live","password":"s3cret-pw"}`)
	h.PurgeDevice(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("active device: %d %s, want 409", rec.Code, rec.Body.String())
	}

	// Unknown device.
	c, rec = purgeCtx(http.MethodPost, 999999, "admin1", u.ID, good)
	h.PurgeDevice(c)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown device: %d, want 404", rec.Code)
	}

	// Wrong name.
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, `{"confirm_name":"fw-oldx","password":"s3cret-pw"}`)
	h.PurgeDevice(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("wrong name: %d, want 400", rec.Code)
	}

	// Wrong password (the RevealDeviceSecret precedent: 403).
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, `{"confirm_name":"fw-old","password":"WRONG"}`)
	h.PurgeDevice(c)
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong password: %d, want 403", rec.Code)
	}
	// Empty password.
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, `{"confirm_name":"fw-old"}`)
	h.PurgeDevice(c)
	if rec.Code != http.StatusForbidden {
		t.Errorf("empty password: %d, want 403", rec.Code)
	}
	// No identity on the context at all.
	c, rec = jsonReq(http.MethodPost, "/x", good)
	c.Params = idParam(dev.ID)
	h.PurgeDevice(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no identity: %d, want 401", rec.Code)
	}
	if n := auditCount(db, "purge_device"); n != 0 {
		t.Fatalf("audit rows before any accepted purge = %d, want 0", n)
	}
	if active, _ := db.GetActiveDevicePurgeJob(dev.ID); active != nil {
		t.Fatalf("a rejected request queued a job: %+v", active)
	}

	// Happy path.
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, good)
	h.PurgeDevice(c)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("purge: %d %s, want 202", rec.Code, rec.Body.String())
	}
	job := decodeJob(t, rec)
	if job.ID == 0 || job.Status != database.DevicePurgeStatusPending || job.DeviceID != dev.ID ||
		job.DeviceName != "fw-old" || job.RequestedBy != "admin1" || job.DeviceUUID == "" {
		t.Errorf("202 job = %+v", job)
	}
	if job.TablesTotal == 0 {
		t.Error("202 job has no tables_total")
	}
	if n := auditCount(db, "purge_device"); n != 1 {
		t.Errorf("purge_device audit rows = %d, want 1", n)
	}
	var audit models.AuditLog
	db.Gorm().Where("action = ?", "purge_device").First(&audit)
	if audit.Actor != "admin1" || audit.ActorID != u.ID || audit.Target == "" {
		t.Errorf("audit row = %+v", audit)
	}

	// Second request while the job is active.
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, good)
	h.PurgeDevice(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate purge: %d %s, want 409", rec.Code, rec.Body.String())
	}
	var dup struct {
		Error string `json:"error"`
		JobID uint   `json:"job_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &dup)
	if dup.JobID != job.ID || dup.Error == "" {
		t.Errorf("409 body = %s, want job_id=%d", rec.Body.String(), job.ID)
	}
	// The already-queued check runs BEFORE the password/TOTP step-up: a
	// conflict with a wrong password is still 409, not 403 — so a 409 can
	// never consume a single-use authenticator code.
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, `{"confirm_name":"fw-old","password":"WRONG"}`)
	h.PurgeDevice(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("duplicate purge with a wrong password: %d, want 409 (active-job check precedes the step-up)", rec.Code)
	}

	// The JSON contract the UI codes against: snake_case field names.
	c, rec = purgeCtx(http.MethodGet, dev.ID, "admin1", u.ID, "")
	h.GetDevicePurge(c)
	var envelope struct {
		Data map[string]interface{} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
	for _, key := range []string{"id", "device_id", "device_uuid", "device_name", "requested_by", "status", "current_table",
		"rows_deleted", "tables_done", "tables_total", "error", "started_at", "finished_at", "created_at", "updated_at"} {
		if _, ok := envelope.Data[key]; !ok {
			t.Errorf("job JSON lacks %q: %s", key, rec.Body.String())
		}
	}
}

// TestPurgeDevice_RefusedWhileTunnelDeploying: an IPSec tunnel on EITHER end
// (the device as B end, and as A end) in deploying/verifying/rolling_back
// blocks the purge (409 naming every such tunnel); once both are settled it
// does not.
func TestPurgeDevice_RefusedWhileTunnelDeploying(t *testing.T) {
	h, db, u, dev := purgeTestSetup(t)
	peer := &models.Device{Name: "fw-peer", IPAddress: "10.0.0.3"}
	if err := db.Gorm().Create(peer).Error; err != nil {
		t.Fatal(err)
	}
	tunB := &models.IPSecTunnel{Name: "hq-branch", ADeviceID: peer.ID, BDeviceID: dev.ID, Status: "deploying", DeployJSON: "{}"}
	tunA := &models.IPSecTunnel{Name: "branch-hq", ADeviceID: dev.ID, BDeviceID: peer.ID, Status: "verifying", DeployJSON: "{}"}
	for _, tun := range []*models.IPSecTunnel{tunB, tunA} {
		if err := db.Gorm().Create(tun).Error; err != nil {
			t.Fatal(err)
		}
	}
	const good = `{"confirm_name":"fw-old","password":"s3cret-pw"}`
	c, rec := purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, good)
	h.PurgeDevice(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("deploying/verifying tunnels on both ends: %d %s, want 409", rec.Code, rec.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	for _, want := range []string{"hq-branch", "deploying", "branch-hq", "verifying"} {
		if !strings.Contains(body.Error, want) {
			t.Errorf("409 error = %q, want it to contain %q (both ends named with their state)", body.Error, want)
		}
	}
	if n := auditCount(db, "purge_device"); n != 0 {
		t.Error("refused purge wrote an audit row")
	}

	// B end settled, A end still busy → still refused, naming only the A end.
	db.Gorm().Model(tunB).Update("status", "up")
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, good)
	h.PurgeDevice(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("verifying tunnel on the A end alone: %d, want 409", rec.Code)
	}
	body.Error = ""
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !strings.Contains(body.Error, "branch-hq") || strings.Contains(body.Error, "hq-branch (") {
		t.Errorf("409 error = %q, want only the A-end tunnel named", body.Error)
	}

	// A end settled, B end rolling back → refused.
	db.Gorm().Model(tunA).Update("status", "up")
	db.Gorm().Model(tunB).Update("status", "rolling_back")
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, good)
	h.PurgeDevice(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("rolling_back tunnel: %d, want 409", rec.Code)
	}

	db.Gorm().Model(tunB).Update("status", "up")
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, good)
	h.PurgeDevice(c)
	if rec.Code != http.StatusAccepted {
		t.Errorf("settled tunnels on both ends: %d %s, want 202", rec.Code, rec.Body.String())
	}
}

// TestRestoreDevice_RefusedWhilePurgeActive: a restore is 409 (with the job
// id and its status) while the device's purge job is pending, running or
// cancelling, before any restore work; once the job is terminal the restore
// goes through.
func TestRestoreDevice_RefusedWhilePurgeActive(t *testing.T) {
	h, db, u, dev := purgeTestSetup(t)
	job := &models.DevicePurgeJob{DeviceID: dev.ID, DeviceName: dev.Name, DeviceUUID: dev.UUID}
	if err := db.CreateDevicePurgeJob(job); err != nil {
		t.Fatal(err)
	}
	restore := func() (int, string, uint) {
		c, rec := purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, "")
		h.RestoreDevice(c)
		var body struct {
			Error string `json:"error"`
			JobID uint   `json:"job_id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Error, body.JobID
	}
	stillRetired := func(step string) {
		t.Helper()
		got, err := db.GetDevice(dev.ID)
		if err != nil || got.RetiredAt == nil || got.Enabled {
			t.Fatalf("%s: device = %+v err=%v, want still retired", step, got, err)
		}
	}

	// pending
	if code, msg, id := restore(); code != http.StatusConflict || id != job.ID ||
		!strings.Contains(msg, "pending") || !strings.Contains(msg, "cancel it first") {
		t.Errorf("restore with a pending job: %d %q job_id=%d, want 409 naming pending and job %d", code, msg, id, job.ID)
	}
	stillRetired("pending")

	// running
	if won, err := db.ClaimDevicePurgeJob(job.ID); err != nil || !won {
		t.Fatalf("claim: %v %v", won, err)
	}
	if code, msg, id := restore(); code != http.StatusConflict || id != job.ID || !strings.Contains(msg, "running") {
		t.Errorf("restore with a running job: %d %q job_id=%d, want 409 naming running", code, msg, id)
	}
	stillRetired("running")

	// cancelling
	if st, ok, err := db.CancelDevicePurgeJob(job.ID); err != nil || !ok || st != database.DevicePurgeStatusCancelling {
		t.Fatalf("cancel running: %q %v %v", st, ok, err)
	}
	if code, msg, id := restore(); code != http.StatusConflict || id != job.ID || !strings.Contains(msg, "cancelling") {
		t.Errorf("restore with a cancelling job: %d %q job_id=%d, want 409 naming cancelling", code, msg, id)
	}
	stillRetired("cancelling")

	// terminal → the restore proceeds
	db.Gorm().Model(job).UpdateColumns(map[string]interface{}{"status": database.DevicePurgeStatusCancelled, "finished_at": time.Now()})
	if code, msg, _ := restore(); code != http.StatusOK {
		t.Fatalf("restore after the job ended: %d %q, want 200", code, msg)
	}
	got, err := db.GetDevice(dev.ID)
	if err != nil || got.RetiredAt != nil || !got.Enabled {
		t.Errorf("restored device = %+v err=%v, want active", got, err)
	}
}

// TestCancelDevicePurge_Handler: pending → cancelled with an audit row, a
// second cancel is 409, cancel with no job is 404, and the status GET reports
// the latest job (404 for a device never queued).
func TestCancelDevicePurge_Handler(t *testing.T) {
	h, db, u, dev := purgeTestSetup(t)

	c, rec := purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, "")
	h.CancelDevicePurge(c)
	if rec.Code != http.StatusNotFound {
		t.Errorf("cancel with no job: %d, want 404", rec.Code)
	}
	c, rec = purgeCtx(http.MethodGet, dev.ID, "admin1", u.ID, "")
	h.GetDevicePurge(c)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status with no job: %d, want 404", rec.Code)
	}

	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, `{"confirm_name":"fw-old","password":"s3cret-pw"}`)
	h.PurgeDevice(c)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("purge: %d %s", rec.Code, rec.Body.String())
	}
	queued := decodeJob(t, rec)

	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, "")
	h.CancelDevicePurge(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel pending: %d %s, want 200", rec.Code, rec.Body.String())
	}
	if got := decodeJob(t, rec); got.ID != queued.ID || got.Status != database.DevicePurgeStatusCancelled || got.FinishedAt == nil {
		t.Errorf("cancelled job = %+v", got)
	}
	if n := auditCount(db, "purge_device_cancel"); n != 1 {
		t.Errorf("purge_device_cancel audit rows = %d, want 1", n)
	}
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, "")
	h.CancelDevicePurge(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("cancel a cancelled job: %d, want 409", rec.Code)
	}
	c, rec = purgeCtx(http.MethodGet, dev.ID, "admin1", u.ID, "")
	h.GetDevicePurge(c)
	if rec.Code != http.StatusOK || decodeJob(t, rec).Status != database.DevicePurgeStatusCancelled {
		t.Errorf("status after cancel: %d %s", rec.Code, rec.Body.String())
	}

	// Cancelled is terminal, so a new purge can be queued (the device is still
	// retired), and the running → cancelling transition goes through the CAS.
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, `{"confirm_name":"fw-old","password":"s3cret-pw"}`)
	h.PurgeDevice(c)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("re-queue after cancel: %d %s", rec.Code, rec.Body.String())
	}
	second := decodeJob(t, rec)
	if won, err := db.ClaimDevicePurgeJob(second.ID); err != nil || !won {
		t.Fatalf("claim: %v %v", won, err)
	}
	c, rec = purgeCtx(http.MethodPost, dev.ID, "admin1", u.ID, "")
	h.CancelDevicePurge(c)
	if rec.Code != http.StatusOK || decodeJob(t, rec).Status != database.DevicePurgeStatusCancelling {
		t.Errorf("cancel running: %d %s, want 200 cancelling", rec.Code, rec.Body.String())
	}
}

// TestListPurgeJobs_Handler: active jobs first, then terminal ones; an empty
// queue is an empty array, not null.
func TestListPurgeJobs_Handler(t *testing.T) {
	h, db, u, dev := purgeTestSetup(t)
	c, rec := purgeCtx(http.MethodGet, 0, "admin1", u.ID, "")
	h.ListPurgeJobs(c)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"success":true,"data":[]}` {
		t.Errorf("empty list: %d %s", rec.Code, rec.Body.String())
	}
	old := &models.DevicePurgeJob{DeviceID: dev.ID, DeviceName: dev.Name}
	if err := db.CreateDevicePurgeJob(old); err != nil {
		t.Fatal(err)
	}
	db.Gorm().Model(old).UpdateColumns(map[string]interface{}{"status": database.DevicePurgeStatusDone, "finished_at": time.Now()})
	live := &models.DevicePurgeJob{DeviceID: dev.ID, DeviceName: dev.Name}
	if err := db.CreateDevicePurgeJob(live); err != nil {
		t.Fatal(err)
	}
	c, rec = purgeCtx(http.MethodGet, 0, "admin1", u.ID, "")
	h.ListPurgeJobs(c)
	var resp struct {
		Data []models.DevicePurgeJob `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Data) != 2 {
		t.Fatalf("list: %v %s", err, rec.Body.String())
	}
	if resp.Data[0].ID != live.ID || resp.Data[1].ID != old.ID {
		t.Errorf("order = %d,%d want live %d then terminal %d", resp.Data[0].ID, resp.Data[1].ID, live.ID, old.ID)
	}
}

// TestEstimateDevicePurge_Handler: retired only (409 otherwise), and the
// response carries the {tables:[{table,rows,capped}], total, tunnels:[...]}
// shape with the peer device name.
func TestEstimateDevicePurge_Handler(t *testing.T) {
	h, db, u, dev := purgeTestSetup(t)
	live := &models.Device{Name: "fw-live", IPAddress: "10.0.0.2"}
	if err := db.Gorm().Create(live).Error; err != nil {
		t.Fatal(err)
	}
	c, rec := purgeCtx(http.MethodGet, live.ID, "admin1", u.ID, "")
	h.EstimateDevicePurge(c)
	if rec.Code != http.StatusConflict {
		t.Errorf("estimate on an active device: %d, want 409", rec.Code)
	}
	c, rec = purgeCtx(http.MethodGet, 999999, "admin1", u.ID, "")
	h.EstimateDevicePurge(c)
	if rec.Code != http.StatusNotFound {
		t.Errorf("estimate on an unknown device: %d, want 404", rec.Code)
	}

	for i := 0; i < 3; i++ {
		if err := db.Gorm().Create(&models.Alert{DeviceID: dev.ID, Message: "m", Timestamp: time.Now()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Gorm().Create(&models.IPSecTunnel{Name: "t1", ADeviceID: dev.ID, BDeviceID: live.ID, Status: "draft"}).Error; err != nil {
		t.Fatal(err)
	}
	c, rec = purgeCtx(http.MethodGet, dev.ID, "admin1", u.ID, "")
	h.EstimateDevicePurge(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("estimate: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Tables []struct {
				Table  string `json:"table"`
				Rows   int64  `json:"rows"`
				Capped bool   `json:"capped"`
			} `json:"tables"`
			Total   int64 `json:"total"`
			Tunnels []struct {
				ID         uint   `json:"id"`
				Name       string `json:"name"`
				PeerDevice string `json:"peer_device"`
			} `json:"tunnels"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Total != 4 {
		t.Errorf("total = %d, want 4 (3 alerts + 1 tunnel)", resp.Data.Total)
	}
	var sawAlerts bool
	for _, row := range resp.Data.Tables {
		if row.Table == "alerts" {
			sawAlerts = row.Rows == 3 && !row.Capped
		}
	}
	if !sawAlerts {
		t.Errorf("tables = %+v, want alerts=3 uncapped", resp.Data.Tables)
	}
	if len(resp.Data.Tunnels) != 1 || resp.Data.Tunnels[0].Name != "t1" || resp.Data.Tunnels[0].PeerDevice != "fw-live" {
		t.Errorf("tunnels = %+v", resp.Data.Tunnels)
	}
}
