package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// Archive restore routes (archive plan PR 9). Synthetic accounts and keys
// only (alice, example-bucket).

func restoreHandler(t *testing.T) (*Handler, *database.Database, *models.Admin) {
	t.Helper()
	h, db, u := profileTestHandler(t, "alice", auth.RoleAdmin, "s3cret-pw")
	h.config.Archive = config.ArchiveConfig{Endpoint: "https://s3.example.com", Region: "us-east-005", Bucket: "example-bucket",
		Prefix: "fwmon-test", AccessKeyID: "005exampleKeyID", SecretAccessKey: config.Secret("not-a-real-secret-fixture"), StagingDir: t.TempDir()}
	// One verified syslog object holding 3 rows of 2 October.
	c := models.ArchiveChunk{SourceTable: "syslog_messages", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC),
		PeriodEnd: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), Month: "2026-10", Status: models.ArchiveChunkVerified}
	if err := db.Gorm().Create(&c).Error; err != nil {
		t.Fatal(err)
	}
	hist := `{"2026-10-02":3}`
	lo, hi := c.PeriodStart, c.PeriodStart.Add(time.Hour)
	if err := db.Gorm().Create(&models.ArchiveObject{ChunkID: c.ID, Stream: "syslog", ObjectKey: "fwmon-test/syslog/v2/2026-10/2026-10-02/device-1.ndjson.gz",
		SchemaVersion: 2, RowCount: 3, MinTs: &lo, MaxTs: &hi, MsgDayHistogram: &hist, Status: models.ArchiveObjectVerified}).Error; err != nil {
		t.Fatal(err)
	}
	return h, db, u
}

// TestStartArchiveRestore walks the POST's checks in order — bucket not
// configured (409), body / days (400), unknown device (404), request rules
// (400), nothing archived for the days (404), disk (409 with the estimate) —
// none of which spends the step-up, then the wrong password (403) and the
// queued job (202, audit row).
func TestStartArchiveRestore(t *testing.T) {
	h, db, u := restoreHandler(t)
	post := func(body string) *httptest.ResponseRecorder {
		c, rec := backfillCtx(http.MethodPost, "/admin/api/archive/restores", "alice", u.ID, body)
		h.StartArchiveRestore(c)
		return rec
	}
	saved := h.config.Archive
	h.config.Archive.Bucket = ""
	if rec := post(`{"stream":"syslog","from":"2026-10-02","to":"2026-10-02","password":"s3cret-pw"}`); rec.Code != http.StatusConflict {
		t.Fatalf("unconfigured bucket: %d %s", rec.Code, rec.Body.String())
	}
	h.config.Archive = saved
	for body, want := range map[string]int{
		`not json`: http.StatusBadRequest,
		`{"stream":"syslog","from":"2026-10-2","to":"2026-10-02","password":"s3cret-pw"}`:                            http.StatusBadRequest,
		`{"stream":"syslog","from":"2026-10-02","to":"2026-10-02","device_id":77,"password":"WRONG"}`:                http.StatusNotFound,
		`{"stream":"sflow","from":"2026-10-02","to":"2026-10-02","renormalize":true,"password":"WRONG"}`:             http.StatusBadRequest,
		`{"stream":"syslog","from":"2026-10-02","to":"2026-10-02","replace":true,"password":"WRONG"}`:                http.StatusBadRequest,
		`{"stream":"syslog","from":"2026-10-05","to":"2026-10-05","password":"WRONG"}`:                               http.StatusNotFound,
		`{"stream":"syslog","from":"2026-10-02","to":"2026-10-02","password":"WRONG"}`:                               http.StatusForbidden,
		`{"stream":"syslog","from":"2026-10-02","to":"2026-10-02","renormalize":true,"replace":true,"ttl_days":200}`: http.StatusBadRequest,
	} {
		if rec := post(body); rec.Code != want {
			t.Errorf("%s: %d %s, want %d", body, rec.Code, rec.Body.String(), want)
		}
	}
	free := uint64(1000)
	db.Gorm().Create(&models.ServerMetric{Timestamp: time.Now(), DataDiskFreeBytes: &free})
	rec := post(`{"stream":"syslog","from":"2026-10-02","to":"2026-10-02","password":"WRONG"}`)
	var refused struct {
		Estimate database.ArchiveRestoreEstimate `json:"estimate"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &refused); rec.Code != http.StatusConflict || refused.Estimate.Rows != 3 || refused.Estimate.FreeBytes != 1000 {
		t.Fatalf("disk precheck: %d %s", rec.Code, rec.Body.String())
	}
	var jobs int64
	db.Gorm().Model(&models.ArchiveRestoreJob{}).Count(&jobs)
	if jobs != 0 || auditCount(db, "archive_restore") != 0 {
		t.Fatalf("refused requests queued %d jobs", jobs)
	}
	db.Gorm().Where("1 = 1").Delete(&models.ServerMetric{})

	rec = post(`{"stream":"syslog","from":"2026-10-02","to":"2026-10-02","renormalize":true,"replace":true,"password":"s3cret-pw"}`)
	var got struct {
		Data models.ArchiveRestoreJob `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusAccepted {
		t.Fatalf("queue: %d %s", rec.Code, rec.Body.String())
	}
	j := got.Data
	if j.Status != models.ArchiveRestorePending || j.RequestedBy != "alice" || j.ObjectsTotal != 1 || !j.Renormalize || !j.Replace ||
		j.StagingTable != "restore_"+strconv.FormatUint(uint64(j.ID), 10)+"_syslog_messages" || j.ExpiresAt.Before(time.Now().Add(6*24*time.Hour)) {
		t.Fatalf("queued job %+v", j)
	}
	if n := auditCount(db, "archive_restore"); n != 1 {
		t.Fatalf("audit rows %d", n)
	}

	c, rec := backfillCtx(http.MethodGet, "/admin/api/archive/restores", "alice", u.ID, "")
	h.ListArchiveRestores(c)
	var list struct {
		Data []archiveRestoreView `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Data) != 1 || list.Data[0].ID != j.ID || list.Data[0].StagingBytes != -1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
}

// TestArchiveRestore_CancelResumeDrop: cancel a pending job (200, audited),
// cancel again (409); resume and drop check the state before the step-up
// (409), then refuse a wrong password (403); a drop of a finished job removes
// it (200, dropped, audit row).
func TestArchiveRestore_CancelResumeDrop(t *testing.T) {
	h, db, u := restoreHandler(t)
	job, _, err := db.QueueArchiveRestore(t.Context(), database.ArchiveRestoreRequest{Stream: "syslog",
		From: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatUint(uint64(job.ID), 10)
	call := func(method, path, body string, fn func(*gin.Context)) *httptest.ResponseRecorder {
		c, rec := backfillCtx(method, path, "alice", u.ID, body)
		c.Params = gin.Params{{Key: "id", Value: id}}
		fn(c)
		return rec
	}
	resume := func(body string) int {
		return call(http.MethodPost, "/admin/api/archive/restores/"+id+"/resume", body, h.ResumeArchiveRestore).Code
	}
	drop := func(body string) int {
		return call(http.MethodDelete, "/admin/api/archive/restores/"+id, body, h.DropArchiveRestore).Code
	}
	cancel := func() int {
		return call(http.MethodPost, "/admin/api/archive/restores/"+id+"/cancel", "", h.CancelArchiveRestore).Code
	}

	if code := drop(`{"password":"s3cret-pw"}`); code != http.StatusConflict {
		t.Fatalf("drop of a pending restore: %d", code)
	}
	if code := resume(`{"password":"s3cret-pw"}`); code != http.StatusConflict {
		t.Fatalf("resume of a pending restore: %d", code)
	}
	if code := cancel(); code != http.StatusOK {
		t.Fatalf("cancel: %d", code)
	}
	if code := cancel(); code != http.StatusConflict {
		t.Fatalf("second cancel: %d", code)
	}
	if code := resume(`{"password":"WRONG"}`); code != http.StatusForbidden {
		t.Fatalf("resume with a wrong password: %d", code)
	}
	if code := resume(`{"password":"s3cret-pw"}`); code != http.StatusOK {
		t.Fatalf("resume: %d", code)
	}
	if j, _ := db.GetArchiveRestoreJob(job.ID); j.Status != models.ArchiveRestorePending {
		t.Fatalf("after resume: %s", j.Status)
	}
	db.Gorm().Model(&models.ArchiveRestoreJob{}).Where("id = ?", job.ID).Update("status", models.ArchiveRestoreDone)
	if code := drop(`{"password":"WRONG"}`); code != http.StatusForbidden {
		t.Fatalf("drop with a wrong password: %d", code)
	}
	if code := drop(`{"password":"s3cret-pw"}`); code != http.StatusOK {
		t.Fatalf("drop: %d", code)
	}
	if j, _ := db.GetArchiveRestoreJob(job.ID); j.Status != models.ArchiveRestoreDropped {
		t.Fatalf("after drop: %s", j.Status)
	}
	for action, want := range map[string]int64{"archive_restore_cancel": 1, "archive_restore_resume": 1, "archive_restore_drop": 1} {
		if n := auditCount(db, action); n != want {
			t.Errorf("%s audit rows %d, want %d", action, n, want)
		}
	}
	if code := call(http.MethodPost, "/x", "", func(c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: "999"}}; h.CancelArchiveRestore(c) }).Code; code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", code)
	}
}
