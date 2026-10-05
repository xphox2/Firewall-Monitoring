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

// backfillCtx builds an authenticated admin session context for the backfill
// routes.
func backfillCtx(method, path, username string, userID uint, body string) (*gin.Context, *httptest.ResponseRecorder) {
	c, rec := jsonReq(method, path, body)
	c.Set("username", username)
	c.Set("user_id", userID)
	c.Set("role", auth.RoleAdmin)
	c.Set("auth_method", "session")
	return c, rec
}

func decodeBackfillJob(t *testing.T, rec *httptest.ResponseRecorder) models.NormalizeBackfillJob {
	t.Helper()
	var resp struct {
		Data models.NormalizeBackfillJob `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode job: %v (%s)", err, rec.Body.String())
	}
	return resp.Data
}

// TestStartNormalizeBackfill walks the POST's checks in their order: no
// watermark yet (409), since_days out of range (400), bad rate (400), bad
// window (400), unknown device (404), wrong password (403 — after every
// structural check, so a bad request never spends a re-auth attempt), the
// happy path (202 + job + audit row, window defaulted from the setting), a
// second request while the job is active (409 with job_id, BEFORE the
// password check), then status, cancel (pending → cancelled + audit row) and
// resume (re-authenticated; → pending).
func TestStartNormalizeBackfill(t *testing.T) {
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	const good = `{"since_days":7,"password":"s3cret-pw"}`
	post := func(body string) *httptest.ResponseRecorder {
		c, rec := backfillCtx(http.MethodPost, "/admin/api/normalize/backfill", "admin1", u.ID, body)
		h.StartNormalizeBackfill(c)
		return rec
	}

	// No watermark: the ingest has not normalized anything yet.
	if rec := post(good); rec.Code != http.StatusConflict {
		t.Fatalf("without the watermark: %d %s, want 409", rec.Code, rec.Body.String())
	}
	wm := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if _, err := db.InsertSettingIfAbsent(&models.SystemSetting{Key: database.NormalizeIngestStartedSetting, Value: wm.Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Create(&models.SystemSetting{Key: database.NormalizeBackfillWindowSetting, Value: "22:00-06:00"}).Error; err != nil {
		t.Fatal(err)
	}

	for body, want := range map[string]int{
		`{"since_days":31,"password":"s3cret-pw"}`:       http.StatusBadRequest,
		`{"since_days":-1,"password":"s3cret-pw"}`:       http.StatusBadRequest,
		`{"rate_rows_per_sec":5,"password":"s3cret-pw"}`: http.StatusBadRequest,
		`{"window":"nope","password":"s3cret-pw"}`:       http.StatusBadRequest,
		`{"device_id":999999,"password":"s3cret-pw"}`:    http.StatusNotFound,
		`{"since_days":7,"password":"WRONG"}`:            http.StatusForbidden,
		`{"since_days":7}`:                               http.StatusForbidden,
		`not json`:                                       http.StatusBadRequest,
	} {
		if rec := post(body); rec.Code != want {
			t.Errorf("%s: %d %s, want %d", body, rec.Code, rec.Body.String(), want)
		}
	}
	if active, _ := db.GetActiveNormalizeBackfillJob(); active != nil {
		t.Fatalf("a refused request queued a job: %+v", active)
	}
	// No identity on the context at all.
	c, rec := jsonReq(http.MethodPost, "/x", good)
	h.StartNormalizeBackfill(c)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no identity: %d, want 401", rec.Code)
	}

	// Happy path.
	rec = post(good)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("happy path: %d %s", rec.Code, rec.Body.String())
	}
	job := decodeBackfillJob(t, rec)
	if job.ID == 0 || job.Status != database.NormalizeBackfillStatusPending || job.RequestedBy != "admin1" ||
		!job.Until.Equal(wm) || job.RateRowsPerSec != database.NormalizeBackfillDefaultRate || job.Window != "22:00-06:00" {
		t.Fatalf("queued job: %+v (want pending, until = watermark, default rate, window from the setting)", job)
	}
	if !job.Since.Before(job.Until) || job.Until.Sub(job.Since) > 7*24*time.Hour {
		t.Fatalf("window [%s, %s) is not inside the last 7 days", job.Since, job.Until)
	}
	if n := auditCount(db, "normalize_backfill"); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}

	// Duplicate while active: 409 + job_id, and the password is NOT checked.
	rec = post(`{"since_days":7,"password":"WRONG"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second request: %d %s, want 409", rec.Code, rec.Body.String())
	}
	var dup struct {
		JobID uint `json:"job_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &dup)
	if dup.JobID != job.ID {
		t.Fatalf("409 body names job %d, want %d: %s", dup.JobID, job.ID, rec.Body.String())
	}

	// Status.
	c, rec = backfillCtx(http.MethodGet, "/admin/api/normalize/backfill/status", "admin1", u.ID, "")
	h.GetNormalizeBackfill(c)
	if rec.Code != http.StatusOK || decodeBackfillJob(t, rec).ID != job.ID {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}

	// Cancel: pending → cancelled, audit row; a second cancel finds no active job.
	c, rec = backfillCtx(http.MethodPost, "/admin/api/normalize/backfill/cancel", "admin1", u.ID, "")
	h.CancelNormalizeBackfill(c)
	if rec.Code != http.StatusOK || decodeBackfillJob(t, rec).Status != database.NormalizeBackfillStatusCancelled {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	if n := auditCount(db, "normalize_backfill_cancel"); n != 1 {
		t.Fatalf("cancel audit rows = %d, want 1", n)
	}
	c, rec = backfillCtx(http.MethodPost, "/admin/api/normalize/backfill/cancel", "admin1", u.ID, "")
	h.CancelNormalizeBackfill(c)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cancel with nothing active: %d, want 404", rec.Code)
	}
	// Status of the cancelled job names the next step.
	c, rec = backfillCtx(http.MethodGet, "/admin/api/normalize/backfill/status", "admin1", u.ID, "")
	h.GetNormalizeBackfill(c)
	var st struct {
		Resumable bool   `json:"resumable"`
		Hint      string `json:"hint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || !st.Resumable || !strings.Contains(st.Hint, "resume") {
		t.Fatalf("status of a cancelled job: %v %s", err, rec.Body.String())
	}

	// Resume: wrong password 403, then → pending (202) with the same id.
	c, rec = backfillCtx(http.MethodPost, "/admin/api/normalize/backfill/resume", "admin1", u.ID, `{"password":"WRONG"}`)
	h.ResumeNormalizeBackfill(c)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("resume wrong password: %d, want 403", rec.Code)
	}
	c, rec = backfillCtx(http.MethodPost, "/admin/api/normalize/backfill/resume", "admin1", u.ID, `{"password":"s3cret-pw"}`)
	h.ResumeNormalizeBackfill(c)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("resume: %d %s", rec.Code, rec.Body.String())
	}
	if got := decodeBackfillJob(t, rec); got.ID != job.ID || got.Status != database.NormalizeBackfillStatusPending {
		t.Fatalf("resumed job: %+v", got)
	}
	// Resuming a pending job is a 409.
	c, rec = backfillCtx(http.MethodPost, "/admin/api/normalize/backfill/resume", "admin1", u.ID, `{"password":"s3cret-pw"}`)
	h.ResumeNormalizeBackfill(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("resume a pending job: %d, want 409", rec.Code)
	}
}

// TestStartNormalizeBackfill_DiskHeadroom: the precheck refuses the job when
// the data volume's known free space is under twice the estimated write, and
// lets it through when free space is unknown; a resume re-runs it.
func TestStartNormalizeBackfill_DiskHeadroom(t *testing.T) {
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	wm := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if _, err := db.InsertSettingIfAbsent(&models.SystemSetting{Key: database.NormalizeIngestStartedSetting, Value: wm.Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	// 10 M rows received yesterday ≈ 5 GB to write.
	if err := db.Gorm().Create(&models.SyslogIngestHourly{Timestamp: wm.Add(-24 * time.Hour).Truncate(time.Hour), Severity: 5, RowCount: 10_000_000}).Error; err != nil {
		t.Fatal(err)
	}
	free := uint64(6 << 30) // 6 GB free: under the 10 GB required
	if err := db.Gorm().Create(&models.ServerMetric{Timestamp: time.Now(), DataDiskFreeBytes: &free}).Error; err != nil {
		t.Fatal(err)
	}
	c, rec := backfillCtx(http.MethodPost, "/admin/api/normalize/backfill", "admin1", u.ID, `{"since_days":7,"password":"s3cret-pw"}`)
	h.StartNormalizeBackfill(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("under headroom: %d %s, want 409", rec.Code, rec.Body.String())
	}
	var body struct {
		Estimate database.NormalizeBackfillEstimate `json:"estimate"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Estimate.Rows != 10_000_000 || body.Estimate.Enough || !body.Estimate.FreeKnown {
		t.Fatalf("estimate in the 409: %+v", body.Estimate)
	}
	// Enough free space: queued.
	plenty := uint64(20 << 30)
	if err := db.Gorm().Create(&models.ServerMetric{Timestamp: time.Now().Add(time.Second), DataDiskFreeBytes: &plenty}).Error; err != nil {
		t.Fatal(err)
	}
	c, rec = backfillCtx(http.MethodPost, "/admin/api/normalize/backfill", "admin1", u.ID, `{"since_days":7,"password":"s3cret-pw"}`)
	h.StartNormalizeBackfill(c)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("with headroom: %d %s", rec.Code, rec.Body.String())
	}
	job := decodeBackfillJob(t, rec)

	// Resume re-runs the precheck over the remaining window: the volume
	// filled while the job was cancelled → 409, the job stays cancelled.
	if _, _, err := db.CancelNormalizeBackfillJob(job.ID); err != nil {
		t.Fatal(err)
	}
	filled := uint64(1 << 30)
	if err := db.Gorm().Create(&models.ServerMetric{Timestamp: time.Now().Add(2 * time.Second), DataDiskFreeBytes: &filled}).Error; err != nil {
		t.Fatal(err)
	}
	c, rec = backfillCtx(http.MethodPost, "/admin/api/normalize/backfill/resume", "admin1", u.ID, `{"password":"s3cret-pw"}`)
	h.ResumeNormalizeBackfill(c)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "insufficient disk headroom") {
		t.Fatalf("resume under headroom: %d %s, want 409", rec.Code, rec.Body.String())
	}
	if got, _ := db.GetNormalizeBackfillJob(job.ID); got.Status != database.NormalizeBackfillStatusCancelled {
		t.Fatalf("job after a refused resume: %s, want cancelled", got.Status)
	}
	if err := db.Gorm().Create(&models.ServerMetric{Timestamp: time.Now().Add(3 * time.Second), DataDiskFreeBytes: &plenty}).Error; err != nil {
		t.Fatal(err)
	}
	c, rec = backfillCtx(http.MethodPost, "/admin/api/normalize/backfill/resume", "admin1", u.ID, `{"password":"s3cret-pw"}`)
	h.ResumeNormalizeBackfill(c)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("resume with headroom: %d %s", rec.Code, rec.Body.String())
	}
}

// TestStartNormalizeBackfill_NormalizeDisabled: with NORMALIZE_ENABLED=false
// there is nothing for a backfill to feed consistently; 409.
func TestStartNormalizeBackfill_NormalizeDisabled(t *testing.T) {
	h, _, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	h.config.Normalize.Disabled = true
	c, rec := backfillCtx(http.MethodPost, "/admin/api/normalize/backfill", "admin1", u.ID, `{"password":"s3cret-pw"}`)
	h.StartNormalizeBackfill(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("normalization disabled: %d %s, want 409", rec.Code, rec.Body.String())
	}
}
