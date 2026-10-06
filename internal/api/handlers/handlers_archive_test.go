package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// The retention gate's operator escapes (archive plan PR 5). Synthetic
// accounts only (alice).

func archiveOverrideUntil(t *testing.T, db *database.Database, stream string) (time.Time, bool) {
	t.Helper()
	return db.ArchiveGateOverride(stream, time.Now())
}

// TestSetArchiveGateOverride walks the POST's checks in order — body (400:
// stream, hours missing / out of range, reason), then re-authentication
// (403) — and the happy paths: releasing both streams for 6 h writes the two
// settings and two audit rows; hours 0 re-engages one stream without a
// password; GET reports the state. The settings page cannot write the key.
func TestSetArchiveGateOverride(t *testing.T) {
	h, db, u := profileTestHandler(t, "alice", auth.RoleAdmin, "s3cret-pw")
	post := func(body string) *httptest.ResponseRecorder {
		c, rec := backfillCtx(http.MethodPost, "/admin/api/archive/override", "alice", u.ID, body)
		h.SetArchiveGateOverride(c)
		return rec
	}
	for body, want := range map[string]int{
		`{"stream":"sflow","hours":6,"reason":"disk","password":"s3cret-pw"}`:   http.StatusBadRequest,
		`{"stream":"syslog","reason":"disk","password":"s3cret-pw"}`:            http.StatusBadRequest,
		`{"stream":"syslog","hours":25,"reason":"disk","password":"s3cret-pw"}`: http.StatusBadRequest,
		`{"stream":"syslog","hours":-1,"reason":"disk","password":"s3cret-pw"}`: http.StatusBadRequest,
		`{"stream":"syslog","hours":6,"password":"s3cret-pw"}`:                  http.StatusBadRequest,
		`{"stream":"syslog","hours":6,"reason":"disk","password":"WRONG"}`:      http.StatusForbidden,
		`{"stream":"syslog","hours":6,"reason":"disk"}`:                         http.StatusForbidden,
		`not json`: http.StatusBadRequest,
	} {
		if rec := post(body); rec.Code != want {
			t.Errorf("%s: %d %s, want %d", body, rec.Code, rec.Body.String(), want)
		}
	}
	for _, s := range database.ArchiveGateStreams {
		if _, active := archiveOverrideUntil(t, db, s); active {
			t.Fatalf("a refused request released %s", s)
		}
	}
	if n := auditCount(db, "archive_gate_override"); n != 0 {
		t.Fatalf("refused requests wrote %d audit rows", n)
	}

	rec := post(`{"stream":"all","hours":6,"reason":"disk at 95%, archive bucket unreachable","password":"s3cret-pw"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("release: %d %s", rec.Code, rec.Body.String())
	}
	for _, s := range database.ArchiveGateStreams {
		until, active := archiveOverrideUntil(t, db, s)
		if !active || until.Before(time.Now().Add(5*time.Hour)) || until.After(time.Now().Add(6*time.Hour+time.Minute)) {
			t.Fatalf("%s override: until %s active %v, want about 6 h from now", s, until, active)
		}
	}
	if n := auditCount(db, "archive_gate_override"); n != 2 {
		t.Fatalf("audit rows = %d, want 2 (one per stream)", n)
	}

	// Re-engaging needs no password (it only restores the safe state).
	rec = post(`{"stream":"syslog","hours":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-engage: %d %s", rec.Code, rec.Body.String())
	}
	if _, active := archiveOverrideUntil(t, db, database.ArchiveGateSyslog); active {
		t.Fatal("syslog override still active after hours 0")
	}
	if _, active := archiveOverrideUntil(t, db, database.ArchiveGateFlows); !active {
		t.Fatal("re-engaging syslog cleared the flows override")
	}
	if n := auditCount(db, "archive_gate_override"); n != 3 {
		t.Fatalf("audit rows = %d, want 3", n)
	}

	c, rec := backfillCtx(http.MethodGet, "/admin/api/archive/override", "alice", u.ID, "")
	h.GetArchiveGate(c)
	var got struct {
		Data struct {
			Streams []archiveGateStatus `json:"streams"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || len(got.Data.Streams) != 2 ||
		got.Data.Streams[0].OverrideActive || !got.Data.Streams[1].OverrideActive {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}

	// The settings page's allowlist must not reach the key.
	c, _ = backfillCtx(http.MethodPost, "/admin/api/settings", "alice", u.ID,
		`[{"key":"`+database.ArchiveGateOverrideKey(database.ArchiveGateSyslog)+`","value":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}]`)
	h.UpdateSettings(c)
	if _, active := archiveOverrideUntil(t, db, database.ArchiveGateSyslog); active {
		t.Fatal("POST /admin/api/settings released the gate without re-authentication")
	}
}

// TestResetArchiveChunk: bad id (400), no reason (400), unknown chunk (404),
// a chunk that is not parked (409, before the step-up), wrong password
// (403), then the reset (200, pending, audit row).
func TestResetArchiveChunk(t *testing.T) {
	h, db, u := profileTestHandler(t, "alice", auth.RoleAdmin, "s3cret-pw")
	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mk := func(seq int64, status string) models.ArchiveChunk {
		c := models.ArchiveChunk{SourceTable: "syslog_messages", Seq: seq, IDLo: (seq - 1) * 10, IDHi: seq * 10,
			PeriodStart: day.AddDate(0, 0, int(seq)), PeriodEnd: day.AddDate(0, 0, int(seq)+1), Month: "2026-09", Status: status, Mismatches: 3}
		if err := db.Gorm().Create(&c).Error; err != nil {
			t.Fatal(err)
		}
		return c
	}
	ok := mk(1, models.ArchiveChunkVerified)
	parked := mk(2, models.ArchiveChunkNeedsAttention)
	post := func(id, body string) *httptest.ResponseRecorder {
		c, rec := backfillCtx(http.MethodPost, "/admin/api/archive/chunks/"+id+"/reset", "alice", u.ID, body)
		c.Params = gin.Params{{Key: "id", Value: id}}
		h.ResetArchiveChunk(c)
		return rec
	}
	const good = `{"reason":"bucket policy fixed","password":"s3cret-pw"}`
	for _, tc := range []struct {
		id, body string
		want     int
	}{
		{"x", good, http.StatusBadRequest},
		{"0", good, http.StatusBadRequest},
		{"2", `{"password":"s3cret-pw"}`, http.StatusBadRequest},
		{"999", good, http.StatusNotFound},
		{"1", `{"reason":"r","password":"WRONG"}`, http.StatusConflict},
		{"2", `{"reason":"r","password":"WRONG"}`, http.StatusForbidden},
	} {
		if rec := post(tc.id, tc.body); rec.Code != tc.want {
			t.Errorf("%s %s: %d %s, want %d", tc.id, tc.body, rec.Code, rec.Body.String(), tc.want)
		}
	}
	if c, _ := db.GetArchiveChunk(parked.ID); c.Status != models.ArchiveChunkNeedsAttention {
		t.Fatalf("a refused request changed the chunk to %s", c.Status)
	}
	rec := post("2", good)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	c, _ := db.GetArchiveChunk(parked.ID)
	if c.Status != models.ArchiveChunkPending || c.Mismatches != 0 {
		t.Fatalf("after reset: %+v", c)
	}
	if c, _ := db.GetArchiveChunk(ok.ID); c.Status != models.ArchiveChunkVerified {
		t.Fatalf("the verified chunk changed to %s", c.Status)
	}
	if n := auditCount(db, "archive_chunk_reset"); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	if rec := post("2", good); rec.Code != http.StatusConflict {
		t.Fatalf("second reset: %d, want 409", rec.Code)
	}
}

// TestGetArchiveStatus: the archive status reports a parked chunk (holding
// its table's deletes), the worker's last failure with the credentials
// redacted, the config with the key id cut to its last four characters — and
// neither credential anywhere in the body.
func TestGetArchiveStatus(t *testing.T) {
	h, db, u := profileTestHandler(t, "alice", auth.RoleAdmin, "s3cret-pw")
	const keyID, secret = "keyid-test-wxyz", "secret-test-value-never-shown"
	h.config.Archive = config.ArchiveConfig{SyslogEnabled: true, Endpoint: "https://s3.example.com", Region: "us-test-1",
		Bucket: "example-bucket", Prefix: "fwmon-test", AccessKeyID: keyID, SecretAccessKey: config.Secret(secret), StagingDir: "/tmp/x"}
	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []models.ArchiveChunk{
		{SourceTable: "syslog_messages", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: day, PeriodEnd: day.AddDate(0, 0, 1), Month: "2026-09", Status: models.ArchiveChunkVerified},
		{SourceTable: "syslog_messages", Seq: 2, IDLo: 10, IDHi: 20, PeriodStart: day.AddDate(0, 0, 1), PeriodEnd: day.AddDate(0, 0, 2), Month: "2026-09",
			Status: models.ArchiveChunkNeedsAttention, Mismatches: 3, Error: "read-back sha256 differs"},
	} {
		if err := db.Gorm().Create(&c).Error; err != nil {
			t.Fatal(err)
		}
	}
	rec := status.NewRecorder("fw-example-01-7", "/tmp/x", 1<<30, secret, keyID)
	rec.Failed("upload", errors.New("403 for "+keyID+"/"+secret), time.Now())
	js, err := rec.JSON(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}

	c, w := backfillCtx(http.MethodGet, "/admin/api/archive/status", "alice", u.ID, "")
	h.GetArchiveStatus(c)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, leak := range []string{keyID, secret} {
		if strings.Contains(body, leak) {
			t.Fatalf("the archive status carries %q: %s", leak, body)
		}
	}
	var got struct {
		Data status.Status `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	st := got.Data
	if len(st.NeedsAttention) != 1 || st.NeedsAttention[0].Seq != 2 || !st.NeedsAttention[0].HoldsGate ||
		st.Config.AccessKeyID != "…wxyz" || st.Worker == nil || len(st.Worker.Stages) != 1 ||
		!strings.Contains(st.Worker.Stages[0].Error, "[redacted]") || st.OverrideMaxHours != database.ArchiveGateOverrideMaxHours {
		t.Fatalf("status: %+v", st)
	}
}

// TestArchiveAlertThresholdSettings: the archive alert thresholds are
// accepted from 0 to 720 (blank = default) and refused otherwise.
func TestArchiveAlertThresholdSettings(t *testing.T) {
	h, db, u := profileTestHandler(t, "alice", auth.RoleAdmin, "s3cret-pw")
	post := func(key, value string) int {
		c, rec := backfillCtx(http.MethodPost, "/admin/api/settings", "alice", u.ID, `[{"key":"`+key+`","value":"`+value+`"}]`)
		h.UpdateSettings(c)
		return rec.Code
	}
	for _, key := range []string{status.LagHoursSyslogKey, status.LagHoursFlowsKey, status.LagHoursCountersKey,
		status.SealOverdueDaysKey, status.HeldHoursKey, status.UnsettledHoursKey} {
		for value, want := range map[string]int{"0": 200, "720": 200, "": 200, "721": 400, "-1": 400, "2.5": 400, "x": 400} {
			if code := post(key, value); code != want {
				t.Errorf("%s=%q: %d, want %d", key, value, code, want)
			}
		}
		if code := post(key, "12"); code != 200 || db.GetIntSetting(key, -1) != 12 {
			t.Errorf("%s=12 not stored: %d %d", key, code, db.GetIntSetting(key, -1))
		}
	}
}

// TestAlertGlobalDefaults_ArchiveThresholds: the Alerting page reads every
// archive threshold with its default, and a stored value replaces it.
func TestAlertGlobalDefaults_ArchiveThresholds(t *testing.T) {
	h, db, _ := profileTestHandler(t, "alice", auth.RoleAdmin, "s3cret-pw")
	if err := db.UpsertSetting(&models.SystemSetting{Key: status.HeldHoursKey, Value: "9"}); err != nil {
		t.Fatal(err)
	}
	g := h.alertGlobalDefaults(db)
	for key, def := range status.ThresholdDefaults {
		want := def
		if key == status.HeldHoursKey {
			want = 9
		}
		if g[key] != want {
			t.Errorf("%s = %v, want %d", key, g[key], want)
		}
	}
}
