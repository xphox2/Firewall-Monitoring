package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// --- AUDIT-193: COUNT-query failure must surface as 500, not 200+total:0 -------

// failCountQueries registers an after-query callback that fails only COUNT
// queries (detected by the built SQL), so the paginated listings' Find succeeds
// while their count query errors — the exact split the pre-fix code swallowed.
func failCountQueries(t *testing.T, g *gorm.DB) {
	t.Helper()
	err := g.Callback().Query().After("gorm:query").Register("batch10_fail_count", func(tx *gorm.DB) {
		if strings.Contains(strings.ToLower(tx.Statement.SQL.String()), "count(") {
			tx.AddError(errors.New("injected count failure"))
		}
	})
	if err != nil {
		t.Fatalf("register count-fail callback: %v", err)
	}
}

func TestGetAlerts_CountError_500_AUDIT193(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().Create(&models.Alert{AlertType: "X", Severity: models.SeverityInfo, Message: "m"}).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	failCountQueries(t, db.Gorm())

	c, rec := jsonReq(http.MethodGet, "/x", "")
	h.GetAlerts(c)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GetAlerts with a failing count = %d, want 500 (pre-fix returned 200 with total:0)", rec.Code)
	}
}

func TestGetSyslogMessages_CountError_500_AUDIT193(t *testing.T) {
	h, db := setupTestHandler(t)
	failCountQueries(t, db.Gorm())

	c, rec := jsonReq(http.MethodGet, "/x", "")
	h.GetSyslogMessages(c)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GetSyslogMessages with a failing count = %d, want 500", rec.Code)
	}
}

func TestGetDeviceConfigHistory_CountError_500_AUDIT193(t *testing.T) {
	h, db := setupTestHandler(t)
	failCountQueries(t, db.Gorm())

	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	h.GetDeviceConfigHistory(c)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GetDeviceConfigHistory with a failing count = %d, want 500 (pre-fix returned 200 with total_all:0)", rec.Code)
	}
}

// --- AUDIT-197: device create/update validate site_id like probe_id ----------

func TestCreateDevice_SiteIDValidation_AUDIT197(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	site := &models.Site{Name: "real-site"}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}

	createReq := func(body map[string]interface{}) int {
		b, _ := json.Marshal(body)
		c, rec := jsonReq(http.MethodPost, "/devices", string(b))
		h.CreateDevice(c)
		return rec.Code
	}

	// probe_id skips the SSRF IP gate; nonexistent site_id must 400.
	if code := createReq(map[string]interface{}{
		"name": "d1", "ip_address": "10.0.0.5", "probe_id": probe.ID, "site_id": 999999,
	}); code != http.StatusBadRequest {
		t.Fatalf("create with nonexistent site_id = %d, want 400", code)
	}
	// A valid site succeeds.
	if code := createReq(map[string]interface{}{
		"name": "d2", "ip_address": "10.0.0.6", "probe_id": probe.ID, "site_id": site.ID,
	}); code != http.StatusCreated {
		t.Fatalf("create with valid site_id = %d, want 201", code)
	}
	// No site_id (unassigned) still succeeds — the >0 guard is load-bearing.
	if code := createReq(map[string]interface{}{
		"name": "d3", "ip_address": "10.0.0.7", "probe_id": probe.ID,
	}); code != http.StatusCreated {
		t.Fatalf("create with no site_id = %d, want 201", code)
	}
}

func TestUpdateDevice_SiteIDValidation_AUDIT197(t *testing.T) {
	h, db := setupTestHandler(t)
	if sqlDB, err := db.Gorm().DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	_, device := setupProbeAndDevice(t, db)
	site := &models.Site{Name: "site-ok"}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}

	update := func(body map[string]interface{}) int {
		b, _ := json.Marshal(body)
		c, rec := jsonReq(http.MethodPut, "/devices/"+strconv.Itoa(int(device.ID)), string(b))
		c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(device.ID))}}
		h.UpdateDevice(c)
		return rec.Code
	}

	if code := update(map[string]interface{}{"site_id": 999999}); code != http.StatusBadRequest {
		t.Fatalf("update to nonexistent site_id = %d, want 400", code)
	}
	if code := update(map[string]interface{}{"site_id": site.ID}); code != http.StatusOK {
		t.Fatalf("update to valid site_id = %d, want 200", code)
	}
	// site_id 0 = explicit unassign, must stay allowed.
	if code := update(map[string]interface{}{"site_id": 0}); code != http.StatusOK {
		t.Fatalf("update to site_id 0 (unassign) = %d, want 200", code)
	}
}

// --- AUDIT-251: non-numeric numeric filters return 400, not a 22P02 500 -------

func TestNumericFilters_400_AUDIT251(t *testing.T) {
	h, _ := setupTestHandler(t)
	cases := []struct {
		name string
		path string
		fn   func(*gin.Context)
	}{
		{"alerts device_id", "/x?device_id=abc", h.GetAlerts},
		{"alerts site_id", "/x?site_id=abc", h.GetAlerts},
		{"traps device_id", "/x?device_id=abc", h.GetTraps},
		{"syslog device_id", "/x?device_id=abc", h.GetSyslogMessages},
		{"syslog probe_id", "/x?probe_id=abc", h.GetSyslogMessages},
	}
	for _, tc := range cases {
		c, rec := jsonReq(http.MethodGet, tc.path, "")
		tc.fn(c)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s (%s) = %d, want 400 (pre-fix SQLite matched nothing → 200)", tc.name, tc.path, rec.Code)
		}
	}

	// A valid numeric filter and a string filter (severity/alert_type) still pass.
	for _, path := range []string{"/x?device_id=5", "/x?severity=critical", "/x?alert_type=CPU_HIGH", "/x?site_id=unassigned"} {
		c, rec := jsonReq(http.MethodGet, path, "")
		h.GetAlerts(c)
		if rec.Code != http.StatusOK {
			t.Errorf("GetAlerts %s = %d, want 200", path, rec.Code)
		}
	}
}

// --- AUDIT-256: DeleteDeviceConfigRevision logs result.Error, not stale nil ---

// slogHasErrAttr installs a capturing text logger and returns the buffer + a
// restore func. InternalError logs the underlying error only when non-nil, so
// the "err=" token appears exactly when result.Error (not the nil parse err) is
// passed.
func captureSlog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
	return &buf, func() { slog.SetDefault(old) }
}

func TestDeleteDeviceConfigRevision_LogsResultError_AUDIT256(t *testing.T) {
	h, db := setupTestHandler(t)
	// Force the Delete to error: drop the table it targets.
	if err := db.Gorm().Migrator().DropTable(&models.DeviceConfigRevision{}); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	buf, restore := captureSlog(t)
	defer restore()

	c, rec := jsonReq(http.MethodDelete, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: "1"}, {Key: "revId", Value: "1"}}
	h.DeleteDeviceConfigRevision(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete on a broken table = %d, want 500", rec.Code)
	}
	if !strings.Contains(buf.String(), "err=") {
		t.Fatalf("the real DB error was not logged (no err attr) — pre-fix passed the stale nil parse err: %q", buf.String())
	}
}

// --- AUDIT-257: DeleteEventRuleProfile does not leak the raw DB error ---------

func TestDeleteEventRuleProfile_NoRawError_AUDIT257(t *testing.T) {
	h, _ := setupTestHandler(t)

	// Deleting a nonexistent profile makes DeleteEventRuleProfile return a wrapped
	// gorm.ErrRecordNotFound ("delete event rule profile N: load: record not
	// found"). Pre-fix that reached the client verbatim with a 400.
	c, rec := jsonReq(http.MethodDelete, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: "999999"}}
	h.DeleteEventRuleProfile(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete nonexistent profile = %d, want 500 (not-found is not a client 400 here)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Failed to delete event rule profile") {
		t.Fatalf("client body = %q, want the generic message", body)
	}
	if strings.Contains(body, "record not found") || strings.Contains(body, "load:") {
		t.Fatalf("client body leaked internal DB detail: %q", body)
	}
}

// --- AUDIT-259 / AUDIT-261: DB-unavailable handlers return 503, not panic -----

func TestDBUnavailable_503_AUDIT259_261(t *testing.T) {
	// A true-nil Store interface (the DB-unavailable state) — reqDB then returns
	// nil and RequireDB must convert that to a 503. Constructed directly rather
	// than via NewHandler so the interface field is a genuine nil, not a typed-nil
	// wrapping a nil *Database.
	h := &Handler{config: &config.Config{}}

	cases := []struct {
		name string
		fn   func(*gin.Context)
	}{
		{"GetSyslogRetention", h.GetSyslogRetention},
		{"GetServerMetricChart", h.GetServerMetricChart},
	}
	for _, tc := range cases {
		c, rec := jsonReq(http.MethodGet, "/x", "")
		tc.fn(c) // must not panic (pre-fix: nil-receiver method call panics)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s with no DB = %d, want 503", tc.name, rec.Code)
		}
	}
}
