package handlers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/local"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/pquerna/otp/totp"
)

// The raw archive's admin settings (A-10): GET / test / save. Synthetic
// fixtures only (alice, example-bucket, documentation key ids).

const (
	archUISecret  = "fake-ui-archive-secret-value"
	archEnvSecret = "fake-env-archive-secret-value"
	archKeyID     = "005exampleKeyIDwxyz"
	archBucket    = "example-bucket"
	archPrefix    = "fwmon-test"
)

type archSettingsFixture struct {
	h   *Handler
	db  *database.Database
	u   *models.Admin
	srv *s3test.Server
	// root is ARCHIVE_ALLOWED_ROOT (a temporary directory the tests treat
	// as a mount point); the staging directory is root/staging.
	root string
}

// archSettingsSetup: an admin (alice), an encryption key, a B2-strict fake
// bucket the environment points at with both streams off, an allowed root
// (a temporary directory, stubbed as a mount point) and a staging directory
// under it with plenty of (stubbed) free space.
func archSettingsSetup(t *testing.T, opts ...s3test.Option) *archSettingsFixture {
	t.Helper()
	h, db, u := profileTestHandler(t, "alice", auth.RoleAdmin, "s3cret-pw")
	db.SetEncryptionKeyForTesting("archive-settings-handler-key")
	srv := s3test.NewB2Strict(t, archBucket, opts...)
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o750); err != nil {
		t.Fatal(err)
	}
	h.config.Archive = config.ArchiveConfig{Endpoint: srv.URL, Region: "us-east-005", Bucket: archBucket, Prefix: archPrefix,
		AccessKeyID: archKeyID, SecretAccessKey: config.Secret(archEnvSecret), PathStyle: true, AllowPrivateEndpoint: true,
		MinAgeHours: 2, SealGraceHours: 48, SealReverify: config.SealReverifyHead, SyslogRateRowsPerSec: 5000,
		FlowRateRowsPerSec: 20000, StagingDir: staging, AllowedRoot: root}
	origMount := local.IsMountPoint
	local.IsMountPoint = func(dir string) (bool, error) { return dir == root, nil }
	t.Cleanup(func() { local.IsMountPoint = origMount })
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	origOpts, origFree := archiveS3Options, archiveStagingFree
	archiveS3Options = func() []s3.Option { return []s3.Option{s3.WithRootCAs(pool)} }
	archiveStagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { archiveS3Options, archiveStagingFree = origOpts, origFree })
	return &archSettingsFixture{h: h, db: db, u: u, srv: srv, root: root}
}

func (f *archSettingsFixture) do(method, path, body string) *httptest.ResponseRecorder {
	c, rec := backfillCtx(method, path, "alice", f.u.ID, body)
	switch {
	case method == http.MethodGet:
		f.h.GetArchiveSettings(c)
	case strings.HasSuffix(path, "/test"):
		f.h.TestArchiveSettings(c)
	default:
		f.h.SaveArchiveSettings(c)
	}
	return rec
}

func (f *archSettingsFixture) save(body string) *httptest.ResponseRecorder {
	f.h.reauth = auth.ReauthLimiter{} // the per-account step-up budget is not under test here
	return f.do(http.MethodPost, "/admin/api/archive/settings", body)
}

func (f *archSettingsFixture) view(t *testing.T) archiveSettingsView {
	t.Helper()
	rec := f.do(http.MethodGet, "/admin/api/archive/settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Data archiveSettingsView `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got.Data
}

func fieldOf(v archiveSettingsView, key string) archiveFieldView {
	for _, f := range v.Fields {
		if f.Key == key {
			return f
		}
	}
	return archiveFieldView{}
}

func (f *archSettingsFixture) resolved(t *testing.T) config.ArchiveConfig {
	t.Helper()
	res, err := f.db.ResolveArchiveConfig(context.Background(), f.h.config.Archive)
	if err != nil {
		t.Fatal(err)
	}
	return res.Config
}

// TestArchiveSettings_Precedence: GET reports each value's source — the
// environment's, a built-in default, or an admin setting — and a revert
// brings the environment's value back.
func TestArchiveSettings_Precedence(t *testing.T) {
	f := archSettingsSetup(t)
	for _, fd := range config.ArchiveFields {
		t.Setenv(fd.Env, "")
	}
	f.h.config.Archive = config.Load().Archive // a real env load: nothing set
	v := f.view(t)
	if s := fieldOf(v, "ARCHIVE_MIN_AGE_HOURS"); s.Source != archiveSourceDefault || s.Value != "2" || s.EnvValue != "2" {
		t.Fatalf("min age: %+v", s)
	}
	t.Setenv("ARCHIVE_S3_REGION", "us-east-005")
	t.Setenv("ARCHIVE_S3_BUCKET", archBucket)
	f.h.config.Archive = config.Load().Archive
	if s := fieldOf(f.view(t), "ARCHIVE_S3_BUCKET"); s.Source != archiveSourceEnv || s.Value != archBucket {
		t.Fatalf("bucket from env: %+v", s)
	}
	if rec := f.save(`{"set":{"ARCHIVE_S3_BUCKET":"example-bucket-ui","ARCHIVE_MIN_AGE_HOURS":"6"},"password":"s3cret-pw"}`); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	v = f.view(t)
	if s := fieldOf(v, "ARCHIVE_S3_BUCKET"); s.Source != archiveSourceUI || s.Value != "example-bucket-ui" || s.EnvValue != archBucket {
		t.Fatalf("bucket set here: %+v", s)
	}
	if s := fieldOf(v, "ARCHIVE_MIN_AGE_HOURS"); s.Source != archiveSourceUI || s.Value != "6" {
		t.Fatalf("min age set here: %+v", s)
	}
	if rec := f.save(`{"revert":["ARCHIVE_S3_BUCKET"],"password":"s3cret-pw"}`); rec.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", rec.Code, rec.Body.String())
	}
	if s := fieldOf(f.view(t), "ARCHIVE_S3_BUCKET"); s.Source != archiveSourceEnv || s.Value != archBucket {
		t.Fatalf("bucket after revert: %+v", s)
	}
}

// TestArchiveSettings_SecretNeverReturned: the secret saved on the admin page
// is stored encrypted and appears in no GET — the archive settings, the
// generic settings list, the archive status (its worker state included) —
// nor in the audit row; the form gets "set" and the KEY ID's last four.
func TestArchiveSettings_SecretNeverReturned(t *testing.T) {
	f := archSettingsSetup(t)
	rec := f.save(`{"set":{"ARCHIVE_S3_SECRET_ACCESS_KEY":"` + archUISecret + `"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), archUISecret) {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.resolved(t).SecretAccessKey.Reveal(); got != archUISecret {
		t.Fatalf("the resolved secret is not the admin's (%d chars)", len(got))
	}
	// The worker records its state with the secret redacted; put the secret
	// in an error to prove the status does not let it through.
	rt := status.NewRecorder("fw-example-01-1", f.h.config.Archive.StagingDir, 1<<30, archUISecret, archKeyID)
	rt.Failed("upload", &net403{archUISecret}, time.Now())
	js, err := rt.JSON(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}

	bodies := map[string]string{}
	v := f.do(http.MethodGet, "/admin/api/archive/settings", "")
	bodies["archive settings"] = v.Body.String()
	c, w := backfillCtx(http.MethodGet, "/admin/api/settings", "alice", f.u.ID, "")
	f.h.GetSettings(c)
	bodies["settings list"] = w.Body.String()
	c, w = backfillCtx(http.MethodGet, "/admin/api/archive/status", "alice", f.u.ID, "")
	f.h.GetArchiveStatus(c)
	bodies["archive status"] = w.Body.String()
	raw, _, _ := f.db.ArchiveWorkerState(context.Background())
	bodies["worker state"] = raw
	var audits []models.AuditLog
	f.db.Gorm().Find(&audits)
	for _, a := range audits {
		bodies["audit "+a.Action] = a.Target
	}
	var row models.SystemSetting
	f.db.Gorm().Where("\"key\" = ?", database.ArchiveSecretSettingKey).First(&row)
	bodies["stored row"] = row.Value
	for name, b := range bodies {
		if strings.Contains(b, archUISecret) {
			t.Errorf("%s carries the secret: %s", name, b)
		}
	}
	if !strings.Contains(bodies["audit archive_settings_update"], "changed=ARCHIVE_S3_SECRET_ACCESS_KEY") {
		t.Errorf("audit target %q does not name the field", bodies["audit archive_settings_update"])
	}
	if !strings.HasPrefix(row.Value, "{enc}") {
		t.Errorf("the secret is stored as %q, want encrypted", row.Value)
	}
	s := fieldOf(f.view(t), "ARCHIVE_S3_SECRET_ACCESS_KEY")
	if s.Value != "" || s.EnvValue != "" || !s.Set || s.Hint != "…wxyz" || s.Source != archiveSourceUI {
		t.Fatalf("secret field: %+v", s)
	}
}

type net403 struct{ secret string }

func (e *net403) Error() string { return "403 Forbidden for credential " + e.secret }

// TestSaveArchiveSettings_ChecksInOrder walks the save's checks: the body
// and values (400) and a location change once chunks exist (409) are refused
// before the step-up, even with a wrong password; then the password (403)
// and the 2FA code; then the staging directory probe (422, only for a
// re-authenticated caller) and the preflight of an enabled stream (422,
// nothing stored); then the save, which is audited by field name.
func TestSaveArchiveSettings_ChecksInOrder(t *testing.T) {
	f := archSettingsSetup(t)
	for body, want := range map[string]int{
		`not json`: http.StatusBadRequest,
		`{}`:       http.StatusBadRequest,
		`{"set":{"ARCHIVE_NOT_A_KEY":"1"},"password":"WRONG"}`:                                                                               http.StatusBadRequest,
		`{"set":{"ARCHIVE_MIN_AGE_HOURS":"0"},"password":"WRONG"}`:                                                                           http.StatusBadRequest,
		`{"set":{"ARCHIVE_MIN_AGE_HOURS":"two"},"password":"WRONG"}`:                                                                         http.StatusBadRequest,
		`{"set":{"ARCHIVE_SYSLOG_ENABLED":"maybe"},"password":"WRONG"}`:                                                                      http.StatusBadRequest,
		`{"set":{"ARCHIVE_SYSLOG_ENABLED":""},"password":"WRONG"}`:                                                                           http.StatusBadRequest,
		`{"set":{"ARCHIVE_S3_SECRET_ACCESS_KEY":"********"},"password":"WRONG"}`:                                                             http.StatusBadRequest,
		`{"set":{"ARCHIVE_S3_SECRET_ACCESS_KEY":""},"password":"WRONG"}`:                                                                     http.StatusBadRequest,
		`{"set":{"ARCHIVE_S3_BUCKET":"x"},"revert":["ARCHIVE_S3_BUCKET"],"password":"WRONG"}`:                                                http.StatusBadRequest,
		`{"set":{"ARCHIVE_S3_ENDPOINT":"https://user:pw@s3.example.com"},"password":"WRONG"}`:                                                http.StatusBadRequest,
		`{"set":{"ARCHIVE_FLOWS_ENABLED":"true","ARCHIVE_STAGING_DIR":"rel"},"password":"WRONG"}`:                                            http.StatusBadRequest,
		`{"set":{"ARCHIVE_SYSLOG_ENABLED":"true","ARCHIVE_STAGING_DIR":"` + filepath.Join(f.root, "missing") + `"},"password":"WRONG"}`:      http.StatusForbidden,
		`{"set":{"ARCHIVE_SYSLOG_ENABLED":"true","ARCHIVE_STAGING_DIR":"` + filepath.Join(f.root, "missing") + `"},"password":"s3cret-pw"}`:  http.StatusUnprocessableEntity,
		`{"set":{"ARCHIVE_SYSLOG_ENABLED":"true","ARCHIVE_STAGING_DIR":"` + filepath.Join(t.TempDir(), "outside") + `"},"password":"WRONG"}`: http.StatusBadRequest,
		`{"set":{"ARCHIVE_STAGING_DIR":"` + f.root + `/../outside"},"password":"WRONG"}`:                                                     http.StatusBadRequest,
		`{"set":{"ARCHIVE_WINDOW":"01:00-05:00"},"password":"WRONG"}`:                                                                        http.StatusForbidden,
		`{"set":{"ARCHIVE_WINDOW":"01:00-05:00"}}`:                                                                                           http.StatusForbidden,
	} {
		if rec := f.save(body); rec.Code != want {
			t.Errorf("%s: %d %s, want %d", body, rec.Code, rec.Body.String(), want)
		}
	}
	if n := auditCount(f.db, "archive_settings_update"); n != 0 {
		t.Fatalf("refused saves wrote %d audit rows", n)
	}
	if res, _ := f.db.ResolveArchiveConfig(context.Background(), f.h.config.Archive); len(res.UI) != 0 {
		t.Fatalf("a refused save stored %v", res.UI)
	}

	// Enabling runs the preflight after the step-up: a bucket that does not
	// exist is refused and nothing is stored.
	rec := f.save(`{"set":{"ARCHIVE_SYSLOG_ENABLED":"true","ARCHIVE_S3_BUCKET":"example-bucket-missing"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "preflight") {
		t.Fatalf("enable with a failing preflight: %d %s", rec.Code, rec.Body.String())
	}
	if f.resolved(t).SyslogEnabled {
		t.Fatal("enabled although the preflight failed")
	}

	// 2FA enrolled: the code is required, then accepted.
	const totpSecret = "JBSWY3DPEHPK3PXP"
	if err := f.db.Gorm().Model(&models.Admin{}).Where("id = ?", f.u.ID).
		Updates(map[string]interface{}{"totp_enabled": true, "totp_secret": totpSecret}).Error; err != nil {
		t.Fatal(err)
	}
	if rec := f.save(`{"set":{"ARCHIVE_SYSLOG_ENABLED":"true"},"password":"s3cret-pw"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("no 2FA code: %d %s", rec.Code, rec.Body.String())
	}
	code, _ := totp.GenerateCode(totpSecret, time.Now())
	rec = f.save(`{"set":{"ARCHIVE_SYSLOG_ENABLED":"true"},"password":"s3cret-pw","totp_code":"` + code + `"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}
	if !f.resolved(t).SyslogEnabled || f.srv.Count(s3test.OpGetLockConfig) != 0 || f.srv.Count(s3test.OpListObjects) < 1 {
		t.Fatalf("after enabling: enabled %v, lock checks %d, lists %d", f.resolved(t).SyslogEnabled,
			f.srv.Count(s3test.OpGetLockConfig), f.srv.Count(s3test.OpListObjects))
	}
	var a models.AuditLog
	f.db.Gorm().Where("action = ?", "archive_settings_update").First(&a)
	if a.Target != "changed=ARCHIVE_SYSLOG_ENABLED enabled=syslog" || a.Actor != "alice" {
		t.Fatalf("audit row %+v", a)
	}
	if err := f.db.Gorm().Model(&models.Admin{}).Where("id = ?", f.u.ID).Update("totp_enabled", false).Error; err != nil {
		t.Fatal(err)
	}

	// Chunks exist: the location is fixed (409, before the step-up), other
	// fields still change.
	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if err := f.db.Gorm().Create(&models.ArchiveChunk{SourceTable: "syslog_messages", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: day,
		PeriodEnd: day.AddDate(0, 0, 1), Month: "2026-09", Status: models.ArchiveChunkVerified}).Error; err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"set":{"ARCHIVE_S3_PREFIX":"fwmon-test/b"},"password":"WRONG"}`,
		`{"set":{"ARCHIVE_S3_BUCKET":"example-bucket-2"},"password":"WRONG"}`,
		`{"set":{"ARCHIVE_S3_ENDPOINT":"https://s3.example.net"},"password":"WRONG"}`,
	} {
		if rec := f.save(body); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "OPERATIONS.md") {
			t.Errorf("%s with chunks: %d %s, want 409", body, rec.Code, rec.Body.String())
		}
	}
	if rec := f.save(`{"set":{"ARCHIVE_S3_PREFIX":"` + archPrefix + `","ARCHIVE_WINDOW":"01:00-05:00"},"password":"s3cret-pw"}`); rec.Code != http.StatusOK {
		t.Fatalf("same location, other field: %d %s", rec.Code, rec.Body.String())
	}

	// Switching off: saved with a warning, and the disabled interval opened.
	rec = f.save(`{"set":{"ARCHIVE_SYSLOG_ENABLED":"false"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sealed partial") {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	var evs []models.ArchiveGateEvent
	f.db.Gorm().Where("stream = ? AND kind = ? AND to_ts IS NULL", database.ArchiveGateSyslog, models.ArchiveGateEventDisabled).Find(&evs)
	if len(evs) != 1 {
		t.Fatalf("disabled intervals %+v, want one open", evs)
	}
}

// TestSaveArchiveSettings_EnableNeedsStagingRoom: the staging directory of an
// enabled stream must have the worker's free-space floor (422 before the
// step-up; probed only after it).
func TestSaveArchiveSettings_EnableNeedsStagingRoom(t *testing.T) {
	f := archSettingsSetup(t)
	archiveStagingFree = func(context.Context, string) (uint64, error) { return 1 << 20, nil }
	if rec := f.save(`{"set":{"ARCHIVE_FLOWS_ENABLED":"true"},"password":"WRONG"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("the staging probe ran before the step-up: %d %s", rec.Code, rec.Body.String())
	}
	rec := f.save(`{"set":{"ARCHIVE_FLOWS_ENABLED":"true"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "free") {
		t.Fatalf("enable on a full staging volume: %d %s", rec.Code, rec.Body.String())
	}
}

// TestTestArchiveSettings: Test connection runs the preflight with the form's
// values and saves nothing — the Object Lock check included, the stored or
// environment secret used without being echoed — and refuses to widen the
// Advanced flags without the re-authenticated save.
func TestTestArchiveSettings(t *testing.T) {
	test := func(f *archSettingsFixture, body string) map[string]any {
		t.Helper()
		rec := f.do(http.MethodPost, "/admin/api/archive/settings/test", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), archEnvSecret) || strings.Contains(rec.Body.String(), archUISecret) {
			t.Fatalf("Test connection echoed a secret: %s", rec.Body.String())
		}
		var got struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got.Data
	}
	f := archSettingsSetup(t)
	if r := test(f, `{}`); r["ok"] != true || !strings.Contains(r["message"].(string), "Object Lock is off") {
		t.Fatalf("the configuration in effect: %v", r)
	}
	if r := test(f, `{"set":{"ARCHIVE_OBJECT_LOCK_DAYS":"400","ARCHIVE_OBJECT_LOCK_MODE":"GOVERNANCE"}}`); r["ok"] != true ||
		!strings.Contains(r["message"].(string), "Object Lock enabled") || f.srv.Count(s3test.OpGetLockConfig) != 1 {
		t.Fatalf("with Object Lock: %v", r)
	}
	if r := test(f, `{"set":{"ARCHIVE_S3_BUCKET":"example-bucket-missing"}}`); r["ok"] != false {
		t.Fatalf("a missing bucket passed: %v", r)
	}
	if r := test(f, `{"set":{"ARCHIVE_S3_REGION":"Not A Region"}}`); r["ok"] != false || !strings.Contains(r["message"].(string), "ARCHIVE_S3_REGION") {
		t.Fatalf("an invalid region: %v", r)
	}
	if r := test(f, `{"set":{"ARCHIVE_ALLOW_HTTP":"true"}}`); r["ok"] != false || !strings.Contains(r["message"].(string), "Advanced") {
		t.Fatalf("widening the Advanced flags: %v", r)
	}
	// The stored secret only goes to the saved endpoint and key ID.
	for _, body := range []string{
		`{"set":{"ARCHIVE_S3_ENDPOINT":"https://s3.example.net"}}`,
		`{"set":{"ARCHIVE_S3_ACCESS_KEY_ID":"005otherKeyID"}}`,
	} {
		if r := test(f, body); r["ok"] != false || !strings.Contains(r["message"].(string), "Enter the secret access key") {
			t.Fatalf("%s with the stored secret: %v", body, r)
		}
	}
	if r := test(f, `{"set":{"ARCHIVE_S3_ACCESS_KEY_ID":"005otherKeyID","ARCHIVE_S3_SECRET_ACCESS_KEY":"`+archUISecret+`"}}`); r["ok"] != true {
		t.Fatalf("another key ID with its secret typed in: %v", r)
	}
	// A staging path typed into the form is probed only under the allowed
	// root: outside it nothing is created or written.
	outside := filepath.Join(t.TempDir(), "typed")
	if err := os.Mkdir(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	if r := test(f, `{"set":{"ARCHIVE_STAGING_DIR":"`+outside+`"}}`); !strings.Contains(r["staging"].(string), "outside ARCHIVE_ALLOWED_ROOT") {
		t.Fatalf("a typed staging path outside the root: %v", r)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("Test connection wrote into a directory outside the root: %v", ents)
	}
	inside := filepath.Join(f.root, "staging-2")
	if err := os.Mkdir(inside, 0o750); err != nil {
		t.Fatal(err)
	}
	if r := test(f, `{"set":{"ARCHIVE_STAGING_DIR":"`+inside+`"}}`); !strings.Contains(r["staging"].(string), "is writable with enough free space") ||
		r["staging_checks"] == nil {
		t.Fatalf("a typed staging path under the root: %v", r)
	}
	if ents, _ := os.ReadDir(inside); len(ents) != 0 {
		t.Fatalf("the probe left files behind: %v", ents)
	}
	if res, _ := f.db.ResolveArchiveConfig(context.Background(), f.h.config.Archive); len(res.UI) != 0 {
		t.Fatalf("Test connection stored %v", res.UI)
	}

	// A bucket without Object Lock fails the lock check.
	g := archSettingsSetup(t, s3test.WithoutObjectLock())
	if r := test(g, `{"set":{"ARCHIVE_OBJECT_LOCK_DAYS":"400","ARCHIVE_OBJECT_LOCK_MODE":"GOVERNANCE"}}`); r["ok"] != false ||
		!strings.Contains(r["message"].(string), "Object Lock") {
		t.Fatalf("a bucket without Object Lock: %v", r)
	}
}
