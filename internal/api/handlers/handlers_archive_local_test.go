package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/local"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// The local target in the admin form (0.11.315): the folder picker, Test
// and the save, with a temporary allowed root stubbed as a mount point.
// Synthetic data only.

// folders calls the folder picker with ?path=p ("" omits it).
func (f *archSettingsFixture) folders(t *testing.T, p string) (int, map[string]any) {
	t.Helper()
	target := "/admin/api/archive/settings/folders"
	if p != "" {
		target += "?path=" + url.QueryEscape(p)
	}
	c, rec := backfillCtx(http.MethodGet, target, "alice", f.u.ID, "")
	f.h.ListArchiveFolders(c)
	var got struct {
		Data  map[string]any `json:"data"`
		Error string         `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Data == nil {
		got.Data = map[string]any{"error": got.Error}
	}
	return rec.Code, got.Data
}

func dirNames(r map[string]any) []string {
	var out []string
	ds, _ := r["dirs"].([]any)
	for _, d := range ds {
		out = append(out, d.(map[string]any)["name"].(string))
	}
	return out
}

// TestListArchiveFolders: the picker lists the subdirectories of a
// directory under the root — no files, no hidden entries, no link leading
// out of the root — and refuses any path outside the root, by its text or
// through a link.
func TestListArchiveFolders(t *testing.T) {
	f := archSettingsSetup(t)
	outside := t.TempDir()
	for _, d := range []string{"nfs-archive", "local-disk", ".snapshot", "local-disk/fwmon"} {
		if err := os.MkdirAll(filepath.Join(f.root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.root, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.root, "local-disk"), filepath.Join(f.root, "alias")); err != nil {
		t.Fatal(err)
	}
	code, r := f.folders(t, "")
	if code != http.StatusOK || r["ok"] != true || r["path"] != f.root || r["root_mounted"] != true ||
		strings.Join(dirNames(r), ",") != "alias,local-disk,nfs-archive,staging" || r["parent"] != nil {
		t.Fatalf("the root: %d %v", code, r)
	}
	code, r = f.folders(t, filepath.Join(f.root, "local-disk"))
	if code != http.StatusOK || strings.Join(dirNames(r), ",") != "fwmon" || r["parent"] != f.root {
		t.Fatalf("a subdirectory: %d %v", code, r)
	}
	for _, p := range []string{outside, f.root + "/../" + filepath.Base(outside), "relative", f.root + "x", "/"} {
		if code, r := f.folders(t, p); code != http.StatusBadRequest {
			t.Errorf("path %q: %d %v, want 400", p, code, r)
		}
	}
	if code, r := f.folders(t, filepath.Join(f.root, "escape")); code != http.StatusOK || r["ok"] != false ||
		!strings.Contains(r["message"].(string), "outside ARCHIVE_ALLOWED_ROOT") || len(dirNames(r)) != 0 {
		t.Fatalf("a link out of the root: %d %v", code, r)
	}
	f.h.config.Archive.AllowedRoot = "/"
	if code, r := f.folders(t, ""); code != http.StatusOK || r["ok"] != false {
		t.Fatalf("root /: %d %v", code, r)
	}
}

// localDraft is the form switching to a local target at dir.
func localDraft(dir string) string {
	return `"ARCHIVE_TARGET":"local","ARCHIVE_LOCAL_DIR":"` + dir + `"`
}

// TestTestArchiveSettings_LocalTarget: Test of a local target probes the
// directory (every check reported), says the worker initialises it, warns
// when target and staging share a filesystem, and refuses a directory that
// is missing, outside the root, or under a root that is not a mount point.
func TestTestArchiveSettings_LocalTarget(t *testing.T) {
	f := archSettingsSetup(t)
	dir := filepath.Join(f.root, "nfs-archive")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	test := func(body string) map[string]any {
		t.Helper()
		rec := f.do(http.MethodPost, "/admin/api/archive/settings/test", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
		var got struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got.Data
	}
	r := test(`{"set":{` + localDraft(dir) + `}}`)
	if r["ok"] != true || r["target"] != "local" || !strings.Contains(r["message"].(string), "initialises") || r["checks"] == nil ||
		r["staging_checks"] == nil || !strings.Contains(strings.Join(anyStrings(r["warnings"]), " "), "same filesystem") {
		t.Fatalf("a local directory: %v", r)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("Test wrote into the directory: %v", ents)
	}
	if f.srv.Count("ListObjects") != 0 {
		t.Fatal("Test of a local target contacted the bucket")
	}
	if r := test(`{"set":{` + localDraft(filepath.Join(f.root, "missing")) + `}}`); r["ok"] != false || !strings.Contains(r["message"].(string), "mounted") {
		t.Fatalf("a missing directory: %v", r)
	}
	if r := test(`{"set":{` + localDraft(t.TempDir()) + `}}`); r["ok"] != false || !strings.Contains(r["message"].(string), "outside ARCHIVE_ALLOWED_ROOT") {
		t.Fatalf("a directory outside the root: %v", r)
	}
	local.IsMountPoint = func(string) (bool, error) { return false, nil }
	if r := test(`{"set":{` + localDraft(dir) + `}}`); r["ok"] != false || !strings.Contains(r["message"].(string), "not a mount point") {
		t.Fatalf("a root that is not a mount point: %v", r)
	}
}

func anyStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, s := range l {
		out = append(out, s.(string))
	}
	return out
}

// TestSaveArchiveSettings_LocalTarget: switching to a local target probes
// the directory after the step-up and enables archiving to it; once chunks
// exist the target type and the directory are locked (409 before the
// step-up, naming the switch), and a directory outside the root is refused
// before it (400).
func TestSaveArchiveSettings_LocalTarget(t *testing.T) {
	f := archSettingsSetup(t)
	dir := filepath.Join(f.root, "local-disk")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if rec := f.save(`{"set":{` + localDraft(t.TempDir()) + `},"password":"WRONG"}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "outside ARCHIVE_ALLOWED_ROOT") {
		t.Fatalf("outside the root: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.save(`{"set":{` + localDraft(filepath.Join(f.root, "missing")) + `,"ARCHIVE_SYSLOG_ENABLED":"true"},"password":"s3cret-pw"}`); rec.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(rec.Body.String(), "mounted") {
		t.Fatalf("a missing directory: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.save(`{"set":{` + localDraft(dir) + `,"ARCHIVE_SYSLOG_ENABLED":"true","ARCHIVE_OBJECT_LOCK_DAYS":"30","ARCHIVE_OBJECT_LOCK_MODE":"GOVERNANCE"},"password":"WRONG"}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "Object Lock") {
		t.Fatalf("Object Lock on a local target: %d %s", rec.Code, rec.Body.String())
	}
	rec := f.save(`{"set":{` + localDraft(dir) + `,"ARCHIVE_SYSLOG_ENABLED":"true"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable a local target: %d %s", rec.Code, rec.Body.String())
	}
	a := f.resolved(t)
	if !a.IsLocal() || a.LocalDir != dir || !a.SyslogEnabled || a.Location() != "file://"+dir+"/"+archPrefix+"/" {
		t.Fatalf("resolved %+v", a)
	}
	if v := f.view(t); v.Target != "local" || v.AllowedRoot != f.root || v.StagingOutsideRoot {
		t.Fatalf("view %+v", v)
	}

	// Chunks exist: the target type and the directory are fixed.
	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if err := f.db.Gorm().Create(&models.ArchiveChunk{SourceTable: "syslog_messages", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: day,
		PeriodEnd: day.AddDate(0, 0, 1), Month: "2026-09", Status: models.ArchiveChunkVerified}).Error; err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(f.root, "other")
	if err := os.Mkdir(other, 0o750); err != nil {
		t.Fatal(err)
	}
	for body, want := range map[string]string{
		`{"set":{"ARCHIVE_TARGET":"s3"},"password":"WRONG"}`:               "switching ARCHIVE_TARGET to s3",
		`{"set":{"ARCHIVE_LOCAL_DIR":"` + other + `"},"password":"WRONG"}`: "local directory and the prefix cannot change",
		`{"set":{"ARCHIVE_S3_PREFIX":"fwmon-test/b"},"password":"WRONG"}`:  "cannot change",
	} {
		if rec := f.save(body); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s with chunks: %d %s, want 409 %q", body, rec.Code, rec.Body.String(), want)
		}
	}
	if rec := f.save(`{"set":{"ARCHIVE_WINDOW":"01:00-05:00"},"password":"s3cret-pw"}`); rec.Code != http.StatusOK {
		t.Fatalf("another field with chunks: %d %s", rec.Code, rec.Body.String())
	}
	if !config.IsLocalLocation(f.resolved(t).Location()) {
		t.Fatal("the location changed")
	}
}
