package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/models"
)

// Bucket names in either case (B2 shows "Firewall-Mon" and resolves it in any
// case): accepted by the form, not a location move once the archive holds
// chunks, and refused with the storage service's own answer — logged — when
// the service does not see the archive under the new spelling.

// syncBuffer is a log destination safe for the server's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return buf
}

// seedArchived gives the fixture's archive a chunk in the manifest and an
// object under its prefix in the bucket: the location is now locked.
func seedArchived(t *testing.T, f *archSettingsFixture) {
	t.Helper()
	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if err := f.db.Gorm().Create(&models.ArchiveChunk{SourceTable: "syslog_messages", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: day,
		PeriodEnd: day.AddDate(0, 0, 1), Month: "2026-09", Status: models.ArchiveChunkVerified}).Error; err != nil {
		t.Fatal(err)
	}
	cl, err := s3.New(f.h.config.Archive, archiveS3Options()...)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("synthetic chunk\n")
	if _, err := cl.Put(context.Background(), "syslog/2026-09/chunk-1.jsonl.zst", bytes.NewReader(body), int64(len(body)), nil); err != nil {
		t.Fatal(err)
	}
}

// TestSaveArchiveSettings_MixedCaseBucket: "Example-Bucket" is a valid bucket
// name (it was a 400 "not a valid bucket name" before), and enabling with it
// passes the preflight against a B2-like service.
func TestSaveArchiveSettings_MixedCaseBucket(t *testing.T) {
	f := archSettingsSetup(t)
	rec := f.save(`{"set":{"ARCHIVE_SYSLOG_ENABLED":"true","ARCHIVE_S3_BUCKET":"Example-Bucket"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable with bucket Example-Bucket: %d %s", rec.Code, rec.Body.String())
	}
	if a := f.resolved(t); !a.SyslogEnabled || a.Bucket != "Example-Bucket" {
		t.Fatalf("stored: enabled %v bucket %q", a.SyslogEnabled, a.Bucket)
	}
}

// TestSaveArchiveSettings_BucketCaseWhileLocked: with chunks, re-casing the
// bucket is not a 409 (the step-up is reached: a wrong password is a 403) and
// saves once the bucket under the new spelling lists the archive's objects;
// a different bucket is still a 409, and the stored location record is not
// touched by the save.
func TestSaveArchiveSettings_BucketCaseWhileLocked(t *testing.T) {
	f := archSettingsSetup(t)
	seedArchived(t, f)
	if rec := f.save(`{"set":{"ARCHIVE_S3_BUCKET":"Example-Bucket"},"password":"WRONG"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("re-cased bucket with chunks, wrong password: %d %s, want 403 (past the location lock)", rec.Code, rec.Body.String())
	}
	if rec := f.save(`{"set":{"ARCHIVE_S3_BUCKET":"example-bucket-2"},"password":"WRONG"}`); rec.Code != http.StatusConflict {
		t.Fatalf("another bucket with chunks: %d %s, want 409", rec.Code, rec.Body.String())
	}
	lists := f.srv.Count(s3test.OpListObjects)
	rec := f.save(`{"set":{"ARCHIVE_S3_BUCKET":"Example-Bucket"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-cased bucket with chunks: %d %s", rec.Code, rec.Body.String())
	}
	if f.resolved(t).Bucket != "Example-Bucket" || f.srv.Count(s3test.OpListObjects) <= lists {
		t.Fatalf("stored bucket %q, lists %d → %d: want Example-Bucket after a listing", f.resolved(t).Bucket, lists, f.srv.Count(s3test.OpListObjects))
	}
	// The prefix is part of every key: re-casing it is a move.
	if rec := f.save(`{"set":{"ARCHIVE_S3_PREFIX":"FWMON-TEST"},"password":"WRONG"}`); rec.Code != http.StatusConflict {
		t.Fatalf("re-cased prefix with chunks: %d %s, want 409", rec.Code, rec.Body.String())
	}
}

// TestSaveArchiveSettings_BucketCaseNotVisible: on a service that matches
// bucket names exactly (legacy AWS, MinIO), the re-cased name is another
// bucket: the save is refused (422) with the service's answer, logged at
// WARNING, and nothing is stored.
func TestSaveArchiveSettings_BucketCaseNotVisible(t *testing.T) {
	f := archSettingsSetup(t, s3test.WithCaseSensitiveBucket())
	seedArchived(t, f)
	logs := captureLog(t)
	rec := f.save(`{"set":{"ARCHIVE_S3_BUCKET":"Example-Bucket"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "not visible under the new spelling") ||
		!strings.Contains(rec.Body.String(), "the storage service answered NoSuchBucket") {
		t.Fatalf("re-cased bucket on a case-sensitive service: %d %s, want 422 with the service's answer", rec.Code, rec.Body.String())
	}
	if got := f.resolved(t).Bucket; got != archBucket {
		t.Fatalf("stored bucket %q after a refused save", got)
	}
	if l := logs.String(); !strings.Contains(l, "WARNING: archive settings: save refused (HTTP 422)") || !strings.Contains(l, "NoSuchBucket") {
		t.Fatalf("log %q, want the refusal and its reason", l)
	}
}

// TestArchiveSettings_ProviderErrorSurfaced: a preflight the storage service
// refuses shows the service's code and message — Test connection's message
// and the save's 422 — and both are logged at WARNING with that reason; the
// secret appears in neither.
func TestArchiveSettings_ProviderErrorSurfaced(t *testing.T) {
	f := archSettingsSetup(t)
	f.srv.SetFail(func(op s3test.Op, _ *http.Request) (int, string) {
		if op == s3test.OpListObjects {
			return http.StatusForbidden, "AccessDenied"
		}
		return 0, ""
	})
	logs := captureLog(t)
	rec := f.do(http.MethodPost, "/admin/api/archive/settings/test", `{}`)
	var got struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if msg, _ := got.Data["message"].(string); got.Data["ok"] != false || !strings.Contains(msg, "the storage service answered AccessDenied") {
		t.Fatalf("Test connection: %s", rec.Body.String())
	}
	rec = f.save(`{"set":{"ARCHIVE_SYSLOG_ENABLED":"true"},"password":"s3cret-pw"}`)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "the storage service answered AccessDenied") {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	l := logs.String()
	for _, want := range []string{
		"WARNING: archive settings: Test connection refused (HTTP 200): the bucket preflight failed: the storage service answered AccessDenied",
		"WARNING: archive settings: save refused (HTTP 422): Not saved: the bucket preflight failed: the storage service answered AccessDenied",
	} {
		if !strings.Contains(l, want) {
			t.Errorf("log %q lacks %q", l, want)
		}
	}
	if strings.Contains(l, archEnvSecret) || strings.Contains(rec.Body.String(), archEnvSecret) {
		t.Fatal("the secret reached the log or the response")
	}
	// A validation refusal (400) is logged with its reason too.
	logs2 := captureLog(t)
	if rec := f.save(`{"set":{"ARCHIVE_S3_BUCKET":"example/bucket"},"password":"WRONG"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid bucket: %d %s", rec.Code, rec.Body.String())
	}
	if l := logs2.String(); !strings.Contains(l, "save refused (HTTP 400)") || !strings.Contains(l, "not a valid bucket name") {
		t.Fatalf("log %q, want the 400 and its reason", l)
	}
}

// TestSaveArchiveSettings_LockFollowsRecordedLocation: the location lock
// judges a change against where the chunks were recorded as written
// (system_settings.archive_location), not against the configuration in
// effect. The environment's prefix changed under the archive: changing it
// back to the recorded one on the form passes the lock (and is saved), any
// other prefix is refused naming the recorded location. A bucket spelled
// exactly as recorded needs no listing even when the environment re-cased it.
func TestSaveArchiveSettings_LockFollowsRecordedLocation(t *testing.T) {
	ctx := context.Background()
	f := archSettingsSetup(t)
	seedArchived(t, f)
	recorded := f.h.config.Archive.Location()
	if rec, mismatch, err := f.db.CheckArchiveLocation(ctx, recorded); err != nil || mismatch || rec != recorded {
		t.Fatalf("record the location: %q %v %v", rec, mismatch, err)
	}
	f.h.config.Archive.Prefix = "fwmon-drift" // the environment changed under the archive

	if rec := f.save(`{"set":{"ARCHIVE_S3_PREFIX":"` + archPrefix + `"},"password":"WRONG"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("back to the recorded prefix: %d %s, want 403 (past the location lock)", rec.Code, rec.Body.String())
	}
	rec := f.save(`{"set":{"ARCHIVE_S3_PREFIX":"fwmon-other"},"password":"WRONG"}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "/"+archBucket+"/"+archPrefix+"/") {
		t.Fatalf("a third prefix: %d %s, want 409 naming the recorded location", rec.Code, rec.Body.String())
	}
	if rec := f.save(`{"set":{"ARCHIVE_S3_PREFIX":"` + archPrefix + `"},"password":"s3cret-pw"}`); rec.Code != http.StatusOK {
		t.Fatalf("back to the recorded prefix: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.resolved(t).Prefix; got != archPrefix {
		t.Fatalf("stored prefix %q, want %q", got, archPrefix)
	}

	// The environment re-cased the bucket; the form names it as recorded:
	// the same place, spelled as the chunks were written — no listing.
	f.h.config.Archive.Bucket = "EXAMPLE-BUCKET"
	lists := f.srv.Count(s3test.OpListObjects)
	if rec := f.save(`{"set":{"ARCHIVE_S3_BUCKET":"` + archBucket + `"},"password":"s3cret-pw"}`); rec.Code != http.StatusOK {
		t.Fatalf("bucket as recorded: %d %s", rec.Code, rec.Body.String())
	}
	if n := f.srv.Count(s3test.OpListObjects); n != lists {
		t.Fatalf("the bucket spelled as recorded was listed (%d → %d)", lists, n)
	}
	// Spelled otherwise than the record: listed, and the record's spelling
	// is the one the refusal would keep.
	if rec := f.save(`{"set":{"ARCHIVE_S3_BUCKET":"Example-Bucket"},"password":"s3cret-pw"}`); rec.Code != http.StatusOK || f.srv.Count(s3test.OpListObjects) <= lists {
		t.Fatalf("re-cased against the record: %d %s, lists %d → %d", rec.Code, rec.Body.String(), lists, f.srv.Count(s3test.OpListObjects))
	}
}
