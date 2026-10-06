package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/worker"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// keepOpenArchive is keepOpen for the archive command's store slice.
type keepOpenArchive struct{ *database.Database }

func (keepOpenArchive) Close() error { return nil }

// TestArchiveCmd: usage errors change nothing; --override releases a stream
// for the given time (audited, reason required, at most 24 h), --clear
// re-engages it; --reset-chunk resets only a chunk in needs_attention;
// --gate-status prints both.
func TestArchiveCmd(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	open := func() (archiveStore, error) { return keepOpenArchive{db}, nil }
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := archiveCmd(args, &out, &errb, open, func() (worker.MonthReader, error) { return nil, errors.New("no bucket in this test") })
		return code, out.String(), errb.String()
	}
	audits := func(action string) int64 {
		var n int64
		db.Gorm().Model(&models.AuditLog{}).Where("action = ? AND actor = ?", action, "cli").Count(&n)
		return n
	}

	for _, args := range [][]string{
		{}, {"extra"}, {"--bogus"},
		{"--override", "sflow", "--for", "1h", "--reason", "r"},
		{"--override", "syslog", "--for", "25h", "--reason", "r"},
		{"--override", "syslog", "--for", "0s", "--reason", "r"},
		{"--override", "syslog", "--for", "1h"},
		{"--override", "syslog", "--for", "1h", "--clear"},
		{"--for", "1h"},
		{"--reset-chunk", "1"},
		{"--reset-chunk", "1", "--gate-status"},
		{"--override", "syslog", "--for", "1h", "--reason", strings.Repeat("x", 501)},
	} {
		if code, _, _ := run(args...); code != 2 {
			t.Fatalf("args %v: exit %d, want 2 (usage)", args, code)
		}
	}
	if _, active := db.ArchiveGateOverride(database.ArchiveGateSyslog, time.Now()); active || audits("archive_gate_override") != 0 {
		t.Fatal("a usage error changed the gate")
	}

	code, out, errb := run("--override", "all", "--for", "2h", "--reason", "disk at 95%")
	if code != 0 || !strings.Contains(out, "RELEASED") {
		t.Fatalf("override: %d %q %q", code, out, errb)
	}
	for _, s := range database.ArchiveGateStreams {
		until, active := db.ArchiveGateOverride(s, time.Now())
		if !active || until.After(time.Now().Add(2*time.Hour+time.Minute)) || until.Before(time.Now().Add(time.Hour)) {
			t.Fatalf("%s: until %s active %v, want about 2 h", s, until, active)
		}
	}
	if n := audits("archive_gate_override"); n != 2 {
		t.Fatalf("audit rows %d, want 2", n)
	}
	if code, _, _ := run("--override", "flows", "--clear"); code != 0 {
		t.Fatalf("clear: %d", code)
	}
	if _, active := db.ArchiveGateOverride(database.ArchiveGateFlows, time.Now()); active {
		t.Fatal("flows override still active after --clear")
	}

	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	parked := models.ArchiveChunk{SourceTable: "flow_samples", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: day, PeriodEnd: day.Add(time.Hour),
		Month: "2026-09", Status: models.ArchiveChunkNeedsAttention, Mismatches: 3, Error: "sha256 mismatch"}
	if err := db.Gorm().Create(&parked).Error; err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run("--gate-status"); code != 0 || !strings.Contains(out, "syslog  gate RELEASED") || !strings.Contains(out, "sha256 mismatch") {
		t.Fatalf("--gate-status: %d %q", code, out)
	}
	if code, _, errb := run("--reset-chunk", "999", "--reason", "r"); code != 1 || !strings.Contains(errb, "not found") {
		t.Fatalf("unknown chunk: %d %q", code, errb)
	}
	if code, _, errb := run("--reset-chunk", "1", "--reason", "bucket policy fixed"); code != 0 {
		t.Fatalf("reset: %d %q", code, errb)
	}
	if c, _ := db.GetArchiveChunk(parked.ID); c.Status != models.ArchiveChunkPending || audits("archive_chunk_reset") != 1 {
		t.Fatalf("after reset: %+v", c)
	}
	if code, _, errb := run("--reset-chunk", "1", "--reason", "again"); code != 1 || !strings.Contains(errb, "not needs_attention") {
		t.Fatalf("second reset: %d %q", code, errb)
	}
}

// monthBucket is a read-only bucket holding one object (a _MONTH.json).
type monthBucket struct {
	key  string
	body []byte
	gets int
}

func (b *monthBucket) Key(rel string) (string, error) { return "fwmon-test/" + rel, nil }
func (b *monthBucket) GetBytes(_ context.Context, rel, _ string, _ int64) ([]byte, s3.ObjectInfo, error) {
	b.gets++
	if rel != b.key {
		return nil, s3.ObjectInfo{}, s3.ErrNotFound
	}
	return b.body, s3.ObjectInfo{Key: "fwmon-test/" + rel, Size: int64(len(b.body))}, nil
}
func (b *monthBucket) Versions(context.Context, string) (int, error) { return 1, nil }
func (b *monthBucket) VerifyFull(context.Context, s3.PutResult, io.Writer) error {
	return errors.New("not expected")
}

// TestArchiveCmd_VerifyMonth: --verify-month takes exactly a stream and a
// month and needs no database; an unsealed month and a manifest that does
// not check out exit 1 with the reasons printed.
func TestArchiveCmd_VerifyMonth(t *testing.T) {
	noDB := func() (archiveStore, error) { t.Fatal("--verify-month opened the database"); return nil, nil }
	bucket := &monthBucket{key: "syslog/v2/2026-10/_MONTH.json", body: []byte(`{"kind":"fwmon-archive-month","manifest_version":1,"stream":"syslog","month":"2026-10","chunks":[]}`)}
	run := func(b *monthBucket, args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := archiveCmd(args, &out, &errb, noDB, func() (worker.MonthReader, error) {
			if b == nil {
				return nil, errors.New("ARCHIVE_S3_ENDPOINT is required")
			}
			return b, nil
		})
		return code, out.String(), errb.String()
	}
	for _, args := range [][]string{
		{"--verify-month", "syslog"},
		{"--verify-month", "syslog", "2026-10", "extra"},
		{"--verify-month", "syslog", "--gate-status", "2026-10"},
		{"--verify-month", "syslog", "--reason", "r", "2026-10"},
	} {
		if code, _, _ := run(bucket, args...); code != 2 {
			t.Fatalf("args %v: exit %d, want 2", args, code)
		}
	}
	if code, _, errb := run(nil, "--verify-month", "syslog", "2026-10"); code != 1 || !strings.Contains(errb, "ARCHIVE_S3_ENDPOINT") {
		t.Fatalf("no bucket config: %d %q", code, errb)
	}
	if code, _, errb := run(bucket, "--verify-month", "syslog", "2026-09"); code != 1 || !strings.Contains(errb, "not sealed") {
		t.Fatalf("unsealed month: %d %q", code, errb)
	}
	code, out, _ := run(bucket, "--verify-month", "syslog", "2026-10")
	if code != 1 || !strings.Contains(out, "PROBLEM:") || !strings.Contains(out, "FAILED:") || strings.Contains(out, "OK:") {
		t.Fatalf("bad manifest: %d %q", code, out)
	}
}
