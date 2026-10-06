package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/archive/worker"
	"firewall-mon/internal/config"
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
		code := archiveCmd(args, &out, &errb, &config.Config{}, open, func() (worker.MonthReader, error) { return nil, errors.New("no bucket in this test") })
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
		code := archiveCmd(args, &out, &errb, &config.Config{}, noDB, func() (worker.MonthReader, error) {
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

// TestArchiveCmd_Status: --status prints the archive (the parked chunk and
// whether it holds its table's deletes, the released gate, the months, the
// worker's last failure) and --status --json the API's JSON; --json alone and
// --status with another option are usage errors. Neither credential is
// printed.
func TestArchiveCmd_Status(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	const keyID, secret = "keyid-test-qrst", "secret-test-value-never-printed"
	cfg := &config.Config{}
	cfg.Archive = config.ArchiveConfig{FlowsEnabled: true, Endpoint: "https://s3.example.com", Region: "us-test-1",
		Bucket: "example-bucket", Prefix: "fwmon-test", AccessKeyID: keyID, SecretAccessKey: config.Secret(secret), StagingDir: "/tmp/x"}
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := archiveCmd(args, &out, &errb, cfg, func() (archiveStore, error) { return keepOpenArchive{db}, nil },
			func() (worker.MonthReader, error) { return nil, errors.New("no bucket in this test") })
		return code, out.String(), errb.String()
	}
	for _, args := range [][]string{{"--json"}, {"--status", "--reason", "r"}, {"--status", "--gate-status"}, {"--status", "extra"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Fatalf("args %v: exit %d, want 2 (usage)", args, code)
		}
	}

	hour := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []models.ArchiveChunk{
		{SourceTable: "flow_samples", Seq: 1, IDLo: 0, IDHi: 10, PeriodStart: hour, PeriodEnd: hour.Add(time.Hour), Month: "2026-09", Status: models.ArchiveChunkVerified},
		{SourceTable: "flow_samples", Seq: 2, IDLo: 10, IDHi: 20, PeriodStart: hour.Add(time.Hour), PeriodEnd: hour.Add(2 * time.Hour), Month: "2026-09",
			Status: models.ArchiveChunkNeedsAttention, Mismatches: 3, Error: "count check shortfall"},
	} {
		if err := db.Gorm().Create(&c).Error; err != nil {
			t.Fatal(err)
		}
	}
	rec := status.NewRecorder("fw-example-02-9", "/tmp/x", 2<<30, secret, keyID)
	rec.Failed("verify", errors.New("GET with "+secret+" failed"), time.Now())
	js, err := rec.JSON(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}
	if err := db.SetArchiveGateOverride(database.ArchiveGateSyslog, time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	code, out, errb := run("--status")
	if code != 0 {
		t.Fatalf("--status: %d %q", code, errb)
	}
	for _, want := range []string{"syslog off, flows on", "key …qrst", "syslog  RELEASED by an override", "flows   engaged",
		"flow_samples (on): verified through id 10", "needs attention: chunk", "HOLDS its table's deletes: count check shortfall",
		"last verify failure", "[redacted]", "2026-09 open due"} {
		if !strings.Contains(out, want) {
			t.Errorf("--status lacks %q:\n%s", want, out)
		}
	}
	code, jsOut, errb := run("--status", "--json")
	if code != 0 {
		t.Fatalf("--status --json: %d %q", code, errb)
	}
	var st status.Status
	if err := json.Unmarshal([]byte(jsOut), &st); err != nil || len(st.NeedsAttention) != 1 || !st.NeedsAttention[0].HoldsGate {
		t.Fatalf("--json: %v %s", err, jsOut)
	}
	for _, leak := range []string{keyID, secret} {
		if strings.Contains(out+jsOut, leak) {
			t.Fatalf("--status printed %q", leak)
		}
	}
}
