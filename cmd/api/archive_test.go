package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

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
		code := archiveCmd(args, &out, &errb, open)
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
