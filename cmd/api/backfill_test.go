package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// keepOpenBackfill is keepOpen for the backfill command's store slice.
type keepOpenBackfill struct{ *database.Database }

func (keepOpenBackfill) Close() error { return nil }

// TestNormalizeBackfillCmd: usage errors change nothing; without the ingest
// watermark the command refuses; with it `--since 7d --rate 500 --window`
// queues one pending job with those parameters; a second queue is refused
// while it is active; --status prints it; --cancel cancels it; --resume puts
// it back to pending; --status on an empty queue says so.
func TestNormalizeBackfillCmd(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	open := func() (backfillStore, error) { return keepOpenBackfill{db}, nil }
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := normalizeBackfill(cfg, args, &out, &errb, open)
		return code, out.String(), errb.String()
	}

	for _, args := range [][]string{{"--since", "0"}, {"--since", "31d"}, {"--since", "x"}, {"--rate", "1"}, {"--window", "nope"},
		{"--status", "--cancel"}, {"extra"}, {"--bogus"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Fatalf("args %v: exit %d, want 2 (usage)", args, code)
		}
	}
	if code, out, _ := run("--status"); code != 0 || !strings.Contains(out, "no backfill job") {
		t.Fatalf("--status on an empty queue: %d %q", code, out)
	}
	if code, _, errb := run(); code != 1 || !strings.Contains(errb, "normalize_ingest_started_at") {
		t.Fatalf("without the watermark: %d %q", code, errb)
	}
	wm := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if _, err := db.InsertSettingIfAbsent(&models.SystemSetting{Key: database.NormalizeIngestStartedSetting, Value: wm.Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	cfg.Normalize.Disabled = true
	if code, _, errb := run(); code != 1 || !strings.Contains(errb, "NORMALIZE_ENABLED") {
		t.Fatalf("normalization disabled: %d %q", code, errb)
	}
	cfg.Normalize.Disabled = false

	code, out, errb := run("--since", "7d", "--rate", "500", "--window", "22:00-06:00", "--device", "0")
	if code != 0 {
		t.Fatalf("queue: exit %d, stderr %q", code, errb)
	}
	if !strings.Contains(out, "queued backfill job 1") {
		t.Fatalf("stdout %q", out)
	}
	job, err := db.GetLatestNormalizeBackfillJob()
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != database.NormalizeBackfillStatusPending || job.RequestedBy != "cli" || job.RateRowsPerSec != 500 ||
		job.Window != "22:00-06:00" || job.DeviceID != nil || !job.Until.Equal(wm) || job.Until.Sub(job.Since) > 7*24*time.Hour {
		t.Fatalf("queued job: %+v", job)
	}
	if code, _, errb := run(); code != 1 || !strings.Contains(errb, "already pending") {
		t.Fatalf("second queue while active: %d %q", code, errb)
	}
	if code, out, _ := run("--status"); code != 0 || !strings.Contains(out, "job 1: pending") || !strings.Contains(out, "run window 22:00-06:00") {
		t.Fatalf("--status: %d %q", code, out)
	}
	if code, out, _ := run("--cancel"); code != 0 || !strings.Contains(out, "job 1: cancelled") {
		t.Fatalf("--cancel: %d %q", code, out)
	}
	if code, _, errb := run("--cancel"); code != 1 || !strings.Contains(errb, "no active job") {
		t.Fatalf("--cancel with nothing active: %d %q", code, errb)
	}
	if code, out, _ := run("--resume"); code != 0 || !strings.Contains(out, "job 1: pending") {
		t.Fatalf("--resume: %d %q", code, out)
	}
	if job, _ = db.GetLatestNormalizeBackfillJob(); job.Status != database.NormalizeBackfillStatusPending {
		t.Fatalf("after --resume: %s", job.Status)
	}
	if code, _, errb := run("--resume"); code != 1 || !strings.Contains(errb, "already active") {
		t.Fatalf("--resume a pending job: %d %q", code, errb)
	}
	// --device must name an existing device (as the API checks); a known one
	// is recorded.
	if _, _, err := db.CancelNormalizeBackfillJob(job.ID); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := run("--device", "7"); code != 1 || !strings.Contains(errb, "device 7 not found") {
		t.Fatalf("queue with an unknown --device: %d %q, want exit 1 not found", code, errb)
	}
	if latest, _ := db.GetLatestNormalizeBackfillJob(); latest.ID != job.ID {
		t.Fatalf("an unknown --device queued job %d", latest.ID)
	}
	dev := &models.Device{Name: "fw-example-07", IPAddress: "192.0.2.7", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	if code, _, errb := run("--device", fmt.Sprint(dev.ID)); code != 0 {
		t.Fatalf("queue with --device: %d %q", code, errb)
	}
	if job, _ = db.GetLatestNormalizeBackfillJob(); job.DeviceID == nil || *job.DeviceID != dev.ID {
		t.Fatalf("device filter not recorded: %+v", job)
	}

	// --resume re-runs the disk precheck over the remaining window.
	if _, _, err := db.CancelNormalizeBackfillJob(job.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Create(&models.SyslogIngestHourly{Timestamp: wm.Add(-24 * time.Hour).Truncate(time.Hour), Severity: 5, RowCount: 10_000_000}).Error; err != nil {
		t.Fatal(err)
	}
	free := uint64(1 << 30)
	if err := db.Gorm().Create(&models.ServerMetric{Timestamp: time.Now(), DataDiskFreeBytes: &free}).Error; err != nil {
		t.Fatal(err)
	}
	if code, _, errb := run("--resume"); code != 1 || !strings.Contains(errb, "insufficient disk headroom") {
		t.Fatalf("--resume under headroom: %d %q, want exit 1", code, errb)
	}
	if job, _ = db.GetLatestNormalizeBackfillJob(); job.Status != database.NormalizeBackfillStatusCancelled {
		t.Fatalf("after a refused --resume: %s, want cancelled", job.Status)
	}
}
