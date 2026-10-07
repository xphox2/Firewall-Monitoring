//go:build integration

package worker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/local"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestWorker_PG_LocalTarget runs the archive worker on a real PostgreSQL
// (TEST_PG_DSN) with a local target: syslog days are exported, written to
// the directory, read back and counted to verified; the first pass writes the
// marker (ArchiveHasChunks false), and once chunks exist a directory without
// it (an unmounted share) makes a new worker's preflight fail instead of
// initialising it again (ArchiveHasChunks true, on PostgreSQL).
func TestWorker_PG_LocalTarget(t *testing.T) {
	d := database.NewIntegrationDB(t)
	if err := d.EnsurePartitions(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "archive")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := config.ArchiveConfig{SyslogEnabled: true, Target: config.ArchiveTargetLocal, LocalDir: dir, AllowedRoot: root,
		Prefix: testPrefix, MinAgeHours: 2, SyslogRateRowsPerSec: 100000, FlowRateRowsPerSec: 100000,
		SealGraceHours: 48, SealReverify: config.SealReverifyHead, StagingDir: t.TempDir()}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	orig := stagingFree
	stagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { stagingFree = orig })
	build := func() *Worker {
		st, err := local.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		w, err := newWorker(d, st, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}

	wall := time.Now().UTC()
	today := wall.Truncate(24 * time.Hour)
	for i, c := range []time.Time{today.AddDate(0, 0, -3).Add(9 * time.Hour), today.AddDate(0, 0, -2).Add(9 * time.Hour)} {
		m := models.SyslogMessage{Timestamp: c.Add(-time.Second), DeviceID: uint(1 + i), ProbeID: 1, Hostname: "fw-example-01",
			Message: "srcip=192.0.2.10 dstip=198.51.100.7", Severity: 5, CreatedAt: c}
		if err := d.Gorm().Create(&m).Error; err != nil {
			t.Fatal(err)
		}
	}
	database.SetArchiveSettleForTesting(t, 200*time.Millisecond, 100*time.Millisecond)
	w := build()
	var cs []models.ArchiveChunk
	for deadline := time.Now().Add(30 * time.Second); ; {
		w.lastPass = time.Time{}
		w.Tick(context.Background())
		cs = nil
		if err := d.Gorm().Where("table_name = ?", export.TableSyslog).Order("seq").Find(&cs).Error; err != nil {
			t.Fatal(err)
		}
		if len(cs) >= 2 && cs[0].Status == models.ArchiveChunkVerified && cs[1].Status == models.ArchiveChunkVerified {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("syslog chunks not verified within 30 s: %+v", cs)
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, c := range cs[:2] {
		if c.Status != models.ArchiveChunkVerified {
			t.Fatalf("chunk %d: %s %s", c.Seq, c.Status, c.Error)
		}
		var objs []models.ArchiveObject
		d.Gorm().Where("chunk_id = ?", c.ID).Find(&objs)
		for _, o := range objs {
			if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(o.ObjectKey))); err != nil || fi.Size() != o.ObjectBytes || o.VersionID != "1" {
				t.Fatalf("object %s: %v %v %+v", o.ObjectKey, fi, err, o)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.LocalBase(), local.MarkerName)); err != nil {
		t.Fatalf("no marker after the first pass: %v", err)
	}

	// The share is unmounted: a new worker must not initialise its mount point.
	if err := os.Rename(dir, dir+"-share"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	w2 := build()
	err := w2.preflightTarget(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the archive holds chunks") {
		t.Fatalf("preflight on the empty mount point = %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("the preflight wrote onto the empty mount point: %v", ents)
	}
}
