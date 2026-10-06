//go:build integration

package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"
)

// TestArchiveRestore_PG_DropRacesQueuedBackfill: two sessions on PostgreSQL
// 16. While the restore worker queues the re-normalize of a loaded restore
// (its backfill row inserted, the transaction still open), an operator's drop
// of the same restore runs: it waits for the job row, then sees the queued
// backfill and refuses — never a pending backfill over a dropped table.
func TestArchiveRestore_PG_DropRacesQueuedBackfill(t *testing.T) {
	d := NewIntegrationDB(t)
	ctx := context.Background()
	job := &models.ArchiveRestoreJob{Stream: "syslog", SourceTable: export.TableSyslog, FromDay: "2026-10-01", ToDay: "2026-10-01",
		Renormalize: true, Status: models.ArchiveRestoreLoaded, ExpiresAt: time.Now().Add(time.Hour)}
	if err := d.db.Create(job).Error; err != nil {
		t.Fatal(err)
	}
	job.StagingTable = ArchiveRestoreTableName(job.ID, export.TableSyslog)
	d.db.Model(job).Update("staging_table", job.StagingTable)
	if err := d.EnsureArchiveRestoreTable(ctx, job); err != nil {
		t.Fatal(err)
	}
	dropped := make(chan error, 1)
	archiveRestoreRetryHook = func(*models.ArchiveRestoreJob) {
		go func() {
			_, err := d.DropArchiveRestore(ctx, job.ID, time.Now())
			dropped <- err
		}()
		select {
		case err := <-dropped:
			t.Errorf("the drop finished while the queueing transaction was open: %v", err)
			dropped <- err
		case <-time.After(500 * time.Millisecond): // the drop is waiting on the job row
		}
	}
	t.Cleanup(func() { archiveRestoreRetryHook = nil })
	n, err := d.RetryLoadedArchiveRestores(ctx)
	if err != nil || n != 1 {
		t.Fatalf("queue: %d %v", n, err)
	}
	if err := <-dropped; !errors.Is(err, ErrArchiveRestoreInUse) {
		t.Fatalf("the concurrent drop: %v, want ErrArchiveRestoreInUse", err)
	}
	got, _ := d.GetArchiveRestoreJob(job.ID)
	if got.Status != models.ArchiveRestoreDone || got.BackfillJobID == nil || !d.db.Migrator().HasTable(job.StagingTable) {
		t.Fatalf("after the race: %+v, table exists %v", got, d.db.Migrator().HasTable(job.StagingTable))
	}
}
