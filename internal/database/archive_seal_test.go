package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"
)

// The month seal's database side (archive plan PR 7 review). SQLite.

func sealMonthRow(t *testing.T, d *Database, stream, month string) {
	t.Helper()
	if err := d.db.Create(&models.ArchiveMonth{Stream: stream, Month: month, Status: models.ArchiveMonthSealed}).Error; err != nil {
		t.Fatal(err)
	}
}

// TestArchiveTableProgress_ParkedChunkOfSealedMonth: a chunk parked in
// needs_attention does not end the verified run when its month is sealed for
// every stream of its table — and still does when it is not, or only for one
// of the flow table's two streams; other statuses still end it.
func TestArchiveTableProgress_ParkedChunkOfSealedMonth(t *testing.T) {
	v, na := models.ArchiveChunkVerified, models.ArchiveChunkNeedsAttention
	for _, tc := range []struct {
		name   string
		table  string
		sealed []string
		status string
		want   int64
	}{
		{"syslog sealed", export.TableSyslog, []string{export.StreamSyslog}, na, 30},
		{"syslog not sealed", export.TableSyslog, nil, na, 10},
		{"syslog sealed, pending", export.TableSyslog, []string{export.StreamSyslog}, models.ArchiveChunkPending, 10},
		{"flows, sflow only", export.TableFlows, []string{export.StreamSFlow}, na, 10},
		{"flows, both", export.TableFlows, []string{export.StreamSFlow, export.StreamNetFlow}, na, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			seedGateChunks(t, d, tc.table, gateChunk{1, 0, 10, v}, gateChunk{2, 10, 20, tc.status}, gateChunk{3, 20, 30, v})
			for _, s := range tc.sealed {
				sealMonthRow(t, d, s, "2026-08")
			}
			p, err := d.ArchiveTableProgress(context.Background(), tc.table)
			if err != nil {
				t.Fatal(err)
			}
			if p.VerifiedThroughID != tc.want {
				t.Fatalf("V = %d, want %d", p.VerifiedThroughID, tc.want)
			}
		})
	}
}

// TestResetArchiveChunk_RefusesSealedMonth: the A-5 reset refuses a parked
// chunk of a sealed month (its folder takes no write) and leaves it parked.
func TestResetArchiveChunk_RefusesSealedMonth(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedGateChunks(t, d, export.TableSyslog, gateChunk{1, 0, 10, models.ArchiveChunkNeedsAttention})
	sealMonthRow(t, d, export.StreamSyslog, "2026-08")
	var c models.ArchiveChunk
	d.db.First(&c)
	if _, err := d.ResetArchiveChunk(context.Background(), c.ID, "r", time.Now()); !errors.Is(err, ErrArchiveChunkSealed) {
		t.Fatalf("reset of a sealed month's chunk: %v", err)
	}
	if got, _ := d.GetArchiveChunk(c.ID); got.Status != models.ArchiveChunkNeedsAttention {
		t.Fatalf("status %s after a refused reset", got.Status)
	}
}

// TestArchiveGateEvents: an override records its interval (a new release
// ends the previous one; a clear ends it now), the poller's start opens a
// "disabled" interval for a disabled stream that has chunks and ends it once
// the stream is enabled again, and the overlap query finds them.
func TestArchiveGateEvents(t *testing.T) {
	d := NewDatabaseForTesting(t)
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	orig := archiveGateClock
	archiveGateClock = func() time.Time { return at }
	t.Cleanup(func() { archiveGateClock = orig })
	events := func(stream string) []models.ArchiveGateEvent {
		var evs []models.ArchiveGateEvent
		d.db.Where("stream = ?", stream).Order("id").Find(&evs)
		return evs
	}

	if err := d.SetArchiveGateOverride(ArchiveGateSyslog, at.Add(6*time.Hour)); err != nil {
		t.Fatal(err)
	}
	at = at.Add(time.Hour)
	if err := d.SetArchiveGateOverride(ArchiveGateSyslog, at.Add(2*time.Hour)); err != nil { // extended: ends the first
		t.Fatal(err)
	}
	at = at.Add(30 * time.Minute)
	if err := d.SetArchiveGateOverride(ArchiveGateSyslog, time.Time{}); err != nil { // cleared
		t.Fatal(err)
	}
	evs := events(ArchiveGateSyslog)
	if len(evs) != 2 || evs[0].Kind != models.ArchiveGateEventOverride || !evs[0].To.Equal(at.Add(-30*time.Minute)) ||
		!evs[1].From.Equal(at.Add(-30*time.Minute)) || !evs[1].To.Equal(at) {
		t.Fatalf("override events %+v", evs)
	}

	// Flows disabled with chunks: opened once, ended on enabling.
	seedGateChunks(t, d, export.TableFlows, gateChunk{1, 0, 10, models.ArchiveChunkVerified})
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true}
	for range 2 {
		if err := d.RecordArchiveGateState(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if evs := events(ArchiveGateFlows); len(evs) != 1 || evs[0].Kind != models.ArchiveGateEventDisabled || evs[0].To != nil {
		t.Fatalf("disabled events %+v", evs)
	}
	if evs := events(ArchiveGateSyslog); len(evs) != 2 {
		t.Fatalf("an enabled stream got a disabled event: %+v", evs)
	}
	at = at.Add(24 * time.Hour)
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true, Flows: true}
	if err := d.RecordArchiveGateState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if evs := events(ArchiveGateFlows); len(evs) != 1 || evs[0].To == nil || !evs[0].To.Equal(at) {
		t.Fatalf("disabled event after enabling %+v", evs)
	}
	got, err := d.ArchiveGateEventsOverlapping(context.Background(), ArchiveGateSyslog, at.Add(-25*time.Hour), at.Add(-24*time.Hour-45*time.Minute))
	if err != nil || len(got) != 1 {
		t.Fatalf("overlapping %+v %v, want the extended override only", got, err)
	}
}
