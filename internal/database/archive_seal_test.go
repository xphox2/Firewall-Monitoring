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

func sealMonthRow(t *testing.T, d *Database, stream, month string, first, last int64) {
	t.Helper()
	if err := d.db.Create(&models.ArchiveMonth{Stream: stream, Month: month, Status: models.ArchiveMonthSealed, FirstID: &first, LastID: &last}).Error; err != nil {
		t.Fatal(err)
	}
}

// TestArchiveTableProgress_ParkedChunkOfSealedMonth: a chunk parked in
// needs_attention does not end the verified run when its month is sealed for
// every stream of its table and its range lies inside the sealed
// (first_id, last_id] — and still does when it is not sealed, sealed for only
// one of the flow table's two streams, or reaches past the sealed last_id
// (an edited row); other statuses still end it.
func TestArchiveTableProgress_ParkedChunkOfSealedMonth(t *testing.T) {
	v, na := models.ArchiveChunkVerified, models.ArchiveChunkNeedsAttention
	for _, tc := range []struct {
		name   string
		table  string
		sealed []string
		lastID int64
		status string
		want   int64
	}{
		{"syslog sealed", export.TableSyslog, []string{export.StreamSyslog}, 30, na, 30},
		{"syslog not sealed", export.TableSyslog, nil, 30, na, 10},
		{"syslog sealed, pending", export.TableSyslog, []string{export.StreamSyslog}, 30, models.ArchiveChunkPending, 10},
		{"chunk beyond the sealed last_id", export.TableSyslog, []string{export.StreamSyslog}, 15, na, 10},
		{"flows, sflow only", export.TableFlows, []string{export.StreamSFlow}, 30, na, 10},
		{"flows, both", export.TableFlows, []string{export.StreamSFlow, export.StreamNetFlow}, 30, na, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			seedGateChunks(t, d, tc.table, gateChunk{1, 0, 10, v}, gateChunk{2, 10, 20, tc.status}, gateChunk{3, 20, 30, v})
			for _, s := range tc.sealed {
				sealMonthRow(t, d, s, "2026-08", 0, tc.lastID)
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
	sealMonthRow(t, d, export.StreamSyslog, "2026-08", 0, 10)
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

// TestBackfillArchiveGateOverrides: v77 rebuilds the pre-upgrade overrides
// from their audit rows — a release is [at, until), ended early by a later
// release or re-engage of the same stream — using only rows older than the
// first recorded override event, and a re-run adds nothing.
func TestBackfillArchiveGateOverrides(t *testing.T) {
	d := NewDatabaseForTesting(t)
	at := func(h int) time.Time { return time.Date(2026, 10, 2, h, 0, 0, 0, time.UTC) }
	audit := func(created time.Time, target string) {
		if err := d.db.Create(&models.AuditLog{CreatedAt: created, Actor: "alice", Action: "archive_gate_override", Target: target, Status: 200}).Error; err != nil {
			t.Fatal(err)
		}
	}
	audit(at(1), `stream=syslog until=2026-10-02T07:00:00Z reason="disk at 95%"`)
	audit(at(3), `stream=syslog re-engaged reason=""`)
	audit(at(4), `stream=flows until=2026-10-02T06:00:00Z reason="bucket outage"`)
	audit(at(5), `stream=flows until=2026-10-02T09:00:00Z reason="longer"`)
	audit(at(6), `garbage`)
	// Recorded by 0.11.307 itself: its audit row must not be rebuilt again.
	u := at(12)
	if err := d.db.Create(&models.ArchiveGateEvent{Stream: ArchiveGateSyslog, Kind: models.ArchiveGateEventOverride, From: at(10), To: &u, CreatedAt: at(10)}).Error; err != nil {
		t.Fatal(err)
	}
	audit(at(10).Add(time.Second), `stream=syslog until=2026-10-02T12:00:00Z reason="recorded"`) // written just after its event
	for range 2 {
		if err := d.migrateArchiveGateEvents(); err != nil {
			t.Fatal(err)
		}
	}
	var evs []models.ArchiveGateEvent
	d.db.Order("from_ts, stream").Find(&evs)
	want := []struct {
		stream   string
		from, to int
	}{{ArchiveGateSyslog, 1, 3}, {ArchiveGateFlows, 4, 5}, {ArchiveGateFlows, 5, 9}, {ArchiveGateSyslog, 10, 12}}
	if len(evs) != len(want) {
		t.Fatalf("%d events, want %d: %+v", len(evs), len(want), evs)
	}
	for i, w := range want {
		e := evs[i]
		if e.Stream != w.stream || e.Kind != models.ArchiveGateEventOverride || !e.From.Equal(at(w.from)) || e.To == nil || !e.To.Equal(at(w.to)) {
			t.Fatalf("event %d = %s %s-%v, want %s %d:00-%d:00", i, e.Stream, e.From, e.To, w.stream, w.from, w.to)
		}
	}
}

// TestArchiveGateHold: a disabled stream whose "disabled" interval cannot be
// recorded at the poller start keeps its deletes gated; once the record
// succeeds (retried at most once a minute) it is recorded from the start and
// the deletes are ungated again.
func TestArchiveGateHold(t *testing.T) {
	d := NewDatabaseForTesting(t)
	start := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	clock := start
	orig := archiveGateClock
	archiveGateClock = func() time.Time { return clock }
	t.Cleanup(func() { archiveGateClock = orig })
	seedGateChunks(t, d, export.TableFlows, gateChunk{1, 0, 10, models.ArchiveChunkVerified})
	d.archiveGateCfg = ArchiveGateConfig{Syslog: true}
	if err := d.db.Migrator().DropTable(&models.ArchiveGateEvent{}); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordArchiveGateState(context.Background()); err == nil {
		t.Fatal("recording without the table succeeded")
	}
	if d.archiveGateFn(export.TableFlows) == nil || !d.archiveGate(context.Background(), export.TableFlows).on {
		t.Fatal("a disabled stream whose interval is not recorded is deleted ungated")
	}
	if err := d.db.AutoMigrate(&models.ArchiveGateEvent{}); err != nil {
		t.Fatal(err)
	}
	clock = start.Add(30 * time.Second)
	if d.archiveGateFn(export.TableFlows) == nil {
		t.Fatal("released before the retry interval")
	}
	clock = start.Add(2 * time.Minute)
	if d.archiveGateFn(export.TableFlows) != nil {
		t.Fatal("still held after the record succeeded")
	}
	var evs []models.ArchiveGateEvent
	d.db.Find(&evs)
	if len(evs) != 1 || evs[0].Kind != models.ArchiveGateEventDisabled || !evs[0].From.Equal(start) || evs[0].To != nil {
		t.Fatalf("events %+v, want one open disabled interval from the start", evs)
	}
}

// TestSetArchiveGateOverride_OneTransaction: when the setting cannot be
// written, the override's interval is not recorded either.
func TestSetArchiveGateOverride_OneTransaction(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.db.Migrator().DropTable(&models.SystemSetting{}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetArchiveGateOverride(ArchiveGateSyslog, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("override without a settings table succeeded")
	}
	var n int64
	d.db.Model(&models.ArchiveGateEvent{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d interval(s) recorded for an override that was not set", n)
	}
}
