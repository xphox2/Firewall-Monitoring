package status

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The sync view of the status (backlog, throughput and ETA, the current
// chunk, recent and retrying chunks, archived totals, the next seal), the
// live countdown of a settling chunk, and the retention gate's switch reads.

// object adds a verified object of c to stream.
func object(t *testing.T, db *database.Database, c models.ArchiveChunk, stream string, rows, objBytes int64) {
	t.Helper()
	o := models.ArchiveObject{ChunkID: c.ID, Stream: stream, ObjectKey: "fwmon-test/" + stream + "/" + c.Month + "/" + strings.Repeat("x", int(c.Seq)),
		SchemaVersion: 1, Compression: "gzip", RowCount: rows, RawBytes: objBytes * 4, ObjectBytes: objBytes, Status: models.ArchiveObjectVerified}
	if err := db.Gorm().Create(&o).Error; err != nil {
		t.Fatal(err)
	}
}

// timed marks chunk c verified at verified after an attempt of dur that
// read rows.
func timed(t *testing.T, db *database.Database, c *models.ArchiveChunk, verified time.Time, dur time.Duration, rows int64) {
	t.Helper()
	started := verified.Add(-dur)
	if err := db.Gorm().Model(c).Updates(map[string]any{"started_at": started, "verified_at": verified, "row_count": rows}).Error; err != nil {
		t.Fatal(err)
	}
}

// TestBuild_SyncProgress: syslog mid catch-up — two days verified at 100
// rows/s, three planned days left (one failed, waiting for its retry) —
// reports its backlog, rate and ETA; the recent list is newest first across
// tables; totals come from the verified objects per stream and month; the
// next seal is the oldest month not sealed; the worker's current chunk
// carries its elapsed time and fraction.
func TestBuild_SyncProgress(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	day := 24 * time.Hour
	d := func(m time.Month, dd int) time.Time { return time.Date(2026, m, dd, 0, 0, 0, 0, time.UTC) }
	c1 := chunk(t, db, export.TableSyslog, 1, 0, 1000, d(9, 29), day, models.ArchiveChunkVerified)
	c2 := chunk(t, db, export.TableSyslog, 2, 1000, 3000, d(9, 30), day, models.ArchiveChunkVerified)
	timed(t, db, &c1, at.Add(-3*time.Hour), 10*time.Second, 1000) // 100 rows/s
	timed(t, db, &c2, at.Add(-2*time.Hour), 20*time.Second, 2000) // 100 rows/s
	chunk(t, db, export.TableSyslog, 3, 3000, 7000, d(10, 1), day, models.ArchiveChunkExporting)
	failed := chunk(t, db, export.TableSyslog, 4, 7000, 8000, d(10, 2), day, models.ArchiveChunkFailed)
	upd := at.Add(-time.Minute)
	db.Gorm().Model(&failed).Updates(map[string]any{"attempts": 2, "error": "upload: 503 SlowDown", "updated_at": upd})
	chunk(t, db, export.TableSyslog, 5, 8000, 9000, d(10, 3), day, models.ArchiveChunkPending)
	fl := chunk(t, db, export.TableFlows, 1, 0, 50, at.Add(-2*time.Hour), time.Hour, models.ArchiveChunkVerified)
	timed(t, db, &fl, at.Add(-time.Hour), 5*time.Second, 50)
	object(t, db, c1, export.StreamSyslog, 600, 1000)
	object(t, db, c1, export.StreamSyslog, 400, 500)
	object(t, db, c2, export.StreamSyslog, 2000, 3000)
	object(t, db, fl, export.StreamSFlow, 30, 70)
	object(t, db, fl, export.StreamNetFlow, 20, 30)

	r := NewRecorder("fw-example-01-1", "/tmp/fwmon-archive-test", 2<<30)
	r.SetPreflight(true)
	r.SetPasses(at.Add(-4*time.Minute), at.Add(6*time.Minute))
	r.StartActivity(&Activity{Table: export.TableSyslog, ChunkID: 3, Seq: 3, PeriodStart: d(10, 1), PeriodEnd: d(10, 2),
		Stage: "export", StartedAt: at.Add(-90 * time.Second), StageStartedAt: at.Add(-80 * time.Second), RowsDone: 900, IDSpan: 4000, IDsDone: 1000})
	js, _ := r.JSON(at.Add(-10 * time.Second))
	if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}

	st := build(t, db, testConfig(true, true), at)
	b := tableOf(t, st, export.TableSyslog).Backlog
	if b == nil || b.Chunks != 5 || b.Verified != 2 || b.Remaining != 3 || b.State != "catching_up" || b.RemainingRows != 6000 ||
		b.OldestRemaining == nil || !b.OldestRemaining.Equal(d(10, 1)) {
		t.Fatalf("syslog backlog %+v", b)
	}
	if b.RateRowsPerSec == nil || *b.RateRowsPerSec != 100 || b.ETASeconds == nil || *b.ETASeconds != 60 {
		t.Fatalf("syslog rate %v, ETA %v: want 100 rows/s and 60 s for 6000 rows", b.RateRowsPerSec, b.ETASeconds)
	}
	if fb := tableOf(t, st, export.TableFlows).Backlog; fb == nil || fb.State != "caught_up" || fb.Remaining != 0 || fb.ETASeconds != nil {
		t.Fatalf("flows backlog %+v", fb)
	}
	if len(st.Recent) != 3 || st.Recent[0].ID != fl.ID || st.Recent[1].ID != c2.ID || st.Recent[2].ID != c1.ID {
		t.Fatalf("recent %+v, want flows then syslog 2, 1", st.Recent)
	}
	if r := st.Recent[2]; r.Objects != 2 || r.ObjectBytes != 1500 || r.RawBytes != 6000 || r.DurationSeconds == nil || *r.DurationSeconds != 10 || r.Rows != 1000 {
		t.Fatalf("recent syslog 1 %+v", r)
	}
	if len(st.Retrying) != 1 || st.Retrying[0].ID != failed.ID || st.Retrying[0].RetryAt == nil ||
		!st.Retrying[0].RetryAt.Equal(upd.Add(database.ArchiveRetryBackoff(2))) || st.Retrying[0].Error != "upload: 503 SlowDown" {
		t.Fatalf("retrying %+v", st.Retrying)
	}
	sv := streamOf(t, st, export.StreamSyslog)
	if sv.ArchivedObjects != 3 || sv.ArchivedRows != 3000 || sv.ArchivedObjectBytes != 4500 || sv.ArchivedRawBytes != 18000 {
		t.Fatalf("syslog totals %+v", sv)
	}
	if sv.NextSeal == nil || sv.NextSeal.Month != "2026-09" || !sv.NextSeal.Due || !sv.NextSeal.DueAt.Equal(d(10, 1).Add(48*time.Hour)) {
		t.Fatalf("syslog next seal %+v, want 2026-09 due at 3 Oct (grace 48 h)", sv.NextSeal)
	}
	for _, m := range sv.Months {
		if m.Month == "2026-09" && (m.ArchivedRows != 3000 || m.ArchivedObjects != 3 || m.ArchivedObjectBytes != 4500) {
			t.Fatalf("2026-09 archived %+v", m)
		}
	}
	if s := streamOf(t, st, export.StreamNetFlow); s.ArchivedRows != 20 || s.ArchivedObjects != 1 {
		t.Fatalf("netflow totals %+v", s)
	}
	w := st.Worker
	if w == nil || w.Activity == nil || w.Activity.ChunkID != 3 || w.Activity.ElapsedSeconds != 90 || w.Activity.StageElapsedSeconds != 80 ||
		w.Activity.Fraction == nil || *w.Activity.Fraction != 0.25 || w.NextPassAt == nil || !w.NextPassAt.Equal(at.Add(6*time.Minute)) {
		t.Fatalf("worker %+v activity %+v", w, w.Activity)
	}
	raw, _ := json.Marshal(st)
	for _, k := range []string{`"backlog"`, `"eta_seconds"`, `"recent"`, `"retrying"`, `"retry_at"`, `"archived_rows"`, `"next_seal"`, `"activity"`, `"fraction"`, `"next_pass_at"`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("status JSON has no %s", k)
		}
	}

	// A snapshot older than the chunk's verification shows it no longer.
	db.Gorm().Model(&models.ArchiveChunk{}).Where("id = ?", 3).Updates(map[string]any{"status": models.ArchiveChunkVerified, "verified_at": at.Add(-5 * time.Second)})
	if w := build(t, db, testConfig(true, true), at).Worker; w == nil || w.Activity != nil {
		t.Fatalf("the activity of a chunk verified since the snapshot is shown: %+v", w)
	}

	// A stale snapshot shows no current chunk: the worker is not running it.
	js, _ = r.JSON(at.Add(-StaleAfter - time.Minute))
	if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}
	if w := build(t, db, testConfig(true, true), at).Worker; w == nil || !w.Stale || w.Activity != nil {
		t.Fatalf("stale worker %+v", w)
	}
}

// TestBuild_SettlingCountsDown: the snapshot records when a settling chunk's
// window ends; the status computes the time left at the moment it is read,
// so the same snapshot read a minute later says less is left (it used to
// carry "1m0s left" for as long as it stood).
func TestBuild_SettlingCountsDown(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	seed(t, db)
	r := NewRecorder("fw-example-01-1", "/tmp/fwmon-archive-test", 2<<30)
	until := at.Add(time.Minute)
	r.SetWait(export.TableFlows, "settling", "chunk 2: the cut is settling", &until, at)
	js, _ := r.JSON(at)
	if err := db.SaveArchiveWorkerState(context.Background(), js); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		now  time.Time
		left float64
	}{{at, 60}, {at.Add(20 * time.Second), 40}, {at.Add(5 * time.Minute), 0}} {
		u := tableOf(t, build(t, db, testConfig(true, true), tc.now), export.TableFlows).Unsettled
		if u == nil || u.Reason != "settling" || u.LeftSeconds == nil || *u.LeftSeconds != tc.left || u.Until == nil || !u.Until.Equal(until) {
			t.Fatalf("at %s: %+v, want %v s left", tc.now.Sub(at), u, tc.left)
		}
	}
}

// TestGateReadCondition: ARCHIVE_GATE_UNREADABLE fires once the gate's reads
// have failed for longer than GateUnreadableAfter, says what the gate does
// meanwhile, and resolves when they succeed.
func TestGateReadCondition(t *testing.T) {
	since := at.Add(-GateUnreadableAfter)
	h := database.ArchiveGateHealth{SeenAt: at, FailingSince: &since, Error: "read the archive settings: no such table", HoldingAll: true}
	if c := GateReadCondition(h, at); c.Breached || !c.Known {
		t.Fatalf("at exactly %v: %+v, want not yet breached", GateUnreadableAfter, c)
	}
	c := GateReadCondition(h, at.Add(time.Second))
	if !c.Breached || c.Type != models.AlertTypeArchiveGateUnreadable || c.Fields["holding"] != "all" ||
		!strings.Contains(c.Message, "holds the retention") || !strings.Contains(c.Message, "no such table") {
		t.Fatalf("past the threshold: %+v", c)
	}
	h.HoldingAll = false
	if c := GateReadCondition(h, at.Add(time.Hour)); !c.Breached || c.Fields["holding"] != "last" || !strings.Contains(c.Message, "read last") {
		t.Fatalf("keeping the last switches: %+v", c)
	}
	if c := GateReadCondition(database.ArchiveGateHealth{SeenAt: at}, at); c.Breached || !c.Known || c.Recovery == "" {
		t.Fatalf("reads succeed: %+v", c)
	}
}

// TestBuild_GateRead: the card shows the poller's record of a failing gate
// while it is fresh, and nothing once it is stale or the reads succeed.
func TestBuild_GateRead(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	since := at.Add(-time.Hour)
	save := func(h database.ArchiveGateHealth) {
		if err := db.SaveArchiveGateHealth(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	}
	save(database.ArchiveGateHealth{SeenAt: at.Add(-5 * time.Minute), FailingSince: &since, Error: "timeout", HoldingAll: true})
	g := build(t, db, testConfig(true, true), at).GateRead
	if g == nil || !g.HoldingAll || g.ForSeconds != 3600 || g.Error != "timeout" {
		t.Fatalf("gate read %+v", g)
	}
	if g := build(t, db, testConfig(true, true), at.Add(StaleAfter+5*time.Minute)).GateRead; g != nil {
		t.Fatalf("a stale record is shown: %+v", g)
	}
	save(database.ArchiveGateHealth{SeenAt: at})
	if g := build(t, db, testConfig(true, true), at).GateRead; g != nil {
		t.Fatalf("reads succeed, still shown: %+v", g)
	}
}
