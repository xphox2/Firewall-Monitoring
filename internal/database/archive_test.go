package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"
)

// The archive planner and export reads (archive plan PR 3) on the SQLite
// lane. Synthetic fixtures only: RFC 5737 addresses, fw-example-NN.

var archiveCtx = context.Background()

func archiveMemOpen(bufs map[export.ObjectID]*bytes.Buffer) export.OpenFunc {
	return func(id export.ObjectID) (io.Writer, error) {
		b := &bytes.Buffer{}
		bufs[id] = b
		return b, nil
	}
}

func archiveLines(t *testing.T, b *bytes.Buffer) []map[string]any {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %v: %s", err, l)
		}
		out = append(out, m)
	}
	return out
}

// seedArchiveSyslog inserts one row per entry of created (ingest instants, in
// id order) and returns their ids.
func seedArchiveSyslog(t *testing.T, d *Database, created []time.Time) []int64 {
	t.Helper()
	ids := make([]int64, len(created))
	for i, c := range created {
		m := models.SyslogMessage{Timestamp: c.Add(-30 * time.Second), DeviceID: uint(1 + i%2), ProbeID: 1,
			Hostname: "fw-example-01", Message: "srcip=192.0.2.10 dstip=198.51.100.7", Severity: 5, CreatedAt: c}
		if err := d.db.Create(&m).Error; err != nil {
			t.Fatal(err)
		}
		ids[i] = int64(m.ID)
	}
	return ids
}

func planAll(t *testing.T, d *Database, table string, now time.Time) []models.ArchiveChunk {
	t.Helper()
	var out []models.ArchiveChunk
	for {
		c, err := d.PlanNextArchiveChunk(archiveCtx, table, now, 0)
		if err != nil {
			t.Fatalf("plan %s: %v", table, err)
		}
		if c == nil {
			return out
		}
		out = append(out, *c)
		if len(out) > 1000 {
			t.Fatal("planner does not terminate")
		}
	}
}

// TestArchiveManifestTables_V75: the four tables exist after the migrations
// and v75 re-runs as a no-op.
func TestArchiveManifestTables_V75(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if err := d.migrateArchiveManifestTables(); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"archive_chunks", "archive_objects", "archive_months", "archive_id_marks"} {
		if !d.db.Migrator().HasTable(tbl) {
			t.Fatalf("%s missing", tbl)
		}
	}
	// (table_name, seq) and (table_name, period_start) are unique.
	p := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	c := models.ArchiveChunk{SourceTable: export.TableSyslog, Seq: 1, PeriodStart: p, PeriodEnd: p.Add(24 * time.Hour), Month: "2026-10", Status: models.ArchiveChunkPending}
	if err := d.db.Create(&c).Error; err != nil {
		t.Fatal(err)
	}
	dup := c
	dup.ID, dup.PeriodStart = 0, p.Add(24*time.Hour)
	if err := d.db.Create(&dup).Error; err == nil {
		t.Fatal("a second chunk with the same seq was accepted")
	}
	dup.ID, dup.Seq, dup.PeriodStart = 0, 2, p
	if err := d.db.Create(&dup).Error; err == nil {
		t.Fatal("a second chunk for the same period was accepted")
	}
}

// TestArchivePlan_SyslogDaily: the syslog chunks are the UTC ingest days, cut
// by created_at, contiguous from id 0, one per day including an empty day,
// filed under the month of their day; a day is not cut before it is minAge old.
func TestArchivePlan_SyslogDaily(t *testing.T) {
	d := NewDatabaseForTesting(t)
	day := func(m time.Month, dd, h, mi int) time.Time { return time.Date(2026, m, dd, h, mi, 0, 0, time.UTC) }
	// 30 Sep (5 rows, the last one second before midnight), nothing on 1 Oct,
	// 2 Oct (3 rows, the first exactly at midnight), 3 Oct (2 rows).
	created := []time.Time{
		day(9, 30, 0, 5), day(9, 30, 6, 0), day(9, 30, 12, 0), day(9, 30, 18, 0), day(10, 1, 0, 0).Add(-time.Second),
		day(10, 2, 0, 0), day(10, 2, 9, 0), day(10, 2, 23, 59),
		day(10, 3, 1, 0), day(10, 3, 2, 0),
	}
	ids := seedArchiveSyslog(t, d, created)

	// 3 Oct is only 1 h old at 01:00 on 4 Oct: three chunks (30 Sep, 1 Oct, 2 Oct).
	got := planAll(t, d, export.TableSyslog, day(10, 4, 1, 0))
	if len(got) != 3 {
		t.Fatalf("%d chunks planned at 01:00 on 4 Oct, want 3: %+v", len(got), got)
	}
	got = append(got, planAll(t, d, export.TableSyslog, day(10, 4, 2, 0))...)
	if len(got) != 4 {
		t.Fatalf("%d chunks, want 4", len(got))
	}
	want := []struct {
		start      time.Time
		month      string
		idLo, idHi int64
	}{
		{day(9, 30, 0, 0), "2026-09", 0, ids[4]},
		{day(10, 1, 0, 0), "2026-10", ids[4], ids[4]}, // empty day: still a chunk
		{day(10, 2, 0, 0), "2026-10", ids[4], ids[7]},
		{day(10, 3, 0, 0), "2026-10", ids[7], ids[9]},
	}
	for i, w := range want {
		c := got[i]
		if c.Seq != int64(i+1) || !c.PeriodStart.Equal(w.start) || !c.PeriodEnd.Equal(w.start.Add(24*time.Hour)) ||
			c.Month != w.month || c.IDLo != w.idLo || c.IDHi != w.idHi || c.Status != models.ArchiveChunkPending || c.MarkLateByMs != nil {
			t.Errorf("chunk %d = seq %d [%s, %s) %s (%d, %d] %s; want [%s) %s (%d, %d]", i, c.Seq, c.PeriodStart, c.PeriodEnd, c.Month,
				c.IDLo, c.IDHi, c.Status, w.start, w.month, w.idLo, w.idHi)
		}
	}
	// Nothing more until 4 Oct is due, and 4 Oct has no rows yet: an empty chunk.
	if more := planAll(t, d, export.TableSyslog, day(10, 5, 1, 59)); len(more) != 0 {
		t.Fatalf("4 Oct planned before it was 2 h old: %+v", more)
	}
	more := planAll(t, d, export.TableSyslog, day(10, 5, 2, 0))
	if len(more) != 1 || more[0].IDLo != ids[9] || more[0].IDHi != ids[9] {
		t.Fatalf("4 Oct = %+v, want one empty chunk at %d", more, ids[9])
	}
}

// TestArchivePlan_SyslogCutIsExact: over many rows and random-length gaps in
// the ids, each chunk holds exactly its day's rows (the binary search lands on
// the last row created before midnight, never one off).
func TestArchivePlan_SyslogCutIsExact(t *testing.T) {
	d := NewDatabaseForTesting(t)
	start := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	var created []time.Time
	for i := 0; i < 400; i++ {
		// About 100 rows a day, with a few minutes' jitter and a run of rows
		// sharing one instant right at midnight.
		created = append(created, start.Add(time.Duration(i)*14*time.Minute+time.Duration(i%7)*time.Second))
	}
	ids := seedArchiveSyslog(t, d, created)
	// Gaps: delete every 5th row, as a purge or a rolled-back batch would.
	for i := 0; i < len(ids); i += 5 {
		if err := d.db.Exec("DELETE FROM syslog_messages WHERE id = ?", ids[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	chunks := planAll(t, d, export.TableSyslog, start.AddDate(0, 0, 10))
	if len(chunks) < 4 {
		t.Fatalf("%d chunks", len(chunks))
	}
	prev := int64(0)
	for _, c := range chunks {
		if c.IDLo != prev {
			t.Fatalf("chunk %d starts at %d, previous ended at %d", c.Seq, c.IDLo, prev)
		}
		prev = c.IDHi
		var inRange, inDay int64
		d.db.Model(&models.SyslogMessage{}).Where("id > ? AND id <= ?", c.IDLo, c.IDHi).Count(&inRange)
		for i, ts := range created {
			if i%5 != 0 && !ts.Before(c.PeriodStart) && ts.Before(c.PeriodEnd) {
				inDay++
			}
		}
		if inRange != inDay {
			t.Fatalf("chunk %d [%s): %d rows in its id range, %d created that day", c.Seq, c.PeriodStart.Format(time.DateOnly), inRange, inDay)
		}
	}
	if prev != ids[len(ids)-1] {
		t.Fatalf("the chunks end at %d, the last row is %d", prev, ids[len(ids)-1])
	}
}

// TestArchiveIDMarks_AndFlowPlan: marks are taken per due boundary (the first
// one only at the current boundary; boundaries missed during an outage all get
// the late mark, so the outage's rows land in the earliest open chunk), and
// the hourly flow chunks end at them.
func TestArchiveIDMarks_AndFlowPlan(t *testing.T) {
	d := NewDatabaseForTesting(t)
	h := func(hh, mm int) time.Time { return time.Date(2026, 10, 4, hh, mm, 0, 0, time.UTC) }
	addFlows := func(n int, src uint8) {
		for i := 0; i < n; i++ {
			f := models.FlowSample{Timestamp: h(9, 0), DeviceID: 7, SrcAddr: "192.0.2.10", DstAddr: "198.51.100.7", FlowSource: src}
			if err := d.db.Create(&f).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	mark := func(now time.Time) int {
		n, err := d.TakeArchiveIDMarks(archiveCtx, export.TableFlows, now)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := d.TakeArchiveIDMarks(archiveCtx, export.TableSyslog, h(10, 0)); err == nil {
		t.Fatal("syslog accepted id marks")
	}
	addFlows(5, 0) // rows from before the archive started
	if n := mark(h(10, 0)); n != 1 {
		t.Fatalf("first tick took %d marks, want 1", n)
	}
	if n := mark(h(10, 1)); n != 0 {
		t.Fatalf("a second tick in the same hour took %d marks", n)
	}
	addFlows(3, 1)
	mark(h(11, 0))
	addFlows(4, 0)
	// The poller is down from 11:30 to 13:20: 12:00 and 13:00 both get the 13:20 mark.
	if n := mark(h(13, 20)); n != 2 {
		t.Fatalf("late tick took %d marks, want 2", n)
	}
	addFlows(2, 3)
	mark(h(14, 0))
	// The newest rows purged before the next mark: max(id) drops, the mark
	// does not (ids are never reused; a lower mark would overlap chunks).
	if err := d.db.Exec("DELETE FROM flow_samples WHERE id > 12").Error; err != nil {
		t.Fatal(err)
	}
	mark(h(15, 0))
	var m15 models.ArchiveIDMark
	if err := d.db.Where("boundary_ts = ?", h(15, 0)).First(&m15).Error; err != nil || m15.MaxID != 14 {
		t.Fatalf("mark after a purge of the newest rows = %d (%v), want 14", m15.MaxID, err)
	}
	d.db.Where("boundary_ts = ?", h(15, 0)).Delete(&models.ArchiveIDMark{})

	var marks []models.ArchiveIDMark
	d.db.Order("boundary_ts").Find(&marks)
	wantMax := []int64{5, 8, 12, 12, 14}
	if len(marks) != len(wantMax) {
		t.Fatalf("marks %+v", marks)
	}
	for i, m := range marks {
		if m.MaxID != wantMax[i] || !m.BoundaryTs.Equal(h(10+i, 0)) {
			t.Fatalf("mark %d = %s %d, want %s %d", i, m.BoundaryTs, m.MaxID, h(10+i, 0), wantMax[i])
		}
	}

	// Flows are due 5 minutes after the hour, minAge or not.
	if got := planAll(t, d, export.TableFlows, h(10, 4)); len(got) != 0 {
		t.Fatalf("planned before the 5-minute age: %+v", got)
	}
	chunks := planAll(t, d, export.TableFlows, h(14, 5))
	want := []struct {
		start      time.Time
		idLo, idHi int64
	}{{h(9, 0), 0, 5}, {h(10, 0), 5, 8}, {h(11, 0), 8, 12}, {h(12, 0), 12, 12}, {h(13, 0), 12, 14}}
	if len(chunks) != len(want) {
		t.Fatalf("%d flow chunks, want %d: %+v", len(chunks), len(want), chunks)
	}
	for i, w := range want {
		c := chunks[i]
		if !c.PeriodStart.Equal(w.start) || c.IDLo != w.idLo || c.IDHi != w.idHi || c.Month != "2026-10" || c.MarkLateByMs == nil {
			t.Fatalf("flow chunk %d = [%s) (%d, %d] late %v; want [%s) (%d, %d]", i, c.PeriodStart, c.IDLo, c.IDHi, c.MarkLateByMs, w.start, w.idLo, w.idHi)
		}
	}
	// The 11:00 chunk closed at the mark taken at 13:20 (SQLite: the Go clock).
	if late := *chunks[2].MarkLateByMs; late < 0 {
		t.Fatalf("mark_late_by_ms %d", late)
	}

	// Export the 11:00 chunk: one sflow object of its 4 rows; no netflow rows.
	bufs := map[export.ObjectID]*bytes.Buffer{}
	res, err := d.ExportArchiveChunk(archiveCtx, &chunks[2], export.FlowSchemaV1, ArchiveReadOptions{PageSize: 3}, archiveMemOpen(bufs))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 4 || len(res.Objects) != 1 || res.Objects[0].ID.Stream != export.StreamSFlow || res.Objects[0].MinID != 9 || res.Objects[0].MaxID != 12 {
		t.Fatalf("export %+v", res)
	}
	// The 10:00 chunk: netflow only.
	res, err = d.ExportArchiveChunk(archiveCtx, &chunks[1], export.FlowSchemaV1, ArchiveReadOptions{}, archiveMemOpen(map[export.ObjectID]*bytes.Buffer{}))
	if err != nil || len(res.Objects) != 1 || res.Objects[0].ID.Stream != export.StreamNetFlow || res.Rows != 3 {
		t.Fatalf("export %+v %v", res, err)
	}
}

// TestArchiveIDMarks_CountersDaily: flow_if_counters are marked at UTC
// midnights and cut daily, across a month boundary.
func TestArchiveIDMarks_CountersDaily(t *testing.T) {
	d := NewDatabaseForTesting(t)
	add := func(n int) {
		for i := 0; i < n; i++ {
			c := models.FlowInterfaceCounter{Timestamp: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC), DeviceID: 7, SamplerAddress: "192.0.2.1", IfIndex: uint32(i)}
			if err := d.db.Create(&c).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	add(3)
	if _, err := d.TakeArchiveIDMarks(archiveCtx, export.TableCounters, time.Date(2026, 9, 30, 0, 0, 30, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	add(2)
	if _, err := d.TakeArchiveIDMarks(archiveCtx, export.TableCounters, time.Date(2026, 10, 1, 0, 1, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	chunks := planAll(t, d, export.TableCounters, time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC))
	if len(chunks) != 2 || chunks[0].Month != "2026-09" || chunks[1].Month != "2026-09" ||
		!chunks[1].PeriodStart.Equal(time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)) || chunks[1].IDLo != 3 || chunks[1].IDHi != 5 {
		t.Fatalf("counter chunks %+v", chunks)
	}
	bufs := map[export.ObjectID]*bytes.Buffer{}
	res, err := d.ExportArchiveChunk(archiveCtx, &chunks[1], export.CounterSchemaV1, ArchiveReadOptions{}, archiveMemOpen(bufs))
	if err != nil || res.Rows != 2 || len(res.Objects) != 1 || res.Objects[0].ID.Stream != export.StreamSFlowCounters {
		t.Fatalf("counter export %+v %v", res, err)
	}
	if rows := archiveLines(t, bufs[res.Objects[0].ID]); len(rows) != 2 || rows[0]["id"].(float64) != 4 {
		t.Fatalf("counter rows %v", rows)
	}
}

// TestArchiveExport_SyslogRoundTrip: an exported chunk holds every row of its
// range once, in id order, per device; a re-export is byte-identical; the
// pacing hook holds the rate; the count check classifies match, a purge
// (shortfall) and a late commit.
func TestArchiveExport_SyslogRoundTrip(t *testing.T) {
	d := NewDatabaseForTesting(t)
	start := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	var created []time.Time
	for i := 0; i < 23; i++ {
		created = append(created, start.Add(time.Duration(i)*time.Hour))
	}
	ids := seedArchiveSyslog(t, d, created)
	fc := models.SyslogFormatRFC5424
	if err := d.db.Model(&models.SyslogMessage{}).Where("id = ?", ids[3]).Update("format", fc).Error; err != nil {
		t.Fatal(err)
	}
	chunks := planAll(t, d, export.TableSyslog, start.Add(30*time.Hour))
	if len(chunks) != 1 || chunks[0].IDHi != ids[22] {
		t.Fatalf("chunks %+v", chunks)
	}
	c := chunks[0]

	var waits []time.Duration
	orig := archiveSleep
	archiveSleep = func(_ context.Context, w time.Duration) error { waits = append(waits, w); return nil }
	t.Cleanup(func() { archiveSleep = orig })

	bufs := map[export.ObjectID]*bytes.Buffer{}
	res, err := d.ExportArchiveChunk(archiveCtx, &c, export.SyslogSchemaV2, ArchiveReadOptions{PageSize: 5, RowsPerSec: 10}, archiveMemOpen(bufs))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 23 || len(res.Objects) != 2 {
		t.Fatalf("export %+v", res)
	}
	// 23 rows in pages of 5: four full pages are paced (0.5 s each at 10
	// rows/s, minus the read time), the short last page ends the walk.
	if len(waits) != 4 {
		t.Fatalf("paced %d times, want 4: %v", len(waits), waits)
	}
	for _, w := range waits {
		if w <= 0 || w > 500*time.Millisecond {
			t.Fatalf("pace wait %s", w)
		}
	}
	seen := map[float64]bool{}
	for _, o := range res.Objects {
		var prev float64
		for _, r := range archiveLines(t, bufs[o.ID]) {
			id := r["id"].(float64)
			if id <= prev || seen[id] || r["device_id"].(float64) != float64(o.ID.DeviceID) {
				t.Fatalf("object %+v: row %v out of order, repeated or of another device", o.ID, r)
			}
			seen[id] = true
			prev = id
			if int64(id) == ids[3] && r["format"].(float64) != float64(fc) {
				t.Fatalf("stored format not exported: %v", r)
			}
			if int64(id) != ids[3] && r["format"] != nil {
				t.Fatalf("NULL format exported as %v", r["format"])
			}
		}
	}
	if len(seen) != 23 {
		t.Fatalf("%d distinct rows exported", len(seen))
	}
	again, err := d.ExportArchiveChunk(archiveCtx, &c, export.SyslogSchemaV2, ArchiveReadOptions{PageSize: 7}, archiveMemOpen(map[export.ObjectID]*bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Objects {
		if res.Objects[i].Sha256Content != again.Objects[i].Sha256Content || res.Objects[i].Sha256Object != again.Objects[i].Sha256Object {
			t.Fatal("a re-export with another page size is not byte-identical")
		}
	}

	var idSum int64
	for _, id := range ids {
		idSum += id
	}
	if res.IDSum != idSum {
		t.Fatalf("exported id sum %d, want %d", res.IDSum, idSum)
	}
	check := func(label string, exported *export.ChunkResult, rows int64, verdict string) {
		t.Helper()
		chk, err := d.CheckArchiveChunkCount(archiveCtx, &c, exported)
		if err != nil || chk.Rows != rows || chk.Verdict != verdict || chk.Verifiable() != (verdict == ArchiveCountMatch) {
			t.Fatalf("%s: %+v %v; want %d rows, %s", label, chk, err, rows, verdict)
		}
	}
	check("as exported", res, 23, ArchiveCountMatch)
	if err := d.db.Exec("DELETE FROM syslog_messages WHERE id = ?", ids[6]).Error; err != nil {
		t.Fatal(err)
	}
	check("after a purge", res, 22, ArchiveCountShortfall)
	// The export missed ids[5] (it committed after the read) and ids[6] was
	// purged since: as many rows as exported, other ids. A count-only check
	// calls that a match.
	missed := &export.ChunkResult{Rows: 22, IDSum: idSum - ids[5]}
	check("a late commit hidden by a purge", missed, 22, ArchiveCountLateCommit)
	// More rows than exported.
	if err := d.db.Create(&models.SyslogMessage{ID: uint(ids[6]), Timestamp: start, DeviceID: 1, CreatedAt: start}).Error; err != nil {
		t.Fatal(err)
	}
	check("a late commit", missed, 23, ArchiveCountLateCommit)
	// Fewer rows than exported, yet a row the export never saw: the export
	// missed the newest row, and the two oldest were purged since. A
	// count-only "fewer = purge" would call it a shortfall.
	if err := d.db.Exec("DELETE FROM syslog_messages WHERE id IN (?, ?)", ids[0], ids[1]).Error; err != nil {
		t.Fatal(err)
	}
	check("a late commit beside a purge", &export.ChunkResult{Rows: 22, IDSum: idSum - ids[22]}, 21, ArchiveCountLateCommit)

	if _, err := d.ExportArchiveChunk(archiveCtx, &models.ArchiveChunk{SourceTable: "interface_stats", IDHi: 1}, 1, ArchiveReadOptions{}, nil); err == nil {
		t.Fatal("an unarchived table was exported")
	}
}

// TestArchivePeriodStart: UTC day and hour floors whatever the zone of the
// input (the suite is also run under other TZ settings).
func TestArchivePeriodStart(t *testing.T) {
	ny := time.FixedZone("UTC-4", -4*3600)
	lh := time.FixedZone("UTC+10:30", 10*3600+1800)
	cases := []struct {
		in     time.Time
		period time.Duration
		want   time.Time
	}{
		{time.Date(2026, 10, 31, 21, 15, 0, 0, ny), 24 * time.Hour, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 10, 1, 9, 45, 0, 0, lh), 24 * time.Hour, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 10, 1, 9, 45, 0, 0, lh), time.Hour, time.Date(2026, 9, 30, 23, 0, 0, 0, time.UTC)},
		{time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC).Add(-time.Nanosecond), 24 * time.Hour, time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		got := archivePeriodStart(c.in, c.period)
		if !got.Equal(c.want) || got.Location() != time.UTC {
			t.Errorf("archivePeriodStart(%s, %s) = %s, want %s", c.in, c.period, got, c.want)
		}
	}
}

// TestArchivePlan_RefusesImplausibleFirstRow: the first syslog chunk starts at
// the ingest day of the oldest row; a created_at far older than any retention
// (a forged stamp from before 0.11.301) or in the future is refused instead of
// planning a chunk per day back to it (or never).
func TestArchivePlan_RefusesImplausibleFirstRow(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name    string
		created time.Time
		ok      bool
	}{
		{"forged past", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"future", now.Add(48 * time.Hour), false},
		{"a month ago", now.AddDate(0, -1, 0), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			seedArchiveSyslog(t, d, []time.Time{c.created, now.Add(-24 * time.Hour)})
			chunk, err := d.PlanNextArchiveChunk(archiveCtx, export.TableSyslog, now, 0)
			if c.ok {
				if err != nil || chunk == nil {
					t.Fatalf("plan = %v, %v; want the first chunk", chunk, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "not planning from it") || chunk != nil {
				t.Fatalf("plan = %+v, %v; want a refusal", chunk, err)
			}
			var n int64
			d.db.Model(&models.ArchiveChunk{}).Count(&n)
			if n != 0 {
				t.Fatalf("%d chunks recorded", n)
			}
		})
	}
}
