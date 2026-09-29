package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The public dashboard tiles read boundary samples instead of every row. These
// pin which rows come back. Fixture rows sit at bucket midpoints, never near an
// edge: SQLite compares the rendered timestamp text, and a row within an hour
// of an edge can land on the other side across a DST change.

// sampleWindow is a 10-hour window split into ten 1-hour buckets.
func sampleWindow() (from, to time.Time) {
	to = time.Now().Truncate(time.Second)
	return to.Add(-10 * time.Hour), to
}

func seedIface(t *testing.T, d *Database, dev uint, idx int, ts time.Time, in int64) uint {
	t.Helper()
	r := models.InterfaceStats{DeviceID: dev, Index: idx, Timestamp: ts, Name: "wan1", InBytes: uint64(in), OutBytes: uint64(in * 2)}
	if err := d.db.Create(&r).Error; err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestSampleInterfaceStats_EarliestPerBucketPlusNewest(t *testing.T) {
	d := NewDatabaseForTesting(t)
	from, to := sampleWindow()
	at := func(h, m int) time.Time { return from.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }

	seedIface(t, d, 1, 1, from.Add(-30*time.Minute), 1) // before the window
	want := []uint{
		seedIface(t, d, 1, 1, at(0, 10), 100), // bucket 0: earliest of two
	}
	seedIface(t, d, 1, 1, at(0, 40), 150)
	// bucket 1: empty — a real gap, nothing returned
	dupA := seedIface(t, d, 1, 1, at(2, 30), 200) // bucket 2: same-instant duplicates
	seedIface(t, d, 1, 1, at(2, 30), 201)
	want = append(want, dupA)
	for h := 3; h <= 8; h++ {
		want = append(want, seedIface(t, d, 1, 1, at(h, 30), int64(h*100)))
	}
	endA := seedIface(t, d, 1, 1, at(9, 30), 900) // last bucket: duplicates at the window's newest instant
	seedIface(t, d, 1, 1, at(9, 30), 901)
	want = append(want, endA)
	seedIface(t, d, 2, 1, at(5, 30), 5) // other device
	seedIface(t, d, 1, 2, at(5, 30), 5) // other interface

	got, err := d.SampleInterfaceStats(1, 1, from, to, 10)
	if err != nil {
		t.Fatal(err)
	}
	var ids []uint
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %v, want %v (earliest per bucket, lowest id on ties, one point at the newest instant)", ids, want)
		}
	}
	for i := 1; i < len(got); i++ {
		if !got[i].Timestamp.After(got[i-1].Timestamp) {
			t.Fatalf("points %d and %d are not strictly increasing in time: a zero-length interval makes a spurious 0 rate", i-1, i)
		}
	}
}

// The newest row is appended even when it is not the earliest of its bucket,
// so the chart reaches "now" as the old stride sampling did.
func TestSampleInterfaceStats_AppendsNewestRow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	from, to := sampleWindow()
	first := seedIface(t, d, 1, 1, from.Add(9*time.Hour+10*time.Minute), 1)
	last := seedIface(t, d, 1, 1, from.Add(9*time.Hour+50*time.Minute), 2)
	got, err := d.SampleInterfaceStats(1, 1, from, to, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != first || got[1].ID != last {
		t.Fatalf("got %d rows, want the bucket's earliest (%d) then the newest (%d)", len(got), first, last)
	}
}

func TestSampleInterfaceStats_BucketBoundsAndEmptyWindow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	from, to := sampleWindow()
	for h := 0; h < 10; h++ {
		seedIface(t, d, 1, 1, from.Add(time.Duration(h)*time.Hour+30*time.Minute), int64(h))
	}
	if got, err := d.SampleInterfaceStats(1, 1, from, to, 5000); err != nil || len(got) != 10 {
		t.Fatalf("1000 buckets (clamped from 5000): %d rows, err %v — SQLite must not hit its compound-SELECT cap", len(got), err)
	}
	if got, err := d.SampleInterfaceStats(1, 1, from, to, 1); err != nil || len(got) != 3 {
		t.Fatalf("buckets clamped up to 2: %d rows, err %v; want 2 bucket rows + the newest", len(got), err)
	}
	if got, err := d.SampleInterfaceStats(1, 1, to, to, 10); err != nil || len(got) != 0 {
		t.Fatalf("empty window: %d rows, err %v", len(got), err)
	}
}

// The public bandwidth tile must never read the window unbounded again: every
// statement against interface_stats has to carry a LIMIT.
func TestSampleInterfaceStats_EveryProbeIsLimited(t *testing.T) {
	d := NewDatabaseForTesting(t)
	from, to := sampleWindow()
	seedIface(t, d, 1, 1, from.Add(30*time.Minute), 1)
	var stmts []string
	capture := func(tx *gorm.DB) { stmts = append(stmts, tx.Statement.SQL.String()) }
	// Raw(...).Scan runs the Row chain; Find runs the Query chain. Watch both.
	if err := d.db.Callback().Query().After("gorm:query").Register("test:sample_sql_q", capture); err != nil {
		t.Fatal(err)
	}
	if err := d.db.Callback().Row().After("gorm:row").Register("test:sample_sql_r", capture); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SampleInterfaceStats(1, 1, from, to, 10); err != nil {
		t.Fatal(err)
	}
	if len(stmts) != 1 {
		t.Fatalf("%d statements, want one", len(stmts))
	}
	if n := strings.Count(stmts[0], "LIMIT 1"); n != 11 {
		t.Fatalf("%d LIMIT 1 probes, want 11 (10 buckets + newest): %s", n, stmts[0])
	}
}

func TestSampleSystemStatus_SpansTheWholeWindow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	to := time.Now().Truncate(time.Second)
	from := to.Add(-168 * time.Hour)
	// 2,500 rows over the week — more than the old 2,000-row cap, which stopped
	// the tile about 31 hours in.
	at := func(i int) time.Time { return from.Add(time.Duration(i)*4*time.Minute + 2*time.Minute) }
	tmpl := models.SystemStatus{DeviceID: 7, Timestamp: at(0), CPUUsage: 0}
	if err := d.db.Create(&tmpl).Error; err != nil {
		t.Fatal(err)
	}
	cloneRows(t, d.db, "system_status", tmpl.ID, []string{"timestamp", "cpu_usage"}, 2499,
		func(k int) []any { i := k + 1; return []any{at(i), float64(i % 100)} })
	got, err := d.SampleSystemStatus(7, from, to, 180)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 170 || len(got) > 181 {
		t.Fatalf("%d points, want about 180", len(got))
	}
	if span := got[len(got)-1].Timestamp.Sub(got[0].Timestamp); span < 160*time.Hour {
		t.Fatalf("points span %v, want nearly the whole week", span)
	}
}

func TestGetSystemStatusSummary_WholeWindowAndEmpty(t *testing.T) {
	d := NewDatabaseForTesting(t)
	to := time.Now().Truncate(time.Second)
	from := to.Add(-168 * time.Hour)
	at := func(i int) time.Time { return from.Add(time.Duration(i)*230*time.Second + 115*time.Second) }
	cpuAt := func(i int) float64 {
		if i == 2400 { // day 6: past the old 2,000-row window
			return 97
		}
		return 10
	}
	tmpl := models.SystemStatus{DeviceID: 3, Timestamp: at(0), CPUUsage: cpuAt(0), MemoryUsage: 40, DiskUsage: 0, SessionCount: 0}
	if err := d.db.Create(&tmpl).Error; err != nil {
		t.Fatal(err)
	}
	cloneRows(t, d.db, "system_status", tmpl.ID, []string{"timestamp", "cpu_usage", "disk_usage", "session_count"}, 2599,
		func(k int) []any { i := k + 1; return []any{at(i), cpuAt(i), float64(i), i} })
	s, err := d.GetSystemStatusSummary(3, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if s.N != 2600 || s.CPUMax != 97 || s.MemAvg != 40 {
		t.Fatalf("summary = %+v, want 2600 rows, the day-6 peak 97 and mem avg 40", s)
	}
	if s.DiskUsage != 2599 || s.SessionCount != 2599 {
		t.Fatalf("disk/sessions = %v/%d, want the newest row's 2599", s.DiskUsage, s.SessionCount)
	}
	empty, err := d.GetSystemStatusSummary(99, from, to)
	if err != nil || empty != (SystemStatusSummary{}) {
		t.Fatalf("empty window = %+v, err %v; want all zero", empty, err)
	}
}
